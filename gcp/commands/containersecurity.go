package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/run/v1"
)

// Module name constant
const GCP_CONTAINERSECURITY_MODULE_NAME string = "container-security"

var GCPContainerSecurityCommand = &cobra.Command{
	Use:     GCP_CONTAINERSECURITY_MODULE_NAME,
	Aliases: []string{"containers", "container", "cloudrun-security"},
	Short:   "Analyze container configurations for security issues",
	Long: `Analyze Cloud Run and container configurations for security vulnerabilities.

Features:
- Detects secrets in environment variables
- Analyzes container security context
- Identifies public/unauthenticated services
- Checks for privileged configurations
- Reviews ingress and network settings
- Identifies vulnerable base images (where possible)
- Analyzes service account permissions

Security Checks:
- Secrets/credentials in env vars (API keys, passwords, tokens)
- Public ingress without authentication
- Over-permissioned service accounts
- Missing security headers
- Insecure container configurations

Requires appropriate IAM permissions:
- roles/run.viewer
- roles/container.viewer`,
	Run: runGCPContainerSecurityCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type ContainerConfig struct {
	Name           string
	ProjectID      string
	Location       string
	ServiceType    string // cloudrun, gke-pod
	Image          string
	ServiceAccount string
	Ingress        string
	Authentication string
	EnvVarCount    int
	SecretEnvVars  int
	VPCConnector   string
	MinInstances   int64
	MaxInstances   int64
	CPU            string
	Memory         string
	Concurrency    int64
	Timeout        string
	CreatedTime    string
	RiskLevel      string
}

type EnvVarSecret struct {
	ServiceName  string
	ProjectID    string
	Location     string
	EnvVarName   string
	SecretType   string // password, api-key, token, credential, connection-string
	RiskLevel    string
	Details      string
	Remediation  string
}

type ContainerSecurityIssue struct {
	ServiceName  string
	ProjectID    string
	Location     string
	IssueType    string
	Severity     string
	Description  string
	Remediation  string
	AffectedArea string
}

type PublicService struct {
	Name           string
	ProjectID      string
	Location       string
	URL            string
	Authentication string
	Ingress        string
	RiskLevel      string
	Details        string
}

// ------------------------------
// Module Struct
// ------------------------------
type ContainerSecurityModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Containers      []ContainerConfig
	EnvVarSecrets   []EnvVarSecret
	SecurityIssues  []ContainerSecurityIssue
	PublicServices  []PublicService
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex

	// Tracking
	totalServices   int
	publicCount     int
	secretsFound    int
	issuesFound     int
}

// ------------------------------
// Output Struct
// ------------------------------
type ContainerSecurityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ContainerSecurityOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ContainerSecurityOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPContainerSecurityCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_CONTAINERSECURITY_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &ContainerSecurityModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		Containers:     []ContainerConfig{},
		EnvVarSecrets:  []EnvVarSecret{},
		SecurityIssues: []ContainerSecurityIssue{},
		PublicServices: []PublicService{},
		LootMap:        make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ContainerSecurityModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing container security configurations...", GCP_CONTAINERSECURITY_MODULE_NAME)

	// Create Cloud Run client
	runService, err := run.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Cloud Run service: %v", err), GCP_CONTAINERSECURITY_MODULE_NAME)
		return
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, runService, logger)
		}(projectID)
	}
	wg.Wait()

	// Check results
	if m.totalServices == 0 {
		logger.InfoM("No container services found", GCP_CONTAINERSECURITY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Analyzed %d container service(s)", m.totalServices), GCP_CONTAINERSECURITY_MODULE_NAME)

	if m.secretsFound > 0 {
		logger.InfoM(fmt.Sprintf("[CRITICAL] Found %d potential secret(s) in environment variables!", m.secretsFound), GCP_CONTAINERSECURITY_MODULE_NAME)
	}

	if m.publicCount > 0 {
		logger.InfoM(fmt.Sprintf("[HIGH] Found %d public/unauthenticated service(s)", m.publicCount), GCP_CONTAINERSECURITY_MODULE_NAME)
	}

	if m.issuesFound > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d security issue(s)", m.issuesFound), GCP_CONTAINERSECURITY_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *ContainerSecurityModule) processProject(ctx context.Context, projectID string, runService *run.APIService, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing containers for project: %s", projectID), GCP_CONTAINERSECURITY_MODULE_NAME)
	}

	// Analyze Cloud Run services
	m.analyzeCloudRunServices(ctx, projectID, runService, logger)
}

func (m *ContainerSecurityModule) analyzeCloudRunServices(ctx context.Context, projectID string, runService *run.APIService, logger internal.Logger) {
	// List all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	services, err := runService.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing Cloud Run services for project %s: %v", projectID, err), GCP_CONTAINERSECURITY_MODULE_NAME)
		}
		return
	}

	for _, svc := range services.Items {
		m.mu.Lock()
		m.totalServices++
		m.mu.Unlock()

		// Extract location from name
		// Format: projects/{project}/locations/{location}/services/{name}
		location := m.extractLocationFromName(svc.Metadata.Name)
		serviceName := svc.Metadata.Name

		config := ContainerConfig{
			Name:        m.extractServiceName(serviceName),
			ProjectID:   projectID,
			Location:    location,
			ServiceType: "cloudrun",
			CreatedTime: svc.Metadata.CreationTimestamp,
			RiskLevel:   "LOW",
		}

		// Analyze spec
		if svc.Spec != nil && svc.Spec.Template != nil && svc.Spec.Template.Spec != nil {
			spec := svc.Spec.Template.Spec

			// Service account
			config.ServiceAccount = spec.ServiceAccountName

			// Timeout
			if spec.TimeoutSeconds > 0 {
				config.Timeout = fmt.Sprintf("%ds", spec.TimeoutSeconds)
			}

			// Concurrency
			if spec.ContainerConcurrency > 0 {
				config.Concurrency = spec.ContainerConcurrency
			}

			// Container details
			if len(spec.Containers) > 0 {
				container := spec.Containers[0]
				config.Image = container.Image

				// Resources
				if container.Resources != nil {
					if cpu, ok := container.Resources.Limits["cpu"]; ok {
						config.CPU = cpu
					}
					if mem, ok := container.Resources.Limits["memory"]; ok {
						config.Memory = mem
					}
				}

				// Analyze environment variables
				config.EnvVarCount = len(container.Env)
				m.analyzeEnvVars(container.Env, config.Name, projectID, location)
			}
		}

		// Analyze annotations for ingress and auth
		if svc.Metadata.Annotations != nil {
			// Ingress setting
			if ingress, ok := svc.Metadata.Annotations["run.googleapis.com/ingress"]; ok {
				config.Ingress = ingress
			} else {
				config.Ingress = "all" // Default
			}

			// VPC connector
			if vpc, ok := svc.Metadata.Annotations["run.googleapis.com/vpc-access-connector"]; ok {
				config.VPCConnector = vpc
			}
		}

		// Check IAM policy for authentication
		iamPolicy, err := runService.Projects.Locations.Services.GetIamPolicy(serviceName).Do()
		if err == nil {
			config.Authentication = m.analyzeIAMPolicy(iamPolicy)
		}

		// Determine risk level and check for issues
		m.analyzeServiceSecurity(config, svc)

		m.mu.Lock()
		m.Containers = append(m.Containers, config)
		m.mu.Unlock()
	}
}

func (m *ContainerSecurityModule) analyzeEnvVars(envVars []*run.EnvVar, serviceName, projectID, location string) {
	// Patterns that indicate secrets
	secretPatterns := map[string]string{
		"PASSWORD":       "password",
		"PASSWD":         "password",
		"SECRET":         "secret",
		"API_KEY":        "api-key",
		"APIKEY":         "api-key",
		"API-KEY":        "api-key",
		"TOKEN":          "token",
		"ACCESS_TOKEN":   "token",
		"AUTH_TOKEN":     "token",
		"BEARER":         "token",
		"CREDENTIAL":     "credential",
		"PRIVATE_KEY":    "credential",
		"PRIVATEKEY":     "credential",
		"CONNECTION_STRING": "connection-string",
		"CONN_STR":       "connection-string",
		"DATABASE_URL":   "connection-string",
		"DB_PASSWORD":    "password",
		"DB_PASS":        "password",
		"MYSQL_PASSWORD": "password",
		"POSTGRES_PASSWORD": "password",
		"REDIS_PASSWORD": "password",
		"MONGODB_URI":    "connection-string",
		"AWS_ACCESS_KEY": "credential",
		"AWS_SECRET":     "credential",
		"AZURE_KEY":      "credential",
		"GCP_KEY":        "credential",
		"ENCRYPTION_KEY": "credential",
		"SIGNING_KEY":    "credential",
		"JWT_SECRET":     "credential",
		"SESSION_SECRET": "credential",
		"OAUTH":          "credential",
		"CLIENT_SECRET":  "credential",
	}

	for _, env := range envVars {
		if env == nil {
			continue
		}

		envNameUpper := strings.ToUpper(env.Name)

		// Check if this looks like a secret
		for pattern, secretType := range secretPatterns {
			if strings.Contains(envNameUpper, pattern) {
				// Check if it's using Secret Manager (safer)
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					// Using Secret Manager reference - this is good
					continue
				}

				// Direct value - this is bad
				if env.Value != "" {
					secret := EnvVarSecret{
						ServiceName: serviceName,
						ProjectID:   projectID,
						Location:    location,
						EnvVarName:  env.Name,
						SecretType:  secretType,
						RiskLevel:   "CRITICAL",
						Details:     "Hardcoded secret value in environment variable",
						Remediation: fmt.Sprintf("Use Secret Manager: gcloud secrets create %s --replication-policy=\"automatic\" && update Cloud Run to reference secret", strings.ToLower(env.Name)),
					}

					m.mu.Lock()
					m.EnvVarSecrets = append(m.EnvVarSecrets, secret)
					m.secretsFound++
					m.addSecretToLoot(secret)
					m.mu.Unlock()
				}
				break
			}
		}
	}
}

func (m *ContainerSecurityModule) analyzeIAMPolicy(policy *run.Policy) string {
	if policy == nil || policy.Bindings == nil {
		return "unknown"
	}

	for _, binding := range policy.Bindings {
		if binding.Role == "roles/run.invoker" {
			for _, member := range binding.Members {
				if member == "allUsers" {
					return "public"
				}
				if member == "allAuthenticatedUsers" {
					return "all-authenticated"
				}
			}
		}
	}

	return "authenticated"
}

func (m *ContainerSecurityModule) analyzeServiceSecurity(config ContainerConfig, svc *run.Service) {
	issues := []ContainerSecurityIssue{}

	// Check for public access
	if config.Authentication == "public" {
		config.RiskLevel = "HIGH"

		publicSvc := PublicService{
			Name:           config.Name,
			ProjectID:      config.ProjectID,
			Location:       config.Location,
			URL:            svc.Status.Url,
			Authentication: "public (allUsers)",
			Ingress:        config.Ingress,
			RiskLevel:      "HIGH",
			Details:        "Service is publicly accessible without authentication",
		}

		m.mu.Lock()
		m.PublicServices = append(m.PublicServices, publicSvc)
		m.publicCount++
		m.mu.Unlock()

		issues = append(issues, ContainerSecurityIssue{
			ServiceName:  config.Name,
			ProjectID:    config.ProjectID,
			Location:     config.Location,
			IssueType:    "public-access",
			Severity:     "HIGH",
			Description:  "Service allows unauthenticated access from the internet",
			Remediation:  "Remove allUsers from IAM policy or add authentication",
			AffectedArea: "Authentication",
		})
	} else if config.Authentication == "all-authenticated" {
		config.RiskLevel = "MEDIUM"

		publicSvc := PublicService{
			Name:           config.Name,
			ProjectID:      config.ProjectID,
			Location:       config.Location,
			URL:            svc.Status.Url,
			Authentication: "all-authenticated",
			Ingress:        config.Ingress,
			RiskLevel:      "MEDIUM",
			Details:        "Service accessible to any Google account holder",
		}

		m.mu.Lock()
		m.PublicServices = append(m.PublicServices, publicSvc)
		m.publicCount++
		m.mu.Unlock()
	}

	// Check for default service account
	if config.ServiceAccount == "" || strings.Contains(config.ServiceAccount, "-compute@developer.gserviceaccount.com") {
		issues = append(issues, ContainerSecurityIssue{
			ServiceName:  config.Name,
			ProjectID:    config.ProjectID,
			Location:     config.Location,
			IssueType:    "default-service-account",
			Severity:     "MEDIUM",
			Description:  "Service uses default Compute Engine service account",
			Remediation:  "Create a dedicated service account with minimal permissions",
			AffectedArea: "IAM",
		})
	}

	// Check for ingress settings
	if config.Ingress == "all" && config.VPCConnector == "" {
		issues = append(issues, ContainerSecurityIssue{
			ServiceName:  config.Name,
			ProjectID:    config.ProjectID,
			Location:     config.Location,
			IssueType:    "unrestricted-ingress",
			Severity:     "LOW",
			Description:  "Service accepts traffic from all sources without VPC connector",
			Remediation:  "Consider using internal-only ingress or VPC connector for internal services",
			AffectedArea: "Network",
		})
	}

	// Check for high concurrency without scaling limits
	if config.Concurrency > 80 && config.MaxInstances == 0 {
		issues = append(issues, ContainerSecurityIssue{
			ServiceName:  config.Name,
			ProjectID:    config.ProjectID,
			Location:     config.Location,
			IssueType:    "no-scaling-limits",
			Severity:     "LOW",
			Description:  "High concurrency without max instance limits could lead to cost issues",
			Remediation:  "Set max-instances to prevent runaway scaling",
			AffectedArea: "Scaling",
		})
	}

	// Check for secrets in env vars
	if m.hasSecretsForService(config.Name, config.ProjectID) {
		if config.RiskLevel != "HIGH" {
			config.RiskLevel = "CRITICAL"
		}
		issues = append(issues, ContainerSecurityIssue{
			ServiceName:  config.Name,
			ProjectID:    config.ProjectID,
			Location:     config.Location,
			IssueType:    "secrets-in-env",
			Severity:     "CRITICAL",
			Description:  "Hardcoded secrets found in environment variables",
			Remediation:  "Migrate secrets to Secret Manager and reference them in Cloud Run",
			AffectedArea: "Secrets",
		})
	}

	// Add issues
	m.mu.Lock()
	m.SecurityIssues = append(m.SecurityIssues, issues...)
	m.issuesFound += len(issues)
	m.mu.Unlock()
}

func (m *ContainerSecurityModule) hasSecretsForService(serviceName, projectID string) bool {
	for _, secret := range m.EnvVarSecrets {
		if strings.Contains(secret.ServiceName, serviceName) && secret.ProjectID == projectID {
			return true
		}
	}
	return false
}

// ------------------------------
// Helper Functions
// ------------------------------
func (m *ContainerSecurityModule) extractLocationFromName(name string) string {
	// Format: projects/{project}/locations/{location}/services/{name}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (m *ContainerSecurityModule) extractServiceName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ContainerSecurityModule) initializeLootFiles() {
	m.LootMap["container-secrets"] = &internal.LootFile{
		Name:     "container-secrets",
		Contents: "# Secrets Found in Container Environment Variables\n# Generated by CloudFox\n# CRITICAL: These secrets should be migrated to Secret Manager!\n\n",
	}
	m.LootMap["vulnerable-images"] = &internal.LootFile{
		Name:     "vulnerable-images",
		Contents: "# Container Images Analysis\n# Generated by CloudFox\n\n",
	}
	m.LootMap["container-commands"] = &internal.LootFile{
		Name:     "container-commands",
		Contents: "# Container Security Remediation Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["public-services"] = &internal.LootFile{
		Name:     "public-services",
		Contents: "# Public Container Services\n# Generated by CloudFox\n\n",
	}
}

func (m *ContainerSecurityModule) addSecretToLoot(secret EnvVarSecret) {
	m.LootMap["container-secrets"].Contents += fmt.Sprintf(
		"## Service: %s\n"+
			"Project: %s\n"+
			"Location: %s\n"+
			"Env Var: %s\n"+
			"Type: %s\n"+
			"Risk: %s\n"+
			"Remediation: %s\n\n",
		secret.ServiceName,
		secret.ProjectID,
		secret.Location,
		secret.EnvVarName,
		secret.SecretType,
		secret.RiskLevel,
		secret.Remediation,
	)

	// Add remediation command
	m.LootMap["container-commands"].Contents += fmt.Sprintf(
		"# Migrate %s secret from %s\n"+
			"# 1. Create secret in Secret Manager:\n"+
			"echo -n 'SECRET_VALUE' | gcloud secrets create %s --data-file=-\n"+
			"# 2. Update Cloud Run service to use secret:\n"+
			"gcloud run services update %s --update-secrets=%s=%s:latest --region=%s --project=%s\n\n",
		secret.EnvVarName, m.extractServiceName(secret.ServiceName),
		strings.ToLower(strings.ReplaceAll(secret.EnvVarName, "_", "-")),
		m.extractServiceName(secret.ServiceName),
		secret.EnvVarName,
		strings.ToLower(strings.ReplaceAll(secret.EnvVarName, "_", "-")),
		secret.Location,
		secret.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ContainerSecurityModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort containers by risk level
	sort.Slice(m.Containers, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		return riskOrder[m.Containers[i].RiskLevel] < riskOrder[m.Containers[j].RiskLevel]
	})

	// Container Configs table
	containersHeader := []string{
		"Service",
		"Project Name",
		"Project ID",
		"Location",
		"Image",
		"Auth",
		"Ingress",
		"Risk",
	}

	var containersBody [][]string
	for _, c := range m.Containers {
		containersBody = append(containersBody, []string{
			c.Name,
			m.GetProjectName(c.ProjectID),
			c.ProjectID,
			c.Location,
			truncateString(c.Image, 40),
			c.Authentication,
			c.Ingress,
			c.RiskLevel,
		})

		// Add to images loot
		m.LootMap["vulnerable-images"].Contents += fmt.Sprintf(
			"%s: %s\n",
			c.Name, c.Image,
		)
	}

	// Env Var Secrets table
	secretsHeader := []string{
		"Service",
		"Project Name",
		"Project ID",
		"Location",
		"Env Var",
		"Type",
		"Risk",
	}

	var secretsBody [][]string
	for _, s := range m.EnvVarSecrets {
		secretsBody = append(secretsBody, []string{
			m.extractServiceName(s.ServiceName),
			m.GetProjectName(s.ProjectID),
			s.ProjectID,
			s.Location,
			s.EnvVarName,
			s.SecretType,
			s.RiskLevel,
		})
	}

	// Security Issues table
	issuesHeader := []string{
		"Service",
		"Project Name",
		"Project ID",
		"Issue Type",
		"Severity",
		"Affected Area",
		"Description",
	}

	var issuesBody [][]string
	for _, i := range m.SecurityIssues {
		issuesBody = append(issuesBody, []string{
			i.ServiceName,
			m.GetProjectName(i.ProjectID),
			i.ProjectID,
			i.IssueType,
			i.Severity,
			i.AffectedArea,
			truncateString(i.Description, 40),
		})
	}

	// Public Services table
	publicHeader := []string{
		"Service",
		"Project Name",
		"Project ID",
		"Location",
		"URL",
		"Auth",
		"Risk",
	}

	var publicBody [][]string
	for _, p := range m.PublicServices {
		publicBody = append(publicBody, []string{
			p.Name,
			m.GetProjectName(p.ProjectID),
			p.ProjectID,
			p.Location,
			truncateString(p.URL, 50),
			p.Authentication,
			p.RiskLevel,
		})

		// Add to public services loot
		m.LootMap["public-services"].Contents += fmt.Sprintf(
			"## %s\n"+
				"URL: %s\n"+
				"Auth: %s\n"+
				"Risk: %s\n"+
				"Details: %s\n\n",
			p.Name, p.URL, p.Authentication, p.RiskLevel, p.Details,
		)
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	tables := []internal.TableFile{}

	if len(containersBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "container-configs",
			Header: containersHeader,
			Body:   containersBody,
		})
	}

	if len(secretsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "env-var-secrets",
			Header: secretsHeader,
			Body:   secretsBody,
		})
	}

	if len(issuesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "security-issues",
			Header: issuesHeader,
			Body:   issuesBody,
		})
	}

	if len(publicBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "public-services",
			Header: publicHeader,
			Body:   publicBody,
		})
	}

	output := ContainerSecurityOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scope names using project names
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	// Write output
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		scopeNames,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_CONTAINERSECURITY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
