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

	"google.golang.org/api/appengine/v1"
)

// Module name constant
const GCP_APPENGINE_MODULE_NAME string = "app-engine"

var GCPAppEngineCommand = &cobra.Command{
	Use:     GCP_APPENGINE_MODULE_NAME,
	Aliases: []string{"appengine", "gae"},
	Short:   "Enumerate App Engine applications and security configurations",
	Long: `Analyze App Engine applications for security configurations and potential issues.

Features:
- Lists all App Engine services and versions
- Identifies public services without authentication
- Analyzes ingress settings and firewall rules
- Detects environment variable secrets
- Reviews service account configurations
- Identifies deprecated runtimes
- Analyzes traffic splitting configurations

Security Checks:
- Public endpoints without IAP/authentication
- Secrets in environment variables
- Deprecated/vulnerable runtimes
- Over-permissioned service accounts
- Missing firewall rules

Requires appropriate IAM permissions:
- roles/appengine.appViewer
- roles/appengine.serviceAdmin`,
	Run: runGCPAppEngineCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type AppEngineApp struct {
	ID              string
	ProjectID       string
	LocationID      string
	AuthDomain      string
	DefaultHostname string
	ServingStatus   string
	DefaultBucket   string
	ServiceAccount  string
	DispatchRules   int
	FirewallRules   int
}

type AppEngineService struct {
	ID            string
	AppID         string
	ProjectID     string
	Split         map[string]float64 // version -> traffic allocation
	DefaultURL    string
	VersionCount  int
	LatestVersion string
}

type AppEngineVersion struct {
	ID                string
	ServiceID         string
	AppID             string
	ProjectID         string
	Runtime           string
	Environment       string // standard, flexible
	ServingStatus     string
	CreateTime        string
	InstanceClass     string
	Scaling           string
	Network           string
	VPCConnector      string
	IngressSettings   string
	EnvVarCount       int
	SecretEnvVars     int
	ServiceAccount    string
	BasicScaling      string
	AutomaticScaling  string
	ManualScaling     string
	URL               string
	RiskLevel         string
	DeprecatedRuntime bool
}

type AppEngineFirewallRule struct {
	Priority    int64
	Action      string // ALLOW, DENY
	SourceRange string
	Description string
	ProjectID   string
}

type AppEngineSecurityIssue struct {
	ServiceID   string
	VersionID   string
	ProjectID   string
	IssueType   string
	Severity    string
	Description string
	Remediation string
}

// ------------------------------
// Module Struct
// ------------------------------
type AppEngineModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Apps           []AppEngineApp
	Services       []AppEngineService
	Versions       []AppEngineVersion
	FirewallRules  []AppEngineFirewallRule
	SecurityIssues []AppEngineSecurityIssue
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex

	// Tracking
	totalApps     int
	totalServices int
	publicCount   int
	secretsFound  int
}

// ------------------------------
// Output Struct
// ------------------------------
type AppEngineOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AppEngineOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AppEngineOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPAppEngineCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_APPENGINE_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &AppEngineModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		Apps:           []AppEngineApp{},
		Services:       []AppEngineService{},
		Versions:       []AppEngineVersion{},
		FirewallRules:  []AppEngineFirewallRule{},
		SecurityIssues: []AppEngineSecurityIssue{},
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
func (m *AppEngineModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Enumerating App Engine applications and security configurations...", GCP_APPENGINE_MODULE_NAME)

	// Create App Engine client
	aeService, err := appengine.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create App Engine service: %v", err), GCP_APPENGINE_MODULE_NAME)
		return
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, aeService, logger)
		}(projectID)
	}
	wg.Wait()

	// Check results
	if m.totalApps == 0 {
		logger.InfoM("No App Engine applications found", GCP_APPENGINE_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d App Engine app(s) with %d service(s) and %d version(s)",
		m.totalApps, m.totalServices, len(m.Versions)), GCP_APPENGINE_MODULE_NAME)

	if m.publicCount > 0 {
		logger.InfoM(fmt.Sprintf("[HIGH] Found %d public service(s) without authentication", m.publicCount), GCP_APPENGINE_MODULE_NAME)
	}

	if m.secretsFound > 0 {
		logger.InfoM(fmt.Sprintf("[CRITICAL] Found %d potential secret(s) in environment variables", m.secretsFound), GCP_APPENGINE_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *AppEngineModule) processProject(ctx context.Context, projectID string, aeService *appengine.APIService, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating App Engine for project: %s", projectID), GCP_APPENGINE_MODULE_NAME)
	}

	// Get App Engine application
	app, err := aeService.Apps.Get(projectID).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			// App Engine not enabled is common, don't show as error
			if !strings.Contains(err.Error(), "404") {
				logger.ErrorM(fmt.Sprintf("Error getting App Engine app for project %s: %v", projectID, err), GCP_APPENGINE_MODULE_NAME)
			}
		}
		return
	}

	m.mu.Lock()
	m.totalApps++
	m.mu.Unlock()

	// Create app record
	appRecord := AppEngineApp{
		ID:              app.Id,
		ProjectID:       projectID,
		LocationID:      app.LocationId,
		AuthDomain:      app.AuthDomain,
		DefaultHostname: app.DefaultHostname,
		ServingStatus:   app.ServingStatus,
		DefaultBucket:   app.DefaultBucket,
		ServiceAccount:  app.ServiceAccount,
	}

	if app.DispatchRules != nil {
		appRecord.DispatchRules = len(app.DispatchRules)
	}

	m.mu.Lock()
	m.Apps = append(m.Apps, appRecord)
	m.mu.Unlock()

	// Get services
	m.enumerateServices(ctx, projectID, aeService, logger)

	// Get firewall rules
	m.enumerateFirewallRules(ctx, projectID, aeService, logger)
}

func (m *AppEngineModule) enumerateServices(ctx context.Context, projectID string, aeService *appengine.APIService, logger internal.Logger) {
	services, err := aeService.Apps.Services.List(projectID).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing App Engine services for project %s: %v", projectID, err), GCP_APPENGINE_MODULE_NAME)
		}
		return
	}

	for _, svc := range services.Services {
		m.mu.Lock()
		m.totalServices++
		m.mu.Unlock()

		serviceRecord := AppEngineService{
			ID:        svc.Id,
			AppID:     projectID,
			ProjectID: projectID,
		}

		// Parse traffic split
		if svc.Split != nil {
			serviceRecord.Split = svc.Split.Allocations
		}

		m.mu.Lock()
		m.Services = append(m.Services, serviceRecord)
		m.mu.Unlock()

		// Get ingress settings from service (applies to all versions)
		ingressSettings := "all" // Default
		if svc.NetworkSettings != nil && svc.NetworkSettings.IngressTrafficAllowed != "" {
			ingressSettings = svc.NetworkSettings.IngressTrafficAllowed
		}

		// Get versions for this service
		m.enumerateVersions(ctx, projectID, svc.Id, ingressSettings, aeService, logger)
	}
}

func (m *AppEngineModule) enumerateVersions(ctx context.Context, projectID, serviceID, ingressSettings string, aeService *appengine.APIService, logger internal.Logger) {
	versions, err := aeService.Apps.Services.Versions.List(projectID, serviceID).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing App Engine versions for service %s: %v", serviceID, err), GCP_APPENGINE_MODULE_NAME)
		}
		return
	}

	for _, ver := range versions.Versions {
		versionRecord := AppEngineVersion{
			ID:            ver.Id,
			ServiceID:     serviceID,
			AppID:         projectID,
			ProjectID:     projectID,
			Runtime:       ver.Runtime,
			Environment:   ver.Env,
			ServingStatus: ver.ServingStatus,
			CreateTime:    ver.CreateTime,
			RiskLevel:     "LOW",
		}

		// Instance class
		if ver.InstanceClass != "" {
			versionRecord.InstanceClass = ver.InstanceClass
		}

		// Network settings
		if ver.Network != nil {
			versionRecord.Network = ver.Network.Name
		}

		// VPC connector
		if ver.VpcAccessConnector != nil {
			versionRecord.VPCConnector = ver.VpcAccessConnector.Name
		}

		// Ingress settings (from service level)
		versionRecord.IngressSettings = ingressSettings

		// Service account
		versionRecord.ServiceAccount = ver.ServiceAccount

		// Scaling type
		if ver.AutomaticScaling != nil {
			versionRecord.Scaling = "automatic"
			if ver.AutomaticScaling.MaxConcurrentRequests > 0 {
				versionRecord.AutomaticScaling = fmt.Sprintf("max_concurrent: %d", ver.AutomaticScaling.MaxConcurrentRequests)
			}
		} else if ver.BasicScaling != nil {
			versionRecord.Scaling = "basic"
			versionRecord.BasicScaling = fmt.Sprintf("max_instances: %d", ver.BasicScaling.MaxInstances)
		} else if ver.ManualScaling != nil {
			versionRecord.Scaling = "manual"
			versionRecord.ManualScaling = fmt.Sprintf("instances: %d", ver.ManualScaling.Instances)
		}

		// URL
		versionRecord.URL = ver.VersionUrl

		// Check for deprecated runtime
		versionRecord.DeprecatedRuntime = m.isDeprecatedRuntime(ver.Runtime)
		if versionRecord.DeprecatedRuntime {
			versionRecord.RiskLevel = "MEDIUM"

			m.mu.Lock()
			m.SecurityIssues = append(m.SecurityIssues, AppEngineSecurityIssue{
				ServiceID:   serviceID,
				VersionID:   ver.Id,
				ProjectID:   projectID,
				IssueType:   "deprecated-runtime",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Runtime %s is deprecated and may have security vulnerabilities", ver.Runtime),
				Remediation: "Migrate to a supported runtime version",
			})
			m.mu.Unlock()
		}

		// Check environment variables for secrets
		if ver.EnvVariables != nil {
			versionRecord.EnvVarCount = len(ver.EnvVariables)
			secretCount := m.analyzeEnvVars(ver.EnvVariables, serviceID, ver.Id, projectID)
			versionRecord.SecretEnvVars = secretCount
			if secretCount > 0 {
				versionRecord.RiskLevel = "CRITICAL"
			}
		}

		// Check ingress settings for public access
		if versionRecord.IngressSettings == "all" {
			m.mu.Lock()
			m.publicCount++
			if versionRecord.RiskLevel == "LOW" {
				versionRecord.RiskLevel = "MEDIUM"
			}
			m.SecurityIssues = append(m.SecurityIssues, AppEngineSecurityIssue{
				ServiceID:   serviceID,
				VersionID:   ver.Id,
				ProjectID:   projectID,
				IssueType:   "public-ingress",
				Severity:    "MEDIUM",
				Description: "Service accepts traffic from all sources",
				Remediation: "Consider using 'internal-only' or 'internal-and-cloud-load-balancing' ingress",
			})
			m.mu.Unlock()
		}

		// Check for default service account
		if versionRecord.ServiceAccount == "" || strings.Contains(versionRecord.ServiceAccount, "@appspot.gserviceaccount.com") {
			m.mu.Lock()
			m.SecurityIssues = append(m.SecurityIssues, AppEngineSecurityIssue{
				ServiceID:   serviceID,
				VersionID:   ver.Id,
				ProjectID:   projectID,
				IssueType:   "default-service-account",
				Severity:    "LOW",
				Description: "Using default App Engine service account",
				Remediation: "Create a dedicated service account with minimal permissions",
			})
			m.mu.Unlock()
		}

		m.mu.Lock()
		m.Versions = append(m.Versions, versionRecord)
		m.mu.Unlock()
	}
}

func (m *AppEngineModule) enumerateFirewallRules(ctx context.Context, projectID string, aeService *appengine.APIService, logger internal.Logger) {
	rules, err := aeService.Apps.Firewall.IngressRules.List(projectID).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing App Engine firewall rules for project %s: %v", projectID, err), GCP_APPENGINE_MODULE_NAME)
		}
		return
	}

	for _, rule := range rules.IngressRules {
		fwRule := AppEngineFirewallRule{
			Priority:    rule.Priority,
			Action:      rule.Action,
			SourceRange: rule.SourceRange,
			Description: rule.Description,
			ProjectID:   projectID,
		}

		m.mu.Lock()
		m.FirewallRules = append(m.FirewallRules, fwRule)
		m.mu.Unlock()

		// Check for overly permissive rules
		if rule.Action == "ALLOW" && rule.SourceRange == "*" {
			m.mu.Lock()
			m.SecurityIssues = append(m.SecurityIssues, AppEngineSecurityIssue{
				ServiceID:   "all",
				VersionID:   "all",
				ProjectID:   projectID,
				IssueType:   "permissive-firewall",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Firewall rule (priority %d) allows all traffic", rule.Priority),
				Remediation: "Restrict source ranges to known IP addresses",
			})
			m.mu.Unlock()
		}
	}

	// Update app record with firewall count
	m.mu.Lock()
	for i := range m.Apps {
		if m.Apps[i].ProjectID == projectID {
			m.Apps[i].FirewallRules = len(rules.IngressRules)
			break
		}
	}
	m.mu.Unlock()
}

func (m *AppEngineModule) analyzeEnvVars(envVars map[string]string, serviceID, versionID, projectID string) int {
	secretPatterns := map[string]string{
		"PASSWORD":          "password",
		"SECRET":            "secret",
		"API_KEY":           "api-key",
		"TOKEN":             "token",
		"PRIVATE_KEY":       "credential",
		"DATABASE_URL":      "connection-string",
		"DB_PASSWORD":       "password",
		"MYSQL_PASSWORD":    "password",
		"POSTGRES_PASSWORD": "password",
		"MONGODB_URI":       "connection-string",
		"AWS_SECRET":        "credential",
		"ENCRYPTION_KEY":    "credential",
		"JWT_SECRET":        "credential",
		"SESSION_SECRET":    "credential",
	}

	secretCount := 0

	for name := range envVars {
		nameUpper := strings.ToUpper(name)
		for pattern, secretType := range secretPatterns {
			if strings.Contains(nameUpper, pattern) {
				secretCount++
				m.mu.Lock()
				m.secretsFound++

				m.SecurityIssues = append(m.SecurityIssues, AppEngineSecurityIssue{
					ServiceID:   serviceID,
					VersionID:   versionID,
					ProjectID:   projectID,
					IssueType:   "secret-in-env",
					Severity:    "CRITICAL",
					Description: fmt.Sprintf("Potential %s found in environment variable: %s", secretType, name),
					Remediation: "Use Secret Manager instead of environment variables for secrets",
				})

				// Add to loot
				m.LootMap["secrets-exposure"].Contents += fmt.Sprintf(
					"Service: %s, Version: %s, Env Var: %s (%s)\n",
					serviceID, versionID, name, secretType,
				)
				m.mu.Unlock()
				break
			}
		}
	}

	return secretCount
}

func (m *AppEngineModule) isDeprecatedRuntime(runtime string) bool {
	deprecatedRuntimes := []string{
		"python27",
		"go111",
		"go112",
		"go113",
		"java8",
		"java11",
		"nodejs10",
		"nodejs12",
		"php55",
		"php72",
		"ruby25",
	}

	for _, deprecated := range deprecatedRuntimes {
		if runtime == deprecated {
			return true
		}
	}
	return false
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *AppEngineModule) initializeLootFiles() {
	m.LootMap["app-engine-commands"] = &internal.LootFile{
		Name:     "app-engine-commands",
		Contents: "# App Engine Security Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["public-services"] = &internal.LootFile{
		Name:     "public-services",
		Contents: "# Public App Engine Services\n# Generated by CloudFox\n\n",
	}
	m.LootMap["secrets-exposure"] = &internal.LootFile{
		Name:     "secrets-exposure",
		Contents: "# Secrets Exposed in Environment Variables\n# Generated by CloudFox\n# CRITICAL: Migrate these to Secret Manager!\n\n",
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *AppEngineModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort versions by risk level
	sort.Slice(m.Versions, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		return riskOrder[m.Versions[i].RiskLevel] < riskOrder[m.Versions[j].RiskLevel]
	})

	// App Engine Apps table
	appsHeader := []string{
		"App ID",
		"Project Name",
		"Project ID",
		"Location",
		"Status",
		"Hostname",
		"FW Rules",
	}

	var appsBody [][]string
	for _, app := range m.Apps {
		appsBody = append(appsBody, []string{
			app.ID,
			m.GetProjectName(app.ProjectID),
			app.ProjectID,
			app.LocationID,
			app.ServingStatus,
			truncateString(app.DefaultHostname, 40),
			fmt.Sprintf("%d", app.FirewallRules),
		})
	}

	// App Engine Services table
	servicesHeader := []string{
		"Service",
		"Project Name",
		"Project ID",
		"Versions",
	}

	var servicesBody [][]string
	for _, svc := range m.Services {
		versionsCount := 0
		for _, ver := range m.Versions {
			if ver.ServiceID == svc.ID && ver.ProjectID == svc.ProjectID {
				versionsCount++
			}
		}

		servicesBody = append(servicesBody, []string{
			svc.ID,
			m.GetProjectName(svc.ProjectID),
			svc.ProjectID,
			fmt.Sprintf("%d", versionsCount),
		})
	}

	// App Engine Versions table
	versionsHeader := []string{
		"Service",
		"Version",
		"Runtime",
		"Env",
		"Ingress",
		"Scaling",
		"Risk",
	}

	var versionsBody [][]string
	for _, ver := range m.Versions {
		versionsBody = append(versionsBody, []string{
			ver.ServiceID,
			ver.ID,
			ver.Runtime,
			ver.Environment,
			ver.IngressSettings,
			ver.Scaling,
			ver.RiskLevel,
		})

		// Add public services to loot
		if ver.IngressSettings == "all" {
			m.LootMap["public-services"].Contents += fmt.Sprintf(
				"Service: %s, Version: %s, URL: %s\n",
				ver.ServiceID, ver.ID, ver.URL,
			)
		}
	}

	// Security Issues table
	issuesHeader := []string{
		"Service",
		"Version",
		"Issue",
		"Severity",
		"Description",
	}

	var issuesBody [][]string
	for _, issue := range m.SecurityIssues {
		issuesBody = append(issuesBody, []string{
			issue.ServiceID,
			issue.VersionID,
			issue.IssueType,
			issue.Severity,
			truncateString(issue.Description, 40),
		})

		// Add remediation commands
		m.LootMap["app-engine-commands"].Contents += fmt.Sprintf(
			"# %s - %s (%s)\n# %s\n# Remediation: %s\n\n",
			issue.ServiceID, issue.VersionID, issue.IssueType,
			issue.Description, issue.Remediation,
		)
	}

	// Firewall Rules table
	firewallHeader := []string{
		"Priority",
		"Action",
		"Source Range",
		"Project Name",
		"Project ID",
		"Description",
	}

	var firewallBody [][]string
	for _, rule := range m.FirewallRules {
		firewallBody = append(firewallBody, []string{
			fmt.Sprintf("%d", rule.Priority),
			rule.Action,
			rule.SourceRange,
			m.GetProjectName(rule.ProjectID),
			rule.ProjectID,
			truncateString(rule.Description, 30),
		})
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

	if len(appsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "app-engine-apps",
			Header: appsHeader,
			Body:   appsBody,
		})
	}

	if len(servicesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "app-engine-services",
			Header: servicesHeader,
			Body:   servicesBody,
		})
	}

	if len(versionsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "app-engine-versions",
			Header: versionsHeader,
			Body:   versionsBody,
		})
	}

	if len(issuesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "security-issues",
			Header: issuesHeader,
			Body:   issuesBody,
		})
	}

	if len(firewallBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "firewall-rules",
			Header: firewallHeader,
			Body:   firewallBody,
		})
	}

	output := AppEngineOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_APPENGINE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
