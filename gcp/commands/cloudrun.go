package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudRunCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDRUN_MODULE_NAME,
	Aliases: []string{"run", "cr"},
	Short:   "Enumerate Cloud Run services and jobs with security analysis",
	Long: `Enumerate Cloud Run services and jobs across projects with security-relevant details.

Features:
- Lists all Cloud Run services and jobs
- Shows security configuration (ingress, VPC, service account)
- Identifies publicly invokable services (allUsers/allAuthenticatedUsers)
- Shows container image, resources, and scaling configuration
- Counts environment variables and secret references
- Generates gcloud commands for further analysis

Security Columns:
- Ingress: INGRESS_TRAFFIC_ALL (public), INTERNAL_ONLY, or INTERNAL_LOAD_BALANCER
- Public: Whether allUsers or allAuthenticatedUsers can invoke the service
- ServiceAccount: The identity the service runs as
- VPCAccess: Network connectivity to VPC resources
- Secrets: Count of secret environment variables and volumes

Attack Surface:
- Public services with ALL ingress are internet-accessible
- Services with default service account may have excessive permissions
- VPC-connected services can access internal resources
- Container images may contain vulnerabilities or secrets`,
	Run: runGCPCloudRunCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CloudRunModule struct {
	gcpinternal.BaseGCPModule

	Services []CloudRunService.ServiceInfo
	Jobs     []CloudRunService.JobInfo
	LootMap  map[string]*internal.LootFile
	mu       sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CloudRunOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudRunOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudRunOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudRunCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDRUN_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudRunModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Services:      []CloudRunService.ServiceInfo{},
		Jobs:          []CloudRunService.JobInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudRunModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDRUN_MODULE_NAME, m.processProject)

	totalResources := len(m.Services) + len(m.Jobs)
	if totalResources == 0 {
		logger.InfoM("No Cloud Run services or jobs found", globals.GCP_CLOUDRUN_MODULE_NAME)
		return
	}

	// Count public services
	publicCount := 0
	for _, svc := range m.Services {
		if svc.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d service(s), %d job(s), %d public", len(m.Services), len(m.Jobs), publicCount), globals.GCP_CLOUDRUN_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d service(s), %d job(s)", len(m.Services), len(m.Jobs)), globals.GCP_CLOUDRUN_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudRunModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud Run in project: %s", projectID), globals.GCP_CLOUDRUN_MODULE_NAME)
	}

	cs := CloudRunService.New()

	// Get services
	services, err := cs.Services(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDRUN_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Run services in project %s", projectID))
	} else {
		m.mu.Lock()
		m.Services = append(m.Services, services...)
		for _, svc := range services {
			m.addServiceToLoot(svc)
		}
		m.mu.Unlock()
	}

	// Get jobs
	jobs, err := cs.Jobs(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDRUN_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Run jobs in project %s", projectID))
	} else {
		m.mu.Lock()
		m.Jobs = append(m.Jobs, jobs...)
		for _, job := range jobs {
			m.addJobToLoot(job)
		}
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d service(s), %d job(s) in project %s", len(services), len(jobs), projectID), globals.GCP_CLOUDRUN_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CloudRunModule) initializeLootFiles() {
	m.LootMap["cloudrun-commands"] = &internal.LootFile{
		Name:     "cloudrun-commands",
		Contents: "# Cloud Run Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["cloudrun-env-vars"] = &internal.LootFile{
		Name:     "cloudrun-env-vars",
		Contents: "# Cloud Run Environment Variables\n# Generated by CloudFox\n\n",
	}
	m.LootMap["cloudrun-secret-refs"] = &internal.LootFile{
		Name:     "cloudrun-secret-refs",
		Contents: "# Cloud Run Secret Manager References\n# Generated by CloudFox\n# Use: gcloud secrets versions access VERSION --secret=SECRET_NAME --project=PROJECT\n\n",
	}
}

func (m *CloudRunModule) addServiceToLoot(svc CloudRunService.ServiceInfo) {
	// All commands for this service
	m.LootMap["cloudrun-commands"].Contents += fmt.Sprintf(
		"## Service: %s (Project: %s, Region: %s)\n"+
			"# Image: %s\n"+
			"# Service Account: %s\n"+
			"# Public: %v\n"+
			"# URL: %s\n\n"+
			"# Describe service:\n"+
			"gcloud run services describe %s --region=%s --project=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud run services get-iam-policy %s --region=%s --project=%s\n"+
			"# List revisions:\n"+
			"gcloud run revisions list --service=%s --region=%s --project=%s\n"+
			"# Invoke the service (if you have run.routes.invoke):\n"+
			"curl -H \"Authorization: Bearer $(gcloud auth print-identity-token)\" %s\n"+
			"# Deploy revision (if you have run.services.update):\n"+
			"gcloud run deploy %s --image=YOUR_IMAGE --region=%s --project=%s\n"+
			"# Read container logs (if you have logging.logEntries.list):\n"+
			"gcloud logging read 'resource.type=\"cloud_run_revision\" resource.labels.service_name=\"%s\"' --project=%s --limit=50\n\n",
		svc.Name, svc.ProjectID, svc.Region,
		svc.ContainerImage,
		svc.ServiceAccount,
		svc.IsPublic,
		svc.URL,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
		svc.URL,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.ProjectID,
	)

	// Add environment variables to loot
	if len(svc.EnvVars) > 0 {
		m.LootMap["cloudrun-env-vars"].Contents += fmt.Sprintf("## Service: %s (Project: %s, Region: %s)\n", svc.Name, svc.ProjectID, svc.Region)
		for _, env := range svc.EnvVars {
			if env.Source == "direct" {
				m.LootMap["cloudrun-env-vars"].Contents += fmt.Sprintf("%s=%s\n", env.Name, env.Value)
			} else {
				m.LootMap["cloudrun-env-vars"].Contents += fmt.Sprintf("%s=[Secret: %s:%s]\n", env.Name, env.SecretName, env.SecretVersion)
			}
		}
		m.LootMap["cloudrun-env-vars"].Contents += "\n"
	}

	// Add secret references to loot
	if len(svc.SecretRefs) > 0 {
		m.LootMap["cloudrun-secret-refs"].Contents += fmt.Sprintf("## Service: %s (Project: %s, Region: %s)\n", svc.Name, svc.ProjectID, svc.Region)
		for _, ref := range svc.SecretRefs {
			if ref.Type == "env" {
				m.LootMap["cloudrun-secret-refs"].Contents += fmt.Sprintf(
					"# Env var: %s\ngcloud secrets versions access %s --secret=%s --project=%s\n",
					ref.EnvVarName, ref.SecretVersion, ref.SecretName, svc.ProjectID,
				)
			} else {
				m.LootMap["cloudrun-secret-refs"].Contents += fmt.Sprintf(
					"# Volume mount: %s\ngcloud secrets versions access latest --secret=%s --project=%s\n",
					ref.MountPath, ref.SecretName, svc.ProjectID,
				)
			}
		}
		m.LootMap["cloudrun-secret-refs"].Contents += "\n"
	}
}

func (m *CloudRunModule) addJobToLoot(job CloudRunService.JobInfo) {
	// All commands for this job
	m.LootMap["cloudrun-commands"].Contents += fmt.Sprintf(
		"## Job: %s (Project: %s, Region: %s)\n"+
			"# Image: %s\n"+
			"# Service Account: %s\n\n"+
			"# Describe job:\n"+
			"gcloud run jobs describe %s --region=%s --project=%s\n"+
			"# List executions:\n"+
			"gcloud run jobs executions list --job=%s --region=%s --project=%s\n"+
			"# Execute the job (if you have run.jobs.run):\n"+
			"gcloud run jobs execute %s --region=%s --project=%s\n"+
			"# Update job image (if you have run.jobs.update):\n"+
			"gcloud run jobs update %s --image=YOUR_IMAGE --region=%s --project=%s\n\n",
		job.Name, job.ProjectID, job.Region,
		job.ContainerImage,
		job.ServiceAccount,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
	)

	// Add environment variables to loot
	if len(job.EnvVars) > 0 {
		m.LootMap["cloudrun-env-vars"].Contents += fmt.Sprintf("## Job: %s (Project: %s, Region: %s)\n", job.Name, job.ProjectID, job.Region)
		for _, env := range job.EnvVars {
			if env.Source == "direct" {
				m.LootMap["cloudrun-env-vars"].Contents += fmt.Sprintf("%s=%s\n", env.Name, env.Value)
			} else {
				m.LootMap["cloudrun-env-vars"].Contents += fmt.Sprintf("%s=[Secret: %s:%s]\n", env.Name, env.SecretName, env.SecretVersion)
			}
		}
		m.LootMap["cloudrun-env-vars"].Contents += "\n"
	}

	// Add secret references to loot
	if len(job.SecretRefs) > 0 {
		m.LootMap["cloudrun-secret-refs"].Contents += fmt.Sprintf("## Job: %s (Project: %s, Region: %s)\n", job.Name, job.ProjectID, job.Region)
		for _, ref := range job.SecretRefs {
			if ref.Type == "env" {
				m.LootMap["cloudrun-secret-refs"].Contents += fmt.Sprintf(
					"# Env var: %s\ngcloud secrets versions access %s --secret=%s --project=%s\n",
					ref.EnvVarName, ref.SecretVersion, ref.SecretName, job.ProjectID,
				)
			} else {
				m.LootMap["cloudrun-secret-refs"].Contents += fmt.Sprintf(
					"# Volume mount: %s\ngcloud secrets versions access latest --secret=%s --project=%s\n",
					ref.MountPath, ref.SecretName, job.ProjectID,
				)
			}
		}
		m.LootMap["cloudrun-secret-refs"].Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudRunModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Services table
	servicesHeader := []string{
		"Project ID",
		"Project Name",
		"Name",
		"Region",
		"URL",
		"Ingress",
		"Public",
		"Invokers",
		"Service Account",
		"Default SA",
		"Image",
		"VPC Access",
		"Min/Max",
		"Env Vars",
		"Secrets",
		"Hardcoded",
	}

	var servicesBody [][]string
	for _, svc := range m.Services {
		// Format public status
		publicStatus := "No"
		if svc.IsPublic {
			publicStatus = "Yes"
		}

		// Format default SA status
		defaultSA := "No"
		if svc.UsesDefaultSA {
			defaultSA = "Yes"
		}

		// Format invokers
		invokers := "-"
		if len(svc.InvokerMembers) > 0 {
			invokers = strings.Join(svc.InvokerMembers, ", ")
		}

		// Format VPC access
		vpcAccess := "-"
		if svc.VPCAccess != "" {
			vpcAccess = extractName(svc.VPCAccess)
			if svc.VPCEgressSettings != "" {
				vpcAccess += fmt.Sprintf(" (%s)", strings.TrimPrefix(svc.VPCEgressSettings, "VPC_EGRESS_"))
			}
		}

		// Format scaling
		scaling := fmt.Sprintf("%d/%d", svc.MinInstances, svc.MaxInstances)

		// Format env var count
		envVars := "-"
		if svc.EnvVarCount > 0 {
			envVars = fmt.Sprintf("%d", svc.EnvVarCount)
		}

		// Format secrets count (Secret Manager references)
		secretCount := svc.SecretEnvVarCount + svc.SecretVolumeCount
		secrets := "-"
		if secretCount > 0 {
			secrets = fmt.Sprintf("%d", secretCount)
		}

		// Format hardcoded secrets count
		hardcoded := "No"
		if len(svc.HardcodedSecrets) > 0 {
			hardcoded = fmt.Sprintf("Yes (%d)", len(svc.HardcodedSecrets))
		}

		servicesBody = append(servicesBody, []string{
			svc.ProjectID,
			m.GetProjectName(svc.ProjectID),
			svc.Name,
			svc.Region,
			svc.URL,
			formatIngress(svc.IngressSettings),
			publicStatus,
			invokers,
			svc.ServiceAccount,
			defaultSA,
			svc.ContainerImage,
			vpcAccess,
			scaling,
			envVars,
			secrets,
			hardcoded,
		})
	}

	// Jobs table
	jobsHeader := []string{
		"Project ID",
		"Project Name",
		"Name",
		"Region",
		"Service Account",
		"Default SA",
		"Image",
		"Tasks",
		"Parallelism",
		"Last Execution",
		"Env Vars",
		"Secrets",
		"Hardcoded",
	}

	var jobsBody [][]string
	for _, job := range m.Jobs {
		// Format default SA status
		defaultSA := "No"
		if job.UsesDefaultSA {
			defaultSA = "Yes"
		}

		// Format env var count
		envVars := "-"
		if job.EnvVarCount > 0 {
			envVars = fmt.Sprintf("%d", job.EnvVarCount)
		}

		// Format secrets count
		secretCount := job.SecretEnvVarCount + job.SecretVolumeCount
		secrets := "-"
		if secretCount > 0 {
			secrets = fmt.Sprintf("%d", secretCount)
		}

		// Format hardcoded secrets count
		hardcoded := "No"
		if len(job.HardcodedSecrets) > 0 {
			hardcoded = fmt.Sprintf("Yes (%d)", len(job.HardcodedSecrets))
		}

		// Format last execution
		lastExec := "-"
		if job.LastExecution != "" {
			lastExec = extractName(job.LastExecution)
		}

		jobsBody = append(jobsBody, []string{
			job.ProjectID,
			m.GetProjectName(job.ProjectID),
			job.Name,
			job.Region,
			job.ServiceAccount,
			defaultSA,
			job.ContainerImage,
			fmt.Sprintf("%d", job.TaskCount),
			fmt.Sprintf("%d", job.Parallelism),
			lastExec,
			envVars,
			secrets,
			hardcoded,
		})
	}

	// Hardcoded secrets table
	secretsHeader := []string{
		"Project ID",
		"Project Name",
		"Resource Type",
		"Name",
		"Region",
		"Env Var",
		"Secret Type",
	}

	var secretsBody [][]string
	// Add service secrets
	for _, svc := range m.Services {
		for _, secret := range svc.HardcodedSecrets {
			secretsBody = append(secretsBody, []string{
				svc.ProjectID,
				m.GetProjectName(svc.ProjectID),
				"Service",
				svc.Name,
				svc.Region,
				secret.EnvVarName,
				secret.SecretType,
			})
			// Add remediation to loot
			m.addSecretRemediationToLoot(svc.Name, svc.ProjectID, svc.Region, secret.EnvVarName, "service")
		}
	}
	// Add job secrets
	for _, job := range m.Jobs {
		for _, secret := range job.HardcodedSecrets {
			secretsBody = append(secretsBody, []string{
				job.ProjectID,
				m.GetProjectName(job.ProjectID),
				"Job",
				job.Name,
				job.Region,
				secret.EnvVarName,
				secret.SecretType,
			})
			// Add remediation to loot
			m.addSecretRemediationToLoot(job.Name, job.ProjectID, job.Region, secret.EnvVarName, "job")
		}
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{}

	if len(servicesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-services",
			Header: servicesHeader,
			Body:   servicesBody,
		})
	}

	if len(jobsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-jobs",
			Header: jobsHeader,
			Body:   jobsBody,
		})
	}

	if len(secretsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_CLOUDRUN_MODULE_NAME + "-secrets",
			Header: secretsHeader,
			Body:   secretsBody,
		})
	}

	output := CloudRunOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDRUN_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// formatIngress formats ingress settings for display
func formatIngress(ingress string) string {
	switch ingress {
	case "INGRESS_TRAFFIC_ALL":
		return "ALL (Public)"
	case "INGRESS_TRAFFIC_INTERNAL_ONLY":
		return "INTERNAL"
	case "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER":
		return "INT+LB"
	default:
		return ingress
	}
}

// extractName extracts just the name from a resource path
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// addSecretRemediationToLoot adds remediation commands for hardcoded secrets
func (m *CloudRunModule) addSecretRemediationToLoot(resourceName, projectID, region, envVarName, resourceType string) {
	secretName := strings.ToLower(strings.ReplaceAll(envVarName, "_", "-"))

	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["cloudrun-commands"].Contents += fmt.Sprintf(
		"# CRITICAL: Migrate hardcoded secret %s from %s %s\n"+
			"# 1. Create secret in Secret Manager:\n"+
			"echo -n 'SECRET_VALUE' | gcloud secrets create %s --data-file=- --project=%s\n"+
			"# 2. Grant access to Cloud Run service account:\n"+
			"gcloud secrets add-iam-policy-binding %s --member='serviceAccount:SERVICE_ACCOUNT' --role='roles/secretmanager.secretAccessor' --project=%s\n",
		envVarName, resourceType, resourceName,
		secretName, projectID,
		secretName, projectID,
	)

	if resourceType == "service" {
		m.LootMap["cloudrun-commands"].Contents += fmt.Sprintf(
			"# 3. Update Cloud Run service to use secret:\n"+
				"gcloud run services update %s --update-secrets=%s=%s:latest --region=%s --project=%s\n\n",
			resourceName, envVarName, secretName, region, projectID,
		)
	} else {
		m.LootMap["cloudrun-commands"].Contents += fmt.Sprintf(
			"# 3. Update Cloud Run job to use secret:\n"+
				"gcloud run jobs update %s --update-secrets=%s=%s:latest --region=%s --project=%s\n\n",
			resourceName, envVarName, secretName, region, projectID,
		)
	}
}
