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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating Cloud Run services in project %s: %v", projectID, err), globals.GCP_CLOUDRUN_MODULE_NAME)
		}
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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating Cloud Run jobs in project %s: %v", projectID, err), globals.GCP_CLOUDRUN_MODULE_NAME)
		}
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
	m.LootMap["cloudrun-gcloud-commands"] = &internal.LootFile{
		Name:     "cloudrun-gcloud-commands",
		Contents: "# Cloud Run gcloud Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["cloudrun-public-urls"] = &internal.LootFile{
		Name:     "cloudrun-public-urls",
		Contents: "# PUBLIC Cloud Run Service URLs\n# Generated by CloudFox\n# These services are publicly accessible!\n\n",
	}
	m.LootMap["cloudrun-exploitation"] = &internal.LootFile{
		Name:     "cloudrun-exploitation",
		Contents: "# Cloud Run Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["cloudrun-images"] = &internal.LootFile{
		Name:     "cloudrun-images",
		Contents: "# Cloud Run Container Images\n# Generated by CloudFox\n# Check these for vulnerabilities and secrets\n\n",
	}
}

func (m *CloudRunModule) addServiceToLoot(svc CloudRunService.ServiceInfo) {
	// gcloud commands
	m.LootMap["cloudrun-gcloud-commands"].Contents += fmt.Sprintf(
		"# Service: %s (Project: %s, Region: %s)\n"+
			"gcloud run services describe %s --region=%s --project=%s\n"+
			"gcloud run services get-iam-policy %s --region=%s --project=%s\n"+
			"gcloud run revisions list --service=%s --region=%s --project=%s\n\n",
		svc.Name, svc.ProjectID, svc.Region,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.Region, svc.ProjectID,
	)

	// Container images
	m.LootMap["cloudrun-images"].Contents += fmt.Sprintf(
		"%s  # %s (%s)\n",
		svc.ContainerImage, svc.Name, svc.ProjectID,
	)

	// Public services
	if svc.IsPublic && svc.URL != "" {
		m.LootMap["cloudrun-public-urls"].Contents += fmt.Sprintf(
			"# SERVICE: %s\n"+
				"# Project: %s, Region: %s\n"+
				"# Ingress: %s\n"+
				"# Service Account: %s\n"+
				"# URL:\n%s\n\n"+
				"# Test with:\ncurl -s %s\n\n",
			svc.Name,
			svc.ProjectID, svc.Region,
			svc.IngressSettings,
			svc.ServiceAccount,
			svc.URL,
			svc.URL,
		)
	}

	// Exploitation commands
	m.LootMap["cloudrun-exploitation"].Contents += fmt.Sprintf(
		"# Service: %s (Project: %s, Region: %s)\n"+
			"# Service Account: %s\n"+
			"# Public: %v\n\n"+
			"# Invoke the service (if you have run.routes.invoke):\n"+
			"curl -H \"Authorization: Bearer $(gcloud auth print-identity-token)\" %s\n\n"+
			"# Deploy malicious revision (if you have run.services.update):\n"+
			"gcloud run deploy %s --image=YOUR_IMAGE --region=%s --project=%s\n\n"+
			"# Read container logs (if you have logging.logEntries.list):\n"+
			"gcloud logging read 'resource.type=\"cloud_run_revision\" resource.labels.service_name=\"%s\"' --project=%s --limit=50\n\n",
		svc.Name, svc.ProjectID, svc.Region,
		svc.ServiceAccount,
		svc.IsPublic,
		svc.URL,
		svc.Name, svc.Region, svc.ProjectID,
		svc.Name, svc.ProjectID,
	)
}

func (m *CloudRunModule) addJobToLoot(job CloudRunService.JobInfo) {
	// gcloud commands
	m.LootMap["cloudrun-gcloud-commands"].Contents += fmt.Sprintf(
		"# Job: %s (Project: %s, Region: %s)\n"+
			"gcloud run jobs describe %s --region=%s --project=%s\n"+
			"gcloud run jobs executions list --job=%s --region=%s --project=%s\n\n",
		job.Name, job.ProjectID, job.Region,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
	)

	// Container images
	m.LootMap["cloudrun-images"].Contents += fmt.Sprintf(
		"%s  # job: %s (%s)\n",
		job.ContainerImage, job.Name, job.ProjectID,
	)

	// Exploitation commands
	m.LootMap["cloudrun-exploitation"].Contents += fmt.Sprintf(
		"# Job: %s (Project: %s, Region: %s)\n"+
			"# Service Account: %s\n\n"+
			"# Execute the job (if you have run.jobs.run):\n"+
			"gcloud run jobs execute %s --region=%s --project=%s\n\n"+
			"# Update job image (if you have run.jobs.update):\n"+
			"gcloud run jobs update %s --image=YOUR_IMAGE --region=%s --project=%s\n\n",
		job.Name, job.ProjectID, job.Region,
		job.ServiceAccount,
		job.Name, job.Region, job.ProjectID,
		job.Name, job.Region, job.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudRunModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Services table
	servicesHeader := []string{
		"Project ID",
		"Name",
		"Region",
		"URL",
		"Ingress",
		"Public",
		"Service Account",
		"Image",
		"VPC Access",
		"Min/Max Instances",
		"Secrets",
	}

	var servicesBody [][]string
	for _, svc := range m.Services {
		// Format public status
		publicStatus := "No"
		if svc.IsPublic {
			publicStatus = "YES"
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

		// Format secrets count
		secretCount := svc.SecretEnvVarCount + svc.SecretVolumeCount
		secrets := "-"
		if secretCount > 0 {
			secrets = fmt.Sprintf("%d", secretCount)
		}

		// Format image (truncate registry prefix for readability)
		image := truncateImage(svc.ContainerImage)

		// Format service account (truncate for readability)
		saDisplay := truncateSA(svc.ServiceAccount)

		servicesBody = append(servicesBody, []string{
			svc.ProjectID,
			svc.Name,
			svc.Region,
			svc.URL,
			formatIngress(svc.IngressSettings),
			publicStatus,
			saDisplay,
			image,
			vpcAccess,
			scaling,
			secrets,
		})
	}

	// Jobs table
	jobsHeader := []string{
		"Project ID",
		"Name",
		"Region",
		"Service Account",
		"Image",
		"Tasks",
		"Parallelism",
		"Last Execution",
		"Secrets",
	}

	var jobsBody [][]string
	for _, job := range m.Jobs {
		// Format secrets count
		secretCount := job.SecretEnvVarCount + job.SecretVolumeCount
		secrets := "-"
		if secretCount > 0 {
			secrets = fmt.Sprintf("%d", secretCount)
		}

		// Format image
		image := truncateImage(job.ContainerImage)

		// Format service account
		saDisplay := truncateSA(job.ServiceAccount)

		// Format last execution
		lastExec := "-"
		if job.LastExecution != "" {
			lastExec = extractName(job.LastExecution)
		}

		jobsBody = append(jobsBody, []string{
			job.ProjectID,
			job.Name,
			job.Region,
			saDisplay,
			image,
			fmt.Sprintf("%d", job.TaskCount),
			fmt.Sprintf("%d", job.Parallelism),
			lastExec,
			secrets,
		})
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

	output := CloudRunOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		m.ProjectIDs,
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

// truncateImage truncates container image for readability
func truncateImage(image string) string {
	// Remove common registry prefixes
	prefixes := []string{
		"gcr.io/",
		"us-docker.pkg.dev/",
		"us-central1-docker.pkg.dev/",
		"europe-docker.pkg.dev/",
		"asia-docker.pkg.dev/",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(image, prefix) {
			image = strings.TrimPrefix(image, prefix)
			break
		}
	}

	// Truncate if still too long
	if len(image) > 50 {
		return image[:47] + "..."
	}
	return image
}

// truncateSA truncates service account email for readability
func truncateSA(sa string) string {
	if len(sa) > 40 {
		// Show name part only
		if idx := strings.Index(sa, "@"); idx > 0 {
			name := sa[:idx]
			if len(name) > 30 {
				return name[:27] + "...@..."
			}
			return name + "@..."
		}
		return sa[:37] + "..."
	}
	return sa
}

// extractName extracts just the name from a resource path
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
