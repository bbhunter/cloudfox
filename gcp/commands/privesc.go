package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	attackpathservice "github.com/BishopFox/cloudfox/gcp/services/attackpathService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPrivescCommand = &cobra.Command{
	Use:     globals.GCP_PRIVESC_MODULE_NAME,
	Aliases: []string{"pe", "escalate", "priv"},
	Short:   "Identify privilege escalation paths in GCP organizations, folders, and projects",
	Long: `Analyze GCP IAM policies to identify privilege escalation opportunities.

This module examines IAM bindings at organization, folder, project, and resource levels
to find principals with dangerous permissions that could be used to escalate
privileges within the GCP environment.

Detected privilege escalation methods (60+) include:

Service Account Abuse:
- Token Creation (getAccessToken, getOpenIdToken)
- Key Creation (serviceAccountKeys.create, hmacKeys.create)
- Implicit Delegation, SignBlob, SignJwt
- Workload Identity Federation (external identity impersonation)

IAM Policy Modification:
- Project/Folder/Org IAM Policy Modification
- Service Account IAM Policy + SA Creation combo
- Custom Role Create/Update (iam.roles.create/update)
- Org Policy Modification (orgpolicy.policy.set)
- Resource-specific IAM (Pub/Sub, BigQuery, Artifact Registry, Compute, KMS, Source Repos)

Compute & Serverless:
- Compute Instance Metadata Injection (SSH keys, startup scripts)
- Create GCE Instance with privileged SA
- Cloud Functions Create/Update with SA Identity
- Cloud Run Services/Jobs Create/Update with SA Identity
- App Engine Deploy with SA Identity
- Cloud Build SA Abuse

AI/ML:
- Vertex AI Custom Jobs with SA
- Vertex AI Notebooks with SA
- AI Platform Jobs with SA

Data Processing & Orchestration:
- Dataproc Cluster Create / Job Submit
- Cloud Composer Environment Create/Update
- Dataflow Job Create
- Cloud Workflows with SA
- Eventarc Triggers with SA

Scheduling & Tasks:
- Cloud Scheduler HTTP Request with SA
- Cloud Tasks with SA

Other:
- Deployment Manager Deployment
- GKE Cluster Access, Pod Exec, Secrets
- Secret Manager Access
- KMS Key Access / Decrypt
- API Key Creation/Listing`,
	Run: runGCPPrivescCommand,
}

type PrivescModule struct {
	gcpinternal.BaseGCPModule

	// All paths from combined analysis
	AllPaths      []attackpathservice.AttackPath
	OrgPaths      []attackpathservice.AttackPath
	FolderPaths   []attackpathservice.AttackPath
	ProjectPaths  map[string][]attackpathservice.AttackPath // projectID -> paths
	ResourcePaths []attackpathservice.AttackPath

	// Org/folder info
	OrgIDs      []string
	OrgNames    map[string]string
	FolderNames map[string]string

	// Loot
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

type PrivescOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivescOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivescOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPPrivescCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PRIVESC_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PrivescModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		AllPaths:      []attackpathservice.AttackPath{},
		OrgPaths:      []attackpathservice.AttackPath{},
		FolderPaths:   []attackpathservice.AttackPath{},
		ProjectPaths:  make(map[string][]attackpathservice.AttackPath),
		ResourcePaths: []attackpathservice.AttackPath{},
		OrgIDs:        []string{},
		OrgNames:      make(map[string]string),
		FolderNames:   make(map[string]string),
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *PrivescModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing privilege escalation paths across organizations, folders, projects, and resources...", globals.GCP_PRIVESC_MODULE_NAME)

	var result *attackpathservice.CombinedAttackPathData

	// Check if attack path analysis was already run (via --attack-paths flag)
	// to avoid duplicate enumeration
	if cache := gcpinternal.GetAttackPathCacheFromContext(ctx); cache != nil && cache.HasRawData() {
		if cachedResult, ok := cache.GetRawData().(*attackpathservice.CombinedAttackPathData); ok {
			logger.InfoM("Using cached attack path analysis results", globals.GCP_PRIVESC_MODULE_NAME)
			// Filter to only include privesc paths (cache has all types)
			result = filterPrivescPaths(cachedResult)
		}
	}

	// If no context cache, try loading from disk cache
	if result == nil {
		diskCache, metadata, err := gcpinternal.LoadAttackPathCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.HasRawData() {
			if cachedResult, ok := diskCache.GetRawData().(*attackpathservice.CombinedAttackPathData); ok {
				logger.InfoM(fmt.Sprintf("Using disk cache (created: %s, projects: %v)",
					metadata.CreatedAt.Format("2006-01-02 15:04:05"), metadata.ProjectsIn), globals.GCP_PRIVESC_MODULE_NAME)
				// Filter to only include privesc paths
				result = filterPrivescPaths(cachedResult)
			}
		}
	}

	// If no cached data, run the analysis and save to disk
	if result == nil {
		logger.InfoM("Running privilege escalation analysis...", globals.GCP_PRIVESC_MODULE_NAME)
		svc := attackpathservice.New()
		var err error
		// Run full analysis (all types) so we can cache for other modules
		fullResult, err := svc.CombinedAttackPathAnalysis(ctx, m.ProjectIDs, m.ProjectNames, "all")
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_PRIVESC_MODULE_NAME, "Failed to analyze privilege escalation")
			return
		}

		// Save to disk cache for future use (skip if running under all-checks)
		m.saveToAttackPathCache(ctx, fullResult, logger)

		// Filter to only include privesc paths for this module
		result = filterPrivescPaths(fullResult)
	}

	// Store results
	m.AllPaths = result.AllPaths
	m.OrgPaths = result.OrgPaths
	m.FolderPaths = result.FolderPaths
	m.ResourcePaths = result.ResourcePaths
	m.OrgIDs = result.OrgIDs
	m.OrgNames = result.OrgNames
	m.FolderNames = result.FolderNames

	// Organize project paths by project ID
	for _, path := range result.ProjectPaths {
		if path.ScopeType == "project" && path.ScopeID != "" {
			m.ProjectPaths[path.ScopeID] = append(m.ProjectPaths[path.ScopeID], path)
		}
	}

	// Generate loot
	m.generateLoot()

	if len(m.AllPaths) == 0 {
		logger.InfoM("No privilege escalation paths found", globals.GCP_PRIVESC_MODULE_NAME)
		return
	}

	// Count by scope type
	orgCount := len(m.OrgPaths)
	folderCount := len(m.FolderPaths)
	projectCount := len(result.ProjectPaths)
	resourceCount := len(m.ResourcePaths)

	logger.SuccessM(fmt.Sprintf("Found %d privilege escalation path(s): %d org-level, %d folder-level, %d project-level, %d resource-level",
		len(m.AllPaths), orgCount, folderCount, projectCount, resourceCount), globals.GCP_PRIVESC_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *PrivescModule) generateLoot() {
	m.LootMap["privesc-exploit-commands"] = &internal.LootFile{
		Name:     "privesc-exploit-commands",
		Contents: "# GCP Privilege Escalation Exploit Commands\n# Generated by CloudFox\n\n",
	}

	for _, path := range m.AllPaths {
		m.addPathToLoot(path)
	}

	// Generate playbook
	m.generatePlaybook()
}

func (m *PrivescModule) generatePlaybook() {
	m.LootMap["privesc-playbook"] = &internal.LootFile{
		Name:     "privesc-playbook",
		Contents: attackpathservice.GeneratePrivescPlaybook(m.AllPaths, ""),
	}
}

func (m *PrivescModule) addPathToLoot(path attackpathservice.AttackPath) {
	lootFile := m.LootMap["privesc-exploit-commands"]
	if lootFile == nil {
		return
	}

	scopeInfo := fmt.Sprintf("%s: %s", path.ScopeType, path.ScopeName)
	if path.ScopeName == "" {
		scopeInfo = fmt.Sprintf("%s: %s", path.ScopeType, path.ScopeID)
	}

	lootFile.Contents += fmt.Sprintf(
		"# Method: %s\n"+
			"# Principal: %s (%s)\n"+
			"# Scope: %s\n"+
			"# Target: %s\n"+
			"# Permissions: %s\n"+
			"%s\n\n",
		path.Method,
		path.Principal, path.PrincipalType,
		scopeInfo,
		path.TargetResource,
		strings.Join(path.Permissions, ", "),
		path.ExploitCommand,
	)
}

func (m *PrivescModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *PrivescModule) getHeader() []string {
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

func (m *PrivescModule) pathsToTableBody(paths []attackpathservice.AttackPath) [][]string {
	var body [][]string
	for _, path := range paths {
		scopeName := path.ScopeName
		if scopeName == "" {
			scopeName = path.ScopeID
		}

		// Format binding scope (where the IAM binding is defined)
		bindingScope := "Project"
		if path.ScopeType == "organization" {
			bindingScope = "Organization"
		} else if path.ScopeType == "folder" {
			bindingScope = "Folder"
		} else if path.ScopeType == "resource" {
			bindingScope = "Resource"
		}

		// Format target resource
		targetResource := path.TargetResource
		if targetResource == "" || targetResource == "*" {
			targetResource = "*"
		}

		// Format permissions
		permissions := strings.Join(path.Permissions, ", ")
		if permissions == "" {
			permissions = "-"
		}

		body = append(body, []string{
			scopeName,
			path.ScopeType,
			path.PrincipalType,
			path.Principal,
			path.Method,
			targetResource,
			path.Category,
			bindingScope,
			permissions,
		})
	}
	return body
}

func (m *PrivescModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile
	if paths, ok := m.ProjectPaths[projectID]; ok && len(paths) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "privesc",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(paths),
		})
	}
	return tableFiles
}

func (m *PrivescModule) buildAllTables() []internal.TableFile {
	if len(m.AllPaths) == 0 {
		return nil
	}
	return []internal.TableFile{
		{
			Name:   "privesc",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(m.AllPaths),
		},
	}
}

func (m *PrivescModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *PrivescModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Determine org ID - prefer hierarchy (for consistent output paths across modules),
	// fall back to discovered orgs if hierarchy doesn't have org info
	orgID := ""
	if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	} else if len(m.OrgIDs) > 0 {
		orgID = m.OrgIDs[0]
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.OrgLevelData[orgID] = PrivescOutput{Table: tables, Loot: lootFiles}

		// DUAL OUTPUT: Filtered per-project output
		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			if len(projectTables) > 0 && len(projectTables[0].Body) > 0 {
				outputData.ProjectLevelData[projectID] = PrivescOutput{Table: projectTables, Loot: nil}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.ProjectLevelData[m.ProjectIDs[0]] = PrivescOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}

func (m *PrivescModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildAllTables()
	lootFiles := m.collectLootFiles()

	output := PrivescOutput{Table: tables, Loot: lootFiles}

	// Determine output scope - use org if available, otherwise fall back to project
	var scopeType string
	var scopeIdentifiers []string
	var scopeNames []string

	if len(m.OrgIDs) > 0 {
		// Use organization scope with [O] prefix format
		scopeType = "organization"
		for _, orgID := range m.OrgIDs {
			scopeIdentifiers = append(scopeIdentifiers, orgID)
			if name, ok := m.OrgNames[orgID]; ok && name != "" {
				scopeNames = append(scopeNames, name)
			} else {
				scopeNames = append(scopeNames, orgID)
			}
		}
	} else {
		// Fall back to project scope
		scopeType = "project"
		scopeIdentifiers = m.ProjectIDs
		for _, id := range m.ProjectIDs {
			scopeNames = append(scopeNames, m.GetProjectName(id))
		}
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIdentifiers,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}

// saveToAttackPathCache saves attack path data to disk cache
func (m *PrivescModule) saveToAttackPathCache(ctx context.Context, data *attackpathservice.CombinedAttackPathData, logger internal.Logger) {
	// Skip saving if running under all-checks (consolidated save happens at the end)
	if gcpinternal.IsAllChecksMode(ctx) {
		logger.InfoM("Skipping individual cache save (all-checks mode)", globals.GCP_PRIVESC_MODULE_NAME)
		return
	}

	cache := gcpinternal.NewAttackPathCache()

	// Populate cache with paths from all scopes
	var pathInfos []gcpinternal.AttackPathInfo
	for _, path := range data.AllPaths {
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
	cache.SetRawData(data)

	// Save to disk
	err := gcpinternal.SaveAttackPathCacheToFile(cache, m.ProjectIDs, m.OutputDirectory, m.Account, "1.0")
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not save attack path cache: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	} else {
		privesc, exfil, lateral := cache.GetStats()
		logger.InfoM(fmt.Sprintf("Saved attack path cache to disk (%d privesc, %d exfil, %d lateral)",
			privesc, exfil, lateral), globals.GCP_PRIVESC_MODULE_NAME)
	}
}

// filterPrivescPaths filters a CombinedAttackPathData to only include privesc paths
// This is used when the cache contains all attack path types but privesc only needs privesc
func filterPrivescPaths(data *attackpathservice.CombinedAttackPathData) *attackpathservice.CombinedAttackPathData {
	result := &attackpathservice.CombinedAttackPathData{
		OrgPaths:      []attackpathservice.AttackPath{},
		FolderPaths:   []attackpathservice.AttackPath{},
		ProjectPaths:  []attackpathservice.AttackPath{},
		ResourcePaths: []attackpathservice.AttackPath{},
		AllPaths:      []attackpathservice.AttackPath{},
		OrgNames:      data.OrgNames,
		FolderNames:   data.FolderNames,
		OrgIDs:        data.OrgIDs,
	}

	// Filter each path slice to only include privesc paths
	for _, path := range data.OrgPaths {
		if path.PathType == "privesc" {
			result.OrgPaths = append(result.OrgPaths, path)
		}
	}
	for _, path := range data.FolderPaths {
		if path.PathType == "privesc" {
			result.FolderPaths = append(result.FolderPaths, path)
		}
	}
	for _, path := range data.ProjectPaths {
		if path.PathType == "privesc" {
			result.ProjectPaths = append(result.ProjectPaths, path)
		}
	}
	for _, path := range data.ResourcePaths {
		if path.PathType == "privesc" {
			result.ResourcePaths = append(result.ResourcePaths, path)
		}
	}
	for _, path := range data.AllPaths {
		if path.PathType == "privesc" {
			result.AllPaths = append(result.AllPaths, path)
		}
	}

	return result
}
