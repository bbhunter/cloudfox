package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	assetservice "github.com/BishopFox/cloudfox/gcp/services/assetService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	"google.golang.org/api/iterator"
)

var (
	assetTypes       []string
	showCounts       bool
	checkIAM         bool
	showDependencies bool
	showAll          bool
)

var GCPAssetInventoryCommand = &cobra.Command{
	Use:     globals.GCP_ASSET_INVENTORY_MODULE_NAME,
	Aliases: []string{"assets", "inventory", "cai", "resource-graph"},
	Short:   "Enumerate Cloud Asset Inventory with optional dependency analysis",
	Long: `Enumerate resources using Cloud Asset Inventory API.

Features:
- Lists all assets in a project
- Provides asset counts by type
- Can check IAM policies for public access
- Supports filtering by asset type
- Analyzes resource dependencies and cross-project relationships
- Generates query templates for common security use cases

Flags can be combined to run multiple analyses in a single run.

Examples:
  cloudfox gcp asset-inventory -p my-project
  cloudfox gcp asset-inventory -p my-project --counts
  cloudfox gcp asset-inventory -p my-project --iam
  cloudfox gcp asset-inventory -p my-project --dependencies
  cloudfox gcp asset-inventory -p my-project --counts --iam --dependencies
  cloudfox gcp asset-inventory -p my-project --all
  cloudfox gcp asset-inventory -p my-project --types compute.googleapis.com/Instance,storage.googleapis.com/Bucket`,
	Run: runGCPAssetInventoryCommand,
}

func init() {
	GCPAssetInventoryCommand.Flags().StringSliceVar(&assetTypes, "types", []string{}, "Filter by asset types (comma-separated)")
	GCPAssetInventoryCommand.Flags().BoolVar(&showCounts, "counts", false, "Show asset counts by type")
	GCPAssetInventoryCommand.Flags().BoolVar(&checkIAM, "iam", false, "Check IAM policies for public access")
	GCPAssetInventoryCommand.Flags().BoolVar(&showDependencies, "dependencies", false, "Analyze resource dependencies and cross-project relationships")
	GCPAssetInventoryCommand.Flags().BoolVar(&showAll, "all", false, "Run all analyses (counts, IAM, dependencies)")
}

// ResourceDependency represents a dependency between two resources
type ResourceDependency struct {
	SourceResource string
	SourceType     string
	TargetResource string
	TargetType     string
	DependencyType string // uses, references, contains
	ProjectID      string
}

// CrossProjectResource represents a resource accessed from multiple projects
type CrossProjectResource struct {
	ResourceName string
	ResourceType string
	OwnerProject string
	AccessedFrom []string
}

type AssetInventoryModule struct {
	gcpinternal.BaseGCPModule
	Assets       []assetservice.AssetInfo
	TypeCounts   []assetservice.AssetTypeCount
	Dependencies []ResourceDependency
	CrossProject []CrossProjectResource
	LootMap      map[string]*internal.LootFile
	mu           sync.Mutex
}

type AssetInventoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o AssetInventoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o AssetInventoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPAssetInventoryCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	if err != nil {
		return
	}

	module := &AssetInventoryModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Assets:        []assetservice.AssetInfo{},
		TypeCounts:    []assetservice.AssetTypeCount{},
		Dependencies:  []ResourceDependency{},
		CrossProject:  []CrossProjectResource{},
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *AssetInventoryModule) Execute(ctx context.Context, logger internal.Logger) {
	// If --all is set, enable all flags
	if showAll {
		showCounts = true
		checkIAM = true
		showDependencies = true
	}

	// If no flags set, default to basic asset listing
	noFlagsSet := !showCounts && !checkIAM && !showDependencies

	// Run requested analyses
	if showCounts {
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProjectCounts)
	}

	if checkIAM {
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProjectIAM)
	} else if noFlagsSet {
		// Only run basic listing if no flags and IAM not requested (IAM includes basic info)
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProject)
	}

	if showDependencies {
		m.processProjectsDependencies(ctx, logger)
	}

	// Build summary message
	var summaryParts []string

	if len(m.TypeCounts) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d asset type(s)", len(m.TypeCounts)))
	}

	if len(m.Assets) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d asset(s)", len(m.Assets)))
	}

	if checkIAM {
		publicCount := 0
		for _, asset := range m.Assets {
			if asset.PublicAccess {
				publicCount++
			}
		}
		if publicCount > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("%d with public access", publicCount))
		}
	}

	if len(m.Dependencies) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d dependencies", len(m.Dependencies)))
	}

	if len(m.CrossProject) > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d cross-project resources", len(m.CrossProject)))
	}

	if len(summaryParts) == 0 {
		logger.InfoM("No assets found", globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %s", strings.Join(summaryParts, ", ")), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	m.writeOutput(ctx, logger)
}

func (m *AssetInventoryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating assets in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	svc := assetservice.New()
	assets, err := svc.ListAssets(projectID, assetTypes)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate assets in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.Assets = append(m.Assets, assets...)
	for _, asset := range assets {
		m.addToLoot(asset)
	}
	m.mu.Unlock()
}

func (m *AssetInventoryModule) processProjectIAM(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating assets with IAM in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	svc := assetservice.New()
	assets, err := svc.ListAssetsWithIAM(projectID, assetTypes)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate assets with IAM in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.Assets = append(m.Assets, assets...)
	for _, asset := range assets {
		m.addToLoot(asset)
	}
	m.mu.Unlock()
}

func (m *AssetInventoryModule) processProjectCounts(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Counting assets in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	svc := assetservice.New()
	counts, err := svc.GetAssetTypeCounts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
			fmt.Sprintf("Could not count assets in project %s", projectID))
		return
	}

	m.mu.Lock()
	// Merge counts from multiple projects
	countMap := make(map[string]int)
	for _, c := range m.TypeCounts {
		countMap[c.AssetType] = c.Count
	}
	for _, c := range counts {
		countMap[c.AssetType] += c.Count
	}

	m.TypeCounts = []assetservice.AssetTypeCount{}
	for assetType, count := range countMap {
		m.TypeCounts = append(m.TypeCounts, assetservice.AssetTypeCount{
			AssetType: assetType,
			Count:     count,
		})
	}
	m.mu.Unlock()
}

// processProjectsDependencies analyzes assets with full dependency tracking
func (m *AssetInventoryModule) processProjectsDependencies(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing assets and dependencies...", globals.GCP_ASSET_INVENTORY_MODULE_NAME)

	assetClient, err := asset.NewClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Cloud Asset client: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		return
	}
	defer assetClient.Close()

	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProjectWithDependencies(ctx, project, assetClient, logger)
		}(projectID)
	}
	wg.Wait()

	// Analyze cross-project dependencies
	m.analyzeCrossProjectResources()

	// Generate query templates
	m.generateQueryTemplates()
}

func (m *AssetInventoryModule) processProjectWithDependencies(ctx context.Context, projectID string, assetClient *asset.Client, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing dependencies in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	parent := fmt.Sprintf("projects/%s", projectID)
	req := &assetpb.ListAssetsRequest{
		Parent:      parent,
		ContentType: assetpb.ContentType_RESOURCE,
		PageSize:    500,
	}

	it := assetClient.ListAssets(ctx, req)

	for {
		assetItem, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_ASSET_INVENTORY_MODULE_NAME,
				fmt.Sprintf("Could not enumerate assets in project %s", projectID))
			break
		}

		// Convert to AssetInfo for consistency
		assetInfo := assetservice.AssetInfo{
			Name:      assetItem.Name,
			AssetType: assetItem.AssetType,
			ProjectID: projectID,
		}

		if assetItem.Resource != nil {
			assetInfo.Location = assetItem.Resource.Location
		}

		m.mu.Lock()
		m.Assets = append(m.Assets, assetInfo)
		m.mu.Unlock()

		// Analyze dependencies
		m.analyzeAssetDependencies(assetItem, projectID)
	}
}

func (m *AssetInventoryModule) analyzeAssetDependencies(assetItem *assetpb.Asset, projectID string) {
	if assetItem.Resource == nil || assetItem.Resource.Data == nil {
		return
	}

	// Common dependency patterns
	dependencyFields := map[string]string{
		"network":        "uses",
		"subnetwork":     "uses",
		"serviceAccount": "uses",
		"disk":           "uses",
		"snapshot":       "references",
		"image":          "references",
		"keyRing":        "uses",
		"cryptoKey":      "uses",
		"topic":          "references",
		"subscription":   "references",
		"bucket":         "uses",
		"dataset":        "references",
		"cluster":        "contains",
	}

	for field, depType := range dependencyFields {
		if value, ok := assetItem.Resource.Data.Fields[field]; ok {
			targetResource := value.GetStringValue()
			if targetResource != "" {
				dependency := ResourceDependency{
					SourceResource: assetItem.Name,
					SourceType:     assetItem.AssetType,
					TargetResource: targetResource,
					TargetType:     m.inferResourceType(field),
					DependencyType: depType,
					ProjectID:      projectID,
				}

				m.mu.Lock()
				m.Dependencies = append(m.Dependencies, dependency)
				m.mu.Unlock()
			}
		}
	}
}

func (m *AssetInventoryModule) inferResourceType(fieldName string) string {
	typeMap := map[string]string{
		"network":        "compute.googleapis.com/Network",
		"subnetwork":     "compute.googleapis.com/Subnetwork",
		"serviceAccount": "iam.googleapis.com/ServiceAccount",
		"disk":           "compute.googleapis.com/Disk",
		"snapshot":       "compute.googleapis.com/Snapshot",
		"image":          "compute.googleapis.com/Image",
		"keyRing":        "cloudkms.googleapis.com/KeyRing",
		"cryptoKey":      "cloudkms.googleapis.com/CryptoKey",
		"topic":          "pubsub.googleapis.com/Topic",
		"subscription":   "pubsub.googleapis.com/Subscription",
		"bucket":         "storage.googleapis.com/Bucket",
		"dataset":        "bigquery.googleapis.com/Dataset",
		"cluster":        "container.googleapis.com/Cluster",
	}

	if assetType, ok := typeMap[fieldName]; ok {
		return assetType
	}
	return "unknown"
}

func (m *AssetInventoryModule) analyzeCrossProjectResources() {
	m.mu.Lock()
	defer m.mu.Unlock()

	targetToSources := make(map[string][]string)
	targetToType := make(map[string]string)

	for _, dep := range m.Dependencies {
		targetProject := m.extractProjectFromResource(dep.TargetResource)
		if targetProject != "" && targetProject != dep.ProjectID {
			targetToSources[dep.TargetResource] = append(targetToSources[dep.TargetResource], dep.ProjectID)
			targetToType[dep.TargetResource] = dep.TargetType
		}
	}

	for target, sources := range targetToSources {
		crossProject := CrossProjectResource{
			ResourceName: target,
			ResourceType: targetToType[target],
			OwnerProject: m.extractProjectFromResource(target),
			AccessedFrom: sources,
		}

		m.CrossProject = append(m.CrossProject, crossProject)
	}
}

func (m *AssetInventoryModule) extractProjectFromResource(resource string) string {
	if strings.Contains(resource, "projects/") {
		parts := strings.Split(resource, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *AssetInventoryModule) extractResourceName(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return resource
}

func (m *AssetInventoryModule) generateQueryTemplates() {
	templates := []struct {
		Name        string
		Description string
		Query       string
	}{
		{"Public Storage Buckets", "Find all public GCS buckets", `resource.type="storage.googleapis.com/Bucket" AND resource.data.iamConfiguration.uniformBucketLevelAccess.enabled=false`},
		{"VMs with External IPs", "Find compute instances with external IP addresses", `resource.type="compute.googleapis.com/Instance" AND resource.data.networkInterfaces.accessConfigs:*`},
		{"Service Account Keys", "Find all user-managed service account keys", `resource.type="iam.googleapis.com/ServiceAccountKey" AND resource.data.keyType="USER_MANAGED"`},
		{"Firewall Rules - Open to Internet", "Find firewall rules allowing 0.0.0.0/0", `resource.type="compute.googleapis.com/Firewall" AND resource.data.sourceRanges:"0.0.0.0/0"`},
		{"Cloud SQL - Public IPs", "Find Cloud SQL instances with public IP", `resource.type="sqladmin.googleapis.com/Instance" AND resource.data.settings.ipConfiguration.ipv4Enabled=true`},
		{"Unencrypted Disks", "Find disks without customer-managed encryption", `resource.type="compute.googleapis.com/Disk" AND NOT resource.data.diskEncryptionKey:*`},
		{"GKE Clusters - Legacy Auth", "Find GKE clusters with legacy authentication", `resource.type="container.googleapis.com/Cluster" AND resource.data.legacyAbac.enabled=true`},
	}

	for _, t := range templates {
		m.LootMap["asset-inventory-commands"].Contents += fmt.Sprintf(
			"# %s - %s\ngcloud asset search-all-resources --scope=projects/PROJECT_ID --query='%s'\n\n",
			t.Name, t.Description, t.Query,
		)
	}

	// Add export commands
	m.LootMap["asset-inventory-commands"].Contents += "# Export complete asset inventory\n"
	for _, projectID := range m.ProjectIDs {
		m.LootMap["asset-inventory-commands"].Contents += fmt.Sprintf(
			"gcloud asset export --project=%s --content-type=resource --output-path=gs://BUCKET_NAME/%s-assets.json\n",
			projectID, projectID,
		)
	}
}

func (m *AssetInventoryModule) initializeLootFiles() {
	m.LootMap["asset-inventory-details"] = &internal.LootFile{
		Name:     "asset-inventory-details",
		Contents: "# Cloud Asset Inventory Details\n# Generated by CloudFox\n\n",
	}
	m.LootMap["asset-inventory-commands"] = &internal.LootFile{
		Name:     "asset-inventory-commands",
		Contents: "# Cloud Asset Inventory Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *AssetInventoryModule) addToLoot(asset assetservice.AssetInfo) {
	m.LootMap["asset-inventory-details"].Contents += fmt.Sprintf(
		"# Asset: %s\n# Type: %s\n# Project: %s\n# Location: %s\n",
		asset.Name, asset.AssetType, asset.ProjectID, asset.Location)

	if asset.PublicAccess {
		m.LootMap["asset-inventory-details"].Contents += "# Public Access: Yes\n"
	}
	m.LootMap["asset-inventory-details"].Contents += "\n"
}

func (m *AssetInventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// Asset counts table (if we have counts)
	if len(m.TypeCounts) > 0 {
		// Sort by count descending
		sort.Slice(m.TypeCounts, func(i, j int) bool {
			return m.TypeCounts[i].Count > m.TypeCounts[j].Count
		})

		header := []string{"Asset Type", "Count"}
		var body [][]string
		for _, tc := range m.TypeCounts {
			body = append(body, []string{
				tc.AssetType,
				fmt.Sprintf("%d", tc.Count),
			})
		}
		tables = append(tables, internal.TableFile{
			Name:   "asset-counts",
			Header: header,
			Body:   body,
		})
	}

	// Assets table (if we have assets)
	if len(m.Assets) > 0 {
		if checkIAM {
			// When checking IAM, show one row per IAM binding member
			header := []string{"Project ID", "Project Name", "Name", "Asset Type", "Location", "Role", "Member", "Public"}

			var body [][]string
			for _, asset := range m.Assets {
				publicAccess := "No"
				if asset.PublicAccess {
					publicAccess = "Yes"
				}

				// If no IAM bindings, still show the asset
				if len(asset.IAMBindings) == 0 {
					body = append(body, []string{
						asset.ProjectID,
						m.GetProjectName(asset.ProjectID),
						asset.Name,
						assetservice.ExtractAssetTypeShort(asset.AssetType),
						asset.Location,
						"-",
						"-",
						publicAccess,
					})
				} else {
					// One row per member per role
					for _, binding := range asset.IAMBindings {
						for _, member := range binding.Members {
							body = append(body, []string{
								asset.ProjectID,
								m.GetProjectName(asset.ProjectID),
								asset.Name,
								assetservice.ExtractAssetTypeShort(asset.AssetType),
								asset.Location,
								binding.Role,
								member,
								publicAccess,
							})
						}
					}
				}
			}
			tables = append(tables, internal.TableFile{
				Name:   "assets",
				Header: header,
				Body:   body,
			})

			// Public assets table
			var publicBody [][]string
			for _, asset := range m.Assets {
				if asset.PublicAccess {
					for _, binding := range asset.IAMBindings {
						for _, member := range binding.Members {
							if member == "allUsers" || member == "allAuthenticatedUsers" {
								publicBody = append(publicBody, []string{
									asset.ProjectID,
									m.GetProjectName(asset.ProjectID),
									asset.Name,
									asset.AssetType,
									binding.Role,
									member,
								})
							}
						}
					}
				}
			}

			if len(publicBody) > 0 {
				tables = append(tables, internal.TableFile{
					Name:   "public-assets",
					Header: []string{"Project ID", "Project Name", "Name", "Asset Type", "Role", "Member"},
					Body:   publicBody,
				})
			}
		} else {
			// Basic listing without IAM
			header := []string{"Project ID", "Project Name", "Name", "Asset Type", "Location"}
			var body [][]string
			for _, asset := range m.Assets {
				body = append(body, []string{
					asset.ProjectID,
					m.GetProjectName(asset.ProjectID),
					asset.Name,
					assetservice.ExtractAssetTypeShort(asset.AssetType),
					asset.Location,
				})
			}
			tables = append(tables, internal.TableFile{
				Name:   "assets",
				Header: header,
				Body:   body,
			})
		}
	}

	// Dependencies table (if we have dependencies)
	if len(m.Dependencies) > 0 {
		depsHeader := []string{"Project ID", "Project Name", "Source", "Dependency Type", "Target", "Target Type"}
		var depsBody [][]string
		for _, d := range m.Dependencies {
			depsBody = append(depsBody, []string{
				d.ProjectID,
				m.GetProjectName(d.ProjectID),
				m.extractResourceName(d.SourceResource),
				d.DependencyType,
				m.extractResourceName(d.TargetResource),
				assetservice.ExtractAssetTypeShort(d.TargetType),
			})

			// Add to loot
			m.LootMap["asset-inventory-details"].Contents += fmt.Sprintf(
				"# Dependency: %s -> %s (%s)\n",
				m.extractResourceName(d.SourceResource),
				m.extractResourceName(d.TargetResource),
				d.DependencyType,
			)
		}
		tables = append(tables, internal.TableFile{
			Name:   "asset-dependencies",
			Header: depsHeader,
			Body:   depsBody,
		})
	}

	// Cross-project resources table (if we have cross-project resources)
	if len(m.CrossProject) > 0 {
		crossHeader := []string{"Resource", "Type", "Owner Project", "Accessed From"}
		var crossBody [][]string
		for _, c := range m.CrossProject {
			crossBody = append(crossBody, []string{
				m.extractResourceName(c.ResourceName),
				assetservice.ExtractAssetTypeShort(c.ResourceType),
				c.OwnerProject,
				strings.Join(c.AccessedFrom, ", "),
			})
		}
		tables = append(tables, internal.TableFile{
			Name:   "cross-project-resources",
			Header: crossHeader,
			Body:   crossBody,
		})
	}

	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	output := AssetInventoryOutput{Table: tables, Loot: lootFiles}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}
}
