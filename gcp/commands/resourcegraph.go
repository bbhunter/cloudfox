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

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"
)

// Module name constant
const GCP_RESOURCEGRAPH_MODULE_NAME string = "resource-graph"

var GCPResourceGraphCommand = &cobra.Command{
	Use:     GCP_RESOURCEGRAPH_MODULE_NAME,
	Aliases: []string{"assets", "inventory", "cai"},
	Short:   "Advanced resource query capabilities using Cloud Asset Inventory",
	Long: `Query and analyze resources across projects using Cloud Asset Inventory.

Features:
- Lists all resources across multiple projects
- Analyzes resource dependencies and relationships
- Identifies cross-project resources
- Generates comprehensive asset inventory
- Provides query templates for common security use cases
- Tracks resource metadata and labels

Use Cases:
- Complete resource inventory for auditing
- Cross-project dependency mapping
- Resource lifecycle analysis
- Compliance evidence gathering
- Security posture assessment

Requires appropriate IAM permissions:
- roles/cloudasset.viewer
- roles/resourcemanager.projectViewer`,
	Run: runGCPResourceGraphCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type AssetResource struct {
	Name           string
	AssetType      string
	ProjectID      string
	Location       string
	DisplayName    string
	ParentFullName string
	CreateTime     string
	UpdateTime     string
	State          string
	Labels         map[string]string
	NetworkTags    []string
	ResourceURL    string
}

type ResourceDependency struct {
	SourceResource string
	SourceType     string
	TargetResource string
	TargetType     string
	DependencyType string // uses, references, contains, manages
	ProjectID      string
}

type CrossProjectResource struct {
	ResourceName   string
	ResourceType   string
	OwnerProject   string
	AccessedFrom   []string
	AccessType     string
	RiskLevel      string
}

type ResourceTypeSummary struct {
	AssetType  string
	Count      int
	ProjectIDs []string
}

// ------------------------------
// Module Struct
// ------------------------------
type ResourceGraphModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Assets          []AssetResource
	Dependencies    []ResourceDependency
	CrossProject    []CrossProjectResource
	TypeSummary     map[string]*ResourceTypeSummary
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex

	// Tracking
	totalAssets     int
	assetsByType    map[string]int
	assetsByProject map[string]int
}

// ------------------------------
// Output Struct
// ------------------------------
type ResourceGraphOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ResourceGraphOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ResourceGraphOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPResourceGraphCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_RESOURCEGRAPH_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &ResourceGraphModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		Assets:          []AssetResource{},
		Dependencies:    []ResourceDependency{},
		CrossProject:    []CrossProjectResource{},
		TypeSummary:     make(map[string]*ResourceTypeSummary),
		LootMap:         make(map[string]*internal.LootFile),
		assetsByType:    make(map[string]int),
		assetsByProject: make(map[string]int),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ResourceGraphModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Querying Cloud Asset Inventory for resource analysis...", GCP_RESOURCEGRAPH_MODULE_NAME)

	// Create Asset client
	assetClient, err := asset.NewClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Cloud Asset client: %v", err), GCP_RESOURCEGRAPH_MODULE_NAME)
		return
	}
	defer assetClient.Close()

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, assetClient, logger)
		}(projectID)
	}
	wg.Wait()

	// Analyze cross-project dependencies
	m.analyzeCrossProjectResources(logger)

	// Generate query templates
	m.generateQueryTemplates()

	// Check results
	if m.totalAssets == 0 {
		logger.InfoM("No assets found via Cloud Asset Inventory", GCP_RESOURCEGRAPH_MODULE_NAME)
		logger.InfoM("Ensure Cloud Asset API is enabled and you have appropriate permissions", GCP_RESOURCEGRAPH_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Inventoried %d asset(s) across %d project(s)",
		m.totalAssets, len(m.assetsByProject)), GCP_RESOURCEGRAPH_MODULE_NAME)

	// Show top asset types
	typeCount := len(m.assetsByType)
	if typeCount > 0 {
		logger.InfoM(fmt.Sprintf("Found %d unique asset type(s)", typeCount), GCP_RESOURCEGRAPH_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *ResourceGraphModule) processProject(ctx context.Context, projectID string, assetClient *asset.Client, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Querying assets for project: %s", projectID), GCP_RESOURCEGRAPH_MODULE_NAME)
	}

	parent := fmt.Sprintf("projects/%s", projectID)

	// List assets with content type set to get full resource details
	req := &assetpb.ListAssetsRequest{
		Parent:      parent,
		ContentType: assetpb.ContentType_RESOURCE,
		PageSize:    500,
	}

	it := assetClient.ListAssets(ctx, req)
	assetCount := 0

	for {
		asset, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing assets for project %s: %v", projectID, err), GCP_RESOURCEGRAPH_MODULE_NAME)
			}
			break
		}

		assetResource := m.parseAsset(asset, projectID)

		m.mu.Lock()
		m.Assets = append(m.Assets, assetResource)
		m.totalAssets++
		assetCount++

		// Track by type
		m.assetsByType[assetResource.AssetType]++

		// Track by project
		m.assetsByProject[projectID]++

		// Update type summary
		if summary, exists := m.TypeSummary[assetResource.AssetType]; exists {
			summary.Count++
			// Add project if not already tracked
			found := false
			for _, p := range summary.ProjectIDs {
				if p == projectID {
					found = true
					break
				}
			}
			if !found {
				summary.ProjectIDs = append(summary.ProjectIDs, projectID)
			}
		} else {
			m.TypeSummary[assetResource.AssetType] = &ResourceTypeSummary{
				AssetType:  assetResource.AssetType,
				Count:      1,
				ProjectIDs: []string{projectID},
			}
		}
		m.mu.Unlock()

		// Analyze dependencies
		m.analyzeAssetDependencies(asset, projectID)
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d assets in project %s", assetCount, projectID), GCP_RESOURCEGRAPH_MODULE_NAME)
	}
}

func (m *ResourceGraphModule) parseAsset(asset *assetpb.Asset, projectID string) AssetResource {
	assetResource := AssetResource{
		Name:      asset.Name,
		AssetType: asset.AssetType,
		ProjectID: projectID,
	}

	// Parse resource data if available
	if asset.Resource != nil {
		assetResource.ParentFullName = asset.Resource.Parent
		assetResource.ResourceURL = asset.Resource.DiscoveryDocumentUri
		assetResource.Location = asset.Resource.Location

		// Extract display name from resource data
		if asset.Resource.Data != nil {
			if name, ok := asset.Resource.Data.Fields["name"]; ok {
				assetResource.DisplayName = name.GetStringValue()
			}
			if displayName, ok := asset.Resource.Data.Fields["displayName"]; ok {
				assetResource.DisplayName = displayName.GetStringValue()
			}

			// Extract labels
			if labels, ok := asset.Resource.Data.Fields["labels"]; ok {
				if labels.GetStructValue() != nil {
					assetResource.Labels = make(map[string]string)
					for k, v := range labels.GetStructValue().Fields {
						assetResource.Labels[k] = v.GetStringValue()
					}
				}
			}

			// Extract network tags for compute instances
			if tags, ok := asset.Resource.Data.Fields["tags"]; ok {
				if tagsStruct := tags.GetStructValue(); tagsStruct != nil {
					if items, ok := tagsStruct.Fields["items"]; ok {
						for _, item := range items.GetListValue().Values {
							assetResource.NetworkTags = append(assetResource.NetworkTags, item.GetStringValue())
						}
					}
				}
			}
		}
	}

	// Parse update time
	if asset.UpdateTime != nil {
		assetResource.UpdateTime = asset.UpdateTime.AsTime().Format("2006-01-02 15:04:05")
	}

	return assetResource
}

func (m *ResourceGraphModule) analyzeAssetDependencies(asset *assetpb.Asset, projectID string) {
	if asset.Resource == nil || asset.Resource.Data == nil {
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
		if value, ok := asset.Resource.Data.Fields[field]; ok {
			targetResource := value.GetStringValue()
			if targetResource != "" {
				dependency := ResourceDependency{
					SourceResource: asset.Name,
					SourceType:     asset.AssetType,
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

func (m *ResourceGraphModule) inferResourceType(fieldName string) string {
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

func (m *ResourceGraphModule) analyzeCrossProjectResources(logger internal.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Group dependencies by target resource
	targetToSources := make(map[string][]string) // target -> source projects
	targetToType := make(map[string]string)

	for _, dep := range m.Dependencies {
		// Check if target is in a different project
		targetProject := m.extractProjectFromResource(dep.TargetResource)
		if targetProject != "" && targetProject != dep.ProjectID {
			targetToSources[dep.TargetResource] = append(targetToSources[dep.TargetResource], dep.ProjectID)
			targetToType[dep.TargetResource] = dep.TargetType
		}
	}

	// Create cross-project records
	for target, sources := range targetToSources {
		crossProject := CrossProjectResource{
			ResourceName: target,
			ResourceType: targetToType[target],
			OwnerProject: m.extractProjectFromResource(target),
			AccessedFrom: sources,
			AccessType:   "dependency",
			RiskLevel:    "LOW",
		}

		// Higher risk if accessed from many projects
		if len(sources) > 2 {
			crossProject.RiskLevel = "MEDIUM"
		}

		m.CrossProject = append(m.CrossProject, crossProject)
	}
}

func (m *ResourceGraphModule) extractProjectFromResource(resource string) string {
	// Format: //service.googleapis.com/projects/{project}/...
	// or: projects/{project}/...
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

func (m *ResourceGraphModule) generateQueryTemplates() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate useful query templates for Cloud Asset Inventory
	templates := []struct {
		Name        string
		Description string
		Query       string
	}{
		{
			Name:        "Public Storage Buckets",
			Description: "Find all public GCS buckets",
			Query:       `resource.type="storage.googleapis.com/Bucket" AND resource.data.iamConfiguration.uniformBucketLevelAccess.enabled=false`,
		},
		{
			Name:        "VMs with External IPs",
			Description: "Find compute instances with external IP addresses",
			Query:       `resource.type="compute.googleapis.com/Instance" AND resource.data.networkInterfaces.accessConfigs:*`,
		},
		{
			Name:        "Service Account Keys",
			Description: "Find all user-managed service account keys",
			Query:       `resource.type="iam.googleapis.com/ServiceAccountKey" AND resource.data.keyType="USER_MANAGED"`,
		},
		{
			Name:        "Firewall Rules - Open to Internet",
			Description: "Find firewall rules allowing 0.0.0.0/0",
			Query:       `resource.type="compute.googleapis.com/Firewall" AND resource.data.sourceRanges:"0.0.0.0/0"`,
		},
		{
			Name:        "Cloud SQL - Public IPs",
			Description: "Find Cloud SQL instances with public IP",
			Query:       `resource.type="sqladmin.googleapis.com/Instance" AND resource.data.settings.ipConfiguration.ipv4Enabled=true`,
		},
		{
			Name:        "Unencrypted Disks",
			Description: "Find disks without customer-managed encryption",
			Query:       `resource.type="compute.googleapis.com/Disk" AND NOT resource.data.diskEncryptionKey:*`,
		},
		{
			Name:        "GKE Clusters - Legacy Auth",
			Description: "Find GKE clusters with legacy authentication",
			Query:       `resource.type="container.googleapis.com/Cluster" AND resource.data.legacyAbac.enabled=true`,
		},
		{
			Name:        "Resources Without Labels",
			Description: "Find resources missing required labels",
			Query:       `NOT labels:* AND (resource.type="compute.googleapis.com/Instance" OR resource.type="storage.googleapis.com/Bucket")`,
		},
	}

	for _, t := range templates {
		m.LootMap["query-templates"].Contents += fmt.Sprintf(
			"## %s\n"+
				"# %s\n"+
				"# Query:\n"+
				"gcloud asset search-all-resources \\\n"+
				"  --scope=projects/PROJECT_ID \\\n"+
				"  --query='%s'\n\n",
			t.Name, t.Description, t.Query,
		)
	}

	// Add asset inventory export commands
	m.LootMap["asset-inventory-commands"].Contents += "# Export complete asset inventory\n"
	for _, projectID := range m.ProjectIDs {
		m.LootMap["asset-inventory-commands"].Contents += fmt.Sprintf(
			"gcloud asset export \\\n"+
				"  --project=%s \\\n"+
				"  --content-type=resource \\\n"+
				"  --output-path=gs://BUCKET_NAME/%s-assets.json\n\n",
			projectID, projectID,
		)
	}

	// Add search commands
	m.LootMap["asset-inventory-commands"].Contents += "\n# Search for specific resource types\n"
	m.LootMap["asset-inventory-commands"].Contents += "gcloud asset search-all-resources --scope=projects/PROJECT_ID --asset-types=compute.googleapis.com/Instance\n"
	m.LootMap["asset-inventory-commands"].Contents += "gcloud asset search-all-resources --scope=projects/PROJECT_ID --asset-types=storage.googleapis.com/Bucket\n"
	m.LootMap["asset-inventory-commands"].Contents += "gcloud asset search-all-resources --scope=projects/PROJECT_ID --asset-types=iam.googleapis.com/ServiceAccount\n"
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ResourceGraphModule) initializeLootFiles() {
	m.LootMap["query-templates"] = &internal.LootFile{
		Name:     "query-templates",
		Contents: "# Cloud Asset Inventory Query Templates\n# Generated by CloudFox\n# Use these queries to search for security-relevant resources\n\n",
	}
	m.LootMap["asset-inventory-commands"] = &internal.LootFile{
		Name:     "asset-inventory-commands",
		Contents: "# Cloud Asset Inventory Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["resource-dependencies"] = &internal.LootFile{
		Name:     "resource-dependencies",
		Contents: "# Resource Dependencies\n# Generated by CloudFox\n\n",
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ResourceGraphModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Create type summary sorted by count
	var summaryList []*ResourceTypeSummary
	for _, summary := range m.TypeSummary {
		summaryList = append(summaryList, summary)
	}
	sort.Slice(summaryList, func(i, j int) bool {
		return summaryList[i].Count > summaryList[j].Count
	})

	// Type Summary table
	summaryHeader := []string{
		"Asset Type",
		"Count",
		"Projects",
	}

	var summaryBody [][]string
	for _, s := range summaryList {
		summaryBody = append(summaryBody, []string{
			truncateString(s.AssetType, 50),
			fmt.Sprintf("%d", s.Count),
			fmt.Sprintf("%d", len(s.ProjectIDs)),
		})
	}

	// Assets table (limited to most recent)
	assetsHeader := []string{
		"Name",
		"Type",
		"Project Name",
		"Project ID",
		"Location",
		"Updated",
	}

	// Sort by update time
	sort.Slice(m.Assets, func(i, j int) bool {
		return m.Assets[i].UpdateTime > m.Assets[j].UpdateTime
	})

	var assetsBody [][]string
	maxAssets := 100 // Limit output size
	for i, a := range m.Assets {
		if i >= maxAssets {
			break
		}
		name := a.DisplayName
		if name == "" {
			name = m.extractResourceName(a.Name)
		}
		assetsBody = append(assetsBody, []string{
			truncateString(name, 40),
			truncateString(a.AssetType, 40),
			m.GetProjectName(a.ProjectID),
			a.ProjectID,
			a.Location,
			truncateString(a.UpdateTime, 20),
		})
	}

	// Dependencies table
	depsHeader := []string{
		"Source",
		"Dependency Type",
		"Target",
		"Target Type",
	}

	var depsBody [][]string
	for _, d := range m.Dependencies {
		depsBody = append(depsBody, []string{
			truncateString(m.extractResourceName(d.SourceResource), 35),
			d.DependencyType,
			truncateString(m.extractResourceName(d.TargetResource), 35),
			truncateString(d.TargetType, 30),
		})

		// Add to loot
		m.LootMap["resource-dependencies"].Contents += fmt.Sprintf(
			"%s -> %s (%s)\n",
			m.extractResourceName(d.SourceResource),
			m.extractResourceName(d.TargetResource),
			d.DependencyType,
		)
	}

	// Cross-project resources table
	crossHeader := []string{
		"Resource",
		"Type",
		"Owner Project Name",
		"Owner Project ID",
		"Accessed From",
		"Risk",
	}

	var crossBody [][]string
	for _, c := range m.CrossProject {
		crossBody = append(crossBody, []string{
			truncateString(m.extractResourceName(c.ResourceName), 35),
			truncateString(c.ResourceType, 30),
			m.GetProjectName(c.OwnerProject),
			c.OwnerProject,
			strings.Join(c.AccessedFrom, ","),
			c.RiskLevel,
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
	tables := []internal.TableFile{
		{
			Name:   "asset-type-summary",
			Header: summaryHeader,
			Body:   summaryBody,
		},
	}

	if len(assetsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "assets",
			Header: assetsHeader,
			Body:   assetsBody,
		})
	}

	if len(depsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "resource-dependencies",
			Header: depsHeader,
			Body:   depsBody,
		})
	}

	if len(crossBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cross-project-resources",
			Header: crossHeader,
			Body:   crossBody,
		})
	}

	output := ResourceGraphOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_RESOURCEGRAPH_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *ResourceGraphModule) extractResourceName(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return resource
}
