package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	assetservice "github.com/BishopFox/cloudfox/gcp/services/assetService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var (
	assetTypes   []string
	showCounts   bool
	checkIAM     bool
)

var GCPAssetInventoryCommand = &cobra.Command{
	Use:     globals.GCP_ASSET_INVENTORY_MODULE_NAME,
	Aliases: []string{"assets", "inventory", "cai"},
	Short:   "Enumerate Cloud Asset Inventory",
	Long: `Enumerate resources using Cloud Asset Inventory API.

Features:
- Lists all assets in a project
- Provides asset counts by type
- Can check IAM policies for public access
- Supports filtering by asset type

Examples:
  cloudfox gcp asset-inventory -p my-project
  cloudfox gcp asset-inventory -p my-project --counts
  cloudfox gcp asset-inventory -p my-project --iam
  cloudfox gcp asset-inventory -p my-project --types compute.googleapis.com/Instance,storage.googleapis.com/Bucket`,
	Run: runGCPAssetInventoryCommand,
}

func init() {
	GCPAssetInventoryCommand.Flags().StringSliceVar(&assetTypes, "types", []string{}, "Filter by asset types (comma-separated)")
	GCPAssetInventoryCommand.Flags().BoolVar(&showCounts, "counts", false, "Show asset counts by type only")
	GCPAssetInventoryCommand.Flags().BoolVar(&checkIAM, "iam", false, "Check IAM policies for public access")
}

type AssetInventoryModule struct {
	gcpinternal.BaseGCPModule
	Assets     []assetservice.AssetInfo
	TypeCounts []assetservice.AssetTypeCount
	LootMap    map[string]*internal.LootFile
	mu         sync.Mutex
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
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *AssetInventoryModule) Execute(ctx context.Context, logger internal.Logger) {
	if showCounts {
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProjectCounts)
	} else if checkIAM {
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProjectIAM)
	} else {
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ASSET_INVENTORY_MODULE_NAME, m.processProject)
	}

	if showCounts {
		if len(m.TypeCounts) == 0 {
			logger.InfoM("No assets found", globals.GCP_ASSET_INVENTORY_MODULE_NAME)
			return
		}
		logger.SuccessM(fmt.Sprintf("Found %d asset type(s)", len(m.TypeCounts)), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	} else {
		if len(m.Assets) == 0 {
			logger.InfoM("No assets found", globals.GCP_ASSET_INVENTORY_MODULE_NAME)
			return
		}

		publicCount := 0
		for _, asset := range m.Assets {
			if asset.PublicAccess {
				publicCount++
			}
		}

		if checkIAM {
			logger.SuccessM(fmt.Sprintf("Found %d asset(s) (%d with public access)",
				len(m.Assets), publicCount), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		} else {
			logger.SuccessM(fmt.Sprintf("Found %d asset(s)", len(m.Assets)), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		}
	}

	m.writeOutput(ctx, logger)
}

func (m *AssetInventoryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating assets in project: %s", projectID), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}

	svc := assetservice.New()
	assets, err := svc.ListAssets(projectID, assetTypes)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not list assets: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		}
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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not list assets with IAM: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		}
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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not count assets: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
		}
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

func (m *AssetInventoryModule) initializeLootFiles() {
	m.LootMap["asset-inventory"] = &internal.LootFile{
		Name:     "asset-inventory",
		Contents: "# Cloud Asset Inventory\n# Generated by CloudFox\n\n",
	}
	m.LootMap["public-assets"] = &internal.LootFile{
		Name:     "public-assets",
		Contents: "",
	}
}

func (m *AssetInventoryModule) addToLoot(asset assetservice.AssetInfo) {
	m.LootMap["asset-inventory"].Contents += fmt.Sprintf(
		"# Asset: %s\n# Type: %s\n# Project: %s\n# Location: %s\n\n",
		asset.Name, asset.AssetType, asset.ProjectID, asset.Location)

	if asset.PublicAccess {
		m.LootMap["public-assets"].Contents += fmt.Sprintf("%s (%s)\n", asset.Name, asset.AssetType)
	}
}

func (m *AssetInventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	if showCounts {
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
	} else {
		header := []string{"Name", "Asset Type", "Location", "Project"}
		if checkIAM {
			header = append(header, "IAM Bindings", "Public Access", "Risk")
		}

		var body [][]string
		for _, asset := range m.Assets {
			row := []string{
				asset.Name,
				assetservice.ExtractAssetTypeShort(asset.AssetType),
				asset.Location,
				asset.ProjectID,
			}
			if checkIAM {
				publicAccess := "No"
				if asset.PublicAccess {
					publicAccess = "Yes"
				}
				row = append(row, fmt.Sprintf("%d", asset.IAMBindings), publicAccess, asset.RiskLevel)
			}
			body = append(body, row)
		}
		tables = append(tables, internal.TableFile{
			Name:   "assets",
			Header: header,
			Body:   body,
		})

		// Public assets table (if checking IAM)
		if checkIAM {
			var publicBody [][]string
			for _, asset := range m.Assets {
				if asset.PublicAccess {
					publicBody = append(publicBody, []string{
						asset.Name,
						asset.AssetType,
						asset.RiskLevel,
						strings.Join(asset.RiskReasons, "; "),
						asset.ProjectID,
					})
				}
			}

			if len(publicBody) > 0 {
				tables = append(tables, internal.TableFile{
					Name:   "public-assets",
					Header: []string{"Name", "Asset Type", "Risk Level", "Reasons", "Project"},
					Body:   publicBody,
				})
			}
		}
	}

	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	output := AssetInventoryOutput{Table: tables, Loot: lootFiles}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, m.ProjectIDs, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ASSET_INVENTORY_MODULE_NAME)
	}
}
