package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	GKEService "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPGKECommand = &cobra.Command{
	Use:     globals.GCP_GKE_MODULE_NAME,
	Aliases: []string{"kubernetes", "k8s", "clusters"},
	Short:   "Enumerate GKE clusters with security analysis",
	Long: `Enumerate GKE clusters across projects with comprehensive security analysis.

Features:
- Lists all GKE clusters accessible to the authenticated user
- Analyzes security configuration (private clusters, authorized networks, RBAC)
- Identifies clusters with public API endpoints
- Shows workload identity configuration
- Detects common misconfigurations (legacy ABAC, basic auth, no network policy)
- Enumerates node pools with service accounts and OAuth scopes
- Shows Binary Authorization status
- Shows GKE Autopilot vs Standard mode
- Shows Config Connector and Istio/ASM status
- Shows maintenance window and exclusions
- Generates kubectl and gcloud commands for further analysis

Security Columns:
- Private: Whether the cluster uses private nodes (no public IPs)
- MasterAuth: Master authorized networks enabled
- NetworkPolicy: Kubernetes network policy controller enabled
- WorkloadIdentity: GKE Workload Identity configured
- ShieldedNodes: Shielded GKE nodes enabled
- BinAuth: Binary Authorization enabled
- Autopilot: GKE Autopilot mode (vs Standard)
- Issues: Detected security misconfigurations

Attack Surface:
- Public API servers are accessible from the internet
- Clusters without Workload Identity use node service accounts
- Default service accounts may have excessive permissions
- Legacy ABAC allows broader access than RBAC
- Autopilot clusters have reduced attack surface
- Binary Authorization prevents untrusted container images`,
	Run: runGCPGKECommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type GKEModule struct {
	gcpinternal.BaseGCPModule

	Clusters  []GKEService.ClusterInfo
	NodePools []GKEService.NodePoolInfo
	LootMap   map[string]*internal.LootFile
	mu        sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type GKEOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o GKEOutput) TableFiles() []internal.TableFile { return o.Table }
func (o GKEOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPGKECommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_GKE_MODULE_NAME)
	if err != nil {
		return
	}

	module := &GKEModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Clusters:      []GKEService.ClusterInfo{},
		NodePools:     []GKEService.NodePoolInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *GKEModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_GKE_MODULE_NAME, m.processProject)

	if len(m.Clusters) == 0 {
		logger.InfoM("No GKE clusters found", globals.GCP_GKE_MODULE_NAME)
		return
	}

	// Count public clusters
	publicCount := 0
	for _, cluster := range m.Clusters {
		if !cluster.PrivateCluster && !cluster.MasterAuthorizedOnly {
			publicCount++
		}
	}

	msg := fmt.Sprintf("Found %d cluster(s), %d node pool(s)", len(m.Clusters), len(m.NodePools))
	if publicCount > 0 {
		msg += fmt.Sprintf(" [%d with public API endpoint]", publicCount)
	}
	logger.SuccessM(msg, globals.GCP_GKE_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *GKEModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating GKE clusters in project: %s", projectID), globals.GCP_GKE_MODULE_NAME)
	}

	gs := GKEService.New()
	clusters, nodePools, err := gs.Clusters(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_GKE_MODULE_NAME,
			fmt.Sprintf("Could not enumerate GKE clusters in project %s", projectID))
		return
	}

	m.mu.Lock()
	m.Clusters = append(m.Clusters, clusters...)
	m.NodePools = append(m.NodePools, nodePools...)

	for _, cluster := range clusters {
		m.addClusterToLoot(cluster)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d cluster(s) in project %s", len(clusters), projectID), globals.GCP_GKE_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *GKEModule) initializeLootFiles() {
	m.LootMap["gke-commands"] = &internal.LootFile{
		Name:     "gke-commands",
		Contents: "# GKE Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *GKEModule) addClusterToLoot(cluster GKEService.ClusterInfo) {
	m.LootMap["gke-commands"].Contents += fmt.Sprintf(
		"# Cluster: %s (%s)\n"+
			"# Project: %s\n"+
			"gcloud container clusters describe %s --location=%s --project=%s\n"+
			"gcloud container clusters get-credentials %s --location=%s --project=%s\n"+
			"gcloud container node-pools list --cluster=%s --location=%s --project=%s\n\n"+
			"# kubectl commands (after getting credentials):\n"+
			"kubectl cluster-info\n"+
			"kubectl get nodes -o wide\n"+
			"kubectl get namespaces\n"+
			"kubectl auth can-i --list\n\n",
		cluster.Name, cluster.Location,
		cluster.ProjectID,
		cluster.Name, cluster.Location, cluster.ProjectID,
		cluster.Name, cluster.Location, cluster.ProjectID,
		cluster.Name, cluster.Location, cluster.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *GKEModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Clusters table - merged with config columns, removed Issues
	clusterHeader := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Location",
		"Endpoint",
		"Status",
		"Version",
		"Mode",
		"Private",
		"MasterAuth",
		"NetPolicy",
		"WorkloadID",
		"Shielded",
		"BinAuth",
		"Release Channel",
		"ConfigConnector",
	}

	var clusterBody [][]string
	for _, cluster := range m.Clusters {
		// Cluster mode
		clusterMode := "Standard"
		if cluster.Autopilot {
			clusterMode = "Autopilot"
		}

		// Release channel
		releaseChannel := cluster.ReleaseChannel
		if releaseChannel == "" || releaseChannel == "UNSPECIFIED" {
			releaseChannel = "-"
		}

		// Endpoint display
		endpoint := cluster.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}

		clusterBody = append(clusterBody, []string{
			m.GetProjectName(cluster.ProjectID),
			cluster.ProjectID,
			cluster.Name,
			cluster.Location,
			endpoint,
			cluster.Status,
			cluster.CurrentMasterVersion,
			clusterMode,
			boolToYesNo(cluster.PrivateCluster),
			boolToYesNo(cluster.MasterAuthorizedOnly),
			boolToYesNo(cluster.NetworkPolicy),
			boolToYesNo(cluster.WorkloadIdentity != ""),
			boolToYesNo(cluster.ShieldedNodes),
			boolToYesNo(cluster.BinaryAuthorization),
			releaseChannel,
			boolToYesNo(cluster.ConfigConnector),
		})
	}

	// Node pools table - no truncation on service account, added Cloud Platform Scope column
	nodePoolHeader := []string{
		"Project Name",
		"Project ID",
		"Cluster",
		"Node Pool",
		"Machine Type",
		"Node Count",
		"Service Account",
		"Cloud Platform Scope",
		"Auto Upgrade",
		"Secure Boot",
		"Preemptible",
	}

	var nodePoolBody [][]string
	for _, np := range m.NodePools {
		// No truncation on service account
		saDisplay := np.ServiceAccount
		if saDisplay == "" {
			saDisplay = "-"
		}

		nodePoolBody = append(nodePoolBody, []string{
			m.GetProjectName(np.ProjectID),
			np.ProjectID,
			np.ClusterName,
			np.Name,
			np.MachineType,
			fmt.Sprintf("%d", np.NodeCount),
			saDisplay,
			boolToYesNo(np.HasCloudPlatformScope),
			boolToYesNo(np.AutoUpgrade),
			boolToYesNo(np.SecureBoot),
			boolToYesNo(np.Preemptible || np.Spot),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files - only 2 tables now
	tableFiles := []internal.TableFile{}

	if len(clusterBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-clusters",
			Header: clusterHeader,
			Body:   clusterBody,
		})
	}

	if len(nodePoolBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-node-pools",
			Header: nodePoolHeader,
			Body:   nodePoolBody,
		})
	}

	output := GKEOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_GKE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
