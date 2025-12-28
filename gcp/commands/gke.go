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
- Generates kubectl and gcloud commands for further analysis

Security Columns:
- Private: Whether the cluster uses private nodes (no public IPs)
- MasterAuth: Master authorized networks enabled
- NetworkPolicy: Kubernetes network policy controller enabled
- WorkloadIdentity: GKE Workload Identity configured
- ShieldedNodes: Shielded GKE nodes enabled
- Issues: Detected security misconfigurations

Attack Surface:
- Public API servers are accessible from the internet
- Clusters without Workload Identity use node service accounts
- Default service accounts may have excessive permissions
- Legacy ABAC allows broader access than RBAC`,
	Run: runGCPGKECommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type GKEModule struct {
	gcpinternal.BaseGCPModule

	Clusters         []GKEService.ClusterInfo
	NodePools        []GKEService.NodePoolInfo
	SecurityAnalyses []GKEService.ClusterSecurityAnalysis
	LootMap          map[string]*internal.LootFile
	mu               sync.Mutex
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
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		Clusters:         []GKEService.ClusterInfo{},
		NodePools:        []GKEService.NodePoolInfo{},
		SecurityAnalyses: []GKEService.ClusterSecurityAnalysis{},
		LootMap:          make(map[string]*internal.LootFile),
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

	// Count clusters with issues
	issueCount := 0
	publicCount := 0
	for _, cluster := range m.Clusters {
		if len(cluster.SecurityIssues) > 0 {
			issueCount++
		}
		if !cluster.PrivateCluster && !cluster.MasterAuthorizedOnly {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d cluster(s), %d with public API endpoint", len(m.Clusters), publicCount), globals.GCP_GKE_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d cluster(s)", len(m.Clusters)), globals.GCP_GKE_MODULE_NAME)
	}

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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating GKE in project %s: %v", projectID, err), globals.GCP_GKE_MODULE_NAME)
		}
		return
	}

	m.mu.Lock()
	m.Clusters = append(m.Clusters, clusters...)
	m.NodePools = append(m.NodePools, nodePools...)

	for _, cluster := range clusters {
		m.addClusterToLoot(cluster)
		// Perform security analysis
		analysis := gs.AnalyzeClusterSecurity(cluster, nodePools)
		m.SecurityAnalyses = append(m.SecurityAnalyses, analysis)
		m.addSecurityAnalysisToLoot(analysis)
	}

	// Add node pool security info
	for _, np := range nodePools {
		m.addNodePoolSecurityToLoot(np)
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
	m.LootMap["gke-gcloud-commands"] = &internal.LootFile{
		Name:     "gke-gcloud-commands",
		Contents: "# GKE gcloud Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["gke-kubectl-commands"] = &internal.LootFile{
		Name:     "gke-kubectl-commands",
		Contents: "# GKE kubectl Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["gke-exploitation"] = &internal.LootFile{
		Name:     "gke-exploitation",
		Contents: "# GKE Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["gke-security-issues"] = &internal.LootFile{
		Name:     "gke-security-issues",
		Contents: "# GKE Security Issues Detected\n# Generated by CloudFox\n\n",
	}
	m.LootMap["gke-security-analysis"] = &internal.LootFile{
		Name:     "gke-security-analysis",
		Contents: "# GKE Security Analysis\n# Generated by CloudFox\n# Detailed risk assessment for GKE clusters\n\n",
	}
	m.LootMap["gke-exploit-commands"] = &internal.LootFile{
		Name:     "gke-exploit-commands",
		Contents: "# GKE Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["gke-risky-nodepools"] = &internal.LootFile{
		Name:     "gke-risky-nodepools",
		Contents: "# GKE Risky Node Pools\n# Generated by CloudFox\n# Node pools with excessive OAuth scopes or default SA\n\n",
	}
}

func (m *GKEModule) addClusterToLoot(cluster GKEService.ClusterInfo) {
	// gcloud commands
	m.LootMap["gke-gcloud-commands"].Contents += fmt.Sprintf(
		"# Cluster: %s (Project: %s, Location: %s)\n"+
			"gcloud container clusters describe %s --location=%s --project=%s\n"+
			"gcloud container clusters get-credentials %s --location=%s --project=%s\n"+
			"gcloud container node-pools list --cluster=%s --location=%s --project=%s\n\n",
		cluster.Name, cluster.ProjectID, cluster.Location,
		cluster.Name, cluster.Location, cluster.ProjectID,
		cluster.Name, cluster.Location, cluster.ProjectID,
		cluster.Name, cluster.Location, cluster.ProjectID,
	)

	// kubectl commands (after getting credentials)
	m.LootMap["gke-kubectl-commands"].Contents += fmt.Sprintf(
		"# Cluster: %s (get credentials first with gcloud command above)\n"+
			"kubectl cluster-info\n"+
			"kubectl get nodes -o wide\n"+
			"kubectl get namespaces\n"+
			"kubectl get serviceaccounts --all-namespaces\n"+
			"kubectl get clusterroles\n"+
			"kubectl get clusterrolebindings\n"+
			"kubectl auth can-i --list\n"+
			"kubectl get secrets --all-namespaces\n"+
			"kubectl get configmaps --all-namespaces\n\n",
		cluster.Name,
	)

	// Exploitation commands
	m.LootMap["gke-exploitation"].Contents += fmt.Sprintf(
		"# Cluster: %s (Project: %s)\n"+
			"# Endpoint: %s\n"+
			"# Service Account: %s\n\n"+
			"# Get credentials:\n"+
			"gcloud container clusters get-credentials %s --location=%s --project=%s\n\n"+
			"# Check your permissions:\n"+
			"kubectl auth can-i --list\n"+
			"kubectl auth can-i create pods\n"+
			"kubectl auth can-i get secrets\n\n"+
			"# List pods with host PID/network (potential container escape):\n"+
			"kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true or .spec.hostPID==true) | {namespace: .metadata.namespace, name: .metadata.name, hostNetwork: .spec.hostNetwork, hostPID: .spec.hostPID}'\n\n"+
			"# Find pods with service accounts:\n"+
			"kubectl get pods -A -o json | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, serviceAccount: .spec.serviceAccountName}'\n\n",
		cluster.Name, cluster.ProjectID,
		cluster.Endpoint,
		cluster.NodeServiceAccount,
		cluster.Name, cluster.Location, cluster.ProjectID,
	)

	// Security issues
	if len(cluster.SecurityIssues) > 0 {
		m.LootMap["gke-security-issues"].Contents += fmt.Sprintf(
			"# CLUSTER: %s (Project: %s)\n"+
				"# Location: %s\n"+
				"# Issues:\n",
			cluster.Name, cluster.ProjectID, cluster.Location,
		)
		for _, issue := range cluster.SecurityIssues {
			m.LootMap["gke-security-issues"].Contents += fmt.Sprintf("  - %s\n", issue)
		}
		m.LootMap["gke-security-issues"].Contents += "\n"
	}
}

func (m *GKEModule) addSecurityAnalysisToLoot(analysis GKEService.ClusterSecurityAnalysis) {
	if analysis.RiskLevel == "CRITICAL" || analysis.RiskLevel == "HIGH" {
		m.LootMap["gke-security-analysis"].Contents += fmt.Sprintf(
			"# [%s] CLUSTER: %s (Project: %s)\n"+
				"# Location: %s\n",
			analysis.RiskLevel, analysis.ClusterName, analysis.ProjectID, analysis.Location,
		)

		if len(analysis.RiskReasons) > 0 {
			m.LootMap["gke-security-analysis"].Contents += "# Risk Reasons:\n"
			for _, reason := range analysis.RiskReasons {
				m.LootMap["gke-security-analysis"].Contents += fmt.Sprintf("#   - %s\n", reason)
			}
		}

		if len(analysis.AttackSurface) > 0 {
			m.LootMap["gke-security-analysis"].Contents += "# Attack Surface:\n"
			for _, surface := range analysis.AttackSurface {
				m.LootMap["gke-security-analysis"].Contents += fmt.Sprintf("#   - %s\n", surface)
			}
		}

		if len(analysis.PrivescPaths) > 0 {
			m.LootMap["gke-security-analysis"].Contents += "# Privilege Escalation Paths:\n"
			for _, path := range analysis.PrivescPaths {
				m.LootMap["gke-security-analysis"].Contents += fmt.Sprintf("#   - %s\n", path)
			}
		}
		m.LootMap["gke-security-analysis"].Contents += "\n"
	}

	// Add exploit commands
	if len(analysis.ExploitCommands) > 0 {
		m.LootMap["gke-exploit-commands"].Contents += fmt.Sprintf(
			"# [%s] CLUSTER: %s (Project: %s)\n",
			analysis.RiskLevel, analysis.ClusterName, analysis.ProjectID,
		)
		for _, cmd := range analysis.ExploitCommands {
			m.LootMap["gke-exploit-commands"].Contents += cmd + "\n"
		}
		m.LootMap["gke-exploit-commands"].Contents += "\n"
	}
}

func (m *GKEModule) addNodePoolSecurityToLoot(np GKEService.NodePoolInfo) {
	// Only add risky node pools
	if np.HasCloudPlatformScope || np.ServiceAccount == "default" ||
		strings.HasSuffix(np.ServiceAccount, "-compute@developer.gserviceaccount.com") {

		m.LootMap["gke-risky-nodepools"].Contents += fmt.Sprintf(
			"# Cluster: %s, Node Pool: %s (Project: %s)\n"+
				"# Service Account: %s\n",
			np.ClusterName, np.Name, np.ProjectID, np.ServiceAccount,
		)

		if np.HasCloudPlatformScope {
			m.LootMap["gke-risky-nodepools"].Contents += "# WARNING: cloud-platform scope - full GCP access!\n"
		}

		if len(np.RiskyScopes) > 0 {
			m.LootMap["gke-risky-nodepools"].Contents += "# Risky OAuth Scopes:\n"
			for _, scope := range np.RiskyScopes {
				m.LootMap["gke-risky-nodepools"].Contents += fmt.Sprintf("#   - %s\n", scope)
			}
		}

		// Add metadata access command
		m.LootMap["gke-risky-nodepools"].Contents += fmt.Sprintf(
			"# From pod on this node pool, access SA token:\n"+
				"curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token\n\n",
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *GKEModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main clusters table
	header := []string{
		"Project ID",
		"Name",
		"Location",
		"Status",
		"Version",
		"Private",
		"MasterAuth",
		"NetworkPolicy",
		"WorkloadID",
		"ShieldedNodes",
		"Issues",
	}

	var body [][]string
	for _, cluster := range m.Clusters {
		// Format workload identity
		workloadIDStatus := "No"
		if cluster.WorkloadIdentity != "" {
			workloadIDStatus = "Yes"
		}

		// Count issues
		issueCount := len(cluster.SecurityIssues)
		issueDisplay := "-"
		if issueCount > 0 {
			issueDisplay = fmt.Sprintf("%d issues", issueCount)
		}

		body = append(body, []string{
			cluster.ProjectID,
			cluster.Name,
			cluster.Location,
			cluster.Status,
			cluster.CurrentMasterVersion,
			boolToYesNo(cluster.PrivateCluster),
			boolToYesNo(cluster.MasterAuthorizedOnly),
			boolToYesNo(cluster.NetworkPolicy),
			workloadIDStatus,
			boolToYesNo(cluster.ShieldedNodes),
			issueDisplay,
		})
	}

	// Security issues table
	issuesHeader := []string{
		"Cluster",
		"Project ID",
		"Location",
		"Issue",
	}

	var issuesBody [][]string
	for _, cluster := range m.Clusters {
		for _, issue := range cluster.SecurityIssues {
			issuesBody = append(issuesBody, []string{
				cluster.Name,
				cluster.ProjectID,
				cluster.Location,
				issue,
			})
		}
	}

	// Node pools table
	nodePoolHeader := []string{
		"Cluster",
		"Node Pool",
		"Project ID",
		"Machine Type",
		"Node Count",
		"Service Account",
		"Auto Upgrade",
		"Secure Boot",
		"Preemptible",
	}

	var nodePoolBody [][]string
	for _, np := range m.NodePools {
		saDisplay := np.ServiceAccount
		if saDisplay == "default" {
			saDisplay = "DEFAULT (INSECURE)"
		} else if strings.Contains(saDisplay, "@") {
			parts := strings.Split(saDisplay, "@")
			saDisplay = parts[0] + "@..."
		}

		preemptible := "No"
		if np.Preemptible || np.Spot {
			preemptible = "Yes"
		}

		nodePoolBody = append(nodePoolBody, []string{
			np.ClusterName,
			np.Name,
			np.ProjectID,
			np.MachineType,
			fmt.Sprintf("%d", np.NodeCount),
			saDisplay,
			boolToYesNo(np.AutoUpgrade),
			boolToYesNo(np.SecureBoot),
			preemptible,
		})
	}

	// Security analysis table (pentest-focused)
	analysisHeader := []string{
		"Risk",
		"Cluster",
		"Project",
		"Attack Surface",
		"Privesc Paths",
	}

	var analysisBody [][]string
	for _, analysis := range m.SecurityAnalyses {
		// Summarize attack surface and privesc paths
		attackSummary := "-"
		if len(analysis.AttackSurface) > 0 {
			attackSummary = fmt.Sprintf("%d vectors", len(analysis.AttackSurface))
		}

		privescSummary := "-"
		if len(analysis.PrivescPaths) > 0 {
			privescSummary = fmt.Sprintf("%d paths", len(analysis.PrivescPaths))
		}

		analysisBody = append(analysisBody, []string{
			analysis.RiskLevel,
			analysis.ClusterName,
			analysis.ProjectID,
			attackSummary,
			privescSummary,
		})
	}

	// Risky node pools table
	riskyNPHeader := []string{
		"Cluster",
		"Node Pool",
		"Service Account",
		"Cloud Platform Scope",
		"Risky Scopes",
		"Project",
	}

	var riskyNPBody [][]string
	for _, np := range m.NodePools {
		if np.HasCloudPlatformScope || np.ServiceAccount == "default" ||
			strings.HasSuffix(np.ServiceAccount, "-compute@developer.gserviceaccount.com") {

			cloudPlatform := "No"
			if np.HasCloudPlatformScope {
				cloudPlatform = "YES!"
			}

			scopeCount := "-"
			if len(np.RiskyScopes) > 0 {
				scopeCount = fmt.Sprintf("%d risky", len(np.RiskyScopes))
			}

			riskyNPBody = append(riskyNPBody, []string{
				np.ClusterName,
				np.Name,
				np.ServiceAccount,
				cloudPlatform,
				scopeCount,
				np.ProjectID,
			})
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
	tableFiles := []internal.TableFile{
		{
			Name:   globals.GCP_GKE_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	if len(issuesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-security-issues",
			Header: issuesHeader,
			Body:   issuesBody,
		})
	}

	if len(nodePoolBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-node-pools",
			Header: nodePoolHeader,
			Body:   nodePoolBody,
		})
	}

	if len(analysisBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-security-analysis",
			Header: analysisHeader,
			Body:   analysisBody,
		})
	}

	if len(riskyNPBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "gke-risky-nodepools",
			Header: riskyNPHeader,
			Body:   riskyNPBody,
		})
	}

	output := GKEOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_GKE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
