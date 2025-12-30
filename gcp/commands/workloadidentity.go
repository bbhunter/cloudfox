package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gkeservice "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	workloadidentityservice "github.com/BishopFox/cloudfox/gcp/services/workloadIdentityService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPWorkloadIdentityCommand = &cobra.Command{
	Use:     globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
	Aliases: []string{"wi", "gke-identity", "workload-id"},
	Short:   "Enumerate GKE Workload Identity and Workload Identity Federation",
	Long: `Enumerate Workload Identity configurations including GKE bindings and external identity federation.

Features:
- Lists GKE clusters with Workload Identity enabled
- Shows Kubernetes service accounts bound to GCP service accounts
- Identifies privilege escalation paths through Workload Identity
- Maps namespace/service account to GCP permissions
- Detects overly permissive bindings

Workload Identity Federation (External Identities):
- Lists Workload Identity Pools and Providers
- Analyzes AWS, OIDC (GitHub Actions, GitLab CI), and SAML providers
- Identifies risky provider configurations (missing attribute conditions)
- Shows federated identity bindings to GCP service accounts
- Generates exploitation commands for pentesting`,
	Run: runGCPWorkloadIdentityCommand,
}

// WorkloadIdentityBinding represents a binding between K8s SA and GCP SA
type WorkloadIdentityBinding struct {
	ProjectID          string   `json:"projectId"`
	ClusterName        string   `json:"clusterName"`
	ClusterLocation    string   `json:"clusterLocation"`
	WorkloadPool       string   `json:"workloadPool"`
	KubernetesNS       string   `json:"kubernetesNamespace"`
	KubernetesSA       string   `json:"kubernetesServiceAccount"`
	GCPServiceAccount  string   `json:"gcpServiceAccount"`
	GCPSARoles         []string `json:"gcpServiceAccountRoles"`
	IsHighPrivilege    bool     `json:"isHighPrivilege"`
	BindingType        string   `json:"bindingType"` // "workloadIdentityUser" or "other"
}

// ClusterWorkloadIdentity represents a cluster's workload identity configuration
type ClusterWorkloadIdentity struct {
	ProjectID           string `json:"projectId"`
	ClusterName         string `json:"clusterName"`
	Location            string `json:"location"`
	WorkloadPoolEnabled bool   `json:"workloadPoolEnabled"`
	WorkloadPool        string `json:"workloadPool"`
	NodePoolsWithWI     int    `json:"nodePoolsWithWI"`
	TotalNodePools      int    `json:"totalNodePools"`
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type WorkloadIdentityModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields (GKE Workload Identity)
	Clusters []ClusterWorkloadIdentity
	Bindings []WorkloadIdentityBinding

	// Workload Identity Federation fields
	Pools              []workloadidentityservice.WorkloadIdentityPool
	Providers          []workloadidentityservice.WorkloadIdentityProvider
	FederatedBindings  []workloadidentityservice.FederatedIdentityBinding

	LootMap  map[string]*internal.LootFile
	mu       sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type WorkloadIdentityOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o WorkloadIdentityOutput) TableFiles() []internal.TableFile { return o.Table }
func (o WorkloadIdentityOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPWorkloadIdentityCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &WorkloadIdentityModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		Clusters:          []ClusterWorkloadIdentity{},
		Bindings:          []WorkloadIdentityBinding{},
		Pools:             []workloadidentityservice.WorkloadIdentityPool{},
		Providers:         []workloadidentityservice.WorkloadIdentityProvider{},
		FederatedBindings: []workloadidentityservice.FederatedIdentityBinding{},
		LootMap:           make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *WorkloadIdentityModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME, m.processProject)

	// Check if we have any findings
	hasGKE := len(m.Clusters) > 0
	hasFederation := len(m.Pools) > 0

	if !hasGKE && !hasFederation {
		logger.InfoM("No Workload Identity configurations found", globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		return
	}

	// Count GKE clusters with Workload Identity
	if hasGKE {
		wiEnabled := 0
		for _, c := range m.Clusters {
			if c.WorkloadPoolEnabled {
				wiEnabled++
			}
		}
		logger.SuccessM(fmt.Sprintf("Found %d GKE cluster(s) (%d with Workload Identity), %d K8s->GCP binding(s)",
			len(m.Clusters), wiEnabled, len(m.Bindings)), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}

	// Count federation findings
	if hasFederation {
		criticalCount := 0
		highCount := 0
		for _, p := range m.Providers {
			switch p.RiskLevel {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			}
		}

		logger.SuccessM(fmt.Sprintf("Found %d Workload Identity Pool(s), %d Provider(s), %d federated binding(s)",
			len(m.Pools), len(m.Providers), len(m.FederatedBindings)), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)

		if criticalCount > 0 || highCount > 0 {
			logger.InfoM(fmt.Sprintf("[PENTEST] Found %d CRITICAL, %d HIGH risk federation provider(s)!", criticalCount, highCount), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		}
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *WorkloadIdentityModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Workload Identity in project: %s", projectID), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}

	// ==========================================
	// Part 1: GKE Workload Identity
	// ==========================================
	gkeSvc := gkeservice.New()
	clusters, _, err := gkeSvc.Clusters(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not enumerate GKE clusters in project %s: %v", projectID, err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		}
	}

	var clusterInfos []ClusterWorkloadIdentity
	var bindings []WorkloadIdentityBinding

	for _, cluster := range clusters {
		// Analyze cluster Workload Identity configuration
		cwi := ClusterWorkloadIdentity{
			ProjectID:      projectID,
			ClusterName:    cluster.Name,
			Location:       cluster.Location,
			TotalNodePools: cluster.NodePoolCount,
		}

		// Check if Workload Identity is enabled at cluster level
		if cluster.WorkloadIdentity != "" {
			cwi.WorkloadPoolEnabled = true
			cwi.WorkloadPool = cluster.WorkloadIdentity
		}

		// Node pools with WI is not tracked individually in ClusterInfo
		// Just mark all as WI-enabled if cluster has WI
		if cwi.WorkloadPoolEnabled {
			cwi.NodePoolsWithWI = cwi.TotalNodePools
		}

		clusterInfos = append(clusterInfos, cwi)

		// If Workload Identity is enabled, look for bindings
		if cwi.WorkloadPoolEnabled {
			clusterBindings := m.findWorkloadIdentityBindings(ctx, projectID, cluster.Name, cluster.Location, cwi.WorkloadPool, logger)
			bindings = append(bindings, clusterBindings...)
		}
	}

	// ==========================================
	// Part 2: Workload Identity Federation
	// ==========================================
	wiSvc := workloadidentityservice.New()

	// Get Workload Identity Pools
	pools, err := wiSvc.ListWorkloadIdentityPools(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not list Workload Identity Pools in project %s: %v", projectID, err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		}
	}

	var providers []workloadidentityservice.WorkloadIdentityProvider

	// Get providers for each pool
	for _, pool := range pools {
		poolProviders, err := wiSvc.ListWorkloadIdentityProviders(projectID, pool.PoolID)
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not list providers for pool %s: %v", pool.PoolID, err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
			}
			continue
		}
		providers = append(providers, poolProviders...)
	}

	// Find federated identity bindings
	fedBindings, err := wiSvc.FindFederatedIdentityBindings(projectID, pools)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not find federated identity bindings in project %s: %v", projectID, err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		}
	}

	// Thread-safe append
	m.mu.Lock()
	m.Clusters = append(m.Clusters, clusterInfos...)
	m.Bindings = append(m.Bindings, bindings...)
	m.Pools = append(m.Pools, pools...)
	m.Providers = append(m.Providers, providers...)
	m.FederatedBindings = append(m.FederatedBindings, fedBindings...)

	// Generate loot
	for _, cwi := range clusterInfos {
		m.addClusterToLoot(cwi)
	}
	for _, binding := range bindings {
		m.addBindingToLoot(binding)
	}
	for _, pool := range pools {
		m.addPoolToLoot(pool)
	}
	for _, provider := range providers {
		m.addProviderToLoot(provider)
	}
	for _, fedBinding := range fedBindings {
		m.addFederatedBindingToLoot(fedBinding)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d GKE cluster(s), %d K8s binding(s), %d pool(s), %d provider(s) in project %s",
			len(clusterInfos), len(bindings), len(pools), len(providers), projectID), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}
}

// findWorkloadIdentityBindings finds all IAM bindings that grant workloadIdentityUser role
func (m *WorkloadIdentityModule) findWorkloadIdentityBindings(ctx context.Context, projectID, clusterName, location, workloadPool string, logger internal.Logger) []WorkloadIdentityBinding {
	var bindings []WorkloadIdentityBinding

	// Get all service accounts in the project and check their IAM policies
	iamSvc := IAMService.New()
	serviceAccounts, err := iamSvc.ServiceAccounts(projectID)
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not list service accounts: %v", err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		return bindings
	}

	// For each service account, get its IAM policy and look for workloadIdentityUser bindings
	for _, sa := range serviceAccounts {
		// Get IAM policy for this service account
		// The workloadIdentityUser role is granted ON the service account
		saPolicy, err := m.getServiceAccountPolicy(ctx, sa.Name)
		if err != nil {
			continue
		}

		// Look for members with workloadIdentityUser role
		for _, binding := range saPolicy {
			if binding.Role == "roles/iam.workloadIdentityUser" {
				for _, member := range binding.Members {
					// Parse member to extract namespace and KSA
					// Format: serviceAccount:[PROJECT_ID].svc.id.goog[NAMESPACE/KSA_NAME]
					if strings.HasPrefix(member, "serviceAccount:") && strings.Contains(member, ".svc.id.goog") {
						ns, ksa := parseWorkloadIdentityMember(member)
						if ns != "" && ksa != "" {
							wib := WorkloadIdentityBinding{
								ProjectID:         projectID,
								ClusterName:       clusterName,
								ClusterLocation:   location,
								WorkloadPool:      workloadPool,
								KubernetesNS:      ns,
								KubernetesSA:      ksa,
								GCPServiceAccount: sa.Email,
								GCPSARoles:        sa.Roles,
								BindingType:       "workloadIdentityUser",
							}

							// Check if high privilege
							wib.IsHighPrivilege = isHighPrivilegeServiceAccount(sa)

							bindings = append(bindings, wib)
						}
					}
				}
			}
		}
	}

	return bindings
}

// getServiceAccountPolicy gets IAM policy for a service account
func (m *WorkloadIdentityModule) getServiceAccountPolicy(ctx context.Context, saName string) ([]IAMService.PolicyBinding, error) {
	iamSvc := IAMService.New()

	// Get the service account's IAM policy
	// This requires calling the IAM API directly
	// For now, we'll return the roles from the project-level bindings
	return iamSvc.Policies(extractProjectFromSAName(saName), "project")
}

// parseWorkloadIdentityMember parses a workload identity member string
// Format: serviceAccount:[PROJECT_ID].svc.id.goog[NAMESPACE/KSA_NAME]
func parseWorkloadIdentityMember(member string) (namespace, serviceAccount string) {
	// Remove serviceAccount: prefix
	member = strings.TrimPrefix(member, "serviceAccount:")

	// Find the workload pool and extract namespace/SA
	// Format: PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME]
	bracketStart := strings.Index(member, "[")
	bracketEnd := strings.Index(member, "]")

	if bracketStart == -1 || bracketEnd == -1 || bracketEnd <= bracketStart {
		return "", ""
	}

	nsAndSA := member[bracketStart+1 : bracketEnd]
	parts := strings.Split(nsAndSA, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return "", ""
}

// extractProjectFromSAName extracts project ID from service account name
func extractProjectFromSAName(saName string) string {
	// Format: projects/PROJECT_ID/serviceAccounts/SA_EMAIL
	parts := strings.Split(saName, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// isHighPrivilegeServiceAccount checks if a service account has high-privilege roles
func isHighPrivilegeServiceAccount(sa IAMService.ServiceAccountInfo) bool {
	highPrivRoles := map[string]bool{
		"roles/owner":                           true,
		"roles/editor":                          true,
		"roles/iam.serviceAccountAdmin":         true,
		"roles/iam.serviceAccountKeyAdmin":      true,
		"roles/iam.serviceAccountTokenCreator":  true,
		"roles/resourcemanager.projectIamAdmin": true,
		"roles/compute.admin":                   true,
		"roles/container.admin":                 true,
		"roles/secretmanager.admin":             true,
		"roles/storage.admin":                   true,
	}

	for _, role := range sa.Roles {
		if highPrivRoles[role] {
			return true
		}
	}
	return false
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *WorkloadIdentityModule) initializeLootFiles() {
	// GKE Workload Identity loot
	m.LootMap["wi-clusters"] = &internal.LootFile{
		Name:     "wi-clusters",
		Contents: "# GKE Clusters with Workload Identity\n# Generated by CloudFox\n\n",
	}
	m.LootMap["wi-bindings"] = &internal.LootFile{
		Name:     "wi-bindings",
		Contents: "# Workload Identity Bindings\n# Generated by CloudFox\n# K8s SA -> GCP SA mappings\n\n",
	}
	m.LootMap["wi-high-privilege"] = &internal.LootFile{
		Name:     "wi-high-privilege",
		Contents: "# High-Privilege Workload Identity Bindings\n# Generated by CloudFox\n# These K8s service accounts have access to high-privilege GCP SAs\n\n",
	}
	m.LootMap["wi-exploit-commands"] = &internal.LootFile{
		Name:     "wi-exploit-commands",
		Contents: "# Workload Identity Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}

	// Workload Identity Federation loot
	m.LootMap["wi-federation-pools"] = &internal.LootFile{
		Name:     "wi-federation-pools",
		Contents: "# Workload Identity Federation Pools\n# Generated by CloudFox\n\n",
	}
	m.LootMap["wi-federation-providers"] = &internal.LootFile{
		Name:     "wi-federation-providers",
		Contents: "# Workload Identity Federation Providers\n# Generated by CloudFox\n# External identity providers (AWS, OIDC, SAML)\n\n",
	}
	m.LootMap["wi-federation-risky"] = &internal.LootFile{
		Name:     "wi-federation-risky",
		Contents: "# Risky Workload Identity Federation Configurations\n# Generated by CloudFox\n# Providers with security concerns\n\n",
	}
	m.LootMap["wi-federation-exploit"] = &internal.LootFile{
		Name:     "wi-federation-exploit",
		Contents: "# Workload Identity Federation Exploitation\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *WorkloadIdentityModule) addClusterToLoot(cwi ClusterWorkloadIdentity) {
	if cwi.WorkloadPoolEnabled {
		m.LootMap["wi-clusters"].Contents += fmt.Sprintf(
			"# Cluster: %s\n"+
				"# Location: %s\n"+
				"# Project: %s\n"+
				"# Workload Pool: %s\n"+
				"# Node Pools with WI: %d/%d\n"+
				"gcloud container clusters get-credentials %s --zone=%s --project=%s\n\n",
			cwi.ClusterName,
			cwi.Location,
			cwi.ProjectID,
			cwi.WorkloadPool,
			cwi.NodePoolsWithWI,
			cwi.TotalNodePools,
			cwi.ClusterName,
			cwi.Location,
			cwi.ProjectID,
		)
	}
}

func (m *WorkloadIdentityModule) addBindingToLoot(binding WorkloadIdentityBinding) {
	// All bindings
	m.LootMap["wi-bindings"].Contents += fmt.Sprintf(
		"# K8s SA: %s/%s\n"+
			"# GCP SA: %s\n"+
			"# Cluster: %s (%s)\n"+
			"# Project: %s\n\n",
		binding.KubernetesNS,
		binding.KubernetesSA,
		binding.GCPServiceAccount,
		binding.ClusterName,
		binding.ClusterLocation,
		binding.ProjectID,
	)

	// High-privilege bindings
	if binding.IsHighPrivilege {
		m.LootMap["wi-high-privilege"].Contents += fmt.Sprintf(
			"# K8s SA: %s/%s -> GCP SA: %s\n"+
				"# Cluster: %s\n"+
				"# Roles: %s\n"+
				"# This K8s SA can access high-privilege GCP permissions!\n\n",
			binding.KubernetesNS,
			binding.KubernetesSA,
			binding.GCPServiceAccount,
			binding.ClusterName,
			strings.Join(binding.GCPSARoles, ", "),
		)
	}

	// Exploitation commands
	m.LootMap["wi-exploit-commands"].Contents += fmt.Sprintf(
		"# To exploit K8s SA %s/%s -> GCP SA %s:\n"+
			"# 1. Get credentials for cluster:\n"+
			"gcloud container clusters get-credentials %s --zone=%s --project=%s\n"+
			"# 2. Create a pod with the K8s service account:\n"+
			"# kubectl run exploit-pod --image=google/cloud-sdk:slim --serviceaccount=%s -n %s -- sleep infinity\n"+
			"# 3. Exec into pod and use GCP credentials:\n"+
			"# kubectl exec -it exploit-pod -n %s -- gcloud auth list\n\n",
		binding.KubernetesNS,
		binding.KubernetesSA,
		binding.GCPServiceAccount,
		binding.ClusterName,
		binding.ClusterLocation,
		binding.ProjectID,
		binding.KubernetesSA,
		binding.KubernetesNS,
		binding.KubernetesNS,
	)
}

func (m *WorkloadIdentityModule) addPoolToLoot(pool workloadidentityservice.WorkloadIdentityPool) {
	status := "Active"
	if pool.Disabled {
		status = "Disabled"
	}
	m.LootMap["wi-federation-pools"].Contents += fmt.Sprintf(
		"## Pool: %s\n"+
			"## Project: %s\n"+
			"## Status: %s\n"+
			"## Description: %s\n\n",
		pool.PoolID,
		pool.ProjectID,
		status,
		pool.Description,
	)
}

func (m *WorkloadIdentityModule) addProviderToLoot(provider workloadidentityservice.WorkloadIdentityProvider) {
	m.LootMap["wi-federation-providers"].Contents += fmt.Sprintf(
		"## Provider: %s/%s\n"+
			"## Project: %s\n"+
			"## Type: %s\n",
		provider.PoolID, provider.ProviderID,
		provider.ProjectID,
		provider.ProviderType,
	)

	if provider.ProviderType == "AWS" {
		m.LootMap["wi-federation-providers"].Contents += fmt.Sprintf(
			"## AWS Account: %s\n", provider.AWSAccountID)
	} else if provider.ProviderType == "OIDC" {
		m.LootMap["wi-federation-providers"].Contents += fmt.Sprintf(
			"## OIDC Issuer: %s\n", provider.OIDCIssuerURI)
	}

	if provider.AttributeCondition != "" {
		m.LootMap["wi-federation-providers"].Contents += fmt.Sprintf(
			"## Attribute Condition: %s\n", provider.AttributeCondition)
	} else {
		m.LootMap["wi-federation-providers"].Contents += "## Attribute Condition: NONE (any identity can authenticate!)\n"
	}
	m.LootMap["wi-federation-providers"].Contents += "\n"

	// Risky providers
	if provider.RiskLevel == "CRITICAL" || provider.RiskLevel == "HIGH" {
		m.LootMap["wi-federation-risky"].Contents += fmt.Sprintf(
			"## [%s] Provider: %s/%s\n"+
				"## Project: %s\n"+
				"## Type: %s\n",
			provider.RiskLevel, provider.PoolID, provider.ProviderID,
			provider.ProjectID, provider.ProviderType,
		)
		if len(provider.RiskReasons) > 0 {
			m.LootMap["wi-federation-risky"].Contents += "## Risk Reasons:\n"
			for _, reason := range provider.RiskReasons {
				m.LootMap["wi-federation-risky"].Contents += fmt.Sprintf("##   - %s\n", reason)
			}
		}
		m.LootMap["wi-federation-risky"].Contents += "\n"
	}

	// Exploitation commands
	if len(provider.ExploitCommands) > 0 {
		m.LootMap["wi-federation-exploit"].Contents += fmt.Sprintf(
			"## [%s] Provider: %s/%s (%s)\n",
			provider.RiskLevel, provider.PoolID, provider.ProviderID, provider.ProviderType,
		)
		for _, cmd := range provider.ExploitCommands {
			m.LootMap["wi-federation-exploit"].Contents += cmd + "\n"
		}
		m.LootMap["wi-federation-exploit"].Contents += "\n"
	}
}

func (m *WorkloadIdentityModule) addFederatedBindingToLoot(binding workloadidentityservice.FederatedIdentityBinding) {
	m.LootMap["wi-federation-providers"].Contents += fmt.Sprintf(
		"## Federated Binding:\n"+
			"## External Subject: %s\n"+
			"## GCP Service Account: %s\n"+
			"## Pool: %s\n"+
			"## Risk Level: %s\n\n",
		binding.ExternalSubject,
		binding.GCPServiceAccount,
		binding.PoolID,
		binding.RiskLevel,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *WorkloadIdentityModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Clusters table
	clustersHeader := []string{
		"Cluster",
		"Location",
		"Project Name",
		"Project",
		"WI Enabled",
		"Workload Pool",
		"Node Pools (WI/Total)",
	}

	var clustersBody [][]string
	for _, cwi := range m.Clusters {
		wiEnabled := "No"
		if cwi.WorkloadPoolEnabled {
			wiEnabled = "Yes"
		}
		workloadPool := "-"
		if cwi.WorkloadPool != "" {
			workloadPool = cwi.WorkloadPool
		}

		clustersBody = append(clustersBody, []string{
			cwi.ClusterName,
			cwi.Location,
			m.GetProjectName(cwi.ProjectID),
			cwi.ProjectID,
			wiEnabled,
			workloadPool,
			fmt.Sprintf("%d/%d", cwi.NodePoolsWithWI, cwi.TotalNodePools),
		})
	}

	// Bindings table
	bindingsHeader := []string{
		"K8s Namespace",
		"K8s Service Account",
		"GCP Service Account",
		"High Privilege",
		"Cluster",
		"Project Name",
		"Project",
	}

	var bindingsBody [][]string
	for _, binding := range m.Bindings {
		highPriv := ""
		if binding.IsHighPrivilege {
			highPriv = "YES"
		}

		bindingsBody = append(bindingsBody, []string{
			binding.KubernetesNS,
			binding.KubernetesSA,
			binding.GCPServiceAccount,
			highPriv,
			binding.ClusterName,
			m.GetProjectName(binding.ProjectID),
			binding.ProjectID,
		})
	}

	// High-privilege bindings table
	highPrivHeader := []string{
		"K8s SA (namespace/name)",
		"GCP Service Account",
		"Roles",
		"Cluster",
	}

	var highPrivBody [][]string
	for _, binding := range m.Bindings {
		if binding.IsHighPrivilege {
			highPrivBody = append(highPrivBody, []string{
				fmt.Sprintf("%s/%s", binding.KubernetesNS, binding.KubernetesSA),
				binding.GCPServiceAccount,
				strings.Join(binding.GCPSARoles, ", "),
				binding.ClusterName,
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

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "workload-identity-clusters",
			Header: clustersHeader,
			Body:   clustersBody,
		},
	}

	// Add bindings table if there are any
	if len(bindingsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "workload-identity-bindings",
			Header: bindingsHeader,
			Body:   bindingsBody,
		})
	}

	// Add high-privilege table if there are any
	if len(highPrivBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "workload-identity-high-privilege",
			Header: highPrivHeader,
			Body:   highPrivBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d high-privilege Workload Identity binding(s)!", len(highPrivBody)), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}

	// ============================
	// Workload Identity Federation tables
	// ============================

	// Federation Pools table
	if len(m.Pools) > 0 {
		poolsHeader := []string{
			"Pool ID",
			"Project Name",
			"Project",
			"Display Name",
			"State",
			"Disabled",
		}

		var poolsBody [][]string
		for _, pool := range m.Pools {
			disabled := "No"
			if pool.Disabled {
				disabled = "Yes"
			}
			poolsBody = append(poolsBody, []string{
				pool.PoolID,
				m.GetProjectName(pool.ProjectID),
				pool.ProjectID,
				pool.DisplayName,
				pool.State,
				disabled,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "wi-federation-pools",
			Header: poolsHeader,
			Body:   poolsBody,
		})
	}

	// Federation Providers table
	if len(m.Providers) > 0 {
		providersHeader := []string{
			"Risk",
			"Pool",
			"Provider",
			"Type",
			"Issuer/Account",
			"Attribute Condition",
			"Project Name",
			"Project",
		}

		var providersBody [][]string
		for _, p := range m.Providers {
			issuerOrAccount := ""
			if p.ProviderType == "AWS" {
				issuerOrAccount = p.AWSAccountID
			} else if p.ProviderType == "OIDC" {
				issuerOrAccount = p.OIDCIssuerURI
				if len(issuerOrAccount) > 40 {
					issuerOrAccount = issuerOrAccount[:40] + "..."
				}
			}

			attrCond := p.AttributeCondition
			if attrCond == "" {
				attrCond = "NONE"
			} else if len(attrCond) > 30 {
				attrCond = attrCond[:30] + "..."
			}

			providersBody = append(providersBody, []string{
				p.RiskLevel,
				p.PoolID,
				p.ProviderID,
				p.ProviderType,
				issuerOrAccount,
				attrCond,
				m.GetProjectName(p.ProjectID),
				p.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "wi-federation-providers",
			Header: providersHeader,
			Body:   providersBody,
		})
	}

	// Federated bindings table
	if len(m.FederatedBindings) > 0 {
		fedBindingsHeader := []string{
			"Risk",
			"Pool",
			"GCP Service Account",
			"External Subject",
			"Project Name",
			"Project",
		}

		var fedBindingsBody [][]string
		for _, fb := range m.FederatedBindings {
			externalSubject := fb.ExternalSubject
			if len(externalSubject) > 50 {
				externalSubject = externalSubject[:50] + "..."
			}

			fedBindingsBody = append(fedBindingsBody, []string{
				fb.RiskLevel,
				fb.PoolID,
				fb.GCPServiceAccount,
				externalSubject,
				m.GetProjectName(fb.ProjectID),
				fb.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "wi-federated-bindings",
			Header: fedBindingsHeader,
			Body:   fedBindingsBody,
		})
	}

	output := WorkloadIdentityOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
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
		"project",           // scopeType
		m.ProjectIDs,        // scopeIdentifiers
		scopeNames,          // scopeNames
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
