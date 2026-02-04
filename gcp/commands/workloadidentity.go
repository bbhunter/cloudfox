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

	// Module-specific fields (GKE Workload Identity) - per-project for hierarchical output
	ProjectClusters          map[string][]ClusterWorkloadIdentity                             // projectID -> clusters
	ProjectBindings          map[string][]WorkloadIdentityBinding                             // projectID -> bindings
	ProjectPools             map[string][]workloadidentityservice.WorkloadIdentityPool        // projectID -> pools
	ProjectProviders         map[string][]workloadidentityservice.WorkloadIdentityProvider    // projectID -> providers
	ProjectFederatedBindings map[string][]workloadidentityservice.FederatedIdentityBinding    // projectID -> federated bindings
	LootMap                  map[string]map[string]*internal.LootFile                         // projectID -> loot files
	AttackPathCache          *gcpinternal.AttackPathCache                                     // Cached attack path analysis results
	mu                       sync.Mutex
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
		BaseGCPModule:            gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectClusters:          make(map[string][]ClusterWorkloadIdentity),
		ProjectBindings:          make(map[string][]WorkloadIdentityBinding),
		ProjectPools:             make(map[string][]workloadidentityservice.WorkloadIdentityPool),
		ProjectProviders:         make(map[string][]workloadidentityservice.WorkloadIdentityProvider),
		ProjectFederatedBindings: make(map[string][]workloadidentityservice.FederatedIdentityBinding),
		LootMap:                  make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *WorkloadIdentityModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get attack path cache from context (populated by all-checks or attack path analysis)
	m.AttackPathCache = gcpinternal.GetAttackPathCacheFromContext(ctx)

	// If no context cache, try loading from disk cache
	if m.AttackPathCache == nil || !m.AttackPathCache.IsPopulated() {
		diskCache, metadata, err := gcpinternal.LoadAttackPathCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			logger.InfoM(fmt.Sprintf("Using attack path cache from disk (created: %s)",
				metadata.CreatedAt.Format("2006-01-02 15:04:05")), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
			m.AttackPathCache = diskCache
		}
	}

	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME, m.processProject)

	// Get all data for stats
	allClusters := m.getAllClusters()
	allBindings := m.getAllBindings()
	allPools := m.getAllPools()
	allProviders := m.getAllProviders()
	allFederatedBindings := m.getAllFederatedBindings()

	// Check if we have any findings
	hasGKE := len(allClusters) > 0
	hasFederation := len(allPools) > 0

	if !hasGKE && !hasFederation {
		logger.InfoM("No Workload Identity configurations found", globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		return
	}

	// Count GKE clusters with Workload Identity
	if hasGKE {
		wiEnabled := 0
		for _, c := range allClusters {
			if c.WorkloadPoolEnabled {
				wiEnabled++
			}
		}
		logger.SuccessM(fmt.Sprintf("Found %d GKE cluster(s) (%d with Workload Identity), %d K8s->GCP binding(s)",
			len(allClusters), wiEnabled, len(allBindings)), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}

	// Count federation findings
	if hasFederation {
		logger.SuccessM(fmt.Sprintf("Found %d Workload Identity Pool(s), %d Provider(s), %d federated binding(s)",
			len(allPools), len(allProviders), len(allFederatedBindings)), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllClusters returns all clusters from all projects (for statistics)
func (m *WorkloadIdentityModule) getAllClusters() []ClusterWorkloadIdentity {
	var all []ClusterWorkloadIdentity
	for _, clusters := range m.ProjectClusters {
		all = append(all, clusters...)
	}
	return all
}

// getAllBindings returns all bindings from all projects (for statistics)
func (m *WorkloadIdentityModule) getAllBindings() []WorkloadIdentityBinding {
	var all []WorkloadIdentityBinding
	for _, bindings := range m.ProjectBindings {
		all = append(all, bindings...)
	}
	return all
}

// getAllPools returns all pools from all projects (for statistics)
func (m *WorkloadIdentityModule) getAllPools() []workloadidentityservice.WorkloadIdentityPool {
	var all []workloadidentityservice.WorkloadIdentityPool
	for _, pools := range m.ProjectPools {
		all = append(all, pools...)
	}
	return all
}

// getAllProviders returns all providers from all projects (for statistics)
func (m *WorkloadIdentityModule) getAllProviders() []workloadidentityservice.WorkloadIdentityProvider {
	var all []workloadidentityservice.WorkloadIdentityProvider
	for _, providers := range m.ProjectProviders {
		all = append(all, providers...)
	}
	return all
}

// getAllFederatedBindings returns all federated bindings from all projects (for statistics)
func (m *WorkloadIdentityModule) getAllFederatedBindings() []workloadidentityservice.FederatedIdentityBinding {
	var all []workloadidentityservice.FederatedIdentityBinding
	for _, bindings := range m.ProjectFederatedBindings {
		all = append(all, bindings...)
	}
	return all
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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate GKE clusters in project %s", projectID))
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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			fmt.Sprintf("Could not list Workload Identity Pools in project %s", projectID))
	}

	var providers []workloadidentityservice.WorkloadIdentityProvider

	// Get providers for each pool
	for _, pool := range pools {
		poolProviders, err := wiSvc.ListWorkloadIdentityProviders(projectID, pool.PoolID)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
				fmt.Sprintf("Could not list providers for pool %s", pool.PoolID))
			continue
		}
		providers = append(providers, poolProviders...)
	}

	// Find federated identity bindings
	fedBindings, err := wiSvc.FindFederatedIdentityBindings(projectID, pools)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			fmt.Sprintf("Could not find federated identity bindings in project %s", projectID))
	}

	// Thread-safe append
	m.mu.Lock()
	m.ProjectClusters[projectID] = clusterInfos
	m.ProjectBindings[projectID] = bindings
	m.ProjectPools[projectID] = pools
	m.ProjectProviders[projectID] = providers
	m.ProjectFederatedBindings[projectID] = fedBindings

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["workloadidentity-commands"] = &internal.LootFile{
			Name:     "workloadidentity-commands",
			Contents: "# Workload Identity Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	// Generate loot
	for _, cwi := range clusterInfos {
		m.addClusterToLoot(projectID, cwi)
	}
	for _, binding := range bindings {
		m.addBindingToLoot(projectID, binding)
	}
	for _, pool := range pools {
		m.addPoolToLoot(projectID, pool)
	}
	for _, provider := range providers {
		m.addProviderToLoot(projectID, provider)
	}
	for _, fedBinding := range fedBindings {
		m.addFederatedBindingToLoot(projectID, fedBinding)
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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			fmt.Sprintf("Could not list service accounts in project %s", projectID))
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
func (m *WorkloadIdentityModule) addClusterToLoot(projectID string, cwi ClusterWorkloadIdentity) {
	lootFile := m.LootMap[projectID]["workloadidentity-commands"]
	if lootFile == nil {
		return
	}
	if cwi.WorkloadPoolEnabled {
		lootFile.Contents += fmt.Sprintf(
			"# ==========================================\n"+
				"# GKE CLUSTER: %s\n"+
				"# ==========================================\n"+
				"# Location: %s\n"+
				"# Project: %s\n"+
				"# Workload Pool: %s\n"+
				"# Node Pools with WI: %d/%d\n"+
				"\n# Get cluster credentials:\n"+
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

func (m *WorkloadIdentityModule) addBindingToLoot(projectID string, binding WorkloadIdentityBinding) {
	lootFile := m.LootMap[projectID]["workloadidentity-commands"]
	if lootFile == nil {
		return
	}
	highPriv := ""
	if binding.IsHighPrivilege {
		highPriv = " [HIGH PRIVILEGE]"
	}

	lootFile.Contents += fmt.Sprintf(
		"# ------------------------------------------\n"+
			"# K8s SA BINDING: %s/%s -> %s%s\n"+
			"# ------------------------------------------\n"+
			"# Cluster: %s (%s)\n"+
			"# Project: %s\n",
		binding.KubernetesNS,
		binding.KubernetesSA,
		binding.GCPServiceAccount,
		highPriv,
		binding.ClusterName,
		binding.ClusterLocation,
		binding.ProjectID,
	)

	if binding.IsHighPrivilege && len(binding.GCPSARoles) > 0 {
		lootFile.Contents += fmt.Sprintf(
			"# GCP SA Roles: %s\n",
			strings.Join(binding.GCPSARoles, ", "),
		)
	}

	lootFile.Contents += fmt.Sprintf(
		"\n# To exploit, create pod with this service account:\n"+
			"# kubectl run exploit-pod --image=google/cloud-sdk:slim --serviceaccount=%s -n %s -- sleep infinity\n"+
			"# kubectl exec -it exploit-pod -n %s -- gcloud auth list\n\n",
		binding.KubernetesSA,
		binding.KubernetesNS,
		binding.KubernetesNS,
	)
}

func (m *WorkloadIdentityModule) addPoolToLoot(projectID string, pool workloadidentityservice.WorkloadIdentityPool) {
	lootFile := m.LootMap[projectID]["workloadidentity-commands"]
	if lootFile == nil {
		return
	}
	status := "Active"
	if pool.Disabled {
		status = "Disabled"
	}
	lootFile.Contents += fmt.Sprintf(
		"# ==========================================\n"+
			"# FEDERATION POOL: %s\n"+
			"# ==========================================\n"+
			"# Project: %s\n"+
			"# Display Name: %s\n"+
			"# State: %s (%s)\n"+
			"# Description: %s\n"+
			"\n# Describe pool:\n"+
			"gcloud iam workload-identity-pools describe %s --location=global --project=%s\n\n"+
			"# List providers:\n"+
			"gcloud iam workload-identity-pools providers list --workload-identity-pool=%s --location=global --project=%s\n\n",
		pool.PoolID,
		pool.ProjectID,
		pool.DisplayName,
		pool.State, status,
		pool.Description,
		pool.PoolID, pool.ProjectID,
		pool.PoolID, pool.ProjectID,
	)
}

func (m *WorkloadIdentityModule) addProviderToLoot(projectID string, provider workloadidentityservice.WorkloadIdentityProvider) {
	lootFile := m.LootMap[projectID]["workloadidentity-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# ------------------------------------------\n"+
			"# PROVIDER: %s/%s (%s)\n"+
			"# ------------------------------------------\n"+
			"# Project: %s\n",
		provider.PoolID, provider.ProviderID,
		provider.ProviderType,
		provider.ProjectID,
	)

	if provider.ProviderType == "AWS" {
		lootFile.Contents += fmt.Sprintf(
			"# AWS Account: %s\n", provider.AWSAccountID)
	} else if provider.ProviderType == "OIDC" {
		lootFile.Contents += fmt.Sprintf(
			"# OIDC Issuer: %s\n", provider.OIDCIssuerURI)
	}

	if provider.AttributeCondition != "" {
		lootFile.Contents += fmt.Sprintf(
			"# Attribute Condition: %s\n", provider.AttributeCondition)
	} else {
		lootFile.Contents += "# Attribute Condition: NONE\n"
	}

	lootFile.Contents += fmt.Sprintf(
		"\n# Describe provider:\n"+
			"gcloud iam workload-identity-pools providers describe %s --workload-identity-pool=%s --location=global --project=%s\n\n",
		provider.ProviderID, provider.PoolID, provider.ProjectID,
	)

	// Add exploitation guidance based on provider type
	switch provider.ProviderType {
	case "AWS":
		lootFile.Contents += fmt.Sprintf(
			"# From AWS account %s, exchange credentials:\n"+
				"# gcloud iam workload-identity-pools create-cred-config \\\n"+
				"#   projects/%s/locations/global/workloadIdentityPools/%s/providers/%s \\\n"+
				"#   --aws --output-file=gcp-creds.json\n\n",
			provider.AWSAccountID,
			provider.ProjectID, provider.PoolID, provider.ProviderID,
		)
	case "OIDC":
		if strings.Contains(provider.OIDCIssuerURI, "github") {
			lootFile.Contents += fmt.Sprintf(
				"# From GitHub Actions workflow, add:\n"+
					"# permissions:\n"+
					"#   id-token: write\n"+
					"#   contents: read\n"+
					"# Then use:\n"+
					"# gcloud iam workload-identity-pools create-cred-config \\\n"+
					"#   projects/%s/locations/global/workloadIdentityPools/%s/providers/%s \\\n"+
					"#   --service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com \\\n"+
					"#   --output-file=gcp-creds.json\n\n",
				provider.ProjectID, provider.PoolID, provider.ProviderID,
			)
		}
	}
}

func (m *WorkloadIdentityModule) addFederatedBindingToLoot(projectID string, binding workloadidentityservice.FederatedIdentityBinding) {
	lootFile := m.LootMap[projectID]["workloadidentity-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# ------------------------------------------\n"+
			"# FEDERATED BINDING\n"+
			"# ------------------------------------------\n"+
			"# Pool: %s\n"+
			"# GCP Service Account: %s\n"+
			"# External Subject: %s\n"+
			"# Project: %s\n\n",
		binding.PoolID,
		binding.GCPServiceAccount,
		binding.ExternalSubject,
		binding.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *WorkloadIdentityModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *WorkloadIdentityModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID := range m.ProjectClusters {
		tables := m.buildTablesForProject(projectID)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = WorkloadIdentityOutput{Table: tables, Loot: lootFiles}
	}

	// Create path builder using the module's hierarchy
	pathBuilder := m.BuildPathBuilder()

	// Write using hierarchical output
	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *WorkloadIdentityModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allClusters := m.getAllClusters()
	allBindings := m.getAllBindings()
	allPools := m.getAllPools()
	allProviders := m.getAllProviders()
	allFederatedBindings := m.getAllFederatedBindings()

	tables := m.buildTables(allClusters, allBindings, allPools, allProviders, allFederatedBindings)

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
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
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WORKLOAD_IDENTITY_MODULE_NAME,
			"Could not write output")
	}
}

// buildTablesForProject builds tables for a specific project
func (m *WorkloadIdentityModule) buildTablesForProject(projectID string) []internal.TableFile {
	clusters := m.ProjectClusters[projectID]
	bindings := m.ProjectBindings[projectID]
	pools := m.ProjectPools[projectID]
	providers := m.ProjectProviders[projectID]
	federatedBindings := m.ProjectFederatedBindings[projectID]

	return m.buildTables(clusters, bindings, pools, providers, federatedBindings)
}

// buildTables builds all tables from the given data
func (m *WorkloadIdentityModule) buildTables(
	clusters []ClusterWorkloadIdentity,
	bindings []WorkloadIdentityBinding,
	pools []workloadidentityservice.WorkloadIdentityPool,
	providers []workloadidentityservice.WorkloadIdentityProvider,
	federatedBindings []workloadidentityservice.FederatedIdentityBinding,
) []internal.TableFile {
	var tables []internal.TableFile

	// Clusters table
	clustersHeader := []string{
		"Project",
		"Cluster",
		"Location",
		"Cluster WI Enabled",
		"Workload Pool",
		"Node Pools WI Enabled",
	}

	var clustersBody [][]string
	for _, cwi := range clusters {
		wiEnabled := "No"
		if cwi.WorkloadPoolEnabled {
			wiEnabled = "Yes"
		}
		workloadPool := "-"
		if cwi.WorkloadPool != "" {
			workloadPool = cwi.WorkloadPool
		}

		// Format as "X of Y" for clarity
		nodePoolsWI := fmt.Sprintf("%d of %d", cwi.NodePoolsWithWI, cwi.TotalNodePools)

		clustersBody = append(clustersBody, []string{
			m.GetProjectName(cwi.ProjectID),
			cwi.ClusterName,
			cwi.Location,
			wiEnabled,
			workloadPool,
			nodePoolsWI,
		})
	}

	// Only add clusters table if there are clusters
	if len(clustersBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "workload-identity-clusters",
			Header: clustersHeader,
			Body:   clustersBody,
		})
	}

	// Bindings table
	bindingsHeader := []string{
		"Project",
		"Cluster",
		"K8s Namespace",
		"K8s Service Account",
		"GCP Service Account",
		"High Privilege SA",
		"SA Attack Paths",
	}

	var bindingsBody [][]string
	for _, binding := range bindings {
		highPriv := "No"
		if binding.IsHighPrivilege {
			highPriv = "Yes"
		}

		// Check attack paths for the GCP service account
		attackPaths := "-"
		if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
			attackPaths = m.AttackPathCache.GetAttackSummary(binding.GCPServiceAccount)
		} else {
			attackPaths = "run --attack-paths"
		}

		bindingsBody = append(bindingsBody, []string{
			m.GetProjectName(binding.ProjectID),
			binding.ClusterName,
			binding.KubernetesNS,
			binding.KubernetesSA,
			binding.GCPServiceAccount,
			highPriv,
			attackPaths,
		})
	}

	// Add bindings table if there are any
	if len(bindingsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "workload-identity-bindings",
			Header: bindingsHeader,
			Body:   bindingsBody,
		})
	}

	// ============================
	// Workload Identity Federation tables
	// ============================

	// Federation Pools table
	if len(pools) > 0 {
		poolsHeader := []string{
			"Project",
			"Pool ID",
			"Display Name",
			"State",
			"Disabled",
		}

		var poolsBody [][]string
		for _, pool := range pools {
			disabled := "No"
			if pool.Disabled {
				disabled = "Yes"
			}
			poolsBody = append(poolsBody, []string{
				m.GetProjectName(pool.ProjectID),
				pool.PoolID,
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
	if len(providers) > 0 {
		providersHeader := []string{
			"Project",
			"Pool",
			"Provider",
			"Type",
			"OIDC Issuer / AWS Account",
			"Access Condition",
		}

		var providersBody [][]string
		for _, p := range providers {
			issuerOrAccount := "-"
			if p.ProviderType == "AWS" {
				issuerOrAccount = p.AWSAccountID
			} else if p.ProviderType == "OIDC" {
				issuerOrAccount = p.OIDCIssuerURI
			}

			attrCond := "-"
			if p.AttributeCondition != "" {
				attrCond = p.AttributeCondition
			}

			providersBody = append(providersBody, []string{
				m.GetProjectName(p.ProjectID),
				p.PoolID,
				p.ProviderID,
				p.ProviderType,
				issuerOrAccount,
				attrCond,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "wi-federation-providers",
			Header: providersHeader,
			Body:   providersBody,
		})
	}

	// Federated bindings table
	if len(federatedBindings) > 0 {
		fedBindingsHeader := []string{
			"Project",
			"Pool",
			"GCP Service Account",
			"External Identity",
			"SA Attack Paths",
		}

		var fedBindingsBody [][]string
		for _, fb := range federatedBindings {
			// Check attack paths for the GCP service account
			attackPaths := "-"
			if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
				attackPaths = m.AttackPathCache.GetAttackSummary(fb.GCPServiceAccount)
			} else {
				attackPaths = "run --attack-paths"
			}

			fedBindingsBody = append(fedBindingsBody, []string{
				m.GetProjectName(fb.ProjectID),
				fb.PoolID,
				fb.GCPServiceAccount,
				fb.ExternalSubject,
				attackPaths,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "wi-federated-bindings",
			Header: fedBindingsHeader,
			Body:   fedBindingsBody,
		})
	}

	return tables
}
