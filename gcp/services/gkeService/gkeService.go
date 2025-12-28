package gkeservice

import (
	"context"
	"fmt"
	"strings"

	container "google.golang.org/api/container/v1"
)

type GKEService struct{}

func New() *GKEService {
	return &GKEService{}
}

// ClusterInfo holds GKE cluster details with security-relevant information
type ClusterInfo struct {
	// Basic info
	Name        string
	ProjectID   string
	Location    string  // Zone or Region
	Status      string
	Description string

	// Version info
	CurrentMasterVersion string
	CurrentNodeVersion   string
	ReleaseChannel       string

	// Network configuration
	Network              string
	Subnetwork           string
	ClusterIPv4CIDR      string
	ServicesIPv4CIDR     string
	Endpoint             string  // Master endpoint
	PrivateCluster       bool
	MasterAuthorizedOnly bool
	MasterAuthorizedCIDRs []string

	// Security configuration
	NetworkPolicy         bool
	PodSecurityPolicy     bool  // Deprecated but may still be in use
	BinaryAuthorization   bool
	ShieldedNodes         bool
	SecureBoot            bool
	IntegrityMonitoring   bool
	WorkloadIdentity      string  // Workload Identity Pool
	NodeServiceAccount    string

	// Authentication
	LegacyABAC            bool   // Legacy ABAC authorization
	IssueClientCertificate bool
	BasicAuthEnabled      bool   // Deprecated

	// Logging and Monitoring
	LoggingService        string
	MonitoringService     string

	// Node pool info (aggregated)
	NodePoolCount         int
	TotalNodeCount        int
	AutoscalingEnabled    bool

	// Security issues detected
	SecurityIssues        []string
}

// NodePoolInfo holds node pool details
type NodePoolInfo struct {
	ClusterName       string
	Name              string
	ProjectID         string
	Location          string
	Status            string
	NodeCount         int
	MachineType       string
	DiskSizeGb        int64
	DiskType          string
	ImageType         string
	ServiceAccount    string
	AutoRepair        bool
	AutoUpgrade       bool
	SecureBoot        bool
	IntegrityMonitoring bool
	Preemptible       bool
	Spot              bool
	OAuthScopes       []string
	// Pentest-specific fields
	HasCloudPlatformScope bool     // Full access to GCP
	RiskyScopes          []string // Scopes that enable attacks
}

// ClusterSecurityAnalysis contains detailed security analysis for a cluster
type ClusterSecurityAnalysis struct {
	ClusterName      string   `json:"clusterName"`
	ProjectID        string   `json:"projectId"`
	Location         string   `json:"location"`
	RiskLevel        string   `json:"riskLevel"`
	RiskReasons      []string `json:"riskReasons"`
	AttackSurface    []string `json:"attackSurface"`
	PrivescPaths     []string `json:"privescPaths"`
	ExploitCommands  []string `json:"exploitCommands"`
}

// Clusters retrieves all GKE clusters in a project
func (gs *GKEService) Clusters(projectID string) ([]ClusterInfo, []NodePoolInfo, error) {
	ctx := context.Background()

	service, err := container.NewService(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GKE service: %v", err)
	}

	// List clusters across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	resp, err := service.Projects.Locations.Clusters.List(parent).Do()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list clusters: %v", err)
	}

	var clusters []ClusterInfo
	var nodePools []NodePoolInfo

	for _, cluster := range resp.Clusters {
		info := parseClusterInfo(cluster, projectID)
		clusters = append(clusters, info)

		// Parse node pools
		for _, np := range cluster.NodePools {
			npInfo := parseNodePoolInfo(np, cluster.Name, projectID, cluster.Location)
			nodePools = append(nodePools, npInfo)
		}
	}

	return clusters, nodePools, nil
}

// parseClusterInfo extracts security-relevant information from a GKE cluster
func parseClusterInfo(cluster *container.Cluster, projectID string) ClusterInfo {
	info := ClusterInfo{
		Name:                  cluster.Name,
		ProjectID:             projectID,
		Location:              cluster.Location,
		Status:                cluster.Status,
		Description:           cluster.Description,
		CurrentMasterVersion:  cluster.CurrentMasterVersion,
		CurrentNodeVersion:    cluster.CurrentNodeVersion,
		Endpoint:              cluster.Endpoint,
		Network:               cluster.Network,
		Subnetwork:            cluster.Subnetwork,
		ClusterIPv4CIDR:       cluster.ClusterIpv4Cidr,
		ServicesIPv4CIDR:      cluster.ServicesIpv4Cidr,
		LoggingService:        cluster.LoggingService,
		MonitoringService:     cluster.MonitoringService,
		SecurityIssues:        []string{},
	}

	// Release channel
	if cluster.ReleaseChannel != nil {
		info.ReleaseChannel = cluster.ReleaseChannel.Channel
	}

	// Private cluster configuration
	if cluster.PrivateClusterConfig != nil {
		info.PrivateCluster = cluster.PrivateClusterConfig.EnablePrivateNodes
		if cluster.PrivateClusterConfig.EnablePrivateEndpoint {
			info.Endpoint = cluster.PrivateClusterConfig.PrivateEndpoint
		}
	}

	// Master authorized networks
	if cluster.MasterAuthorizedNetworksConfig != nil {
		info.MasterAuthorizedOnly = cluster.MasterAuthorizedNetworksConfig.Enabled
		for _, cidr := range cluster.MasterAuthorizedNetworksConfig.CidrBlocks {
			info.MasterAuthorizedCIDRs = append(info.MasterAuthorizedCIDRs, cidr.CidrBlock)
		}
	}

	// Network policy
	if cluster.NetworkPolicy != nil {
		info.NetworkPolicy = cluster.NetworkPolicy.Enabled
	}

	// Binary authorization
	if cluster.BinaryAuthorization != nil {
		info.BinaryAuthorization = cluster.BinaryAuthorization.Enabled
	}

	// Shielded nodes
	if cluster.ShieldedNodes != nil {
		info.ShieldedNodes = cluster.ShieldedNodes.Enabled
	}

	// Workload Identity
	if cluster.WorkloadIdentityConfig != nil {
		info.WorkloadIdentity = cluster.WorkloadIdentityConfig.WorkloadPool
	}

	// Legacy ABAC (should be disabled)
	if cluster.LegacyAbac != nil {
		info.LegacyABAC = cluster.LegacyAbac.Enabled
	}

	// Master auth (legacy)
	if cluster.MasterAuth != nil {
		info.IssueClientCertificate = cluster.MasterAuth.ClientCertificateConfig != nil &&
			cluster.MasterAuth.ClientCertificateConfig.IssueClientCertificate
		// Check for basic auth (deprecated)
		if cluster.MasterAuth.Username != "" {
			info.BasicAuthEnabled = true
		}
	}

	// Count node pools and nodes
	info.NodePoolCount = len(cluster.NodePools)
	for _, np := range cluster.NodePools {
		if np.Autoscaling != nil && np.Autoscaling.Enabled {
			info.AutoscalingEnabled = true
		}
		info.TotalNodeCount += int(np.InitialNodeCount)

		// Get node service account from first pool
		if info.NodeServiceAccount == "" && np.Config != nil {
			info.NodeServiceAccount = np.Config.ServiceAccount
		}

		// Check shielded node config
		if np.Config != nil && np.Config.ShieldedInstanceConfig != nil {
			info.SecureBoot = np.Config.ShieldedInstanceConfig.EnableSecureBoot
			info.IntegrityMonitoring = np.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring
		}
	}

	// Identify security issues
	info.SecurityIssues = identifySecurityIssues(info)

	return info
}

// parseNodePoolInfo extracts information from a node pool
func parseNodePoolInfo(np *container.NodePool, clusterName, projectID, location string) NodePoolInfo {
	info := NodePoolInfo{
		ClusterName: clusterName,
		Name:        np.Name,
		ProjectID:   projectID,
		Location:    location,
		Status:      np.Status,
		NodeCount:   int(np.InitialNodeCount),
	}

	if np.Config != nil {
		info.MachineType = np.Config.MachineType
		info.DiskSizeGb = np.Config.DiskSizeGb
		info.DiskType = np.Config.DiskType
		info.ImageType = np.Config.ImageType
		info.ServiceAccount = np.Config.ServiceAccount
		info.OAuthScopes = np.Config.OauthScopes
		info.Preemptible = np.Config.Preemptible
		info.Spot = np.Config.Spot

		if np.Config.ShieldedInstanceConfig != nil {
			info.SecureBoot = np.Config.ShieldedInstanceConfig.EnableSecureBoot
			info.IntegrityMonitoring = np.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring
		}

		// Analyze OAuth scopes for risky permissions
		info.HasCloudPlatformScope, info.RiskyScopes = analyzeOAuthScopes(np.Config.OauthScopes)
	}

	if np.Management != nil {
		info.AutoRepair = np.Management.AutoRepair
		info.AutoUpgrade = np.Management.AutoUpgrade
	}

	return info
}

// analyzeOAuthScopes identifies risky OAuth scopes
func analyzeOAuthScopes(scopes []string) (hasCloudPlatform bool, riskyScopes []string) {
	riskyPatterns := map[string]string{
		"https://www.googleapis.com/auth/cloud-platform":       "Full GCP access",
		"https://www.googleapis.com/auth/compute":              "Full Compute Engine access",
		"https://www.googleapis.com/auth/devstorage.full_control": "Full Cloud Storage access",
		"https://www.googleapis.com/auth/devstorage.read_write":   "Read/write Cloud Storage",
		"https://www.googleapis.com/auth/logging.admin":        "Logging admin (can delete logs)",
		"https://www.googleapis.com/auth/source.full_control":  "Full source repo access",
		"https://www.googleapis.com/auth/sqlservice.admin":     "Cloud SQL admin",
	}

	for _, scope := range scopes {
		if scope == "https://www.googleapis.com/auth/cloud-platform" {
			hasCloudPlatform = true
		}
		if desc, found := riskyPatterns[scope]; found {
			riskyScopes = append(riskyScopes, fmt.Sprintf("%s: %s", scope, desc))
		}
	}

	return
}

// identifySecurityIssues checks for common security misconfigurations
func identifySecurityIssues(cluster ClusterInfo) []string {
	var issues []string

	// Public endpoint without authorized networks
	if !cluster.PrivateCluster && !cluster.MasterAuthorizedOnly {
		issues = append(issues, "Public endpoint without master authorized networks")
	}

	// Legacy ABAC enabled
	if cluster.LegacyABAC {
		issues = append(issues, "Legacy ABAC authorization enabled")
	}

	// Basic auth enabled
	if cluster.BasicAuthEnabled {
		issues = append(issues, "Basic authentication enabled (deprecated)")
	}

	// Client certificate
	if cluster.IssueClientCertificate {
		issues = append(issues, "Client certificate authentication enabled")
	}

	// No network policy
	if !cluster.NetworkPolicy {
		issues = append(issues, "Network policy not enabled")
	}

	// No workload identity
	if cluster.WorkloadIdentity == "" {
		issues = append(issues, "Workload Identity not configured")
	}

	// Shielded nodes not enabled
	if !cluster.ShieldedNodes {
		issues = append(issues, "Shielded nodes not enabled")
	}

	// Default service account on nodes
	if cluster.NodeServiceAccount == "default" ||
	   strings.HasSuffix(cluster.NodeServiceAccount, "-compute@developer.gserviceaccount.com") {
		issues = append(issues, "Default service account used on nodes")
	}

	// No release channel (manual upgrades)
	if cluster.ReleaseChannel == "" || cluster.ReleaseChannel == "UNSPECIFIED" {
		issues = append(issues, "No release channel configured")
	}

	return issues
}

// AnalyzeClusterSecurity performs detailed security analysis on a cluster
func (gs *GKEService) AnalyzeClusterSecurity(cluster ClusterInfo, nodePools []NodePoolInfo) ClusterSecurityAnalysis {
	analysis := ClusterSecurityAnalysis{
		ClusterName:     cluster.Name,
		ProjectID:       cluster.ProjectID,
		Location:        cluster.Location,
		RiskReasons:     []string{},
		AttackSurface:   []string{},
		PrivescPaths:    []string{},
		ExploitCommands: []string{},
	}

	score := 0

	// Analyze attack surface
	if !cluster.PrivateCluster {
		analysis.AttackSurface = append(analysis.AttackSurface, "Public cluster endpoint")
		if !cluster.MasterAuthorizedOnly {
			analysis.AttackSurface = append(analysis.AttackSurface, "No master authorized networks")
			analysis.RiskReasons = append(analysis.RiskReasons, "Public endpoint accessible from any IP")
			score += 3
		}
	}

	if cluster.LegacyABAC {
		analysis.AttackSurface = append(analysis.AttackSurface, "Legacy ABAC enabled")
		analysis.RiskReasons = append(analysis.RiskReasons, "Legacy ABAC can be exploited for privilege escalation")
		score += 2
	}

	if cluster.BasicAuthEnabled {
		analysis.AttackSurface = append(analysis.AttackSurface, "Basic auth enabled")
		analysis.RiskReasons = append(analysis.RiskReasons, "Basic auth credentials may be leaked")
		score += 2
	}

	// Analyze privilege escalation paths
	if cluster.WorkloadIdentity == "" {
		analysis.PrivescPaths = append(analysis.PrivescPaths,
			"No Workload Identity - pods can access node SA via metadata")
		analysis.RiskReasons = append(analysis.RiskReasons, "Metadata server accessible from pods")
		score += 2
	}

	// Analyze node pools for risky configurations
	for _, np := range nodePools {
		if np.ClusterName != cluster.Name {
			continue
		}

		if np.HasCloudPlatformScope {
			analysis.PrivescPaths = append(analysis.PrivescPaths,
				fmt.Sprintf("Node pool %s has cloud-platform scope - full GCP access from pods", np.Name))
			analysis.RiskReasons = append(analysis.RiskReasons,
				fmt.Sprintf("Node pool %s: cloud-platform scope enables full GCP access", np.Name))
			score += 3
		}

		if strings.HasSuffix(np.ServiceAccount, "-compute@developer.gserviceaccount.com") ||
			np.ServiceAccount == "default" {
			analysis.PrivescPaths = append(analysis.PrivescPaths,
				fmt.Sprintf("Node pool %s uses default SA (often has broad permissions)", np.Name))
			score += 1
		}
	}

	if !cluster.NetworkPolicy {
		analysis.AttackSurface = append(analysis.AttackSurface, "No network policy - pods can communicate freely")
		score += 1
	}

	// Generate exploitation commands
	analysis.ExploitCommands = append(analysis.ExploitCommands,
		fmt.Sprintf("# Get cluster credentials:\ngcloud container clusters get-credentials %s --zone=%s --project=%s",
			cluster.Name, cluster.Location, cluster.ProjectID))

	if !cluster.PrivateCluster && !cluster.MasterAuthorizedOnly {
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			"# Cluster API is publicly accessible, attempt kubectl commands")
	}

	if cluster.WorkloadIdentity == "" {
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			"# No Workload Identity - access metadata from pod:\n# curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token")
	}

	// Check for node pools with cloud-platform scope
	for _, np := range nodePools {
		if np.ClusterName == cluster.Name && np.HasCloudPlatformScope {
			analysis.ExploitCommands = append(analysis.ExploitCommands,
				fmt.Sprintf("# From pod on node pool %s, access any GCP API:\n# TOKEN=$(curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token)\n# curl -H \"Authorization: Bearer $TOKEN\" https://www.googleapis.com/storage/v1/b?project=%s",
					np.Name, cluster.ProjectID))
		}
	}

	// Determine risk level
	if score >= 6 {
		analysis.RiskLevel = "CRITICAL"
	} else if score >= 4 {
		analysis.RiskLevel = "HIGH"
	} else if score >= 2 {
		analysis.RiskLevel = "MEDIUM"
	} else if score >= 1 {
		analysis.RiskLevel = "LOW"
	} else {
		analysis.RiskLevel = "INFO"
	}

	return analysis
}
