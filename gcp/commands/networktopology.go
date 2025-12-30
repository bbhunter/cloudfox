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

	"google.golang.org/api/compute/v1"
)

// Module name constant
const GCP_NETWORKTOPOLOGY_MODULE_NAME string = "network-topology"

var GCPNetworkTopologyCommand = &cobra.Command{
	Use:     GCP_NETWORKTOPOLOGY_MODULE_NAME,
	Aliases: []string{"topology", "network-map", "vpc-topology"},
	Short:   "Visualize VPC network topology, peering relationships, and trust boundaries",
	Long: `Analyze and visualize VPC network topology, peering relationships, and trust boundaries.

Features:
- Maps all VPC networks and their subnets
- Identifies VPC peering relationships
- Detects Shared VPC configurations
- Analyzes VPC Service Controls perimeters
- Maps Cloud NAT and Private Google Access
- Identifies potential trust boundary issues
- Detects cross-project network access paths

Requires appropriate IAM permissions:
- roles/compute.networkViewer
- roles/compute.viewer`,
	Run: runGCPNetworkTopologyCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type VPCNetwork struct {
	Name               string
	ProjectID          string
	SelfLink           string
	Description        string
	RoutingMode        string
	AutoCreateSubnets  bool
	SubnetCount        int
	PeeringCount       int
	IsSharedVPC        bool
	SharedVPCRole      string // "host" or "service"
	SharedVPCHost      string
	MTU                int64
	CreationTimestamp  string
	FirewallRuleCount  int
	PrivateGoogleAcces bool
}

type Subnet struct {
	Name                  string
	ProjectID             string
	Network               string
	Region                string
	IPCIDRRange           string
	SecondaryRanges       []string
	PrivateIPGoogleAccess bool
	FlowLogsEnabled       bool
	Purpose               string
	Role                  string
	StackType             string
}

type VPCPeering struct {
	Name              string
	Network           string
	PeerNetwork       string
	State             string
	StateDetails      string
	ExportCustomRoute bool
	ImportCustomRoute bool
	ExportSubnetRoute bool
	ImportSubnetRoute bool
	ProjectID         string
	PeerProjectID     string
	AutoCreateRoutes  bool
}

type SharedVPCConfig struct {
	HostProject     string
	ServiceProjects []string
	SharedSubnets   []string
	SharedNetworks  []string
}

type CloudNATConfig struct {
	Name                 string
	ProjectID            string
	Region               string
	Network              string
	Subnets              []string
	NATIPAddresses       []string
	MinPortsPerVM        int64
	SourceSubnetworkType string
	EnableLogging        bool
}

type TrustBoundary struct {
	Name        string
	Type        string // "vpc-peering", "shared-vpc", "service-perimeter"
	SourceScope string
	TargetScope string
	RiskLevel   string
	Details     string
}

type NetworkRoute struct {
	Name        string
	ProjectID   string
	Network     string
	DestRange   string
	NextHop     string
	NextHopType string
	Priority    int64
	Tags        []string
}

// ------------------------------
// Module Struct
// ------------------------------
type NetworkTopologyModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Networks       []VPCNetwork
	Subnets        []Subnet
	Peerings       []VPCPeering
	SharedVPCs     map[string]*SharedVPCConfig
	NATs           []CloudNATConfig
	TrustBoundarie []TrustBoundary
	Routes         []NetworkRoute
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type NetworkTopologyOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkTopologyOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkTopologyOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPNetworkTopologyCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_NETWORKTOPOLOGY_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &NetworkTopologyModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		Networks:       []VPCNetwork{},
		Subnets:        []Subnet{},
		Peerings:       []VPCPeering{},
		SharedVPCs:     make(map[string]*SharedVPCConfig),
		NATs:           []CloudNATConfig{},
		TrustBoundarie: []TrustBoundary{},
		Routes:         []NetworkRoute{},
		LootMap:        make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *NetworkTopologyModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Mapping network topology and trust boundaries...", GCP_NETWORKTOPOLOGY_MODULE_NAME)

	// Create Compute client
	computeService, err := compute.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Compute service: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		return
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, computeService, logger)
		}(projectID)
	}
	wg.Wait()

	// Analyze trust boundaries
	m.analyzeTrustBoundaries(logger)

	// Check results
	if len(m.Networks) == 0 {
		logger.InfoM("No VPC networks found", GCP_NETWORKTOPOLOGY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Mapped %d VPC network(s), %d subnet(s), %d peering(s)",
		len(m.Networks), len(m.Subnets), len(m.Peerings)), GCP_NETWORKTOPOLOGY_MODULE_NAME)

	if len(m.TrustBoundarie) > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d trust boundary relationship(s)", len(m.TrustBoundarie)), GCP_NETWORKTOPOLOGY_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *NetworkTopologyModule) processProject(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating networks for project: %s", projectID), GCP_NETWORKTOPOLOGY_MODULE_NAME)
	}

	// List networks
	m.enumerateNetworks(ctx, projectID, computeService, logger)

	// List subnets
	m.enumerateSubnets(ctx, projectID, computeService, logger)

	// List routes
	m.enumerateRoutes(ctx, projectID, computeService, logger)

	// List Cloud NAT
	m.enumerateCloudNAT(ctx, projectID, computeService, logger)
}

func (m *NetworkTopologyModule) enumerateNetworks(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Networks.List(projectID)
	err := req.Pages(ctx, func(page *compute.NetworkList) error {
		for _, network := range page.Items {
			vpc := VPCNetwork{
				Name:              network.Name,
				ProjectID:         projectID,
				SelfLink:          network.SelfLink,
				Description:       network.Description,
				RoutingMode:       network.RoutingConfig.RoutingMode,
				AutoCreateSubnets: network.AutoCreateSubnetworks,
				MTU:               network.Mtu,
				CreationTimestamp: network.CreationTimestamp,
				SubnetCount:       len(network.Subnetworks),
			}

			// Check for peerings
			for _, peering := range network.Peerings {
				vpc.PeeringCount++

				peeringRecord := VPCPeering{
					Name:              peering.Name,
					Network:           network.SelfLink,
					PeerNetwork:       peering.Network,
					State:             peering.State,
					StateDetails:      peering.StateDetails,
					ExportCustomRoute: peering.ExportCustomRoutes,
					ImportCustomRoute: peering.ImportCustomRoutes,
					ExportSubnetRoute: peering.ExportSubnetRoutesWithPublicIp,
					ImportSubnetRoute: peering.ImportSubnetRoutesWithPublicIp,
					ProjectID:         projectID,
					AutoCreateRoutes:  peering.AutoCreateRoutes,
				}

				// Extract peer project ID from peer network URL
				peeringRecord.PeerProjectID = m.extractProjectFromURL(peering.Network)

				m.mu.Lock()
				m.Peerings = append(m.Peerings, peeringRecord)
				m.mu.Unlock()
			}

			m.mu.Lock()
			m.Networks = append(m.Networks, vpc)
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing networks for project %s: %v", projectID, err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		}
	}

	// Check for Shared VPC host project
	m.checkSharedVPCHost(ctx, projectID, computeService, logger)
}

func (m *NetworkTopologyModule) enumerateSubnets(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Subnetworks.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for region, subnetList := range page.Items {
			if subnetList.Subnetworks == nil {
				continue
			}
			for _, subnet := range subnetList.Subnetworks {
				subnetRecord := Subnet{
					Name:                  subnet.Name,
					ProjectID:             projectID,
					Network:               subnet.Network,
					Region:                m.extractRegionFromURL(region),
					IPCIDRRange:           subnet.IpCidrRange,
					PrivateIPGoogleAccess: subnet.PrivateIpGoogleAccess,
					Purpose:               subnet.Purpose,
					Role:                  subnet.Role,
					StackType:             subnet.StackType,
				}

				// Check for flow logs
				if subnet.LogConfig != nil {
					subnetRecord.FlowLogsEnabled = subnet.LogConfig.Enable
				}

				// Secondary ranges
				for _, sr := range subnet.SecondaryIpRanges {
					subnetRecord.SecondaryRanges = append(subnetRecord.SecondaryRanges,
						fmt.Sprintf("%s:%s", sr.RangeName, sr.IpCidrRange))
				}

				m.mu.Lock()
				m.Subnets = append(m.Subnets, subnetRecord)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing subnets for project %s: %v", projectID, err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		}
	}
}

func (m *NetworkTopologyModule) enumerateRoutes(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Routes.List(projectID)
	err := req.Pages(ctx, func(page *compute.RouteList) error {
		for _, route := range page.Items {
			routeRecord := NetworkRoute{
				Name:      route.Name,
				ProjectID: projectID,
				Network:   route.Network,
				DestRange: route.DestRange,
				Priority:  route.Priority,
				Tags:      route.Tags,
			}

			// Determine next hop type
			switch {
			case route.NextHopGateway != "":
				routeRecord.NextHopType = "gateway"
				routeRecord.NextHop = route.NextHopGateway
			case route.NextHopInstance != "":
				routeRecord.NextHopType = "instance"
				routeRecord.NextHop = route.NextHopInstance
			case route.NextHopIp != "":
				routeRecord.NextHopType = "ip"
				routeRecord.NextHop = route.NextHopIp
			case route.NextHopNetwork != "":
				routeRecord.NextHopType = "network"
				routeRecord.NextHop = route.NextHopNetwork
			case route.NextHopPeering != "":
				routeRecord.NextHopType = "peering"
				routeRecord.NextHop = route.NextHopPeering
			case route.NextHopIlb != "":
				routeRecord.NextHopType = "ilb"
				routeRecord.NextHop = route.NextHopIlb
			case route.NextHopVpnTunnel != "":
				routeRecord.NextHopType = "vpn"
				routeRecord.NextHop = route.NextHopVpnTunnel
			}

			m.mu.Lock()
			m.Routes = append(m.Routes, routeRecord)
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing routes for project %s: %v", projectID, err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		}
	}
}

func (m *NetworkTopologyModule) enumerateCloudNAT(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	// List routers to find NAT configurations
	req := computeService.Routers.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.RouterAggregatedList) error {
		for region, routerList := range page.Items {
			if routerList.Routers == nil {
				continue
			}
			for _, router := range routerList.Routers {
				for _, nat := range router.Nats {
					natRecord := CloudNATConfig{
						Name:                 nat.Name,
						ProjectID:            projectID,
						Region:               m.extractRegionFromURL(region),
						Network:              router.Network,
						MinPortsPerVM:        nat.MinPortsPerVm,
						SourceSubnetworkType: nat.SourceSubnetworkIpRangesToNat,
					}

					// NAT IP addresses
					for _, natIP := range nat.NatIps {
						natRecord.NATIPAddresses = append(natRecord.NATIPAddresses, natIP)
					}

					// Subnets using this NAT
					for _, subnet := range nat.Subnetworks {
						natRecord.Subnets = append(natRecord.Subnets, subnet.Name)
					}

					// Logging
					if nat.LogConfig != nil {
						natRecord.EnableLogging = nat.LogConfig.Enable
					}

					m.mu.Lock()
					m.NATs = append(m.NATs, natRecord)
					m.mu.Unlock()
				}
			}
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing Cloud NAT for project %s: %v", projectID, err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		}
	}
}

func (m *NetworkTopologyModule) checkSharedVPCHost(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	// Check if project is a Shared VPC host
	project, err := computeService.Projects.Get(projectID).Do()
	if err != nil {
		return
	}

	if project.XpnProjectStatus == "HOST" {
		m.mu.Lock()
		m.SharedVPCs[projectID] = &SharedVPCConfig{
			HostProject:     projectID,
			ServiceProjects: []string{},
			SharedSubnets:   []string{},
			SharedNetworks:  []string{},
		}
		m.mu.Unlock()

		// List service projects
		xpnReq := computeService.Projects.GetXpnResources(projectID)
		err := xpnReq.Pages(ctx, func(page *compute.ProjectsGetXpnResources) error {
			for _, resource := range page.Resources {
				if resource.Type == "PROJECT" {
					m.mu.Lock()
					m.SharedVPCs[projectID].ServiceProjects = append(
						m.SharedVPCs[projectID].ServiceProjects, resource.Id)
					m.mu.Unlock()
				}
			}
			return nil
		})
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing XPN resources for project %s: %v", projectID, err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
			}
		}

		// Mark host networks
		for i := range m.Networks {
			if m.Networks[i].ProjectID == projectID {
				m.Networks[i].IsSharedVPC = true
				m.Networks[i].SharedVPCRole = "host"
			}
		}
	}
}

// ------------------------------
// Trust Boundary Analysis
// ------------------------------
func (m *NetworkTopologyModule) analyzeTrustBoundaries(logger internal.Logger) {
	// Analyze VPC peering trust boundaries
	for _, peering := range m.Peerings {
		boundary := TrustBoundary{
			Name:        peering.Name,
			Type:        "vpc-peering",
			SourceScope: fmt.Sprintf("projects/%s/networks/%s", peering.ProjectID, m.extractNetworkName(peering.Network)),
			TargetScope: peering.PeerNetwork,
		}

		// Assess risk level
		if peering.ProjectID != peering.PeerProjectID {
			boundary.RiskLevel = "HIGH"
			boundary.Details = "Cross-project VPC peering enables network connectivity between different projects"
		} else {
			boundary.RiskLevel = "MEDIUM"
			boundary.Details = "Same-project VPC peering enables connectivity between networks"
		}

		// Check route sharing
		if peering.ExportCustomRoute || peering.ImportCustomRoute {
			boundary.Details += "; Custom routes are shared"
		}

		m.mu.Lock()
		m.TrustBoundarie = append(m.TrustBoundarie, boundary)
		m.mu.Unlock()

		// Add to loot
		m.addTrustBoundaryToLoot(boundary)
	}

	// Analyze Shared VPC trust boundaries
	for hostProject, config := range m.SharedVPCs {
		for _, serviceProject := range config.ServiceProjects {
			boundary := TrustBoundary{
				Name:        fmt.Sprintf("shared-vpc-%s-%s", hostProject, serviceProject),
				Type:        "shared-vpc",
				SourceScope: fmt.Sprintf("projects/%s", hostProject),
				TargetScope: fmt.Sprintf("projects/%s", serviceProject),
				RiskLevel:   "MEDIUM",
				Details:     fmt.Sprintf("Shared VPC: %s provides network resources to %s", hostProject, serviceProject),
			}

			m.mu.Lock()
			m.TrustBoundarie = append(m.TrustBoundarie, boundary)
			m.mu.Unlock()

			m.addTrustBoundaryToLoot(boundary)
		}
	}

	// Analyze routes for potential trust issues
	for _, route := range m.Routes {
		if route.NextHopType == "vpn" || route.NextHopType == "peering" {
			boundary := TrustBoundary{
				Name:        route.Name,
				Type:        "network-route",
				SourceScope: route.Network,
				TargetScope: route.NextHop,
				RiskLevel:   "LOW",
				Details:     fmt.Sprintf("Route to %s via %s", route.DestRange, route.NextHopType),
			}

			// Elevated risk for default route (0.0.0.0/0) going through external paths
			if route.DestRange == "0.0.0.0/0" && (route.NextHopType == "vpn" || route.NextHopType == "peering") {
				boundary.RiskLevel = "HIGH"
				boundary.Details = fmt.Sprintf("Default route (%s) via %s - all internet traffic routes through external path",
					route.DestRange, route.NextHopType)
			}

			m.mu.Lock()
			m.TrustBoundarie = append(m.TrustBoundarie, boundary)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func (m *NetworkTopologyModule) extractProjectFromURL(url string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}
	if strings.Contains(url, "projects/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *NetworkTopologyModule) extractNetworkName(url string) string {
	// Extract network name from full URL
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func (m *NetworkTopologyModule) extractRegionFromURL(url string) string {
	// Extract region from URL like regions/us-central1
	if strings.Contains(url, "regions/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "regions" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return url
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *NetworkTopologyModule) initializeLootFiles() {
	m.LootMap["network-topology"] = &internal.LootFile{
		Name:     "network-topology",
		Contents: "# Network Topology Map\n# Generated by CloudFox\n\n",
	}
	m.LootMap["peering-analysis"] = &internal.LootFile{
		Name:     "peering-analysis",
		Contents: "# VPC Peering Analysis\n# Generated by CloudFox\n\n",
	}
	m.LootMap["shared-vpc-commands"] = &internal.LootFile{
		Name:     "shared-vpc-commands",
		Contents: "# Shared VPC Analysis Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["trust-boundaries"] = &internal.LootFile{
		Name:     "trust-boundaries",
		Contents: "# Trust Boundary Analysis\n# Generated by CloudFox\n\n",
	}
	m.LootMap["nat-analysis"] = &internal.LootFile{
		Name:     "nat-analysis",
		Contents: "# Cloud NAT Configuration Analysis\n# Generated by CloudFox\n\n",
	}
}

func (m *NetworkTopologyModule) addTrustBoundaryToLoot(boundary TrustBoundary) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["trust-boundaries"].Contents += fmt.Sprintf(
		"## %s (%s)\n"+
			"Type: %s\n"+
			"Source: %s\n"+
			"Target: %s\n"+
			"Risk Level: %s\n"+
			"Details: %s\n\n",
		boundary.Name,
		boundary.RiskLevel,
		boundary.Type,
		boundary.SourceScope,
		boundary.TargetScope,
		boundary.RiskLevel,
		boundary.Details,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *NetworkTopologyModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort networks by project and name
	sort.Slice(m.Networks, func(i, j int) bool {
		if m.Networks[i].ProjectID != m.Networks[j].ProjectID {
			return m.Networks[i].ProjectID < m.Networks[j].ProjectID
		}
		return m.Networks[i].Name < m.Networks[j].Name
	})

	// VPC Networks table
	networksHeader := []string{
		"Network",
		"Project Name",
		"Project ID",
		"Routing Mode",
		"Subnets",
		"Peerings",
		"Shared VPC",
		"MTU",
	}

	var networksBody [][]string
	for _, n := range m.Networks {
		sharedVPC := "-"
		if n.IsSharedVPC {
			sharedVPC = n.SharedVPCRole
		}

		networksBody = append(networksBody, []string{
			n.Name,
			m.GetProjectName(n.ProjectID),
			n.ProjectID,
			n.RoutingMode,
			fmt.Sprintf("%d", n.SubnetCount),
			fmt.Sprintf("%d", n.PeeringCount),
			sharedVPC,
			fmt.Sprintf("%d", n.MTU),
		})

		// Add to topology loot
		m.LootMap["network-topology"].Contents += fmt.Sprintf(
			"## VPC: %s (%s)\n"+
				"Routing Mode: %s\n"+
				"Subnets: %d\n"+
				"Peerings: %d\n"+
				"Shared VPC: %s\n\n",
			n.Name, n.ProjectID,
			n.RoutingMode,
			n.SubnetCount,
			n.PeeringCount,
			sharedVPC,
		)
	}

	// Subnets table
	subnetsHeader := []string{
		"Subnet",
		"Network",
		"Region",
		"CIDR",
		"Private Google Access",
		"Flow Logs",
		"Purpose",
	}

	var subnetsBody [][]string
	for _, s := range m.Subnets {
		purpose := s.Purpose
		if purpose == "" {
			purpose = "PRIVATE"
		}

		subnetsBody = append(subnetsBody, []string{
			s.Name,
			m.extractNetworkName(s.Network),
			s.Region,
			s.IPCIDRRange,
			fmt.Sprintf("%t", s.PrivateIPGoogleAccess),
			fmt.Sprintf("%t", s.FlowLogsEnabled),
			purpose,
		})
	}

	// VPC Peerings table
	peeringsHeader := []string{
		"Name",
		"Local Network",
		"Peer Network",
		"Peer Project",
		"State",
		"Import Routes",
		"Export Routes",
	}

	var peeringsBody [][]string
	for _, p := range m.Peerings {
		peeringsBody = append(peeringsBody, []string{
			p.Name,
			m.extractNetworkName(p.Network),
			m.extractNetworkName(p.PeerNetwork),
			p.PeerProjectID,
			p.State,
			fmt.Sprintf("%t", p.ImportCustomRoute),
			fmt.Sprintf("%t", p.ExportCustomRoute),
		})

		// Add to peering analysis loot
		m.LootMap["peering-analysis"].Contents += fmt.Sprintf(
			"## Peering: %s\n"+
				"Local: %s\n"+
				"Peer: %s (project: %s)\n"+
				"State: %s\n"+
				"Custom Routes - Import: %t, Export: %t\n\n"+
				"# Commands to analyze:\n"+
				"gcloud compute networks peerings list --project=%s\n"+
				"gcloud compute networks peerings list-routes %s --project=%s --network=%s --region=REGION --direction=INCOMING\n\n",
			p.Name,
			m.extractNetworkName(p.Network),
			m.extractNetworkName(p.PeerNetwork), p.PeerProjectID,
			p.State,
			p.ImportCustomRoute, p.ExportCustomRoute,
			p.ProjectID,
			p.Name, p.ProjectID, m.extractNetworkName(p.Network),
		)
	}

	// Trust Boundaries table
	trustHeader := []string{
		"Name",
		"Type",
		"Source",
		"Target",
		"Risk Level",
	}

	var trustBody [][]string
	for _, t := range m.TrustBoundarie {
		trustBody = append(trustBody, []string{
			t.Name,
			t.Type,
			truncateString(t.SourceScope, 40),
			truncateString(t.TargetScope, 40),
			t.RiskLevel,
		})
	}

	// Cloud NAT table
	natHeader := []string{
		"Name",
		"Project Name",
		"Project ID",
		"Region",
		"Network",
		"NAT IPs",
		"Logging",
	}

	var natBody [][]string
	for _, nat := range m.NATs {
		natIPs := strings.Join(nat.NATIPAddresses, ",")
		if len(natIPs) > 30 {
			natIPs = fmt.Sprintf("%d IPs", len(nat.NATIPAddresses))
		}

		natBody = append(natBody, []string{
			nat.Name,
			m.GetProjectName(nat.ProjectID),
			nat.ProjectID,
			nat.Region,
			m.extractNetworkName(nat.Network),
			natIPs,
			fmt.Sprintf("%t", nat.EnableLogging),
		})

		// Add to NAT analysis loot
		m.LootMap["nat-analysis"].Contents += fmt.Sprintf(
			"## Cloud NAT: %s\n"+
				"Project: %s\n"+
				"Region: %s\n"+
				"Network: %s\n"+
				"NAT IPs: %v\n"+
				"Min Ports Per VM: %d\n"+
				"Logging Enabled: %t\n\n",
			nat.Name,
			nat.ProjectID,
			nat.Region,
			m.extractNetworkName(nat.Network),
			nat.NATIPAddresses,
			nat.MinPortsPerVM,
			nat.EnableLogging,
		)
	}

	// Shared VPC commands
	for hostProject, config := range m.SharedVPCs {
		m.LootMap["shared-vpc-commands"].Contents += fmt.Sprintf(
			"## Shared VPC Host: %s\n"+
				"Service Projects: %v\n\n"+
				"# List Shared VPC resources:\n"+
				"gcloud compute shared-vpc list-associated-resources %s\n"+
				"gcloud compute shared-vpc get-host-project %s\n\n",
			hostProject,
			config.ServiceProjects,
			hostProject,
			hostProject,
		)
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
			Name:   "vpc-networks",
			Header: networksHeader,
			Body:   networksBody,
		},
	}

	if len(subnetsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "subnets",
			Header: subnetsHeader,
			Body:   subnetsBody,
		})
	}

	if len(peeringsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "vpc-peerings",
			Header: peeringsHeader,
			Body:   peeringsBody,
		})
	}

	if len(trustBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "trust-boundaries",
			Header: trustHeader,
			Body:   trustBody,
		})
	}

	if len(natBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cloud-nat",
			Header: natHeader,
			Body:   natBody,
		})
	}

	output := NetworkTopologyOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scope names with project names
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
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_NETWORKTOPOLOGY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
