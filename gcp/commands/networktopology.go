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
	IAMBindings           []SubnetIAMBinding
}

type SubnetIAMBinding struct {
	Role   string
	Member string
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

	Networks   []VPCNetwork
	Subnets    []Subnet
	Peerings   []VPCPeering
	SharedVPCs map[string]*SharedVPCConfig
	NATs       []CloudNATConfig
	Routes     []NetworkRoute
	LootMap    map[string]*internal.LootFile
	mu         sync.Mutex
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
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Networks:      []VPCNetwork{},
		Subnets:       []Subnet{},
		Peerings:      []VPCPeering{},
		SharedVPCs:    make(map[string]*SharedVPCConfig),
		NATs:          []CloudNATConfig{},
		Routes:        []NetworkRoute{},
		LootMap:       make(map[string]*internal.LootFile),
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

	// Check results
	if len(m.Networks) == 0 {
		logger.InfoM("No VPC networks found", GCP_NETWORKTOPOLOGY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d VPC network(s), %d subnet(s), %d peering(s), %d Cloud NAT(s)",
		len(m.Networks), len(m.Subnets), len(m.Peerings), len(m.NATs)), GCP_NETWORKTOPOLOGY_MODULE_NAME)

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
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list networks in project %s", projectID))
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
			regionName := m.extractRegionFromURL(region)
			for _, subnet := range subnetList.Subnetworks {
				subnetRecord := Subnet{
					Name:                  subnet.Name,
					ProjectID:             projectID,
					Network:               subnet.Network,
					Region:                regionName,
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

				// Get IAM bindings for the subnet
				subnetRecord.IAMBindings = m.getSubnetIAMBindings(ctx, computeService, projectID, regionName, subnet.Name)

				m.mu.Lock()
				m.Subnets = append(m.Subnets, subnetRecord)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list subnets in project %s", projectID))
	}
}

// getSubnetIAMBindings retrieves IAM bindings for a subnet
func (m *NetworkTopologyModule) getSubnetIAMBindings(ctx context.Context, computeService *compute.Service, projectID, region, subnetName string) []SubnetIAMBinding {
	policy, err := computeService.Subnetworks.GetIamPolicy(projectID, region, subnetName).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var bindings []SubnetIAMBinding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, SubnetIAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}
	return bindings
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
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list routes in project %s", projectID))
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
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
			fmt.Sprintf("Could not list Cloud NAT in project %s", projectID))
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
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_NETWORKTOPOLOGY_MODULE_NAME,
				fmt.Sprintf("Could not list XPN resources in project %s", projectID))
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
	m.LootMap["network-topology-commands"] = &internal.LootFile{
		Name:     "network-topology-commands",
		Contents: "# Network Topology Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
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
		"Project Name",
		"Project ID",
		"Network",
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
			m.GetProjectName(n.ProjectID),
			n.ProjectID,
			n.Name,
			n.RoutingMode,
			fmt.Sprintf("%d", n.SubnetCount),
			fmt.Sprintf("%d", n.PeeringCount),
			sharedVPC,
			fmt.Sprintf("%d", n.MTU),
		})

		// Add network commands to loot
		m.LootMap["network-topology-commands"].Contents += fmt.Sprintf(
			"## VPC Network: %s (Project: %s)\n"+
				"# Describe network:\n"+
				"gcloud compute networks describe %s --project=%s\n\n"+
				"# List subnets in network:\n"+
				"gcloud compute networks subnets list --network=%s --project=%s\n\n"+
				"# List firewall rules for network:\n"+
				"gcloud compute firewall-rules list --filter=\"network:%s\" --project=%s\n\n",
			n.Name, n.ProjectID,
			n.Name, n.ProjectID,
			n.Name, n.ProjectID,
			n.Name, n.ProjectID,
		)
	}

	// Subnets table - one row per IAM binding if present, otherwise one row per subnet
	subnetsHeader := []string{
		"Project Name",
		"Project ID",
		"Subnet",
		"Network",
		"Region",
		"CIDR",
		"Private Google Access",
		"Flow Logs",
		"Purpose",
		"IAM Role",
		"IAM Member",
	}

	var subnetsBody [][]string
	for _, s := range m.Subnets {
		purpose := s.Purpose
		if purpose == "" {
			purpose = "PRIVATE"
		}

		if len(s.IAMBindings) > 0 {
			// One row per IAM binding
			for _, binding := range s.IAMBindings {
				subnetsBody = append(subnetsBody, []string{
					m.GetProjectName(s.ProjectID),
					s.ProjectID,
					s.Name,
					m.extractNetworkName(s.Network),
					s.Region,
					s.IPCIDRRange,
					boolToYesNo(s.PrivateIPGoogleAccess),
					boolToYesNo(s.FlowLogsEnabled),
					purpose,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// No IAM bindings - single row
			subnetsBody = append(subnetsBody, []string{
				m.GetProjectName(s.ProjectID),
				s.ProjectID,
				s.Name,
				m.extractNetworkName(s.Network),
				s.Region,
				s.IPCIDRRange,
				boolToYesNo(s.PrivateIPGoogleAccess),
				boolToYesNo(s.FlowLogsEnabled),
				purpose,
				"-",
				"-",
			})
		}

		// Add subnet commands to loot
		m.LootMap["network-topology-commands"].Contents += fmt.Sprintf(
			"## Subnet: %s (Project: %s, Region: %s)\n"+
				"# Describe subnet:\n"+
				"gcloud compute networks subnets describe %s --region=%s --project=%s\n\n"+
				"# Get subnet IAM policy:\n"+
				"gcloud compute networks subnets get-iam-policy %s --region=%s --project=%s\n\n",
			s.Name, s.ProjectID, s.Region,
			s.Name, s.Region, s.ProjectID,
			s.Name, s.Region, s.ProjectID,
		)
	}

	// VPC Peerings table
	peeringsHeader := []string{
		"Project Name",
		"Project ID",
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
			m.GetProjectName(p.ProjectID),
			p.ProjectID,
			p.Name,
			m.extractNetworkName(p.Network),
			m.extractNetworkName(p.PeerNetwork),
			p.PeerProjectID,
			p.State,
			boolToYesNo(p.ImportCustomRoute),
			boolToYesNo(p.ExportCustomRoute),
		})

		// Add peering commands to loot
		m.LootMap["network-topology-commands"].Contents += fmt.Sprintf(
			"## VPC Peering: %s (Project: %s)\n"+
				"# Local: %s -> Peer: %s (project: %s)\n"+
				"# List peerings:\n"+
				"gcloud compute networks peerings list --project=%s\n\n"+
				"# List peering routes (incoming):\n"+
				"gcloud compute networks peerings list-routes %s --project=%s --network=%s --region=REGION --direction=INCOMING\n\n"+
				"# List peering routes (outgoing):\n"+
				"gcloud compute networks peerings list-routes %s --project=%s --network=%s --region=REGION --direction=OUTGOING\n\n",
			p.Name, p.ProjectID,
			m.extractNetworkName(p.Network), m.extractNetworkName(p.PeerNetwork), p.PeerProjectID,
			p.ProjectID,
			p.Name, p.ProjectID, m.extractNetworkName(p.Network),
			p.Name, p.ProjectID, m.extractNetworkName(p.Network),
		)
	}

	// Cloud NAT table
	natHeader := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"Network",
		"NAT IPs",
		"Logging",
	}

	var natBody [][]string
	for _, nat := range m.NATs {
		natIPs := strings.Join(nat.NATIPAddresses, ", ")
		if natIPs == "" {
			natIPs = "AUTO"
		}

		natBody = append(natBody, []string{
			m.GetProjectName(nat.ProjectID),
			nat.ProjectID,
			nat.Name,
			nat.Region,
			m.extractNetworkName(nat.Network),
			natIPs,
			boolToYesNo(nat.EnableLogging),
		})

		// Add NAT commands to loot
		m.LootMap["network-topology-commands"].Contents += fmt.Sprintf(
			"## Cloud NAT: %s (Project: %s, Region: %s)\n"+
				"# Describe router with NAT config:\n"+
				"gcloud compute routers describe ROUTER_NAME --region=%s --project=%s\n\n"+
				"# List NAT mappings:\n"+
				"gcloud compute routers get-nat-mapping-info ROUTER_NAME --region=%s --project=%s\n\n",
			nat.Name, nat.ProjectID, nat.Region,
			nat.Region, nat.ProjectID,
			nat.Region, nat.ProjectID,
		)
	}

	// Add Shared VPC commands to loot
	for hostProject, config := range m.SharedVPCs {
		m.LootMap["network-topology-commands"].Contents += fmt.Sprintf(
			"## Shared VPC Host: %s\n"+
				"# Service Projects: %v\n"+
				"# List Shared VPC resources:\n"+
				"gcloud compute shared-vpc list-associated-resources %s\n\n"+
				"# Get host project for service project:\n"+
				"gcloud compute shared-vpc get-host-project SERVICE_PROJECT_ID\n\n"+
				"# List usable subnets for service project:\n"+
				"gcloud compute networks subnets list-usable --project=%s\n\n",
			hostProject,
			config.ServiceProjects,
			hostProject,
			hostProject,
		)
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
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
