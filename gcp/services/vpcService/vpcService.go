package vpcservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	compute "google.golang.org/api/compute/v1"
)

type VPCService struct {
	session *gcpinternal.SafeSession
}

func New() *VPCService {
	return &VPCService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *VPCService {
	return &VPCService{session: session}
}

// VPCNetworkInfo represents a VPC network
type VPCNetworkInfo struct {
	Name                  string   `json:"name"`
	ProjectID             string   `json:"projectId"`
	Description           string   `json:"description"`
	AutoCreateSubnetworks bool     `json:"autoCreateSubnetworks"`
	RoutingMode           string   `json:"routingMode"` // REGIONAL or GLOBAL
	MTU                   int64    `json:"mtu"`
	Subnetworks           []string `json:"subnetworks"`
	Peerings              []string `json:"peerings"`
	FirewallPolicyCount   int      `json:"firewallPolicyCount"`
	RiskLevel             string   `json:"riskLevel"`
	RiskReasons           []string `json:"riskReasons"`
}

// SubnetInfo represents a subnetwork
type SubnetInfo struct {
	Name                  string   `json:"name"`
	ProjectID             string   `json:"projectId"`
	Network               string   `json:"network"`
	Region                string   `json:"region"`
	IPCidrRange           string   `json:"ipCidrRange"`
	GatewayAddress        string   `json:"gatewayAddress"`
	PrivateIPGoogleAccess bool     `json:"privateIpGoogleAccess"`
	Purpose               string   `json:"purpose"`
	EnableFlowLogs        bool     `json:"enableFlowLogs"`
	SecondaryIPRanges     []string `json:"secondaryIpRanges"`
	RiskLevel             string   `json:"riskLevel"`
	RiskReasons           []string `json:"riskReasons"`
}

// VPCPeeringInfo represents a VPC peering connection
type VPCPeeringInfo struct {
	Name                 string `json:"name"`
	ProjectID            string `json:"projectId"`
	Network              string `json:"network"`
	PeerNetwork          string `json:"peerNetwork"`
	PeerProjectID        string `json:"peerProjectId"`
	State                string `json:"state"`
	ExportCustomRoutes   bool   `json:"exportCustomRoutes"`
	ImportCustomRoutes   bool   `json:"importCustomRoutes"`
	ExchangeSubnetRoutes bool   `json:"exchangeSubnetRoutes"`
	RiskLevel            string `json:"riskLevel"`
	RiskReasons          []string `json:"riskReasons"`
	LateralMovementPath  bool     `json:"lateralMovementPath"`
	ExploitCommands      []string `json:"exploitCommands"`
}

// RouteInfo represents a route
type RouteInfo struct {
	Name             string   `json:"name"`
	ProjectID        string   `json:"projectId"`
	Network          string   `json:"network"`
	DestRange        string   `json:"destRange"`
	NextHopType      string   `json:"nextHopType"`
	NextHop          string   `json:"nextHop"`
	Priority         int64    `json:"priority"`
	Tags             []string `json:"tags"`
	RiskLevel        string   `json:"riskLevel"`
	RiskReasons      []string `json:"riskReasons"`
}

// ListVPCNetworks retrieves all VPC networks
func (s *VPCService) ListVPCNetworks(projectID string) ([]VPCNetworkInfo, error) {
	ctx := context.Background()
	var service *compute.Service
	var err error

	if s.session != nil {
		service, err = compute.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service: %v", err)
	}

	var networks []VPCNetworkInfo

	resp, err := service.Networks.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list VPC networks: %v", err)
	}

	for _, network := range resp.Items {
		info := s.parseNetwork(network, projectID)
		networks = append(networks, info)
	}

	return networks, nil
}

// ListSubnets retrieves all subnets
func (s *VPCService) ListSubnets(projectID string) ([]SubnetInfo, error) {
	ctx := context.Background()
	var service *compute.Service
	var err error

	if s.session != nil {
		service, err = compute.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service: %v", err)
	}

	var subnets []SubnetInfo

	req := service.Subnetworks.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, subnet := range scopedList.Subnetworks {
				info := s.parseSubnet(subnet, projectID)
				subnets = append(subnets, info)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list subnets: %v", err)
	}

	return subnets, nil
}

// ListVPCPeerings retrieves all VPC peering connections
func (s *VPCService) ListVPCPeerings(projectID string) ([]VPCPeeringInfo, error) {
	ctx := context.Background()
	var service *compute.Service
	var err error

	if s.session != nil {
		service, err = compute.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service: %v", err)
	}

	var peerings []VPCPeeringInfo

	networks, err := service.Networks.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %v", err)
	}

	for _, network := range networks.Items {
		for _, peering := range network.Peerings {
			// Extract peer project ID from the full network path
			peerProjectID := extractProjectFromNetwork(peering.Network)

			info := VPCPeeringInfo{
				Name:                 peering.Name,
				ProjectID:            projectID,
				Network:              network.Name,
				PeerNetwork:          extractName(peering.Network),
				PeerProjectID:        peerProjectID,
				State:                peering.State,
				ExportCustomRoutes:   peering.ExportCustomRoutes,
				ImportCustomRoutes:   peering.ImportCustomRoutes,
				ExchangeSubnetRoutes: peering.ExchangeSubnetRoutes,
				RiskReasons:          []string{},
				ExploitCommands:      []string{},
			}
			info.RiskLevel, info.RiskReasons, info.LateralMovementPath = s.analyzePeeringRisk(info)
			info.ExploitCommands = s.generatePeeringExploitCommands(info)
			peerings = append(peerings, info)
		}
	}

	return peerings, nil
}

// ListRoutes retrieves all routes
func (s *VPCService) ListRoutes(projectID string) ([]RouteInfo, error) {
	ctx := context.Background()
	var service *compute.Service
	var err error

	if s.session != nil {
		service, err = compute.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute service: %v", err)
	}

	var routes []RouteInfo

	resp, err := service.Routes.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %v", err)
	}

	for _, route := range resp.Items {
		info := s.parseRoute(route, projectID)
		routes = append(routes, info)
	}

	return routes, nil
}

func (s *VPCService) parseNetwork(network *compute.Network, projectID string) VPCNetworkInfo {
	info := VPCNetworkInfo{
		Name:                  network.Name,
		ProjectID:             projectID,
		Description:           network.Description,
		AutoCreateSubnetworks: network.AutoCreateSubnetworks,
		RoutingMode:           network.RoutingConfig.RoutingMode,
		MTU:                   network.Mtu,
		RiskReasons:           []string{},
	}

	for _, subnet := range network.Subnetworks {
		info.Subnetworks = append(info.Subnetworks, extractName(subnet))
	}

	for _, peering := range network.Peerings {
		info.Peerings = append(info.Peerings, peering.Name)
	}

	info.RiskLevel, info.RiskReasons = s.analyzeNetworkRisk(info)

	return info
}

func (s *VPCService) parseSubnet(subnet *compute.Subnetwork, projectID string) SubnetInfo {
	info := SubnetInfo{
		Name:                  subnet.Name,
		ProjectID:             projectID,
		Network:               extractName(subnet.Network),
		Region:                extractRegion(subnet.Region),
		IPCidrRange:           subnet.IpCidrRange,
		GatewayAddress:        subnet.GatewayAddress,
		PrivateIPGoogleAccess: subnet.PrivateIpGoogleAccess,
		Purpose:               subnet.Purpose,
		RiskReasons:           []string{},
	}

	if subnet.LogConfig != nil {
		info.EnableFlowLogs = subnet.LogConfig.Enable
	}

	for _, secondary := range subnet.SecondaryIpRanges {
		info.SecondaryIPRanges = append(info.SecondaryIPRanges, fmt.Sprintf("%s:%s", secondary.RangeName, secondary.IpCidrRange))
	}

	info.RiskLevel, info.RiskReasons = s.analyzeSubnetRisk(info)

	return info
}

func (s *VPCService) parseRoute(route *compute.Route, projectID string) RouteInfo {
	info := RouteInfo{
		Name:      route.Name,
		ProjectID: projectID,
		Network:   extractName(route.Network),
		DestRange: route.DestRange,
		Priority:  route.Priority,
		Tags:      route.Tags,
		RiskReasons: []string{},
	}

	// Determine next hop type
	if route.NextHopGateway != "" {
		info.NextHopType = "gateway"
		info.NextHop = extractName(route.NextHopGateway)
	} else if route.NextHopInstance != "" {
		info.NextHopType = "instance"
		info.NextHop = extractName(route.NextHopInstance)
	} else if route.NextHopIp != "" {
		info.NextHopType = "ip"
		info.NextHop = route.NextHopIp
	} else if route.NextHopNetwork != "" {
		info.NextHopType = "network"
		info.NextHop = extractName(route.NextHopNetwork)
	} else if route.NextHopPeering != "" {
		info.NextHopType = "peering"
		info.NextHop = route.NextHopPeering
	} else if route.NextHopIlb != "" {
		info.NextHopType = "ilb"
		info.NextHop = extractName(route.NextHopIlb)
	} else if route.NextHopVpnTunnel != "" {
		info.NextHopType = "vpn_tunnel"
		info.NextHop = extractName(route.NextHopVpnTunnel)
	}

	info.RiskLevel, info.RiskReasons = s.analyzeRouteRisk(info)

	return info
}

func (s *VPCService) analyzeNetworkRisk(network VPCNetworkInfo) (string, []string) {
	var reasons []string
	score := 0

	// Auto-create subnetworks can be less controlled
	if network.AutoCreateSubnetworks {
		reasons = append(reasons, "Auto-create subnetworks enabled")
		score += 1
	}

	// Has peerings (potential lateral movement path)
	if len(network.Peerings) > 0 {
		reasons = append(reasons, fmt.Sprintf("Has %d VPC peering(s)", len(network.Peerings)))
		score += 1
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *VPCService) analyzeSubnetRisk(subnet SubnetInfo) (string, []string) {
	var reasons []string
	score := 0

	// No Private Google Access
	if !subnet.PrivateIPGoogleAccess {
		reasons = append(reasons, "Private Google Access not enabled")
		score += 1
	}

	// No flow logs
	if !subnet.EnableFlowLogs {
		reasons = append(reasons, "VPC Flow Logs not enabled")
		score += 1
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *VPCService) analyzePeeringRisk(peering VPCPeeringInfo) (string, []string, bool) {
	var reasons []string
	score := 0
	lateralMovement := false

	// Exports custom routes (potential route leakage)
	if peering.ExportCustomRoutes {
		reasons = append(reasons, "Exports custom routes to peer")
		score += 1
	}

	// Imports custom routes
	if peering.ImportCustomRoutes {
		reasons = append(reasons, "Imports custom routes from peer")
		score += 1
	}

	// Cross-project peering - lateral movement opportunity
	if peering.PeerProjectID != "" && peering.PeerProjectID != peering.ProjectID {
		reasons = append(reasons, fmt.Sprintf("Cross-project peering to %s", peering.PeerProjectID))
		lateralMovement = true
		score += 2
	}

	// Exchange subnet routes - full network visibility
	if peering.ExchangeSubnetRoutes {
		reasons = append(reasons, "Exchanges subnet routes (full network reachability)")
		lateralMovement = true
		score += 1
	}

	// Active peering
	if peering.State == "ACTIVE" && lateralMovement {
		reasons = append(reasons, "Active peering enables lateral movement")
		score += 1
	}

	if score >= 3 {
		return "HIGH", reasons, lateralMovement
	} else if score >= 2 {
		return "MEDIUM", reasons, lateralMovement
	} else if score >= 1 {
		return "LOW", reasons, lateralMovement
	}
	return "INFO", reasons, lateralMovement
}

func (s *VPCService) generatePeeringExploitCommands(peering VPCPeeringInfo) []string {
	var commands []string

	if peering.State != "ACTIVE" {
		return commands
	}

	commands = append(commands,
		fmt.Sprintf("# VPC Peering: %s -> %s", peering.Network, peering.PeerNetwork))

	if peering.PeerProjectID != "" && peering.PeerProjectID != peering.ProjectID {
		commands = append(commands,
			fmt.Sprintf("# Target project: %s", peering.PeerProjectID),
			fmt.Sprintf("# List instances in peer project:\ngcloud compute instances list --project=%s", peering.PeerProjectID),
			fmt.Sprintf("# List subnets in peer project:\ngcloud compute networks subnets list --project=%s", peering.PeerProjectID))
	}

	if peering.ExchangeSubnetRoutes {
		commands = append(commands,
			"# Network scan from compromised instance in this VPC:",
			"# nmap -sn <peer-subnet-cidr>",
			"# Can reach resources in peered VPC via internal IPs")
	}

	return commands
}

func extractProjectFromNetwork(networkPath string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{network}
	// or: projects/{project}/global/networks/{network}
	parts := strings.Split(networkPath, "/")
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (s *VPCService) analyzeRouteRisk(route RouteInfo) (string, []string) {
	var reasons []string
	score := 0

	// Route to 0.0.0.0/0 via instance (NAT instance)
	if route.DestRange == "0.0.0.0/0" && route.NextHopType == "instance" {
		reasons = append(reasons, "Default route via instance (NAT instance)")
		score += 1
	}

	// Route to specific external IP via instance
	if route.NextHopType == "ip" {
		reasons = append(reasons, "Route to specific IP address")
		score += 1
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func extractName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}

func extractRegion(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	for i, part := range parts {
		if part == "regions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return fullPath
}
