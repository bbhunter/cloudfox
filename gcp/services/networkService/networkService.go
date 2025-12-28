package networkservice

import (
	"context"
	"log"
	"net"
	"strings"

	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"google.golang.org/api/compute/v1"
)

// VPC / network / subnets
// gcloud compute networks list
// gcloud compute networks get-effective-firewalls terragoat-dev-network
// gcloud compute networks subnets list
// FirewallRule structure for JSON output

// firewall-rules
// gcloud compute firewall-rules list - `terragoat-dev-firewall`

// forwarding rules (load balancers)
// gcloud compute forwarding-rules list

// Router & NAT gateways
// gcloud compute routers list
// gcloud compute routers nats list --router

// Global network firewall policy
// gcloud compute network-firewall-policies
// gcloud compute network-firewall-policies rules list
// gcloud compute network-firewall-policies associations list

type FirewallRule struct {
	FWName            string              `json:"fw_name"`
	Description       string              `json:"description"`
	Direction         string              `json:"direction"`
	Allowed           map[string][]string `json:"allowed"`
	Denied            map[string][]string `json:"denied"`
	SourceRanges      []string            `json:"source_ranges"`
	TargetTag         string              `json:"target_tag"`
	AllowedTraffic    Traffic             `json:"allowed_traffic"`
	ExposedEndpoints  []Endpoint          `json:"exposed_endpoints"`
	DestinationRanges []string            `json:"destinatioRanges"`
	TargetTags        []string            `json:"targetTags"`
}

type Traffic struct {
	TCP []string `json:"tcp"`
	UDP []string `json:"udp"`
}

type Endpoint struct {
	IP       string   `json:"ip"`
	Ports    []string `json:"ports"`
	Protocol string   `json:"protocol"`
}

type NetwworkService struct {
	session *gcpinternal.SafeSession
}

// New creates a new NetworkService (legacy - uses ADC directly)
func New() *NetwworkService {
	return &NetwworkService{}
}

// NewWithSession creates a NetworkService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *NetwworkService {
	return &NetwworkService{session: session}
}

// Returns firewall rules for a project.
func (ns *NetwworkService) FirewallRules(projectID string) ([]*compute.Firewall, error) {
	ctx := context.Background()
	var computeService *compute.Service
	var err error

	if ns.session != nil {
		computeService, err = compute.NewService(ctx, ns.session.GetClientOption())
	} else {
		computeService, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, err
	}

	firewallList, err := computeService.Firewalls.List(projectID).Do()
	if err != nil {
		return nil, err
	}
	return firewallList.Items, nil
}

// Returns firewall rules with additional logic to tag rules that expose resources to the public
func (ns *NetwworkService) FirewallRulesWithPublicExposure(projectID string) ([]FirewallRule, error) {
	var results []FirewallRule

	log.Printf("Retrieving firewall rules for project %s", projectID)
	firewalls, err := ns.FirewallRules(projectID)
	log.Print("Done")
	if err != nil {
		log.Printf("Error fetching firewall rules for project %s: %v", projectID, err)
		return nil, err
	}
	log.Print("Parsing firewall rules")
	for _, fw := range firewalls {
		parsedRule, err := parseFirewallRule(fw, projectID)
		if err != nil {
			log.Printf("Error parsing firewall rule for project %s: %v", projectID, err)
			continue
		}
		results = append(results, parsedRule)
	}
	log.Print("Done")
	return results, nil
}

// Returns a list of IPs that are mapped to a given tag. Uses a list of instances
func getIPAddressesForTargetTag(instances []ComputeEngineService.ComputeEngineInfo, tag string) ([]string, error) {
	var ips []string
	for _, instance := range instances {
		if contains(instance.Tags.Items, tag) {
			ips = append(ips, instance.NetworkInterfaces[0].NetworkIP)
		}
	}
	return ips, nil
}

// Returns the zone from a GCP URL string with the zone in it
func getZoneNameFromURL(zoneURL string) string {
	splits := strings.Split(zoneURL, "/")
	return splits[len(splits)-1]
}

// Returns true of a string is in the given list of strings. Else false
func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

// Returns true if a string in compute.Firewall.SourceRanges is "0.0.0.0/0"
func isExposedToInternet(fw *compute.Firewall) bool {
	for _, rangeVal := range fw.SourceRanges {
		if rangeVal == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

// Returns true if the IP is an internal ipv4 or ipv6 IP
func IsInternalIP(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try parsing as just an IP (not CIDR)
		ip = net.ParseIP(cidr)
		if ip == nil {
			log.Printf("Error parsing input %s\n", cidr)
			return false
		}
	}

	// Check for IPv4 private ranges
	if ip.To4() != nil {
		for _, privateCIDR := range []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		} {
			_, block, _ := net.ParseCIDR(privateCIDR)
			if block.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Check for IPv6 ULA range fc00::/7
	// This checks if the first byte of the address is in the range 0xfc to 0xfd
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}

	return false
}

// getPublicEndpoints fetches the endpoints exposed to the internet
// and, if a TargetTag is provided, gets the IP associated with it.
func getPublicEndpoints(fw *compute.Firewall, projectID string) ([]Endpoint, error) {
	var exposedEndpoints []Endpoint
	ces := ComputeEngineService.New()
	if isExposedToInternet(fw) {
		for _, allowed := range fw.Allowed {
			// Handle destination ranges
			for _, destRange := range fw.DestinationRanges {
				if !IsInternalIP(destRange) {
					exposed := Endpoint{
						IP:       destRange,
						Ports:    allowed.Ports,
						Protocol: allowed.IPProtocol,
					}
					exposedEndpoints = append(exposedEndpoints, exposed)
				}
			}

			// If TargetTag is provided, fetch the associated IP addresses.
			if len(fw.TargetTags) > 0 {
				log.Printf("Target tags found, getting their IP...")
				instances, err := ces.Instances(projectID)
				if err != nil {
					log.Printf("Error retrieving instances: %v", err)
					return nil, err
				}
				for _, tag := range fw.TargetTags {
					ips, err := getIPAddressesForTargetTag(instances, tag)
					if err != nil {
						return nil, err
					}
					for _, ip := range ips {
						if !IsInternalIP(ip) {
							exposed := Endpoint{
								IP:       ip,
								Ports:    allowed.Ports,
								Protocol: allowed.IPProtocol,
							}
							exposedEndpoints = append(exposedEndpoints, exposed)
						}
					}
				}
			}
		}
	}
	return exposedEndpoints, nil
}

// The original parseFirewallRule function
func parseFirewallRule(fw *compute.Firewall, projectID string) (FirewallRule, error) {
	var exposedEndpoints []Endpoint
	trafficAllowed := make(map[string][]string)
	trafficDenied := make(map[string][]string)

	for _, allowed := range fw.Allowed {
		trafficAllowed[allowed.IPProtocol] = append(trafficAllowed[allowed.IPProtocol], allowed.Ports...)
	}

	exposedEndpoints, err := getPublicEndpoints(fw, projectID)
	if err != nil {
		return FirewallRule{}, err
	}

	for _, denied := range fw.Denied {
		trafficDenied[denied.IPProtocol] = append(trafficDenied[denied.IPProtocol], denied.Ports...)
	}

	return FirewallRule{
		FWName:           fw.Name,
		Description:      fw.Description,
		Direction:        fw.Direction,
		Allowed:          trafficAllowed,
		Denied:           trafficDenied,
		SourceRanges:     fw.SourceRanges,
		TargetTag:        strings.Join(fw.TargetTags, ","),
		ExposedEndpoints: exposedEndpoints,
	}, nil
}

// VPCInfo holds VPC network details
type VPCInfo struct {
	Name                  string
	ProjectID             string
	Description           string
	AutoCreateSubnetworks bool
	RoutingMode           string // REGIONAL or GLOBAL
	Mtu                   int64
	Subnetworks           []string
	Peerings              []VPCPeering
	CreationTime          string
}

// VPCPeering holds VPC peering details
type VPCPeering struct {
	Name                 string
	Network              string
	State                string
	ExportCustomRoutes   bool
	ImportCustomRoutes   bool
	ExchangeSubnetRoutes bool
}

// SubnetInfo holds subnet details
type SubnetInfo struct {
	Name                  string
	ProjectID             string
	Region                string
	Network               string
	IPCidrRange           string
	GatewayAddress        string
	PrivateIPGoogleAccess bool
	Purpose               string
	StackType             string
	CreationTime          string
}

// FirewallRuleInfo holds enhanced firewall rule details for security analysis
type FirewallRuleInfo struct {
	Name              string
	ProjectID         string
	Description       string
	Network           string
	Priority          int64
	Direction         string // INGRESS or EGRESS
	Disabled          bool

	// Source/Destination
	SourceRanges      []string
	SourceTags        []string
	SourceSAs         []string
	DestinationRanges []string
	TargetTags        []string
	TargetSAs         []string

	// Traffic
	AllowedProtocols  map[string][]string // protocol -> ports
	DeniedProtocols   map[string][]string

	// Security analysis
	IsPublicIngress   bool   // 0.0.0.0/0 in source ranges
	IsPublicEgress    bool   // 0.0.0.0/0 in destination ranges
	AllowsAllPorts    bool   // Empty ports = all ports
	RiskLevel         string // HIGH, MEDIUM, LOW
	SecurityIssues    []string
}

// Networks retrieves all VPC networks in a project
func (ns *NetwworkService) Networks(projectID string) ([]VPCInfo, error) {
	ctx := context.Background()
	var computeService *compute.Service
	var err error

	if ns.session != nil {
		computeService, err = compute.NewService(ctx, ns.session.GetClientOption())
	} else {
		computeService, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, err
	}

	var networks []VPCInfo

	networkList, err := computeService.Networks.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, network := range networkList.Items {
		info := VPCInfo{
			Name:                  network.Name,
			ProjectID:             projectID,
			Description:           network.Description,
			AutoCreateSubnetworks: network.AutoCreateSubnetworks,
			RoutingMode:           network.RoutingConfig.RoutingMode,
			Mtu:                   network.Mtu,
			Subnetworks:           network.Subnetworks,
			CreationTime:          network.CreationTimestamp,
		}

		// Parse peerings
		for _, peering := range network.Peerings {
			info.Peerings = append(info.Peerings, VPCPeering{
				Name:                 peering.Name,
				Network:              peering.Network,
				State:                peering.State,
				ExportCustomRoutes:   peering.ExportCustomRoutes,
				ImportCustomRoutes:   peering.ImportCustomRoutes,
				ExchangeSubnetRoutes: peering.ExchangeSubnetRoutes,
			})
		}

		networks = append(networks, info)
	}

	return networks, nil
}

// Subnets retrieves all subnets in a project
func (ns *NetwworkService) Subnets(projectID string) ([]SubnetInfo, error) {
	ctx := context.Background()
	var computeService *compute.Service
	var err error

	if ns.session != nil {
		computeService, err = compute.NewService(ctx, ns.session.GetClientOption())
	} else {
		computeService, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, err
	}

	var subnets []SubnetInfo

	// List subnets across all regions
	subnetList, err := computeService.Subnetworks.AggregatedList(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, scopedList := range subnetList.Items {
		for _, subnet := range scopedList.Subnetworks {
			info := SubnetInfo{
				Name:                  subnet.Name,
				ProjectID:             projectID,
				Region:                extractRegionFromURL(subnet.Region),
				Network:               extractNameFromURL(subnet.Network),
				IPCidrRange:           subnet.IpCidrRange,
				GatewayAddress:        subnet.GatewayAddress,
				PrivateIPGoogleAccess: subnet.PrivateIpGoogleAccess,
				Purpose:               subnet.Purpose,
				StackType:             subnet.StackType,
				CreationTime:          subnet.CreationTimestamp,
			}
			subnets = append(subnets, info)
		}
	}

	return subnets, nil
}

// FirewallRulesEnhanced retrieves firewall rules with security analysis
func (ns *NetwworkService) FirewallRulesEnhanced(projectID string) ([]FirewallRuleInfo, error) {
	ctx := context.Background()
	var computeService *compute.Service
	var err error

	if ns.session != nil {
		computeService, err = compute.NewService(ctx, ns.session.GetClientOption())
	} else {
		computeService, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, err
	}

	var rules []FirewallRuleInfo

	firewallList, err := computeService.Firewalls.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, fw := range firewallList.Items {
		info := FirewallRuleInfo{
			Name:              fw.Name,
			ProjectID:         projectID,
			Description:       fw.Description,
			Network:           extractNameFromURL(fw.Network),
			Priority:          fw.Priority,
			Direction:         fw.Direction,
			Disabled:          fw.Disabled,
			SourceRanges:      fw.SourceRanges,
			SourceTags:        fw.SourceTags,
			SourceSAs:         fw.SourceServiceAccounts,
			DestinationRanges: fw.DestinationRanges,
			TargetTags:        fw.TargetTags,
			TargetSAs:         fw.TargetServiceAccounts,
			AllowedProtocols:  make(map[string][]string),
			DeniedProtocols:   make(map[string][]string),
		}

		// Parse allowed protocols
		for _, allowed := range fw.Allowed {
			info.AllowedProtocols[allowed.IPProtocol] = allowed.Ports
			if len(allowed.Ports) == 0 {
				info.AllowsAllPorts = true
			}
		}

		// Parse denied protocols
		for _, denied := range fw.Denied {
			info.DeniedProtocols[denied.IPProtocol] = denied.Ports
		}

		// Security analysis
		analyzeFirewallRule(&info)

		rules = append(rules, info)
	}

	return rules, nil
}

// analyzeFirewallRule performs security analysis on a firewall rule
func analyzeFirewallRule(rule *FirewallRuleInfo) {
	// Check for public ingress (0.0.0.0/0 in source ranges)
	for _, source := range rule.SourceRanges {
		if source == "0.0.0.0/0" || source == "::/0" {
			rule.IsPublicIngress = true
			break
		}
	}

	// Check for public egress
	for _, dest := range rule.DestinationRanges {
		if dest == "0.0.0.0/0" || dest == "::/0" {
			rule.IsPublicEgress = true
			break
		}
	}

	// Determine risk level and security issues
	if rule.Direction == "INGRESS" && rule.IsPublicIngress && len(rule.AllowedProtocols) > 0 {
		// Check for high-risk configurations
		for proto, ports := range rule.AllowedProtocols {
			if len(ports) == 0 {
				// All ports allowed
				rule.SecurityIssues = append(rule.SecurityIssues,
					"Allows all "+proto+" ports from 0.0.0.0/0")
				rule.RiskLevel = "HIGH"
			} else {
				// Check for sensitive ports
				for _, port := range ports {
					if isSensitivePort(port) {
						rule.SecurityIssues = append(rule.SecurityIssues,
							"Exposes sensitive port "+port+" ("+proto+") to internet")
						if rule.RiskLevel != "HIGH" {
							rule.RiskLevel = "HIGH"
						}
					}
				}
			}
		}

		if rule.RiskLevel == "" && rule.IsPublicIngress {
			rule.RiskLevel = "MEDIUM"
			rule.SecurityIssues = append(rule.SecurityIssues, "Allows ingress from 0.0.0.0/0")
		}
	}

	if rule.RiskLevel == "" {
		rule.RiskLevel = "LOW"
	}

	// Check if no target restrictions (applies to all instances)
	if len(rule.TargetTags) == 0 && len(rule.TargetSAs) == 0 && rule.IsPublicIngress {
		rule.SecurityIssues = append(rule.SecurityIssues, "No target restrictions - applies to ALL instances in network")
	}
}

// isSensitivePort checks if a port is considered sensitive
func isSensitivePort(port string) bool {
	sensitivePorts := map[string]bool{
		"22": true, "3389": true, "5985": true, "5986": true, // Remote access
		"3306": true, "5432": true, "1433": true, "1521": true, "27017": true, // Databases
		"6379": true, "11211": true, // Caches
		"9200": true, "9300": true, // Elasticsearch
		"2379": true, "2380": true, // etcd
		"8080": true, "8443": true, // Common web
		"23": true, // Telnet
		"21": true, "20": true, // FTP
		"25": true, "587": true, "465": true, // SMTP
		"110": true, "143": true, // POP3/IMAP
		"445": true, "139": true, // SMB
		"135": true, // RPC
	}
	return sensitivePorts[port]
}

// Helper functions
func extractNameFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func extractRegionFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

// GetComputeService returns a compute.Service instance for external use
func (ns *NetwworkService) GetComputeService(ctx context.Context) (*compute.Service, error) {
	var computeService *compute.Service
	var err error

	if ns.session != nil {
		computeService, err = compute.NewService(ctx, ns.session.GetClientOption())
	} else {
		computeService, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, err
	}
	return computeService, nil
}
