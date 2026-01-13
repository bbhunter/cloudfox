package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	compute "google.golang.org/api/compute/v1"
	run "google.golang.org/api/run/v1"
)

var GCPEndpointsCommand = &cobra.Command{
	Use:     "endpoints",
	Aliases: []string{"exposure", "external", "public-ips", "internet-facing"},
	Short:   "Enumerate all network endpoints (external and internal) with IPs, ports, and hostnames",
	Long: `Enumerate all network endpoints in GCP with comprehensive analysis.

Features:
- Enumerates external IP addresses (static and ephemeral)
- Enumerates internal IP addresses for instances
- Lists load balancers (HTTP(S), TCP, UDP) - both external and internal
- Shows instances with external and internal IPs
- Lists Cloud Run and Cloud Functions URLs
- Analyzes firewall rules to determine open ports
- Generates nmap commands for penetration testing

Output includes separate tables and loot files for external and internal endpoints.`,
	Run: runGCPEndpointsCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type Endpoint struct {
	ProjectID      string
	Name           string
	Type           string // Static IP, Instance IP, LoadBalancer, Cloud Run, etc.
	Address        string
	FQDN           string
	Protocol       string
	Port           string
	Resource       string
	ResourceType   string
	Region         string
	Status         string
	ServiceAccount string
	TLSEnabled     bool
	RiskLevel      string
	RiskReasons    []string
	IsExternal     bool   // true for external IPs, false for internal
	NetworkTags    []string // Tags for firewall rule matching
	Network        string   // VPC network name
}

type FirewallRule struct {
	ProjectID    string
	RuleName     string
	Network      string
	Direction    string
	SourceRanges []string
	Ports        []string
	Protocol     string
	TargetTags   []string
	RiskLevel    string
	RiskReasons  []string
}

// ------------------------------
// Module Struct
// ------------------------------
type EndpointsModule struct {
	gcpinternal.BaseGCPModule

	ExternalEndpoints []Endpoint
	InternalEndpoints []Endpoint
	FirewallRules     []FirewallRule
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex

	// Firewall rule mapping: "network:tag1,tag2" -> allowed ports
	// Key format: "network-name" for rules with no target tags, or "network-name:tag1,tag2" for tagged rules
	firewallPortMap map[string][]string
}

// ------------------------------
// Output Struct
// ------------------------------
type EndpointsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o EndpointsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o EndpointsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPEndpointsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, "endpoints")
	if err != nil {
		return
	}

	module := &EndpointsModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ExternalEndpoints: []Endpoint{},
		InternalEndpoints: []Endpoint{},
		FirewallRules:     []FirewallRule{},
		LootMap:           make(map[string]*internal.LootFile),
		firewallPortMap:   make(map[string][]string),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *EndpointsModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, "endpoints", m.processProject)

	totalEndpoints := len(m.ExternalEndpoints) + len(m.InternalEndpoints)
	if totalEndpoints == 0 && len(m.FirewallRules) == 0 {
		logger.InfoM("No endpoints found", "endpoints")
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d external endpoint(s), %d internal endpoint(s), %d firewall rule(s)",
		len(m.ExternalEndpoints), len(m.InternalEndpoints), len(m.FirewallRules)), "endpoints")

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *EndpointsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing endpoints in project: %s", projectID), "endpoints")
	}

	computeService, err := compute.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not create Compute service in project %s", projectID))
		return
	}

	// 1. Analyze firewall rules FIRST to build port mapping for instances
	m.analyzeFirewallRules(ctx, computeService, projectID, logger)

	// 2. Get static external IPs
	m.getStaticExternalIPs(ctx, computeService, projectID, logger)

	// 3. Get instances (both external and internal IPs)
	m.getInstanceIPs(ctx, computeService, projectID, logger)

	// 4. Get load balancers (both external and internal)
	m.getLoadBalancers(ctx, computeService, projectID, logger)

	// 5. Get Cloud Run services (always external)
	m.getCloudRunServices(ctx, projectID, logger)
}

// getStaticExternalIPs retrieves static external IP addresses
func (m *EndpointsModule) getStaticExternalIPs(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	// Global addresses
	req := svc.GlobalAddresses.List(projectID)
	err := req.Pages(ctx, func(page *compute.AddressList) error {
		for _, addr := range page.Items {
			if addr.AddressType == "EXTERNAL" {
				user := ""
				if len(addr.Users) > 0 {
					user = extractResourceName(addr.Users[0])
				}
				ep := Endpoint{
					ProjectID:    projectID,
					Name:         addr.Name,
					Type:         "Static IP",
					Address:      addr.Address,
					Protocol:     "TCP/UDP",
					Port:         "ALL",
					Resource:     user,
					ResourceType: "Address",
					Region:       "global",
					Status:       addr.Status,
					RiskLevel:    "Medium",
					RiskReasons:  []string{"Static external IP"},
					IsExternal:   true,
				}
				if user == "" {
					ep.RiskReasons = append(ep.RiskReasons, "Unused static IP")
				}
				m.addEndpoint(ep)
			}
		}
		return nil
	})
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list global addresses in project %s", projectID))
	}

	// Regional addresses
	regionsReq := svc.Regions.List(projectID)
	err = regionsReq.Pages(ctx, func(page *compute.RegionList) error {
		for _, region := range page.Items {
			addrReq := svc.Addresses.List(projectID, region.Name)
			err := addrReq.Pages(ctx, func(addrPage *compute.AddressList) error {
				for _, addr := range addrPage.Items {
					if addr.AddressType == "EXTERNAL" {
						user := ""
						if len(addr.Users) > 0 {
							user = extractResourceName(addr.Users[0])
						}
						ep := Endpoint{
							ProjectID:    projectID,
							Name:         addr.Name,
							Type:         "Static IP",
							Address:      addr.Address,
							Protocol:     "TCP/UDP",
							Port:         "ALL",
							Resource:     user,
							ResourceType: "Address",
							Region:       region.Name,
							Status:       addr.Status,
							RiskLevel:    "Medium",
							RiskReasons:  []string{"Static external IP"},
							IsExternal:   true,
						}
						if user == "" {
							ep.RiskReasons = append(ep.RiskReasons, "Unused static IP")
						}
						m.addEndpoint(ep)
					}
				}
				return nil
			})
			if err != nil {
				gcpinternal.HandleGCPError(err, logger, "endpoints",
					fmt.Sprintf("Could not list addresses in region %s", region.Name))
			}
		}
		return nil
	})
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list regions in project %s", projectID))
	}
}

// getInstanceIPs retrieves instances with both external and internal IPs
func (m *EndpointsModule) getInstanceIPs(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	req := svc.Instances.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, scopedList := range page.Items {
			if scopedList.Instances == nil {
				continue
			}
			for _, instance := range scopedList.Instances {
				zoneName := extractZoneFromScope(zone)

				// Get service account
				var serviceAccount string
				if len(instance.ServiceAccounts) > 0 {
					serviceAccount = instance.ServiceAccounts[0].Email
				}

				for _, iface := range instance.NetworkInterfaces {
					networkName := extractResourceName(iface.Network)

					// Collect external IPs
					for _, accessConfig := range iface.AccessConfigs {
						if accessConfig.NatIP != "" {
							ep := Endpoint{
								ProjectID:      projectID,
								Name:           instance.Name,
								Type:           "Instance IP",
								Address:        accessConfig.NatIP,
								Protocol:       "TCP/UDP",
								Port:           "ALL",
								Resource:       instance.Name,
								ResourceType:   "Instance",
								Region:         zoneName,
								Status:         instance.Status,
								ServiceAccount: serviceAccount,
								IsExternal:     true,
								NetworkTags:    instance.Tags.Items,
								Network:        networkName,
							}

							// Classify risk
							ep.RiskLevel, ep.RiskReasons = m.classifyInstanceRisk(instance)

							m.addEndpoint(ep)
						}
					}

					// Collect internal IPs
					if iface.NetworkIP != "" {
						// Determine ports from firewall rules
						ports := m.getPortsForInstance(networkName, instance.Tags)

						ep := Endpoint{
							ProjectID:      projectID,
							Name:           instance.Name,
							Type:           "Internal IP",
							Address:        iface.NetworkIP,
							Protocol:       "TCP/UDP",
							Port:           ports,
							Resource:       instance.Name,
							ResourceType:   "Instance",
							Region:         zoneName,
							Status:         instance.Status,
							ServiceAccount: serviceAccount,
							IsExternal:     false,
							NetworkTags:    instance.Tags.Items,
							Network:        networkName,
						}

						ep.RiskLevel, ep.RiskReasons = m.classifyInternalInstanceRisk(instance, ports)
						m.addEndpoint(ep)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list instances in project %s", projectID))
	}
}

// getPortsForInstance determines open ports for an instance based on firewall rules
func (m *EndpointsModule) getPortsForInstance(network string, tags *compute.Tags) string {
	var allPorts []string

	// Check for rules with no target tags (apply to all instances in network)
	if ports, ok := m.firewallPortMap[network]; ok {
		allPorts = append(allPorts, ports...)
	}

	// Check for rules matching instance tags
	if tags != nil {
		for _, tag := range tags.Items {
			key := fmt.Sprintf("%s:%s", network, tag)
			if ports, ok := m.firewallPortMap[key]; ok {
				allPorts = append(allPorts, ports...)
			}
		}
	}

	if len(allPorts) == 0 {
		return "ALL" // Unknown, scan all ports
	}

	// Deduplicate ports
	portSet := make(map[string]bool)
	for _, p := range allPorts {
		portSet[p] = true
	}
	var uniquePorts []string
	for p := range portSet {
		uniquePorts = append(uniquePorts, p)
	}

	return strings.Join(uniquePorts, ",")
}

// classifyInternalInstanceRisk determines risk for internal endpoints
func (m *EndpointsModule) classifyInternalInstanceRisk(instance *compute.Instance, ports string) (string, []string) {
	var reasons []string
	score := 0

	reasons = append(reasons, "Internal network access")

	for _, sa := range instance.ServiceAccounts {
		if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") {
			reasons = append(reasons, "Uses default Compute Engine SA")
			score += 1
		}

		for _, scope := range sa.Scopes {
			if scope == "https://www.googleapis.com/auth/cloud-platform" {
				reasons = append(reasons, "Has cloud-platform scope")
				score += 2
			}
		}
	}

	// Check for dangerous ports
	dangerousPorts := []string{"22", "3389", "3306", "5432", "27017", "6379"}
	for _, dp := range dangerousPorts {
		if strings.Contains(ports, dp) {
			score += 1
			break
		}
	}

	if score >= 3 {
		return "High", reasons
	} else if score >= 1 {
		return "Medium", reasons
	}
	return "Low", reasons
}

// getLoadBalancers retrieves both external and internal load balancers
func (m *EndpointsModule) getLoadBalancers(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	// Regional forwarding rules
	req := svc.ForwardingRules.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for region, scopedList := range page.Items {
			if scopedList.ForwardingRules == nil {
				continue
			}
			for _, rule := range scopedList.ForwardingRules {
				ports := "ALL"
				if rule.PortRange != "" {
					ports = rule.PortRange
				} else if len(rule.Ports) > 0 {
					ports = strings.Join(rule.Ports, ",")
				}

				target := extractResourceName(rule.Target)
				if target == "" && rule.BackendService != "" {
					target = extractResourceName(rule.BackendService)
				}

				isExternal := rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED"
				isInternal := rule.LoadBalancingScheme == "INTERNAL" || rule.LoadBalancingScheme == "INTERNAL_MANAGED" || rule.LoadBalancingScheme == "INTERNAL_SELF_MANAGED"

				if isExternal {
					ep := Endpoint{
						ProjectID:    projectID,
						Name:         rule.Name,
						Type:         "LoadBalancer",
						Address:      rule.IPAddress,
						Protocol:     rule.IPProtocol,
						Port:         ports,
						Resource:     target,
						ResourceType: "ForwardingRule",
						Region:       extractRegionFromScope(region),
						TLSEnabled:   rule.PortRange == "443" || strings.Contains(strings.ToLower(rule.Name), "https"),
						RiskLevel:    "Medium",
						RiskReasons:  []string{"External load balancer"},
						IsExternal:   true,
						Network:      extractResourceName(rule.Network),
					}

					if !ep.TLSEnabled && ports != "443" {
						ep.RiskLevel = "High"
						ep.RiskReasons = append(ep.RiskReasons, "No TLS/HTTPS")
					}

					m.addEndpoint(ep)
				} else if isInternal {
					ep := Endpoint{
						ProjectID:    projectID,
						Name:         rule.Name,
						Type:         "Internal LB",
						Address:      rule.IPAddress,
						Protocol:     rule.IPProtocol,
						Port:         ports,
						Resource:     target,
						ResourceType: "ForwardingRule",
						Region:       extractRegionFromScope(region),
						TLSEnabled:   rule.PortRange == "443" || strings.Contains(strings.ToLower(rule.Name), "https"),
						RiskLevel:    "Low",
						RiskReasons:  []string{"Internal load balancer"},
						IsExternal:   false,
						Network:      extractResourceName(rule.Network),
					}

					m.addEndpoint(ep)
				}
			}
		}
		return nil
	})
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list forwarding rules in project %s", projectID))
	}

	// Global forwarding rules (external only - no internal global LBs)
	globalReq := svc.GlobalForwardingRules.List(projectID)
	err = globalReq.Pages(ctx, func(page *compute.ForwardingRuleList) error {
		for _, rule := range page.Items {
			if rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED" {
				ports := "ALL"
				if rule.PortRange != "" {
					ports = rule.PortRange
				}

				ep := Endpoint{
					ProjectID:    projectID,
					Name:         rule.Name,
					Type:         "Global LoadBalancer",
					Address:      rule.IPAddress,
					Protocol:     rule.IPProtocol,
					Port:         ports,
					Resource:     extractResourceName(rule.Target),
					ResourceType: "GlobalForwardingRule",
					Region:       "global",
					TLSEnabled:   rule.PortRange == "443" || strings.Contains(strings.ToLower(rule.Name), "https"),
					RiskLevel:    "Medium",
					RiskReasons:  []string{"External global load balancer"},
					IsExternal:   true,
				}

				if !ep.TLSEnabled && ports != "443" {
					ep.RiskLevel = "High"
					ep.RiskReasons = append(ep.RiskReasons, "No TLS/HTTPS")
				}

				m.addEndpoint(ep)
			}
		}
		return nil
	})
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list global forwarding rules in project %s", projectID))
	}
}

// getCloudRunServices retrieves Cloud Run services with public URLs
func (m *EndpointsModule) getCloudRunServices(ctx context.Context, projectID string, logger internal.Logger) {
	runService, err := run.NewService(ctx)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not create Cloud Run service in project %s", projectID))
		return
	}

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := runService.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list Cloud Run services in project %s", projectID))
		return
	}

	for _, service := range resp.Items {
		if service.Status != nil && service.Status.Url != "" {
			ep := Endpoint{
				ProjectID:    projectID,
				Name:         service.Metadata.Name,
				Type:         "Cloud Run",
				FQDN:         service.Status.Url,
				Protocol:     "HTTPS",
				Port:         "443",
				ResourceType: "CloudRun",
				TLSEnabled:   true,
				RiskLevel:    "Medium",
				RiskReasons:  []string{"Public Cloud Run service"},
				IsExternal:   true, // Cloud Run services are always external
			}

			// Extract region from metadata
			if service.Metadata != nil && service.Metadata.Labels != nil {
				if region, ok := service.Metadata.Labels["cloud.googleapis.com/location"]; ok {
					ep.Region = region
				}
			}

			// Get service account
			if service.Spec != nil && service.Spec.Template != nil && service.Spec.Template.Spec != nil {
				ep.ServiceAccount = service.Spec.Template.Spec.ServiceAccountName
			}

			m.addEndpoint(ep)
		}
	}
}

// analyzeFirewallRules analyzes firewall rules and builds port mapping for instances
func (m *EndpointsModule) analyzeFirewallRules(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) {
	req := svc.Firewalls.List(projectID)
	err := req.Pages(ctx, func(page *compute.FirewallList) error {
		for _, fw := range page.Items {
			if fw.Direction != "INGRESS" {
				continue
			}

			networkName := extractResourceName(fw.Network)

			// Collect all allowed ports for this rule
			var rulePorts []string
			for _, allowed := range fw.Allowed {
				if len(allowed.Ports) == 0 {
					// No specific ports means all ports for this protocol
					rulePorts = append(rulePorts, "ALL")
				} else {
					rulePorts = append(rulePorts, allowed.Ports...)
				}
			}

			// Build firewall port map for internal IP port determination
			m.mu.Lock()
			if len(fw.TargetTags) == 0 {
				// Rule applies to all instances in network
				m.firewallPortMap[networkName] = append(m.firewallPortMap[networkName], rulePorts...)
			} else {
				// Rule applies to instances with specific tags
				for _, tag := range fw.TargetTags {
					key := fmt.Sprintf("%s:%s", networkName, tag)
					m.firewallPortMap[key] = append(m.firewallPortMap[key], rulePorts...)
				}
			}
			m.mu.Unlock()

			// Check if rule allows ingress from 0.0.0.0/0 (public access)
			isPublic := false
			for _, sr := range fw.SourceRanges {
				if sr == "0.0.0.0/0" {
					isPublic = true
					break
				}
			}

			if isPublic {
				fwRule := FirewallRule{
					ProjectID:    projectID,
					RuleName:     fw.Name,
					Network:      networkName,
					Direction:    fw.Direction,
					SourceRanges: fw.SourceRanges,
					TargetTags:   fw.TargetTags,
					Ports:        rulePorts,
				}

				// Get protocol
				if len(fw.Allowed) > 0 {
					fwRule.Protocol = fw.Allowed[0].IPProtocol
				}

				// Classify risk
				fwRule.RiskLevel, fwRule.RiskReasons = m.classifyFirewallRisk(fwRule)

				m.mu.Lock()
				m.FirewallRules = append(m.FirewallRules, fwRule)
				m.mu.Unlock()
			}
		}
		return nil
	})
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, "endpoints",
			fmt.Sprintf("Could not list firewall rules in project %s", projectID))
	}
}

// addEndpoint adds an endpoint thread-safely to appropriate list and to loot
func (m *EndpointsModule) addEndpoint(ep Endpoint) {
	m.mu.Lock()
	if ep.IsExternal {
		m.ExternalEndpoints = append(m.ExternalEndpoints, ep)
	} else {
		m.InternalEndpoints = append(m.InternalEndpoints, ep)
	}
	m.addEndpointToLoot(ep)
	m.mu.Unlock()
}

// classifyInstanceRisk determines the risk level of an exposed instance
func (m *EndpointsModule) classifyInstanceRisk(instance *compute.Instance) (string, []string) {
	var reasons []string
	score := 0

	reasons = append(reasons, "Has external IP")
	score += 1

	for _, sa := range instance.ServiceAccounts {
		if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") {
			reasons = append(reasons, "Uses default Compute Engine SA")
			score += 2
		}

		for _, scope := range sa.Scopes {
			if scope == "https://www.googleapis.com/auth/cloud-platform" {
				reasons = append(reasons, "Has cloud-platform scope (full access)")
				score += 3
			}
		}
	}

	if score >= 4 {
		return "Critical", reasons
	} else if score >= 2 {
		return "High", reasons
	}
	return "Medium", reasons
}

// classifyFirewallRisk determines the risk level of a public firewall rule
func (m *EndpointsModule) classifyFirewallRisk(rule FirewallRule) (string, []string) {
	var reasons []string
	score := 0

	reasons = append(reasons, "Allows traffic from 0.0.0.0/0")
	score += 1

	dangerousPorts := map[string]string{
		"22":    "SSH",
		"3389":  "RDP",
		"3306":  "MySQL",
		"5432":  "PostgreSQL",
		"27017": "MongoDB",
		"6379":  "Redis",
		"9200":  "Elasticsearch",
	}

	for _, port := range rule.Ports {
		if name, ok := dangerousPorts[port]; ok {
			reasons = append(reasons, fmt.Sprintf("Exposes %s (port %s)", name, port))
			score += 3
		}
		if strings.Contains(port, "-") {
			reasons = append(reasons, fmt.Sprintf("Wide port range: %s", port))
			score += 2
		}
	}

	if len(rule.TargetTags) == 0 {
		reasons = append(reasons, "No target tags (applies to all instances)")
		score += 2
	}

	if score >= 5 {
		return "Critical", reasons
	} else if score >= 3 {
		return "High", reasons
	}
	return "Medium", reasons
}

// ------------------------------
// Helper Functions
// ------------------------------
func extractResourceName(url string) string {
	if url == "" {
		return ""
	}
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func extractRegionFromScope(scope string) string {
	// Format: regions/us-central1
	parts := strings.Split(scope, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return scope
}

func extractZoneFromScope(scope string) string {
	// Format: zones/us-central1-a
	parts := strings.Split(scope, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return scope
}

// getIPAndHostname extracts IP address and hostname from an endpoint
// Returns "-" for fields that are not applicable
func getIPAndHostname(ep Endpoint) (ipAddr string, hostname string) {
	ipAddr = "-"
	hostname = "-"

	// If we have an IP address (Address field)
	if ep.Address != "" {
		ipAddr = ep.Address
	}

	// If we have a FQDN/hostname
	if ep.FQDN != "" {
		// Strip protocol prefix
		host := ep.FQDN
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		// Remove any trailing path
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		hostname = host
	}

	return ipAddr, hostname
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *EndpointsModule) initializeLootFiles() {
	m.LootMap["endpoints-external-commands"] = &internal.LootFile{
		Name: "endpoints-external-commands",
		Contents: "# External Endpoints Scan Commands\n" +
			"# Generated by CloudFox\n" +
			"# Use these commands for authorized penetration testing of internet-facing resources\n\n",
	}
	m.LootMap["endpoints-internal-commands"] = &internal.LootFile{
		Name: "endpoints-internal-commands",
		Contents: "# Internal Endpoints Scan Commands\n" +
			"# Generated by CloudFox\n" +
			"# Use these commands for authorized internal network penetration testing\n" +
			"# Note: These targets require internal network access or VPN connection\n\n",
	}
}

func (m *EndpointsModule) addEndpointToLoot(ep Endpoint) {
	target := ep.Address
	if target == "" {
		target = ep.FQDN
	}
	if target == "" {
		return
	}

	// Strip protocol prefix for nmap (needs just hostname/IP)
	hostname := target
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	// Remove any trailing path
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}

	// Build nmap command based on endpoint type and port info
	var nmapCmd string
	switch {
	case ep.Port == "ALL" || ep.Port == "":
		// Unknown ports - scan all common ports (or full range for internal)
		if ep.IsExternal {
			nmapCmd = fmt.Sprintf("nmap -sV -Pn %s", hostname)
		} else {
			// For internal, scan all ports since we don't know what's open
			nmapCmd = fmt.Sprintf("nmap -sV -Pn -p- %s", hostname)
		}
	case strings.Contains(ep.Port, ","):
		nmapCmd = fmt.Sprintf("nmap -sV -Pn -p %s %s", ep.Port, hostname)
	case strings.Contains(ep.Port, "-"):
		nmapCmd = fmt.Sprintf("nmap -sV -Pn -p %s %s", ep.Port, hostname)
	default:
		nmapCmd = fmt.Sprintf("nmap -sV -Pn -p %s %s", ep.Port, hostname)
	}

	// Select appropriate loot file
	lootKey := "endpoints-external-commands"
	if !ep.IsExternal {
		lootKey = "endpoints-internal-commands"
	}

	m.LootMap[lootKey].Contents += fmt.Sprintf(
		"# %s: %s (%s)\n"+
			"# Project: %s | Region: %s | Network: %s\n"+
			"%s\n\n",
		ep.Type, ep.Name, ep.ResourceType,
		ep.ProjectID, ep.Region, ep.Network,
		nmapCmd,
	)

	// Add HTTP/HTTPS test for web-facing endpoints
	if ep.Type == "LoadBalancer" || ep.Type == "Global LoadBalancer" || ep.Type == "Cloud Run" {
		if ep.TLSEnabled || ep.Port == "443" {
			m.LootMap[lootKey].Contents += fmt.Sprintf("curl -vk https://%s/\n\n", hostname)
		} else {
			m.LootMap[lootKey].Contents += fmt.Sprintf("curl -v http://%s/\n\n", hostname)
		}
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *EndpointsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Status column shows operational state: RUNNING, STOPPED, IN_USE, RESERVED, etc.
	header := []string{
		"Project ID",
		"Project Name",
		"Name",
		"Type",
		"IP Address",
		"Hostname",
		"Protocol",
		"Port",
		"Region",
		"Network",
		"Status",
	}

	// External endpoints table
	var externalBody [][]string
	for _, ep := range m.ExternalEndpoints {
		ipAddr, hostname := getIPAndHostname(ep)
		externalBody = append(externalBody, []string{
			ep.ProjectID,
			m.GetProjectName(ep.ProjectID),
			ep.Name,
			ep.Type,
			ipAddr,
			hostname,
			ep.Protocol,
			ep.Port,
			ep.Region,
			ep.Network,
			ep.Status,
		})
	}

	// Internal endpoints table
	var internalBody [][]string
	for _, ep := range m.InternalEndpoints {
		ipAddr, hostname := getIPAndHostname(ep)
		internalBody = append(internalBody, []string{
			ep.ProjectID,
			m.GetProjectName(ep.ProjectID),
			ep.Name,
			ep.Type,
			ipAddr,
			hostname,
			ep.Protocol,
			ep.Port,
			ep.Region,
			ep.Network,
			ep.Status,
		})
	}

	// Firewall rules table (public 0.0.0.0/0 rules only)
	var fwBody [][]string
	if len(m.FirewallRules) > 0 {
		for _, fw := range m.FirewallRules {
			tags := strings.Join(fw.TargetTags, ",")
			if tags == "" {
				tags = "ALL"
			}
			fwBody = append(fwBody, []string{
				fw.ProjectID,
				m.GetProjectName(fw.ProjectID),
				fw.RuleName,
				fw.Network,
				fw.Protocol,
				strings.Join(fw.Ports, ","),
				tags,
			})
		}
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	var tables []internal.TableFile

	if len(externalBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "endpoints-external",
			Header: header,
			Body:   externalBody,
		})
	}

	if len(internalBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "endpoints-internal",
			Header: header,
			Body:   internalBody,
		})
	}

	if len(fwBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name: "endpoints-firewall",
			Header: []string{
				"Project ID",
				"Project Name",
				"Rule",
				"Network",
				"Protocol",
				"Ports",
				"Target Tags",
			},
			Body: fwBody,
		})
	}

	output := EndpointsOutput{
		Table: tables,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), "exposure")
		m.CommandCounter.Error++
	}
}
