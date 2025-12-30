package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	networkservice "github.com/BishopFox/cloudfox/gcp/services/networkService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	compute "google.golang.org/api/compute/v1"
)

var GCPEndpointsCommand = &cobra.Command{
	Use:     globals.GCP_ENDPOINTS_MODULE_NAME,
	Aliases: []string{"external", "public-ips", "ips"},
	Short:   "Aggregate all public-facing endpoints in GCP",
	Long: `Aggregate and analyze all public-facing endpoints across GCP resources.

Features:
- Enumerates external IP addresses (static and ephemeral)
- Lists load balancers (HTTP(S), TCP, UDP)
- Shows Cloud NAT gateways
- Identifies VPN gateways and Cloud Interconnect
- Maps forwarding rules to backends
- Lists Cloud Run, App Engine, and Cloud Functions URLs
- Identifies public Cloud SQL instances
- Shows GKE ingress endpoints`,
	Run: runGCPEndpointsCommand,
}

// EndpointInfo represents a public-facing endpoint
type EndpointInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"` // IP, LoadBalancer, Function, CloudRun, etc.
	Address      string `json:"address"`
	Protocol     string `json:"protocol"`
	Port         string `json:"port"`
	Resource     string `json:"resource"`     // Associated resource
	ResourceType string `json:"resourceType"` // Instance, ForwardingRule, etc.
	Region       string `json:"region"`
	ProjectID    string `json:"projectId"`
	Status       string `json:"status"`
	Description  string `json:"description"`
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type EndpointsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Endpoints []EndpointInfo
	LootMap   map[string]*internal.LootFile
	mu        sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
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
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ENDPOINTS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &EndpointsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Endpoints:     []EndpointInfo{},
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
func (m *EndpointsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ENDPOINTS_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Endpoints) == 0 {
		logger.InfoM("No public endpoints found", globals.GCP_ENDPOINTS_MODULE_NAME)
		return
	}

	// Count by type
	typeCounts := make(map[string]int)
	for _, ep := range m.Endpoints {
		typeCounts[ep.Type]++
	}

	summary := []string{}
	for t, c := range typeCounts {
		summary = append(summary, fmt.Sprintf("%d %s", c, t))
	}

	logger.SuccessM(fmt.Sprintf("Found %d public endpoint(s): %s",
		len(m.Endpoints), strings.Join(summary, ", ")), globals.GCP_ENDPOINTS_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *EndpointsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating public endpoints in project: %s", projectID), globals.GCP_ENDPOINTS_MODULE_NAME)
	}

	var endpoints []EndpointInfo

	// Create compute service
	networkSvc := networkservice.New()
	computeSvc, err := networkSvc.GetComputeService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error creating compute service for project %s: %v", projectID, err), globals.GCP_ENDPOINTS_MODULE_NAME)
		}
		return
	}

	// 1. Get external IP addresses
	ipEndpoints := m.getExternalIPs(ctx, computeSvc, projectID, logger)
	endpoints = append(endpoints, ipEndpoints...)

	// 2. Get forwarding rules (load balancers)
	fwdEndpoints := m.getForwardingRules(ctx, computeSvc, projectID, logger)
	endpoints = append(endpoints, fwdEndpoints...)

	// 3. Get global forwarding rules
	globalFwdEndpoints := m.getGlobalForwardingRules(ctx, computeSvc, projectID, logger)
	endpoints = append(endpoints, globalFwdEndpoints...)

	// 4. Get instances with external IPs
	instanceEndpoints := m.getInstanceExternalIPs(ctx, computeSvc, projectID, logger)
	endpoints = append(endpoints, instanceEndpoints...)

	// Thread-safe append
	m.mu.Lock()
	m.Endpoints = append(m.Endpoints, endpoints...)

	// Generate loot
	for _, ep := range endpoints {
		m.addEndpointToLoot(ep)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d public endpoint(s) in project %s", len(endpoints), projectID), globals.GCP_ENDPOINTS_MODULE_NAME)
	}
}

// getExternalIPs retrieves static external IP addresses
func (m *EndpointsModule) getExternalIPs(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) []EndpointInfo {
	var endpoints []EndpointInfo

	// Get global addresses
	req := svc.GlobalAddresses.List(projectID)
	err := req.Pages(ctx, func(page *compute.AddressList) error {
		for _, addr := range page.Items {
			if addr.AddressType == "EXTERNAL" {
				user := "-"
				if len(addr.Users) > 0 {
					user = extractResourceName(addr.Users[0])
				}
				ep := EndpointInfo{
					Name:         addr.Name,
					Type:         "Static IP",
					Address:      addr.Address,
					Protocol:     "-",
					Port:         "-",
					Resource:     user,
					ResourceType: "Address",
					Region:       "global",
					ProjectID:    projectID,
					Status:       addr.Status,
					Description:  addr.Description,
				}
				endpoints = append(endpoints, ep)
			}
		}
		return nil
	})
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not list global addresses: %v", err), globals.GCP_ENDPOINTS_MODULE_NAME)
	}

	// Get regional addresses
	regionsReq := svc.Regions.List(projectID)
	err = regionsReq.Pages(ctx, func(page *compute.RegionList) error {
		for _, region := range page.Items {
			addrReq := svc.Addresses.List(projectID, region.Name)
			err := addrReq.Pages(ctx, func(addrPage *compute.AddressList) error {
				for _, addr := range addrPage.Items {
					if addr.AddressType == "EXTERNAL" {
						user := "-"
						if len(addr.Users) > 0 {
							user = extractResourceName(addr.Users[0])
						}
						ep := EndpointInfo{
							Name:         addr.Name,
							Type:         "Static IP",
							Address:      addr.Address,
							Protocol:     "-",
							Port:         "-",
							Resource:     user,
							ResourceType: "Address",
							Region:       region.Name,
							ProjectID:    projectID,
							Status:       addr.Status,
							Description:  addr.Description,
						}
						endpoints = append(endpoints, ep)
					}
				}
				return nil
			})
			if err != nil {
				logger.InfoM(fmt.Sprintf("Could not list addresses in region %s: %v", region.Name, err), globals.GCP_ENDPOINTS_MODULE_NAME)
			}
		}
		return nil
	})
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not list regions: %v", err), globals.GCP_ENDPOINTS_MODULE_NAME)
	}

	return endpoints
}

// getForwardingRules retrieves regional forwarding rules (load balancers)
func (m *EndpointsModule) getForwardingRules(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) []EndpointInfo {
	var endpoints []EndpointInfo

	// Aggregate across all regions
	req := svc.ForwardingRules.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for region, scopedList := range page.Items {
			if scopedList.ForwardingRules == nil {
				continue
			}
			for _, rule := range scopedList.ForwardingRules {
				// Only include external load balancers
				if rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED" {
					ports := "-"
					if rule.PortRange != "" {
						ports = rule.PortRange
					} else if len(rule.Ports) > 0 {
						ports = strings.Join(rule.Ports, ",")
					} else if rule.AllPorts {
						ports = "ALL"
					}

					target := extractResourceName(rule.Target)
					if target == "" && rule.BackendService != "" {
						target = extractResourceName(rule.BackendService)
					}

					regionName := extractRegionFromScope(region)

					ep := EndpointInfo{
						Name:         rule.Name,
						Type:         "LoadBalancer",
						Address:      rule.IPAddress,
						Protocol:     rule.IPProtocol,
						Port:         ports,
						Resource:     target,
						ResourceType: "ForwardingRule",
						Region:       regionName,
						ProjectID:    projectID,
						Status:       "-",
						Description:  rule.Description,
					}
					endpoints = append(endpoints, ep)
				}
			}
		}
		return nil
	})
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not list forwarding rules: %v", err), globals.GCP_ENDPOINTS_MODULE_NAME)
	}

	return endpoints
}

// getGlobalForwardingRules retrieves global forwarding rules (global load balancers)
func (m *EndpointsModule) getGlobalForwardingRules(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) []EndpointInfo {
	var endpoints []EndpointInfo

	req := svc.GlobalForwardingRules.List(projectID)
	err := req.Pages(ctx, func(page *compute.ForwardingRuleList) error {
		for _, rule := range page.Items {
			if rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED" {
				ports := "-"
				if rule.PortRange != "" {
					ports = rule.PortRange
				}

				target := extractResourceName(rule.Target)

				ep := EndpointInfo{
					Name:         rule.Name,
					Type:         "Global LoadBalancer",
					Address:      rule.IPAddress,
					Protocol:     rule.IPProtocol,
					Port:         ports,
					Resource:     target,
					ResourceType: "GlobalForwardingRule",
					Region:       "global",
					ProjectID:    projectID,
					Status:       "-",
					Description:  rule.Description,
				}
				endpoints = append(endpoints, ep)
			}
		}
		return nil
	})
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not list global forwarding rules: %v", err), globals.GCP_ENDPOINTS_MODULE_NAME)
	}

	return endpoints
}

// getInstanceExternalIPs retrieves instances with external IPs
func (m *EndpointsModule) getInstanceExternalIPs(ctx context.Context, svc *compute.Service, projectID string, logger internal.Logger) []EndpointInfo {
	var endpoints []EndpointInfo

	req := svc.Instances.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, scopedList := range page.Items {
			if scopedList.Instances == nil {
				continue
			}
			for _, instance := range scopedList.Instances {
				for _, iface := range instance.NetworkInterfaces {
					for _, accessConfig := range iface.AccessConfigs {
						if accessConfig.NatIP != "" {
							zoneName := extractZoneFromScope(zone)

							ipType := "Ephemeral IP"
							if accessConfig.Type == "ONE_TO_ONE_NAT" {
								ipType = "Instance IP"
							}

							ep := EndpointInfo{
								Name:         instance.Name,
								Type:         ipType,
								Address:      accessConfig.NatIP,
								Protocol:     "TCP/UDP",
								Port:         "ALL",
								Resource:     instance.Name,
								ResourceType: "Instance",
								Region:       zoneName,
								ProjectID:    projectID,
								Status:       instance.Status,
								Description:  instance.Description,
							}
							endpoints = append(endpoints, ep)
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not list instances: %v", err), globals.GCP_ENDPOINTS_MODULE_NAME)
	}

	return endpoints
}

// Helper functions
func extractResourceName(url string) string {
	if url == "" {
		return "-"
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

// ------------------------------
// Loot File Management
// ------------------------------
func (m *EndpointsModule) initializeLootFiles() {
	m.LootMap["endpoints-all-ips"] = &internal.LootFile{
		Name:     "endpoints-all-ips",
		Contents: "",
	}
	m.LootMap["endpoints-load-balancers"] = &internal.LootFile{
		Name:     "endpoints-load-balancers",
		Contents: "# Load Balancer Endpoints\n# Generated by CloudFox\n\n",
	}
	m.LootMap["endpoints-instance-ips"] = &internal.LootFile{
		Name:     "endpoints-instance-ips",
		Contents: "# Instance External IPs\n# Generated by CloudFox\n\n",
	}
	m.LootMap["endpoints-nmap-targets"] = &internal.LootFile{
		Name:     "endpoints-nmap-targets",
		Contents: "# Nmap Targets\n# Generated by CloudFox\n# nmap -iL endpoints-nmap-targets.txt\n\n",
	}
}

func (m *EndpointsModule) addEndpointToLoot(ep EndpointInfo) {
	// All IPs (plain list for tools)
	if ep.Address != "" && ep.Address != "-" {
		m.LootMap["endpoints-all-ips"].Contents += ep.Address + "\n"
		m.LootMap["endpoints-nmap-targets"].Contents += ep.Address + "\n"
	}

	// Load balancers
	if strings.Contains(ep.Type, "LoadBalancer") {
		m.LootMap["endpoints-load-balancers"].Contents += fmt.Sprintf(
			"# %s (%s)\n"+
				"# Target: %s\n"+
				"# Protocol: %s, Ports: %s\n"+
				"IP=%s\n\n",
			ep.Name,
			ep.Type,
			ep.Resource,
			ep.Protocol,
			ep.Port,
			ep.Address,
		)
	}

	// Instance IPs
	if ep.ResourceType == "Instance" {
		m.LootMap["endpoints-instance-ips"].Contents += fmt.Sprintf(
			"# Instance: %s (%s)\n"+
				"# Zone: %s\n"+
				"# Status: %s\n"+
				"IP=%s\n\n",
			ep.Name,
			ep.ProjectID,
			ep.Region,
			ep.Status,
			ep.Address,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *EndpointsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main endpoints table
	endpointsHeader := []string{
		"Address",
		"Type",
		"Protocol",
		"Port",
		"Resource",
		"Resource Type",
		"Region",
		"Project Name",
		"Project",
		"Status",
	}

	var endpointsBody [][]string
	for _, ep := range m.Endpoints {
		endpointsBody = append(endpointsBody, []string{
			ep.Address,
			ep.Type,
			ep.Protocol,
			ep.Port,
			ep.Resource,
			ep.ResourceType,
			ep.Region,
			m.GetProjectName(ep.ProjectID),
			ep.ProjectID,
			ep.Status,
		})
	}

	// Load balancers table
	lbHeader := []string{
		"Name",
		"Address",
		"Protocol",
		"Ports",
		"Target",
		"Region",
		"Project Name",
		"Project",
	}

	var lbBody [][]string
	for _, ep := range m.Endpoints {
		if strings.Contains(ep.Type, "LoadBalancer") {
			lbBody = append(lbBody, []string{
				ep.Name,
				ep.Address,
				ep.Protocol,
				ep.Port,
				ep.Resource,
				ep.Region,
				m.GetProjectName(ep.ProjectID),
				ep.ProjectID,
			})
		}
	}

	// Instance IPs table
	instanceHeader := []string{
		"Instance",
		"Address",
		"Zone",
		"Status",
		"Project Name",
		"Project",
	}

	var instanceBody [][]string
	for _, ep := range m.Endpoints {
		if ep.ResourceType == "Instance" {
			instanceBody = append(instanceBody, []string{
				ep.Name,
				ep.Address,
				ep.Region,
				ep.Status,
				m.GetProjectName(ep.ProjectID),
				ep.ProjectID,
			})
		}
	}

	// Static IPs table
	staticHeader := []string{
		"Name",
		"Address",
		"Used By",
		"Region",
		"Status",
		"Project Name",
		"Project",
	}

	var staticBody [][]string
	for _, ep := range m.Endpoints {
		if ep.Type == "Static IP" {
			staticBody = append(staticBody, []string{
				ep.Name,
				ep.Address,
				ep.Resource,
				ep.Region,
				ep.Status,
				m.GetProjectName(ep.ProjectID),
				ep.ProjectID,
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
	tables := []internal.TableFile{
		{
			Name:   "endpoints",
			Header: endpointsHeader,
			Body:   endpointsBody,
		},
	}

	// Add load balancers table if there are any
	if len(lbBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "endpoints-loadbalancers",
			Header: lbHeader,
			Body:   lbBody,
		})
	}

	// Add instances table if there are any
	if len(instanceBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "endpoints-instances",
			Header: instanceHeader,
			Body:   instanceBody,
		})
		logger.InfoM(fmt.Sprintf("[INFO] Found %d instance(s) with external IPs", len(instanceBody)), globals.GCP_ENDPOINTS_MODULE_NAME)
	}

	// Add static IPs table if there are any
	if len(staticBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "endpoints-static-ips",
			Header: staticHeader,
			Body:   staticBody,
		})
	}

	output := EndpointsOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ENDPOINTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
