package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	NetworkService "github.com/BishopFox/cloudfox/gcp/services/networkService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPFirewallCommand = &cobra.Command{
	Use:     globals.GCP_FIREWALL_MODULE_NAME,
	Aliases: []string{"fw", "firewall-rules", "network-security"},
	Short:   "Enumerate VPC networks and firewall rules with security analysis",
	Long: `Enumerate VPC networks, subnets, and firewall rules across projects with security analysis.

Features:
- Lists all VPC networks and their peering relationships
- Shows all subnets with CIDR ranges and configurations
- Enumerates firewall rules with security risk analysis
- Identifies overly permissive rules (0.0.0.0/0 ingress)
- Detects exposed sensitive ports (SSH, RDP, databases)
- Generates gcloud commands for remediation

Security Columns:
- Risk: HIGH, MEDIUM, LOW based on exposure analysis
- Direction: INGRESS or EGRESS
- Source: Source IP ranges (0.0.0.0/0 = internet)
- Ports: Allowed ports and protocols
- Issues: Detected security misconfigurations

Attack Surface:
- 0.0.0.0/0 ingress allows internet access to resources
- All ports allowed means no port restrictions
- No target tags means rule applies to ALL instances
- VPC peering may expose internal resources`,
	Run: runGCPFirewallCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type FirewallModule struct {
	gcpinternal.BaseGCPModule

	Networks      []NetworkService.VPCInfo
	Subnets       []NetworkService.SubnetInfo
	FirewallRules []NetworkService.FirewallRuleInfo
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type FirewallOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FirewallOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FirewallOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPFirewallCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_FIREWALL_MODULE_NAME)
	if err != nil {
		return
	}

	module := &FirewallModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Networks:      []NetworkService.VPCInfo{},
		Subnets:       []NetworkService.SubnetInfo{},
		FirewallRules: []NetworkService.FirewallRuleInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *FirewallModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_FIREWALL_MODULE_NAME, m.processProject)

	if len(m.FirewallRules) == 0 && len(m.Networks) == 0 {
		logger.InfoM("No networks or firewall rules found", globals.GCP_FIREWALL_MODULE_NAME)
		return
	}

	// Count public ingress rules and peerings
	publicIngressCount := 0
	for _, rule := range m.FirewallRules {
		if rule.IsPublicIngress {
			publicIngressCount++
		}
	}

	peeringCount := 0
	for _, network := range m.Networks {
		peeringCount += len(network.Peerings)
	}

	msg := fmt.Sprintf("Found %d network(s), %d subnet(s), %d firewall rule(s)",
		len(m.Networks), len(m.Subnets), len(m.FirewallRules))
	if publicIngressCount > 0 {
		msg += fmt.Sprintf(" [%d public ingress]", publicIngressCount)
	}
	if peeringCount > 0 {
		msg += fmt.Sprintf(" [%d peerings]", peeringCount)
	}
	logger.SuccessM(msg, globals.GCP_FIREWALL_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *FirewallModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating networks and firewall in project: %s", projectID), globals.GCP_FIREWALL_MODULE_NAME)
	}

	ns := NetworkService.New()

	// Get networks
	networks, err := ns.Networks(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FIREWALL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate networks in project %s", projectID))
	} else {
		m.mu.Lock()
		m.Networks = append(m.Networks, networks...)
		for _, network := range networks {
			m.addNetworkToLoot(network)
		}
		m.mu.Unlock()
	}

	// Get subnets
	subnets, err := ns.Subnets(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FIREWALL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate subnets in project %s", projectID))
	} else {
		m.mu.Lock()
		m.Subnets = append(m.Subnets, subnets...)
		m.mu.Unlock()
	}

	// Get firewall rules
	rules, err := ns.FirewallRulesEnhanced(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_FIREWALL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate firewall rules in project %s", projectID))
	} else {
		m.mu.Lock()
		m.FirewallRules = append(m.FirewallRules, rules...)
		for _, rule := range rules {
			m.addFirewallRuleToLoot(rule)
		}
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d network(s), %d subnet(s), %d rule(s) in project %s",
			len(networks), len(subnets), len(rules), projectID), globals.GCP_FIREWALL_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *FirewallModule) initializeLootFiles() {
	m.LootMap["firewall-commands"] = &internal.LootFile{
		Name:     "firewall-commands",
		Contents: "# Firewall Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *FirewallModule) addNetworkToLoot(network NetworkService.VPCInfo) {
	m.LootMap["firewall-commands"].Contents += fmt.Sprintf(
		"# Network: %s\n"+
			"# Project: %s\n"+
			"gcloud compute networks describe %s --project=%s\n"+
			"gcloud compute networks subnets list --network=%s --project=%s\n"+
			"gcloud compute firewall-rules list --filter=\"network:%s\" --project=%s\n\n",
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
	)
}

func (m *FirewallModule) addFirewallRuleToLoot(rule NetworkService.FirewallRuleInfo) {
	m.LootMap["firewall-commands"].Contents += fmt.Sprintf(
		"# Rule: %s (%s)\n"+
			"# Project: %s\n"+
			"gcloud compute firewall-rules describe %s --project=%s\n\n",
		rule.Name, rule.Network,
		rule.ProjectID,
		rule.Name, rule.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *FirewallModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Firewall rules table
	rulesHeader := []string{
		"Project Name",
		"Project ID",
		"Rule Name",
		"Network",
		"Direction",
		"Priority",
		"Source Ranges",
		"Allowed",
		"Targets",
		"Disabled",
		"Logging",
	}

	var rulesBody [][]string
	for _, rule := range m.FirewallRules {
		// Format source ranges - no truncation
		sources := strings.Join(rule.SourceRanges, ", ")
		if sources == "" {
			sources = "-"
		}

		// Format allowed protocols - no truncation
		allowed := formatProtocols(rule.AllowedProtocols)
		if allowed == "" {
			allowed = "-"
		}

		// Format targets - no truncation
		targets := "-"
		if len(rule.TargetTags) > 0 {
			targets = strings.Join(rule.TargetTags, ", ")
		} else if len(rule.TargetSAs) > 0 {
			targets = strings.Join(rule.TargetSAs, ", ")
		} else {
			targets = "ALL"
		}

		rulesBody = append(rulesBody, []string{
			m.GetProjectName(rule.ProjectID),
			rule.ProjectID,
			rule.Name,
			rule.Network,
			rule.Direction,
			fmt.Sprintf("%d", rule.Priority),
			sources,
			allowed,
			targets,
			boolToYesNo(rule.Disabled),
			boolToYesNo(rule.LoggingEnabled),
		})
	}

	// Networks table
	networksHeader := []string{
		"Project Name",
		"Project ID",
		"Network Name",
		"Routing Mode",
		"Subnets",
		"Peerings",
		"Auto Subnets",
	}

	var networksBody [][]string
	for _, network := range m.Networks {
		// Count subnets
		subnetCount := len(network.Subnetworks)

		// Format peerings - no truncation
		peerings := "-"
		if len(network.Peerings) > 0 {
			var peerNames []string
			for _, p := range network.Peerings {
				peerNames = append(peerNames, p.Name)
			}
			peerings = strings.Join(peerNames, ", ")
		}

		networksBody = append(networksBody, []string{
			m.GetProjectName(network.ProjectID),
			network.ProjectID,
			network.Name,
			network.RoutingMode,
			fmt.Sprintf("%d", subnetCount),
			peerings,
			boolToYesNo(network.AutoCreateSubnetworks),
		})
	}

	// Subnets table
	subnetsHeader := []string{
		"Project Name",
		"Project ID",
		"Network",
		"Subnet Name",
		"Region",
		"CIDR Range",
		"Private Google Access",
	}

	var subnetsBody [][]string
	for _, subnet := range m.Subnets {
		subnetsBody = append(subnetsBody, []string{
			m.GetProjectName(subnet.ProjectID),
			subnet.ProjectID,
			subnet.Network,
			subnet.Name,
			subnet.Region,
			subnet.IPCidrRange,
			boolToYesNo(subnet.PrivateIPGoogleAccess),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{}

	if len(rulesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FIREWALL_MODULE_NAME + "-rules",
			Header: rulesHeader,
			Body:   rulesBody,
		})
	}

	if len(networksBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FIREWALL_MODULE_NAME + "-networks",
			Header: networksHeader,
			Body:   networksBody,
		})
	}

	if len(subnetsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_FIREWALL_MODULE_NAME + "-subnets",
			Header: subnetsHeader,
			Body:   subnetsBody,
		})
	}

	output := FirewallOutput{
		Table: tableFiles,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_FIREWALL_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// formatProtocols formats allowed/denied protocols for display
func formatProtocols(protocols map[string][]string) string {
	var parts []string
	for proto, ports := range protocols {
		if len(ports) == 0 {
			parts = append(parts, proto+":all")
		} else {
			parts = append(parts, proto+":"+strings.Join(ports, ","))
		}
	}
	return strings.Join(parts, "; ")
}

