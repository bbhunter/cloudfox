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

	// Count security issues
	highRiskCount := 0
	publicIngressCount := 0
	for _, rule := range m.FirewallRules {
		if rule.RiskLevel == "HIGH" {
			highRiskCount++
		}
		if rule.IsPublicIngress {
			publicIngressCount++
		}
	}

	// Count peerings
	peeringCount := 0
	for _, network := range m.Networks {
		peeringCount += len(network.Peerings)
	}

	msg := fmt.Sprintf("Found %d network(s), %d subnet(s), %d firewall rule(s)",
		len(m.Networks), len(m.Subnets), len(m.FirewallRules))
	if highRiskCount > 0 {
		msg += fmt.Sprintf(" [%d HIGH RISK!]", highRiskCount)
	}
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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating networks in project %s: %v", projectID, err), globals.GCP_FIREWALL_MODULE_NAME)
		}
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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating subnets in project %s: %v", projectID, err), globals.GCP_FIREWALL_MODULE_NAME)
		}
	} else {
		m.mu.Lock()
		m.Subnets = append(m.Subnets, subnets...)
		m.mu.Unlock()
	}

	// Get firewall rules
	rules, err := ns.FirewallRulesEnhanced(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating firewall rules in project %s: %v", projectID, err), globals.GCP_FIREWALL_MODULE_NAME)
		}
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
	m.LootMap["firewall-gcloud-commands"] = &internal.LootFile{
		Name:     "firewall-gcloud-commands",
		Contents: "# Firewall gcloud Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["firewall-public-ingress"] = &internal.LootFile{
		Name:     "firewall-public-ingress",
		Contents: "# PUBLIC INGRESS Firewall Rules (0.0.0.0/0)\n# Generated by CloudFox\n# These rules allow access from the internet!\n\n",
	}
	m.LootMap["firewall-high-risk"] = &internal.LootFile{
		Name:     "firewall-high-risk",
		Contents: "# HIGH RISK Firewall Rules\n# Generated by CloudFox\n# These rules have serious security issues\n\n",
	}
	m.LootMap["firewall-vpc-peerings"] = &internal.LootFile{
		Name:     "firewall-vpc-peerings",
		Contents: "# VPC Peering Relationships\n# Generated by CloudFox\n# These networks are connected\n\n",
	}
	m.LootMap["firewall-exploitation"] = &internal.LootFile{
		Name:     "firewall-exploitation",
		Contents: "# Firewall Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["firewall-network-tags"] = &internal.LootFile{
		Name:     "firewall-network-tags",
		Contents: "# Firewall Rules by Network Tag\n# Generated by CloudFox\n# Network tags control which instances receive firewall rules\n\n",
	}
	m.LootMap["firewall-service-account-rules"] = &internal.LootFile{
		Name:     "firewall-service-account-rules",
		Contents: "# Firewall Rules by Service Account\n# Generated by CloudFox\n# These rules apply based on instance service account\n\n",
	}
	m.LootMap["firewall-all-instances-rules"] = &internal.LootFile{
		Name:     "firewall-all-instances-rules",
		Contents: "# Firewall Rules Applying to ALL Instances\n# Generated by CloudFox\n# These rules have no target tags or SAs - apply to everything!\n\n",
	}
	m.LootMap["firewall-disabled-rules"] = &internal.LootFile{
		Name:     "firewall-disabled-rules",
		Contents: "# DISABLED Firewall Rules\n# Generated by CloudFox\n# These rules are inactive but may be enabled later\n\n",
	}
	m.LootMap["firewall-security-recommendations"] = &internal.LootFile{
		Name:     "firewall-security-recommendations",
		Contents: "# Firewall Security Recommendations\n# Generated by CloudFox\n# Remediation commands for security issues\n\n",
	}
}

func (m *FirewallModule) addNetworkToLoot(network NetworkService.VPCInfo) {
	// gcloud commands
	m.LootMap["firewall-gcloud-commands"].Contents += fmt.Sprintf(
		"# Network: %s (Project: %s)\n"+
			"gcloud compute networks describe %s --project=%s\n"+
			"gcloud compute networks subnets list --network=%s --project=%s\n"+
			"gcloud compute firewall-rules list --filter=\"network:%s\" --project=%s\n\n",
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
		network.Name, network.ProjectID,
	)

	// VPC peerings
	if len(network.Peerings) > 0 {
		m.LootMap["firewall-vpc-peerings"].Contents += fmt.Sprintf(
			"# Network: %s (Project: %s)\n",
			network.Name, network.ProjectID,
		)
		for _, peering := range network.Peerings {
			m.LootMap["firewall-vpc-peerings"].Contents += fmt.Sprintf(
				"  Peering: %s\n"+
					"    -> Network: %s\n"+
					"    -> State: %s\n"+
					"    -> Export Routes: %v\n"+
					"    -> Import Routes: %v\n",
				peering.Name,
				peering.Network,
				peering.State,
				peering.ExportCustomRoutes,
				peering.ImportCustomRoutes,
			)
		}
		m.LootMap["firewall-vpc-peerings"].Contents += "\n"
	}
}

func (m *FirewallModule) addFirewallRuleToLoot(rule NetworkService.FirewallRuleInfo) {
	// gcloud commands
	m.LootMap["firewall-gcloud-commands"].Contents += fmt.Sprintf(
		"# Rule: %s (Project: %s, Network: %s)\n"+
			"gcloud compute firewall-rules describe %s --project=%s\n\n",
		rule.Name, rule.ProjectID, rule.Network,
		rule.Name, rule.ProjectID,
	)

	// Public ingress rules
	if rule.IsPublicIngress && rule.Direction == "INGRESS" {
		m.LootMap["firewall-public-ingress"].Contents += fmt.Sprintf(
			"# RULE: %s\n"+
				"# Project: %s, Network: %s\n"+
				"# Priority: %d, Disabled: %v\n"+
				"# Source Ranges: %s\n"+
				"# Allowed: %s\n"+
				"# Target Tags: %s\n"+
				"# Target SAs: %s\n",
			rule.Name,
			rule.ProjectID, rule.Network,
			rule.Priority, rule.Disabled,
			strings.Join(rule.SourceRanges, ", "),
			formatProtocols(rule.AllowedProtocols),
			strings.Join(rule.TargetTags, ", "),
			strings.Join(rule.TargetSAs, ", "),
		)
		if len(rule.SecurityIssues) > 0 {
			m.LootMap["firewall-public-ingress"].Contents += "# Issues:\n"
			for _, issue := range rule.SecurityIssues {
				m.LootMap["firewall-public-ingress"].Contents += fmt.Sprintf("#   - %s\n", issue)
			}
		}
		m.LootMap["firewall-public-ingress"].Contents += "\n"
	}

	// High risk rules
	if rule.RiskLevel == "HIGH" {
		m.LootMap["firewall-high-risk"].Contents += fmt.Sprintf(
			"# RULE: %s [HIGH RISK]\n"+
				"# Project: %s, Network: %s\n"+
				"# Direction: %s\n"+
				"# Source Ranges: %s\n"+
				"# Allowed: %s\n"+
				"# Issues:\n",
			rule.Name,
			rule.ProjectID, rule.Network,
			rule.Direction,
			strings.Join(rule.SourceRanges, ", "),
			formatProtocols(rule.AllowedProtocols),
		)
		for _, issue := range rule.SecurityIssues {
			m.LootMap["firewall-high-risk"].Contents += fmt.Sprintf("#   - %s\n", issue)
		}
		m.LootMap["firewall-high-risk"].Contents += fmt.Sprintf(
			"# Remediation:\n"+
				"gcloud compute firewall-rules update %s --source-ranges=\"10.0.0.0/8\" --project=%s\n"+
				"# Or delete if not needed:\n"+
				"gcloud compute firewall-rules delete %s --project=%s\n\n",
			rule.Name, rule.ProjectID,
			rule.Name, rule.ProjectID,
		)
	}

	// Exploitation commands for high/medium risk
	if rule.RiskLevel == "HIGH" || rule.RiskLevel == "MEDIUM" {
		m.LootMap["firewall-exploitation"].Contents += fmt.Sprintf(
			"# Rule: %s (Project: %s) [%s RISK]\n"+
				"# Network: %s\n"+
				"# Source Ranges: %s\n"+
				"# Allowed: %s\n\n",
			rule.Name, rule.ProjectID, rule.RiskLevel,
			rule.Network,
			strings.Join(rule.SourceRanges, ", "),
			formatProtocols(rule.AllowedProtocols),
		)

		// Add specific exploitation suggestions based on allowed ports
		for proto, ports := range rule.AllowedProtocols {
			if proto == "tcp" || proto == "all" {
				for _, port := range ports {
					switch port {
					case "22":
						m.LootMap["firewall-exploitation"].Contents += "# SSH brute force / key-based auth:\n# nmap -p 22 --script ssh-brute <TARGET_IP>\n\n"
					case "3389":
						m.LootMap["firewall-exploitation"].Contents += "# RDP enumeration:\n# nmap -p 3389 --script rdp-enum-encryption <TARGET_IP>\n\n"
					case "3306":
						m.LootMap["firewall-exploitation"].Contents += "# MySQL enumeration:\n# nmap -p 3306 --script mysql-info <TARGET_IP>\n\n"
					case "5432":
						m.LootMap["firewall-exploitation"].Contents += "# PostgreSQL enumeration:\n# nmap -p 5432 --script pgsql-brute <TARGET_IP>\n\n"
					}
				}
				if len(ports) == 0 {
					m.LootMap["firewall-exploitation"].Contents += "# All TCP ports allowed - full port scan:\n# nmap -p- <TARGET_IP>\n\n"
				}
			}
		}
	}

	// Rules with network tags
	if len(rule.TargetTags) > 0 {
		m.LootMap["firewall-network-tags"].Contents += fmt.Sprintf(
			"# RULE: %s (Project: %s, Network: %s)\n"+
				"# Direction: %s, Priority: %d\n"+
				"# Target Tags: %s\n"+
				"# Allowed: %s\n"+
				"# Find instances with these tags:\n"+
				"gcloud compute instances list --filter=\"tags.items=%s\" --project=%s\n\n",
			rule.Name, rule.ProjectID, rule.Network,
			rule.Direction, rule.Priority,
			strings.Join(rule.TargetTags, ", "),
			formatProtocols(rule.AllowedProtocols),
			rule.TargetTags[0], rule.ProjectID,
		)
	}

	// Rules with service accounts
	if len(rule.TargetSAs) > 0 {
		m.LootMap["firewall-service-account-rules"].Contents += fmt.Sprintf(
			"# RULE: %s (Project: %s, Network: %s)\n"+
				"# Direction: %s, Priority: %d\n"+
				"# Target Service Accounts:\n",
			rule.Name, rule.ProjectID, rule.Network,
			rule.Direction, rule.Priority,
		)
		for _, sa := range rule.TargetSAs {
			m.LootMap["firewall-service-account-rules"].Contents += fmt.Sprintf("#   - %s\n", sa)
		}
		m.LootMap["firewall-service-account-rules"].Contents += fmt.Sprintf(
			"# Allowed: %s\n"+
				"# Find instances with these SAs:\n"+
				"gcloud compute instances list --filter=\"serviceAccounts.email=%s\" --project=%s\n\n",
			formatProtocols(rule.AllowedProtocols),
			rule.TargetSAs[0], rule.ProjectID,
		)
	}

	// Rules applying to all instances (no tags or SAs)
	if len(rule.TargetTags) == 0 && len(rule.TargetSAs) == 0 {
		m.LootMap["firewall-all-instances-rules"].Contents += fmt.Sprintf(
			"# RULE: %s (Project: %s, Network: %s)\n"+
				"# Direction: %s, Priority: %d\n"+
				"# Source Ranges: %s\n"+
				"# Allowed: %s\n"+
				"# WARNING: Applies to ALL instances in the network!\n\n",
			rule.Name, rule.ProjectID, rule.Network,
			rule.Direction, rule.Priority,
			strings.Join(rule.SourceRanges, ", "),
			formatProtocols(rule.AllowedProtocols),
		)
	}

	// Disabled rules
	if rule.Disabled {
		m.LootMap["firewall-disabled-rules"].Contents += fmt.Sprintf(
			"# RULE: %s (Project: %s, Network: %s)\n"+
				"# Direction: %s, Priority: %d\n"+
				"# Source Ranges: %s\n"+
				"# Allowed: %s\n"+
				"# Enable with:\n"+
				"gcloud compute firewall-rules update %s --no-disabled --project=%s\n\n",
			rule.Name, rule.ProjectID, rule.Network,
			rule.Direction, rule.Priority,
			strings.Join(rule.SourceRanges, ", "),
			formatProtocols(rule.AllowedProtocols),
			rule.Name, rule.ProjectID,
		)
	}

	// Security recommendations
	m.addFirewallSecurityRecommendations(rule)
}

// addFirewallSecurityRecommendations adds remediation commands for firewall security issues
func (m *FirewallModule) addFirewallSecurityRecommendations(rule NetworkService.FirewallRuleInfo) {
	hasRecommendations := false
	recommendations := fmt.Sprintf(
		"# RULE: %s (Project: %s, Network: %s)\n",
		rule.Name, rule.ProjectID, rule.Network,
	)

	// Public ingress
	if rule.IsPublicIngress && rule.Direction == "INGRESS" {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Allows ingress from 0.0.0.0/0 (internet)\n"+
				"# Restrict source ranges:\n"+
				"gcloud compute firewall-rules update %s \\\n"+
				"  --source-ranges=\"10.0.0.0/8\" \\\n"+
				"  --project=%s\n\n",
			rule.Name, rule.ProjectID,
		)
	}

	// All ports allowed
	for proto, ports := range rule.AllowedProtocols {
		if len(ports) == 0 && (proto == "all" || proto == "tcp" || proto == "udp") {
			hasRecommendations = true
			recommendations += fmt.Sprintf(
				"# Issue: Allows all %s ports\n"+
					"# Restrict to specific ports:\n"+
					"gcloud compute firewall-rules update %s \\\n"+
					"  --allow=\"tcp:80,tcp:443\" \\\n"+
					"  --project=%s\n\n",
				proto, rule.Name, rule.ProjectID,
			)
		}
	}

	// No target restriction
	if len(rule.TargetTags) == 0 && len(rule.TargetSAs) == 0 && rule.IsPublicIngress {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Applies to ALL instances with public ingress\n"+
				"# Add target tags or SAs to limit scope:\n"+
				"gcloud compute firewall-rules update %s \\\n"+
				"  --target-tags=\"web-server\" \\\n"+
				"  --project=%s\n\n",
			rule.Name, rule.ProjectID,
		)
	}

	if hasRecommendations {
		m.LootMap["firewall-security-recommendations"].Contents += recommendations + "\n"
	}
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
		"Risk",
		"Issues",
	}

	var rulesBody [][]string
	for _, rule := range m.FirewallRules {
		// Format source ranges
		sources := strings.Join(rule.SourceRanges, ", ")
		if len(sources) > 30 {
			sources = sources[:27] + "..."
		}

		// Format allowed protocols
		allowed := formatProtocolsShort(rule.AllowedProtocols)

		// Format targets
		targets := "-"
		if len(rule.TargetTags) > 0 {
			targets = strings.Join(rule.TargetTags, ",")
		} else if len(rule.TargetSAs) > 0 {
			targets = "SAs:" + fmt.Sprintf("%d", len(rule.TargetSAs))
		} else {
			targets = "ALL"
		}
		if len(targets) > 20 {
			targets = targets[:17] + "..."
		}

		// Format issues count
		issues := "-"
		if len(rule.SecurityIssues) > 0 {
			issues = fmt.Sprintf("%d issue(s)", len(rule.SecurityIssues))
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
			rule.RiskLevel,
			issues,
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

		// Format peerings
		peerings := "-"
		if len(network.Peerings) > 0 {
			var peerNames []string
			for _, p := range network.Peerings {
				peerNames = append(peerNames, p.Name)
			}
			peerings = strings.Join(peerNames, ", ")
			if len(peerings) > 30 {
				peerings = fmt.Sprintf("%d peering(s)", len(network.Peerings))
			}
		}

		// Format auto subnets
		autoSubnets := "No"
		if network.AutoCreateSubnetworks {
			autoSubnets = "Yes"
		}

		networksBody = append(networksBody, []string{
			m.GetProjectName(network.ProjectID),
			network.ProjectID,
			network.Name,
			network.RoutingMode,
			fmt.Sprintf("%d", subnetCount),
			peerings,
			autoSubnets,
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
		privateAccess := "No"
		if subnet.PrivateIPGoogleAccess {
			privateAccess = "Yes"
		}

		subnetsBody = append(subnetsBody, []string{
			m.GetProjectName(subnet.ProjectID),
			subnet.ProjectID,
			subnet.Network,
			subnet.Name,
			subnet.Region,
			subnet.IPCidrRange,
			privateAccess,
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

// formatProtocolsShort formats protocols for table display
func formatProtocolsShort(protocols map[string][]string) string {
	var parts []string
	for proto, ports := range protocols {
		if len(ports) == 0 {
			parts = append(parts, proto+":*")
		} else if len(ports) > 3 {
			parts = append(parts, fmt.Sprintf("%s:%d ports", proto, len(ports)))
		} else {
			parts = append(parts, proto+":"+strings.Join(ports, ","))
		}
	}
	result := strings.Join(parts, " ")
	if len(result) > 25 {
		return result[:22] + "..."
	}
	return result
}
