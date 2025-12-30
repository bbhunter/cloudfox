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

	compute "google.golang.org/api/compute/v1"
	run "google.golang.org/api/run/v1"
)

// Module name constant
const GCP_NETWORKEXPOSURE_MODULE_NAME string = "network-exposure"

var GCPNetworkExposureCommand = &cobra.Command{
	Use:     GCP_NETWORKEXPOSURE_MODULE_NAME,
	Aliases: []string{"exposure", "public", "internet-facing"},
	Short:   "Comprehensive view of all internet-exposed resources with risk scoring",
	Long: `Enumerate all internet-facing resources in GCP with risk-based analysis.

Features:
- Aggregates all public endpoints (Compute, Load Balancers, Cloud Run, Functions)
- Analyzes firewall rules for exposed ports
- Identifies exposed management ports (SSH, RDP, databases)
- Checks TLS/SSL configuration
- Risk-based prioritization
- Maps attack surface across projects
- Generates exploitation commands for penetration testing

This module combines data from multiple sources to provide a complete picture
of the internet-facing attack surface.`,
	Run: runGCPNetworkExposureCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type ExposedResource struct {
	ResourceType   string // "compute_instance", "load_balancer", "cloud_run", "cloud_function", etc.
	ResourceName   string
	ProjectID      string
	ExternalIP     string
	FQDN           string
	ExposedPorts   []string
	Protocol       string
	ServiceAccount string
	TLSEnabled     bool
	TLSVersion     string
	RiskLevel      string // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons    []string
	ExploitCommand string
}

type FirewallExposure struct {
	RuleName      string
	ProjectID     string
	Network       string
	Direction     string
	Action        string
	SourceRanges  []string
	Ports         []string
	Protocol      string
	TargetTags    []string
	IsPublic      bool // 0.0.0.0/0
	RiskLevel     string
	RiskReasons   []string
}

type ExposureSummary struct {
	ResourceType string
	Count        int
	CriticalCount int
	HighCount     int
}

// ------------------------------
// Module Struct
// ------------------------------
type NetworkExposureModule struct {
	gcpinternal.BaseGCPModule

	ExposedResources  []ExposedResource
	FirewallExposures []FirewallExposure
	Summaries         []ExposureSummary
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type NetworkExposureOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkExposureOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkExposureOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPNetworkExposureCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_NETWORKEXPOSURE_MODULE_NAME)
	if err != nil {
		return
	}

	module := &NetworkExposureModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ExposedResources:  []ExposedResource{},
		FirewallExposures: []FirewallExposure{},
		Summaries:         []ExposureSummary{},
		LootMap:           make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *NetworkExposureModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Mapping network exposure across all resources...", GCP_NETWORKEXPOSURE_MODULE_NAME)

	// Process each project
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_NETWORKEXPOSURE_MODULE_NAME, m.processProject)

	// Check results
	if len(m.ExposedResources) == 0 && len(m.FirewallExposures) == 0 {
		logger.InfoM("No exposed resources found", GCP_NETWORKEXPOSURE_MODULE_NAME)
		return
	}

	// Generate summaries
	m.generateSummaries()

	// Count by risk level
	criticalCount := 0
	highCount := 0
	for _, r := range m.ExposedResources {
		switch r.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d exposed resource(s) and %d firewall exposure(s): %d CRITICAL, %d HIGH",
		len(m.ExposedResources), len(m.FirewallExposures), criticalCount, highCount), GCP_NETWORKEXPOSURE_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *NetworkExposureModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing network exposure in project: %s", projectID), GCP_NETWORKEXPOSURE_MODULE_NAME)
	}

	// 1. Find exposed compute instances
	m.findExposedInstances(ctx, projectID, logger)

	// 2. Find exposed load balancers
	m.findExposedLoadBalancers(ctx, projectID, logger)

	// 3. Find exposed Cloud Run services
	m.findExposedCloudRun(ctx, projectID, logger)

	// 4. Analyze firewall rules for public exposure
	m.analyzeFirewallExposure(ctx, projectID, logger)
}

// findExposedInstances finds compute instances with external IPs
func (m *NetworkExposureModule) findExposedInstances(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error creating Compute service: %v", err), GCP_NETWORKEXPOSURE_MODULE_NAME)
		}
		return
	}

	// List all instances across zones
	req := computeService.Instances.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, scopedList := range page.Items {
			if scopedList.Instances == nil {
				continue
			}
			for _, instance := range scopedList.Instances {
				// Check for external IP
				for _, ni := range instance.NetworkInterfaces {
					for _, ac := range ni.AccessConfigs {
						if ac.NatIP != "" {
							exposed := ExposedResource{
								ResourceType: "compute_instance",
								ResourceName: instance.Name,
								ProjectID:    projectID,
								ExternalIP:   ac.NatIP,
								Protocol:     "TCP/UDP",
							}

							// Get service account
							if len(instance.ServiceAccounts) > 0 {
								exposed.ServiceAccount = instance.ServiceAccounts[0].Email
							}

							// Determine risk level
							exposed.RiskLevel, exposed.RiskReasons = m.classifyInstanceRisk(instance)

							// Generate exploit command
							exposed.ExploitCommand = fmt.Sprintf("nmap -Pn -p- %s", ac.NatIP)

							m.mu.Lock()
							m.ExposedResources = append(m.ExposedResources, exposed)
							m.addExposedResourceToLoot(exposed)
							m.mu.Unlock()
						}
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing instances: %v", err), GCP_NETWORKEXPOSURE_MODULE_NAME)
		}
	}
}

// findExposedLoadBalancers finds load balancers with external IPs
func (m *NetworkExposureModule) findExposedLoadBalancers(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return
	}

	// List global forwarding rules (external load balancers)
	req := computeService.GlobalForwardingRules.List(projectID)
	err = req.Pages(ctx, func(page *compute.ForwardingRuleList) error {
		for _, rule := range page.Items {
			if rule.IPAddress != "" {
				exposed := ExposedResource{
					ResourceType:   "load_balancer",
					ResourceName:   rule.Name,
					ProjectID:      projectID,
					ExternalIP:     rule.IPAddress,
					ExposedPorts:   []string{rule.PortRange},
					Protocol:       rule.IPProtocol,
					TLSEnabled:     strings.ToLower(rule.IPProtocol) == "https" || rule.PortRange == "443",
				}

				// Determine risk level
				exposed.RiskLevel = "MEDIUM"
				exposed.RiskReasons = []string{"External load balancer"}

				if !exposed.TLSEnabled && rule.PortRange != "80" {
					exposed.RiskLevel = "HIGH"
					exposed.RiskReasons = append(exposed.RiskReasons, "No TLS/HTTPS")
				}

				exposed.ExploitCommand = fmt.Sprintf("curl -v http://%s", rule.IPAddress)

				m.mu.Lock()
				m.ExposedResources = append(m.ExposedResources, exposed)
				m.addExposedResourceToLoot(exposed)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil && globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Error listing forwarding rules: %v", err), GCP_NETWORKEXPOSURE_MODULE_NAME)
	}
}

// findExposedCloudRun finds Cloud Run services with public access
func (m *NetworkExposureModule) findExposedCloudRun(ctx context.Context, projectID string, logger internal.Logger) {
	runService, err := run.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error creating Cloud Run service: %v", err), GCP_NETWORKEXPOSURE_MODULE_NAME)
		}
		return
	}

	// List Cloud Run services
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := runService.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing Cloud Run services: %v", err), GCP_NETWORKEXPOSURE_MODULE_NAME)
		}
		return
	}

	for _, service := range resp.Items {
		// Check if service is publicly accessible
		isPublic := false
		if service.Spec != nil && service.Spec.Template != nil {
			// Check IAM policy or ingress settings
			// For simplicity, we check if the service has a URL
			if service.Status != nil && service.Status.Url != "" {
				isPublic = true
			}
		}

		if isPublic && service.Status != nil && service.Status.Url != "" {
			exposed := ExposedResource{
				ResourceType: "cloud_run",
				ResourceName: service.Metadata.Name,
				ProjectID:    projectID,
				FQDN:         service.Status.Url,
				ExposedPorts: []string{"443"},
				Protocol:     "HTTPS",
				TLSEnabled:   true,
			}

			// Get service account
			if service.Spec != nil && service.Spec.Template != nil && service.Spec.Template.Spec != nil {
				exposed.ServiceAccount = service.Spec.Template.Spec.ServiceAccountName
			}

			// Determine risk level
			exposed.RiskLevel = "MEDIUM"
			exposed.RiskReasons = []string{"Public Cloud Run service"}

			// Check for allUsers invoker
			// This would require checking IAM policy
			exposed.ExploitCommand = fmt.Sprintf("curl -v %s", service.Status.Url)

			m.mu.Lock()
			m.ExposedResources = append(m.ExposedResources, exposed)
			m.addExposedResourceToLoot(exposed)
			m.mu.Unlock()
		}
	}
}

// analyzeFirewallExposure analyzes firewall rules for public exposure
func (m *NetworkExposureModule) analyzeFirewallExposure(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return
	}

	req := computeService.Firewalls.List(projectID)
	err = req.Pages(ctx, func(page *compute.FirewallList) error {
		for _, fw := range page.Items {
			// Check if rule allows ingress from 0.0.0.0/0
			isPublic := false
			for _, sr := range fw.SourceRanges {
				if sr == "0.0.0.0/0" {
					isPublic = true
					break
				}
			}

			if isPublic && fw.Direction == "INGRESS" {
				exposure := FirewallExposure{
					RuleName:     fw.Name,
					ProjectID:    projectID,
					Network:      fw.Network,
					Direction:    fw.Direction,
					SourceRanges: fw.SourceRanges,
					TargetTags:   fw.TargetTags,
					IsPublic:     true,
				}

				// Get allowed ports
				for _, allowed := range fw.Allowed {
					exposure.Protocol = allowed.IPProtocol
					for _, port := range allowed.Ports {
						exposure.Ports = append(exposure.Ports, port)
					}
				}

				// Determine risk level
				exposure.RiskLevel, exposure.RiskReasons = m.classifyFirewallRisk(exposure)

				m.mu.Lock()
				m.FirewallExposures = append(m.FirewallExposures, exposure)
				m.addFirewallExposureToLoot(exposure)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil && globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Error listing firewall rules: %v", err), GCP_NETWORKEXPOSURE_MODULE_NAME)
	}
}

// classifyInstanceRisk determines the risk level of an exposed instance
func (m *NetworkExposureModule) classifyInstanceRisk(instance *compute.Instance) (string, []string) {
	var reasons []string
	score := 0

	// Check for default service account
	for _, sa := range instance.ServiceAccounts {
		if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") {
			reasons = append(reasons, "Uses default Compute Engine SA")
			score += 2
		}

		// Check for broad scopes
		for _, scope := range sa.Scopes {
			if scope == "https://www.googleapis.com/auth/cloud-platform" {
				reasons = append(reasons, "Has cloud-platform scope (full access)")
				score += 3
			}
		}
	}

	// External IP is always a risk
	reasons = append(reasons, "Has external IP")
	score += 1

	if score >= 4 {
		return "CRITICAL", reasons
	} else if score >= 2 {
		return "HIGH", reasons
	}
	return "MEDIUM", reasons
}

// classifyFirewallRisk determines the risk level of a firewall exposure
func (m *NetworkExposureModule) classifyFirewallRisk(exposure FirewallExposure) (string, []string) {
	var reasons []string
	score := 0

	// Check for dangerous ports
	dangerousPorts := map[string]string{
		"22":    "SSH",
		"3389":  "RDP",
		"3306":  "MySQL",
		"5432":  "PostgreSQL",
		"27017": "MongoDB",
		"6379":  "Redis",
		"9200":  "Elasticsearch",
		"8080":  "HTTP Alt",
	}

	for _, port := range exposure.Ports {
		if name, ok := dangerousPorts[port]; ok {
			reasons = append(reasons, fmt.Sprintf("Exposes %s (port %s)", name, port))
			score += 3
		}
	}

	// Check for wide port ranges
	for _, port := range exposure.Ports {
		if strings.Contains(port, "-") {
			reasons = append(reasons, fmt.Sprintf("Wide port range: %s", port))
			score += 2
		}
	}

	// Check for no target tags (applies to all instances)
	if len(exposure.TargetTags) == 0 {
		reasons = append(reasons, "No target tags (applies to all instances)")
		score += 2
	}

	// 0.0.0.0/0 is always a risk
	reasons = append(reasons, "Allows traffic from 0.0.0.0/0")
	score += 1

	if score >= 5 {
		return "CRITICAL", reasons
	} else if score >= 3 {
		return "HIGH", reasons
	}
	return "MEDIUM", reasons
}

// generateSummaries creates exposure summaries by resource type
func (m *NetworkExposureModule) generateSummaries() {
	typeCount := make(map[string]*ExposureSummary)

	for _, r := range m.ExposedResources {
		if _, exists := typeCount[r.ResourceType]; !exists {
			typeCount[r.ResourceType] = &ExposureSummary{
				ResourceType: r.ResourceType,
			}
		}
		typeCount[r.ResourceType].Count++
		if r.RiskLevel == "CRITICAL" {
			typeCount[r.ResourceType].CriticalCount++
		} else if r.RiskLevel == "HIGH" {
			typeCount[r.ResourceType].HighCount++
		}
	}

	for _, summary := range typeCount {
		m.Summaries = append(m.Summaries, *summary)
	}

	// Sort by count
	sort.Slice(m.Summaries, func(i, j int) bool {
		return m.Summaries[i].Count > m.Summaries[j].Count
	})
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *NetworkExposureModule) initializeLootFiles() {
	m.LootMap["exposure-critical"] = &internal.LootFile{
		Name:     "exposure-critical",
		Contents: "# Critical Network Exposures\n# Generated by CloudFox\n# These require immediate attention!\n\n",
	}
	m.LootMap["exposure-management-ports"] = &internal.LootFile{
		Name:     "exposure-management-ports",
		Contents: "# Exposed Management Ports\n# Generated by CloudFox\n# SSH, RDP, Database ports exposed to internet\n\n",
	}
	m.LootMap["exposure-scan-targets"] = &internal.LootFile{
		Name:     "exposure-scan-targets",
		Contents: "# Scan Targets\n# Generated by CloudFox\n# Use for authorized penetration testing\n\n",
	}
	m.LootMap["exposure-remediation"] = &internal.LootFile{
		Name:     "exposure-remediation",
		Contents: "# Remediation Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *NetworkExposureModule) addExposedResourceToLoot(resource ExposedResource) {
	// Critical exposures
	if resource.RiskLevel == "CRITICAL" {
		m.LootMap["exposure-critical"].Contents += fmt.Sprintf(
			"## %s: %s\n"+
				"Project: %s\n"+
				"IP/FQDN: %s%s\n"+
				"Risk Reasons:\n",
			resource.ResourceType,
			resource.ResourceName,
			resource.ProjectID,
			resource.ExternalIP,
			resource.FQDN,
		)
		for _, reason := range resource.RiskReasons {
			m.LootMap["exposure-critical"].Contents += fmt.Sprintf("  - %s\n", reason)
		}
		m.LootMap["exposure-critical"].Contents += fmt.Sprintf("Exploit: %s\n\n", resource.ExploitCommand)
	}

	// Scan targets
	target := resource.ExternalIP
	if target == "" {
		target = resource.FQDN
	}
	if target != "" {
		m.LootMap["exposure-scan-targets"].Contents += fmt.Sprintf(
			"%s # %s (%s)\n",
			target,
			resource.ResourceName,
			resource.ResourceType,
		)
	}
}

func (m *NetworkExposureModule) addFirewallExposureToLoot(exposure FirewallExposure) {
	// Management ports
	dangerousPorts := []string{"22", "3389", "3306", "5432", "27017", "6379"}
	for _, port := range exposure.Ports {
		for _, dp := range dangerousPorts {
			if port == dp || strings.HasPrefix(port, dp+"-") {
				m.LootMap["exposure-management-ports"].Contents += fmt.Sprintf(
					"## Firewall Rule: %s\n"+
						"Project: %s\n"+
						"Port: %s\n"+
						"Source: %s\n"+
						"Risk: %s\n\n",
					exposure.RuleName,
					exposure.ProjectID,
					port,
					strings.Join(exposure.SourceRanges, ", "),
					exposure.RiskLevel,
				)
				break
			}
		}
	}

	// Remediation
	if exposure.RiskLevel == "CRITICAL" || exposure.RiskLevel == "HIGH" {
		m.LootMap["exposure-remediation"].Contents += fmt.Sprintf(
			"# Fix firewall rule: %s\n"+
				"gcloud compute firewall-rules update %s --source-ranges=<restricted_range> --project=%s\n"+
				"# Or delete if unnecessary:\n"+
				"# gcloud compute firewall-rules delete %s --project=%s\n\n",
			exposure.RuleName,
			exposure.RuleName,
			exposure.ProjectID,
			exposure.RuleName,
			exposure.ProjectID,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *NetworkExposureModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort resources by risk level
	sort.Slice(m.ExposedResources, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
		return riskOrder[m.ExposedResources[i].RiskLevel] > riskOrder[m.ExposedResources[j].RiskLevel]
	})

	// Exposed resources table
	resourcesHeader := []string{
		"Type",
		"Name",
		"Project Name",
		"Project ID",
		"IP/FQDN",
		"Ports",
		"TLS",
		"Risk",
	}

	var resourcesBody [][]string
	for _, r := range m.ExposedResources {
		endpoint := r.ExternalIP
		if endpoint == "" {
			endpoint = r.FQDN
		}
		tls := "No"
		if r.TLSEnabled {
			tls = "Yes"
		}
		resourcesBody = append(resourcesBody, []string{
			r.ResourceType,
			r.ResourceName,
			m.GetProjectName(r.ProjectID),
			r.ProjectID,
			truncateString(endpoint, 40),
			strings.Join(r.ExposedPorts, ","),
			tls,
			r.RiskLevel,
		})
	}

	// Firewall exposures table
	firewallHeader := []string{
		"Rule",
		"Project Name",
		"Project ID",
		"Ports",
		"Protocol",
		"Target Tags",
		"Risk",
	}

	var firewallBody [][]string
	for _, f := range m.FirewallExposures {
		firewallBody = append(firewallBody, []string{
			f.RuleName,
			m.GetProjectName(f.ProjectID),
			f.ProjectID,
			strings.Join(f.Ports, ","),
			f.Protocol,
			strings.Join(f.TargetTags, ","),
			f.RiskLevel,
		})
	}

	// Summary table
	summaryHeader := []string{
		"Resource Type",
		"Total",
		"Critical",
		"High",
	}

	var summaryBody [][]string
	for _, s := range m.Summaries {
		summaryBody = append(summaryBody, []string{
			s.ResourceType,
			fmt.Sprintf("%d", s.Count),
			fmt.Sprintf("%d", s.CriticalCount),
			fmt.Sprintf("%d", s.HighCount),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	tables := []internal.TableFile{}

	if len(resourcesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "exposure-resources",
			Header: resourcesHeader,
			Body:   resourcesBody,
		})
	}

	if len(firewallBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "exposure-firewall",
			Header: firewallHeader,
			Body:   firewallBody,
		})
	}

	if len(summaryBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "exposure-summary",
			Header: summaryHeader,
			Body:   summaryBody,
		})
	}

	output := NetworkExposureOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scopeNames using GetProjectName
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_NETWORKEXPOSURE_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
