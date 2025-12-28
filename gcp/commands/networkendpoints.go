package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	networkendpointsservice "github.com/BishopFox/cloudfox/gcp/services/networkEndpointsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPNetworkEndpointsCommand = &cobra.Command{
	Use:     globals.GCP_NETWORKENDPOINTS_MODULE_NAME,
	Aliases: []string{"psc", "private-service-connect", "endpoints"},
	Short:   "Enumerate Private Service Connect endpoints and service attachments",
	Long: `Enumerate Private Service Connect (PSC) endpoints, private connections, and service attachments.

Private Service Connect allows private connectivity to Google APIs and services,
as well as to services hosted by other organizations.

Security Relevance:
- PSC endpoints provide internal network paths to external services
- Service attachments expose internal services to other projects
- Private connections (VPC peering for managed services) provide access to Cloud SQL, etc.
- These can be used for lateral movement or data exfiltration

What this module finds:
- PSC forwarding rules (consumer endpoints)
- Service attachments (producer endpoints)
- Private service connections (e.g., to Cloud SQL private IPs)
- Connection acceptance policies (auto vs manual)`,
	Run: runGCPNetworkEndpointsCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type NetworkEndpointsModule struct {
	gcpinternal.BaseGCPModule

	PSCEndpoints       []networkendpointsservice.PrivateServiceConnectEndpoint
	PrivateConnections []networkendpointsservice.PrivateConnection
	ServiceAttachments []networkendpointsservice.ServiceAttachment
	LootMap            map[string]*internal.LootFile
	mu                 sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type NetworkEndpointsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o NetworkEndpointsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o NetworkEndpointsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPNetworkEndpointsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &NetworkEndpointsModule{
		BaseGCPModule:      gcpinternal.NewBaseGCPModule(cmdCtx),
		PSCEndpoints:       []networkendpointsservice.PrivateServiceConnectEndpoint{},
		PrivateConnections: []networkendpointsservice.PrivateConnection{},
		ServiceAttachments: []networkendpointsservice.ServiceAttachment{},
		LootMap:            make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *NetworkEndpointsModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_NETWORKENDPOINTS_MODULE_NAME, m.processProject)

	totalFindings := len(m.PSCEndpoints) + len(m.PrivateConnections) + len(m.ServiceAttachments)

	if totalFindings == 0 {
		logger.InfoM("No network endpoints found", globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d PSC endpoint(s), %d private connection(s), %d service attachment(s)",
		len(m.PSCEndpoints), len(m.PrivateConnections), len(m.ServiceAttachments)), globals.GCP_NETWORKENDPOINTS_MODULE_NAME)

	// Count high-risk findings
	autoAcceptCount := 0
	for _, sa := range m.ServiceAttachments {
		if sa.ConnectionPreference == "ACCEPT_AUTOMATIC" {
			autoAcceptCount++
		}
	}
	if autoAcceptCount > 0 {
		logger.InfoM(fmt.Sprintf("[HIGH] %d service attachment(s) auto-accept connections from any project", autoAcceptCount), globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *NetworkEndpointsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking network endpoints in project: %s", projectID), globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
	}

	svc := networkendpointsservice.New()

	// Get PSC endpoints
	pscEndpoints, err := svc.GetPrivateServiceConnectEndpoints(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting PSC endpoints for %s: %v", projectID, err), globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
		}
	}

	// Get private connections
	privateConns, err := svc.GetPrivateConnections(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting private connections for %s: %v", projectID, err), globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
		}
	}

	// Get service attachments
	attachments, err := svc.GetServiceAttachments(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting service attachments for %s: %v", projectID, err), globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
		}
	}

	m.mu.Lock()
	m.PSCEndpoints = append(m.PSCEndpoints, pscEndpoints...)
	m.PrivateConnections = append(m.PrivateConnections, privateConns...)
	m.ServiceAttachments = append(m.ServiceAttachments, attachments...)

	for _, endpoint := range pscEndpoints {
		m.addPSCEndpointToLoot(endpoint)
	}
	for _, conn := range privateConns {
		m.addPrivateConnectionToLoot(conn)
	}
	for _, attachment := range attachments {
		m.addServiceAttachmentToLoot(attachment)
	}
	m.mu.Unlock()
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *NetworkEndpointsModule) initializeLootFiles() {
	m.LootMap["psc-endpoints"] = &internal.LootFile{
		Name:     "psc-endpoints",
		Contents: "# Private Service Connect Endpoints\n# Generated by CloudFox\n\n",
	}
	m.LootMap["private-connections"] = &internal.LootFile{
		Name:     "private-connections",
		Contents: "# Private Service Connections (VPC Peering for Managed Services)\n# Generated by CloudFox\n\n",
	}
	m.LootMap["service-attachments"] = &internal.LootFile{
		Name:     "service-attachments",
		Contents: "# PSC Service Attachments (Producer Side)\n# Generated by CloudFox\n\n",
	}
	m.LootMap["auto-accept-attachments"] = &internal.LootFile{
		Name:     "auto-accept-attachments",
		Contents: "# HIGH RISK: Service Attachments with Auto-Accept\n# Generated by CloudFox\n# These accept connections from ANY project!\n\n",
	}
}

func (m *NetworkEndpointsModule) addPSCEndpointToLoot(endpoint networkendpointsservice.PrivateServiceConnectEndpoint) {
	m.LootMap["psc-endpoints"].Contents += fmt.Sprintf(
		"## [%s] %s\n"+
			"## Project: %s | Region: %s\n"+
			"## Network: %s | Subnet: %s\n"+
			"## IP Address: %s\n"+
			"## Target Type: %s\n"+
			"## Target: %s\n"+
			"## Connection State: %s\n",
		endpoint.RiskLevel, endpoint.Name,
		endpoint.ProjectID, endpoint.Region,
		endpoint.Network, endpoint.Subnetwork,
		endpoint.IPAddress,
		endpoint.TargetType,
		endpoint.Target,
		endpoint.ConnectionState,
	)
	for _, reason := range endpoint.RiskReasons {
		m.LootMap["psc-endpoints"].Contents += fmt.Sprintf("##   - %s\n", reason)
	}
	for _, cmd := range endpoint.ExploitCommands {
		m.LootMap["psc-endpoints"].Contents += cmd + "\n"
	}
	m.LootMap["psc-endpoints"].Contents += "\n"
}

func (m *NetworkEndpointsModule) addPrivateConnectionToLoot(conn networkendpointsservice.PrivateConnection) {
	m.LootMap["private-connections"].Contents += fmt.Sprintf(
		"## [%s] %s\n"+
			"## Project: %s | Network: %s\n"+
			"## Service: %s\n"+
			"## Peering: %s\n"+
			"## Reserved Ranges: %s\n"+
			"## Accessible Services: %s\n",
		conn.RiskLevel, conn.Name,
		conn.ProjectID, conn.Network,
		conn.Service,
		conn.PeeringName,
		strings.Join(conn.ReservedRanges, ", "),
		strings.Join(conn.AccessibleServices, ", "),
	)
	for _, reason := range conn.RiskReasons {
		m.LootMap["private-connections"].Contents += fmt.Sprintf("##   - %s\n", reason)
	}
	m.LootMap["private-connections"].Contents += "\n"
}

func (m *NetworkEndpointsModule) addServiceAttachmentToLoot(attachment networkendpointsservice.ServiceAttachment) {
	m.LootMap["service-attachments"].Contents += fmt.Sprintf(
		"## [%s] %s\n"+
			"## Project: %s | Region: %s\n"+
			"## Target Service: %s\n"+
			"## Connection Preference: %s\n"+
			"## Connected Endpoints: %d\n"+
			"## NAT Subnets: %s\n",
		attachment.RiskLevel, attachment.Name,
		attachment.ProjectID, attachment.Region,
		attachment.TargetService,
		attachment.ConnectionPreference,
		attachment.ConnectedEndpoints,
		strings.Join(attachment.NatSubnets, ", "),
	)

	if len(attachment.ConsumerAcceptLists) > 0 {
		m.LootMap["service-attachments"].Contents += fmt.Sprintf("## Accept List: %s\n", strings.Join(attachment.ConsumerAcceptLists, ", "))
	}
	if len(attachment.ConsumerRejectLists) > 0 {
		m.LootMap["service-attachments"].Contents += fmt.Sprintf("## Reject List: %s\n", strings.Join(attachment.ConsumerRejectLists, ", "))
	}

	for _, reason := range attachment.RiskReasons {
		m.LootMap["service-attachments"].Contents += fmt.Sprintf("##   - %s\n", reason)
	}
	m.LootMap["service-attachments"].Contents += "\n"

	// Add to auto-accept loot if applicable
	if attachment.ConnectionPreference == "ACCEPT_AUTOMATIC" {
		m.LootMap["auto-accept-attachments"].Contents += fmt.Sprintf(
			"## [HIGH] %s\n"+
				"## Project: %s | Region: %s\n"+
				"## Target Service: %s\n"+
				"## This service attachment accepts connections from ANY project!\n"+
				"## An attacker with their own GCP project can create a PSC endpoint to this service.\n"+
				"##\n"+
				"## To connect from another project:\n"+
				"gcloud compute forwarding-rules create attacker-psc-endpoint \\\n"+
				"  --region=%s \\\n"+
				"  --network=ATTACKER_VPC \\\n"+
				"  --address=RESERVED_IP \\\n"+
				"  --target-service-attachment=projects/%s/regions/%s/serviceAttachments/%s\n\n",
			attachment.Name,
			attachment.ProjectID, attachment.Region,
			attachment.TargetService,
			attachment.Region,
			attachment.ProjectID, attachment.Region, attachment.Name,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *NetworkEndpointsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// PSC Endpoints table
	if len(m.PSCEndpoints) > 0 {
		header := []string{"Risk", "Name", "Region", "Network", "IP", "Target Type", "Target", "Project"}
		var body [][]string

		for _, endpoint := range m.PSCEndpoints {
			target := endpoint.Target
			if len(target) > 40 {
				target = "..." + target[len(target)-37:]
			}

			body = append(body, []string{
				endpoint.RiskLevel,
				endpoint.Name,
				endpoint.Region,
				endpoint.Network,
				endpoint.IPAddress,
				endpoint.TargetType,
				target,
				endpoint.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "psc-endpoints",
			Header: header,
			Body:   body,
		})
	}

	// Private Connections table
	if len(m.PrivateConnections) > 0 {
		header := []string{"Risk", "Name", "Network", "Service", "Reserved Ranges", "Accessible Services", "Project"}
		var body [][]string

		for _, conn := range m.PrivateConnections {
			ranges := strings.Join(conn.ReservedRanges, ", ")
			if len(ranges) > 30 {
				ranges = ranges[:27] + "..."
			}

			services := strings.Join(conn.AccessibleServices, ", ")
			if len(services) > 30 {
				services = services[:27] + "..."
			}

			body = append(body, []string{
				conn.RiskLevel,
				conn.Name,
				conn.Network,
				conn.Service,
				ranges,
				services,
				conn.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "private-connections",
			Header: header,
			Body:   body,
		})
	}

	// Service Attachments table
	if len(m.ServiceAttachments) > 0 {
		header := []string{"Risk", "Name", "Region", "Target Service", "Accept Policy", "Connected", "Project"}
		var body [][]string

		for _, attachment := range m.ServiceAttachments {
			body = append(body, []string{
				attachment.RiskLevel,
				attachment.Name,
				attachment.Region,
				attachment.TargetService,
				attachment.ConnectionPreference,
				fmt.Sprintf("%d", attachment.ConnectedEndpoints),
				attachment.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "service-attachments",
			Header: header,
			Body:   body,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	output := NetworkEndpointsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_NETWORKENDPOINTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
