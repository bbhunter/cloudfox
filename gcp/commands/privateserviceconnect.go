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

var GCPPrivateServiceConnectCommand = &cobra.Command{
	Use:     "private-service-connect",
	Aliases: []string{"psc", "private-endpoints", "internal-endpoints"},
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
- Connection acceptance policies (auto vs manual)

Output includes nmap commands for scanning internal endpoints.`,
	Run: runGCPPrivateServiceConnectCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type PrivateServiceConnectModule struct {
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
type PrivateServiceConnectOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivateServiceConnectOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivateServiceConnectOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPPrivateServiceConnectCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, "private-service-connect")
	if err != nil {
		return
	}

	module := &PrivateServiceConnectModule{
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
func (m *PrivateServiceConnectModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, "private-service-connect", m.processProject)

	totalFindings := len(m.PSCEndpoints) + len(m.PrivateConnections) + len(m.ServiceAttachments)

	if totalFindings == 0 {
		logger.InfoM("No private service connect endpoints found", "private-service-connect")
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d PSC endpoint(s), %d private connection(s), %d service attachment(s)",
		len(m.PSCEndpoints), len(m.PrivateConnections), len(m.ServiceAttachments)), "private-service-connect")

	// Count high-risk findings
	autoAcceptCount := 0
	for _, sa := range m.ServiceAttachments {
		if sa.ConnectionPreference == "ACCEPT_AUTOMATIC" {
			autoAcceptCount++
		}
	}
	if autoAcceptCount > 0 {
		logger.InfoM(fmt.Sprintf("[High] %d service attachment(s) auto-accept connections from any project", autoAcceptCount), "private-service-connect")
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *PrivateServiceConnectModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking private service connect in project: %s", projectID), "private-service-connect")
	}

	svc := networkendpointsservice.New()

	// Get PSC endpoints
	pscEndpoints, err := svc.GetPrivateServiceConnectEndpoints(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "private-service-connect",
			fmt.Sprintf("Could not get PSC endpoints in project %s", projectID))
	}

	// Get private connections
	privateConns, err := svc.GetPrivateConnections(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "private-service-connect",
			fmt.Sprintf("Could not get private connections in project %s", projectID))
	}

	// Get service attachments
	attachments, err := svc.GetServiceAttachments(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, "private-service-connect",
			fmt.Sprintf("Could not get service attachments in project %s", projectID))
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
func (m *PrivateServiceConnectModule) initializeLootFiles() {
	m.LootMap["private-service-connect-commands"] = &internal.LootFile{
		Name: "private-service-connect-commands",
		Contents: "# Private Service Connect Commands\n" +
			"# Generated by CloudFox\n" +
			"# WARNING: Only use with proper authorization\n" +
			"# NOTE: These are internal IPs - you must be on the VPC network to reach them\n\n",
	}
}

func (m *PrivateServiceConnectModule) addPSCEndpointToLoot(endpoint networkendpointsservice.PrivateServiceConnectEndpoint) {
	m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf(
		"## PSC Endpoint: %s (Project: %s, Region: %s)\n"+
			"# Network: %s, Subnet: %s\n"+
			"# Target Type: %s, Target: %s\n"+
			"# State: %s, IP: %s\n\n"+
			"# Describe forwarding rule:\n"+
			"gcloud compute forwarding-rules describe %s --region=%s --project=%s\n\n",
		endpoint.Name, endpoint.ProjectID, endpoint.Region,
		endpoint.Network, endpoint.Subnetwork,
		endpoint.TargetType, endpoint.Target,
		endpoint.ConnectionState, endpoint.IPAddress,
		endpoint.Name, endpoint.Region, endpoint.ProjectID,
	)

	if endpoint.IPAddress != "" {
		m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf(
			"# Scan internal endpoint (from within VPC):\n"+
				"nmap -sV -Pn %s\n\n",
			endpoint.IPAddress,
		)
	}
}

func (m *PrivateServiceConnectModule) addPrivateConnectionToLoot(conn networkendpointsservice.PrivateConnection) {
	reservedRanges := "-"
	if len(conn.ReservedRanges) > 0 {
		reservedRanges = strings.Join(conn.ReservedRanges, ", ")
	}
	accessibleServices := "-"
	if len(conn.AccessibleServices) > 0 {
		accessibleServices = strings.Join(conn.AccessibleServices, ", ")
	}

	m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf(
		"## Private Connection: %s (Project: %s)\n"+
			"# Network: %s, Service: %s\n"+
			"# Peering: %s\n"+
			"# Reserved Ranges: %s\n"+
			"# Accessible Services: %s\n\n"+
			"# List private connections:\n"+
			"gcloud services vpc-peerings list --network=%s --project=%s\n\n",
		conn.Name, conn.ProjectID,
		conn.Network, conn.Service,
		conn.PeeringName,
		reservedRanges,
		accessibleServices,
		conn.Network, conn.ProjectID,
	)

	// Add nmap commands for each reserved range
	for _, ipRange := range conn.ReservedRanges {
		m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf(
			"# Scan private connection range (from within VPC):\n"+
				"nmap -sV -Pn %s\n\n",
			ipRange,
		)
	}
}

func (m *PrivateServiceConnectModule) addServiceAttachmentToLoot(attachment networkendpointsservice.ServiceAttachment) {
	natSubnets := "-"
	if len(attachment.NatSubnets) > 0 {
		natSubnets = strings.Join(attachment.NatSubnets, ", ")
	}

	m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf(
		"## Service Attachment: %s (Project: %s, Region: %s)\n"+
			"# Target Service: %s\n"+
			"# Connection Preference: %s\n"+
			"# Connected Endpoints: %d\n"+
			"# NAT Subnets: %s\n",
		attachment.Name, attachment.ProjectID, attachment.Region,
		attachment.TargetService,
		attachment.ConnectionPreference,
		attachment.ConnectedEndpoints,
		natSubnets,
	)

	if len(attachment.ConsumerAcceptLists) > 0 {
		m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf("# Accept List: %s\n", strings.Join(attachment.ConsumerAcceptLists, ", "))
	}
	if len(attachment.ConsumerRejectLists) > 0 {
		m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf("# Reject List: %s\n", strings.Join(attachment.ConsumerRejectLists, ", "))
	}

	// Add IAM bindings info
	if len(attachment.IAMBindings) > 0 {
		m.LootMap["private-service-connect-commands"].Contents += "# IAM Bindings:\n"
		for _, binding := range attachment.IAMBindings {
			m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf("#   %s -> %s\n", binding.Role, binding.Member)
		}
	}

	m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf(
		"\n# Describe service attachment:\n"+
			"gcloud compute service-attachments describe %s --region=%s --project=%s\n\n"+
			"# Get IAM policy:\n"+
			"gcloud compute service-attachments get-iam-policy %s --region=%s --project=%s\n\n",
		attachment.Name, attachment.Region, attachment.ProjectID,
		attachment.Name, attachment.Region, attachment.ProjectID,
	)

	// If auto-accept, add exploitation command
	if attachment.ConnectionPreference == "ACCEPT_AUTOMATIC" {
		m.LootMap["private-service-connect-commands"].Contents += fmt.Sprintf(
			"# [HIGH RISK] This service attachment accepts connections from ANY project!\n"+
				"# To connect from another project:\n"+
				"gcloud compute forwarding-rules create attacker-psc-endpoint \\\n"+
				"  --region=%s \\\n"+
				"  --network=ATTACKER_VPC \\\n"+
				"  --address=RESERVED_IP \\\n"+
				"  --target-service-attachment=projects/%s/regions/%s/serviceAttachments/%s\n\n",
			attachment.Region,
			attachment.ProjectID, attachment.Region, attachment.Name,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PrivateServiceConnectModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// PSC Endpoints table
	if len(m.PSCEndpoints) > 0 {
		header := []string{
			"Project Name",
			"Project ID",
			"Name",
			"Region",
			"Network",
			"Subnet",
			"IP Address",
			"Target Type",
			"Target",
			"State",
		}
		var body [][]string

		for _, endpoint := range m.PSCEndpoints {
			body = append(body, []string{
				m.GetProjectName(endpoint.ProjectID),
				endpoint.ProjectID,
				endpoint.Name,
				endpoint.Region,
				endpoint.Network,
				endpoint.Subnetwork,
				endpoint.IPAddress,
				endpoint.TargetType,
				endpoint.Target,
				endpoint.ConnectionState,
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
		header := []string{
			"Project Name",
			"Project ID",
			"Name",
			"Network",
			"Service",
			"Peering Name",
			"Reserved Ranges",
			"Accessible Services",
		}
		var body [][]string

		for _, conn := range m.PrivateConnections {
			reservedRanges := "-"
			if len(conn.ReservedRanges) > 0 {
				reservedRanges = strings.Join(conn.ReservedRanges, ", ")
			}
			accessibleServices := "-"
			if len(conn.AccessibleServices) > 0 {
				accessibleServices = strings.Join(conn.AccessibleServices, ", ")
			}

			body = append(body, []string{
				m.GetProjectName(conn.ProjectID),
				conn.ProjectID,
				conn.Name,
				conn.Network,
				conn.Service,
				conn.PeeringName,
				reservedRanges,
				accessibleServices,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "private-connections",
			Header: header,
			Body:   body,
		})
	}

	// Service Attachments table - one row per IAM binding
	if len(m.ServiceAttachments) > 0 {
		header := []string{
			"Project Name",
			"Project ID",
			"Name",
			"Region",
			"Target Service",
			"Accept Policy",
			"Connected",
			"NAT Subnets",
			"IAM Role",
			"IAM Member",
		}
		var body [][]string

		for _, attachment := range m.ServiceAttachments {
			natSubnets := "-"
			if len(attachment.NatSubnets) > 0 {
				natSubnets = strings.Join(attachment.NatSubnets, ", ")
			}

			if len(attachment.IAMBindings) > 0 {
				// One row per IAM binding
				for _, binding := range attachment.IAMBindings {
					body = append(body, []string{
						m.GetProjectName(attachment.ProjectID),
						attachment.ProjectID,
						attachment.Name,
						attachment.Region,
						attachment.TargetService,
						attachment.ConnectionPreference,
						fmt.Sprintf("%d", attachment.ConnectedEndpoints),
						natSubnets,
						binding.Role,
						binding.Member,
					})
				}
			} else {
				// No IAM bindings - single row with empty IAM columns
				body = append(body, []string{
					m.GetProjectName(attachment.ProjectID),
					attachment.ProjectID,
					attachment.Name,
					attachment.Region,
					attachment.TargetService,
					attachment.ConnectionPreference,
					fmt.Sprintf("%d", attachment.ConnectedEndpoints),
					natSubnets,
					"-",
					"-",
				})
			}
		}

		tables = append(tables, internal.TableFile{
			Name:   "service-attachments",
			Header: header,
			Body:   body,
		})
	}

	// Collect loot files - only include if they have content beyond the header
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# NOTE: These are internal IPs - you must be on the VPC network to reach them\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	output := PrivateServiceConnectOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), "private-service-connect")
		m.CommandCounter.Error++
	}
}
