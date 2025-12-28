package networkendpointsservice

import (
	"context"
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
	servicenetworking "google.golang.org/api/servicenetworking/v1"
)

type NetworkEndpointsService struct{}

func New() *NetworkEndpointsService {
	return &NetworkEndpointsService{}
}

// PrivateServiceConnectEndpoint represents a PSC endpoint
type PrivateServiceConnectEndpoint struct {
	Name            string   `json:"name"`
	ProjectID       string   `json:"projectId"`
	Region          string   `json:"region"`
	Network         string   `json:"network"`
	Subnetwork      string   `json:"subnetwork"`
	IPAddress       string   `json:"ipAddress"`
	Target          string   `json:"target"`         // Service attachment or API
	TargetType      string   `json:"targetType"`     // google-apis, service-attachment
	ConnectionState string   `json:"connectionState"`
	RiskLevel       string   `json:"riskLevel"`
	RiskReasons     []string `json:"riskReasons"`
	ExploitCommands []string `json:"exploitCommands"`
}

// PrivateConnection represents a private service connection (e.g., for Cloud SQL)
type PrivateConnection struct {
	Name              string   `json:"name"`
	ProjectID         string   `json:"projectId"`
	Network           string   `json:"network"`
	Service           string   `json:"service"`
	ReservedRanges    []string `json:"reservedRanges"`
	PeeringName       string   `json:"peeringName"`
	RiskLevel         string   `json:"riskLevel"`
	RiskReasons       []string `json:"riskReasons"`
	AccessibleServices []string `json:"accessibleServices"`
}

// ServiceAttachment represents a PSC service attachment (producer side)
type ServiceAttachment struct {
	Name                  string   `json:"name"`
	ProjectID             string   `json:"projectId"`
	Region                string   `json:"region"`
	TargetService         string   `json:"targetService"`
	ConnectionPreference  string   `json:"connectionPreference"` // ACCEPT_AUTOMATIC, ACCEPT_MANUAL
	ConsumerAcceptLists   []string `json:"consumerAcceptLists"`
	ConsumerRejectLists   []string `json:"consumerRejectLists"`
	EnableProxyProtocol   bool     `json:"enableProxyProtocol"`
	NatSubnets            []string `json:"natSubnets"`
	ConnectedEndpoints    int      `json:"connectedEndpoints"`
	RiskLevel             string   `json:"riskLevel"`
	RiskReasons           []string `json:"riskReasons"`
}

// GetPrivateServiceConnectEndpoints retrieves PSC forwarding rules
func (s *NetworkEndpointsService) GetPrivateServiceConnectEndpoints(projectID string) ([]PrivateServiceConnectEndpoint, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	var endpoints []PrivateServiceConnectEndpoint

	// List forwarding rules across all regions
	req := service.ForwardingRules.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for region, scopedList := range page.Items {
			regionName := region
			if strings.HasPrefix(region, "regions/") {
				regionName = strings.TrimPrefix(region, "regions/")
			}

			for _, rule := range scopedList.ForwardingRules {
				// Check if this is a PSC endpoint
				if rule.Target == "" {
					continue
				}

				// PSC endpoints target service attachments or Google APIs
				isPSC := false
				targetType := ""

				if strings.Contains(rule.Target, "serviceAttachments") {
					isPSC = true
					targetType = "service-attachment"
				} else if strings.Contains(rule.Target, "all-apis") ||
				           strings.Contains(rule.Target, "vpc-sc") ||
				           rule.Target == "all-apis" {
					isPSC = true
					targetType = "google-apis"
				}

				if !isPSC {
					continue
				}

				endpoint := PrivateServiceConnectEndpoint{
					Name:            rule.Name,
					ProjectID:       projectID,
					Region:          regionName,
					Network:         extractName(rule.Network),
					Subnetwork:      extractName(rule.Subnetwork),
					IPAddress:       rule.IPAddress,
					Target:          rule.Target,
					TargetType:      targetType,
					RiskReasons:     []string{},
					ExploitCommands: []string{},
				}

				// Check connection state (for PSC endpoints to service attachments)
				if rule.PscConnectionStatus != "" {
					endpoint.ConnectionState = rule.PscConnectionStatus
				} else {
					endpoint.ConnectionState = "ACTIVE"
				}

				endpoint.RiskLevel, endpoint.RiskReasons = s.analyzePSCRisk(endpoint)
				endpoint.ExploitCommands = s.generatePSCExploitCommands(endpoint)

				endpoints = append(endpoints, endpoint)
			}
		}
		return nil
	})

	return endpoints, err
}

// GetPrivateConnections retrieves private service connections
func (s *NetworkEndpointsService) GetPrivateConnections(projectID string) ([]PrivateConnection, error) {
	ctx := context.Background()
	service, err := servicenetworking.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create service networking service: %v", err)
	}

	var connections []PrivateConnection

	// List connections for the project's networks
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return nil, err
	}

	// Get all networks
	networks, err := computeService.Networks.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, network := range networks.Items {
		networkName := fmt.Sprintf("projects/%s/global/networks/%s", projectID, network.Name)

		// List connections for this network
		resp, err := service.Services.Connections.List("services/servicenetworking.googleapis.com").
			Network(networkName).Context(ctx).Do()
		if err != nil {
			continue // May not have permissions or no connections
		}

		for _, conn := range resp.Connections {
			connection := PrivateConnection{
				Name:           conn.Peering,
				ProjectID:      projectID,
				Network:        network.Name,
				Service:        conn.Service,
				ReservedRanges: conn.ReservedPeeringRanges,
				PeeringName:    conn.Peering,
				RiskReasons:    []string{},
			}

			// Determine accessible services based on the connection
			connection.AccessibleServices = s.determineAccessibleServices(conn.Service)

			connection.RiskLevel, connection.RiskReasons = s.analyzeConnectionRisk(connection)

			connections = append(connections, connection)
		}
	}

	return connections, nil
}

// GetServiceAttachments retrieves PSC service attachments (producer side)
func (s *NetworkEndpointsService) GetServiceAttachments(projectID string) ([]ServiceAttachment, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	var attachments []ServiceAttachment

	req := service.ServiceAttachments.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.ServiceAttachmentAggregatedList) error {
		for region, scopedList := range page.Items {
			regionName := region
			if strings.HasPrefix(region, "regions/") {
				regionName = strings.TrimPrefix(region, "regions/")
			}

			for _, attachment := range scopedList.ServiceAttachments {
				sa := ServiceAttachment{
					Name:                 attachment.Name,
					ProjectID:            projectID,
					Region:               regionName,
					TargetService:        extractName(attachment.TargetService),
					ConnectionPreference: attachment.ConnectionPreference,
					EnableProxyProtocol:  attachment.EnableProxyProtocol,
					RiskReasons:          []string{},
				}

				// Extract NAT subnets
				for _, subnet := range attachment.NatSubnets {
					sa.NatSubnets = append(sa.NatSubnets, extractName(subnet))
				}

				// Count connected endpoints
				if attachment.ConnectedEndpoints != nil {
					sa.ConnectedEndpoints = len(attachment.ConnectedEndpoints)
				}

				// Extract consumer accept/reject lists
				for _, accept := range attachment.ConsumerAcceptLists {
					sa.ConsumerAcceptLists = append(sa.ConsumerAcceptLists, accept.ProjectIdOrNum)
				}
				for _, reject := range attachment.ConsumerRejectLists {
					sa.ConsumerRejectLists = append(sa.ConsumerRejectLists, reject)
				}

				sa.RiskLevel, sa.RiskReasons = s.analyzeAttachmentRisk(sa)

				attachments = append(attachments, sa)
			}
		}
		return nil
	})

	return attachments, err
}

func (s *NetworkEndpointsService) analyzePSCRisk(endpoint PrivateServiceConnectEndpoint) (string, []string) {
	var reasons []string
	score := 0

	if endpoint.TargetType == "google-apis" {
		reasons = append(reasons, "PSC endpoint to Google APIs - internal access to GCP services")
		score += 1
	}

	if endpoint.TargetType == "service-attachment" {
		reasons = append(reasons, "PSC endpoint to service attachment - access to producer service")
		score += 1
	}

	if endpoint.ConnectionState == "ACCEPTED" || endpoint.ConnectionState == "ACTIVE" {
		reasons = append(reasons, "Connection is active")
		score += 1
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *NetworkEndpointsService) generatePSCExploitCommands(endpoint PrivateServiceConnectEndpoint) []string {
	var commands []string

	commands = append(commands,
		fmt.Sprintf("# PSC Endpoint: %s", endpoint.Name),
		fmt.Sprintf("# IP Address: %s", endpoint.IPAddress),
		fmt.Sprintf("# Network: %s", endpoint.Network),
	)

	if endpoint.TargetType == "google-apis" {
		commands = append(commands,
			"# This endpoint provides private access to Google APIs",
			"# From instances in this VPC, access Google APIs via this IP:",
			fmt.Sprintf("# curl -H 'Host: storage.googleapis.com' https://%s/storage/v1/b", endpoint.IPAddress),
		)
	} else if endpoint.TargetType == "service-attachment" {
		commands = append(commands,
			"# This endpoint connects to a producer service",
			fmt.Sprintf("# Target: %s", endpoint.Target),
			fmt.Sprintf("# Connect from VPC instance to: %s", endpoint.IPAddress),
		)
	}

	return commands
}

func (s *NetworkEndpointsService) analyzeConnectionRisk(connection PrivateConnection) (string, []string) {
	var reasons []string
	score := 0

	if len(connection.ReservedRanges) > 0 {
		reasons = append(reasons, fmt.Sprintf("Has %d reserved IP range(s)", len(connection.ReservedRanges)))
		score += 1
	}

	if len(connection.AccessibleServices) > 0 {
		reasons = append(reasons, fmt.Sprintf("Provides access to: %s", strings.Join(connection.AccessibleServices, ", ")))
		score += 1
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *NetworkEndpointsService) determineAccessibleServices(service string) []string {
	// Map service names to what they provide access to
	serviceMap := map[string][]string{
		"servicenetworking.googleapis.com": {"Cloud SQL", "Memorystore", "Filestore", "Cloud Build"},
	}

	if services, ok := serviceMap[service]; ok {
		return services
	}
	return []string{service}
}

func (s *NetworkEndpointsService) analyzeAttachmentRisk(attachment ServiceAttachment) (string, []string) {
	var reasons []string
	score := 0

	if attachment.ConnectionPreference == "ACCEPT_AUTOMATIC" {
		reasons = append(reasons, "Auto-accepts connections from any project")
		score += 2
	}

	if len(attachment.ConsumerAcceptLists) == 0 && attachment.ConnectionPreference == "ACCEPT_MANUAL" {
		reasons = append(reasons, "No explicit accept list - manual review required")
		score += 1
	}

	if attachment.ConnectedEndpoints > 0 {
		reasons = append(reasons, fmt.Sprintf("Has %d connected consumer endpoint(s)", attachment.ConnectedEndpoints))
		score += 1
	}

	if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
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
