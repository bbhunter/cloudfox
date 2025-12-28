package beyondcorpservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	beyondcorp "google.golang.org/api/beyondcorp/v1"
)

type BeyondCorpService struct {
	session *gcpinternal.SafeSession
}

func New() *BeyondCorpService {
	return &BeyondCorpService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *BeyondCorpService {
	return &BeyondCorpService{session: session}
}

// AppConnectorInfo represents a BeyondCorp app connector
type AppConnectorInfo struct {
	Name          string   `json:"name"`
	ProjectID     string   `json:"projectId"`
	Location      string   `json:"location"`
	DisplayName   string   `json:"displayName"`
	State         string   `json:"state"`
	CreateTime    string   `json:"createTime"`
	UpdateTime    string   `json:"updateTime"`
	PrincipalInfo string   `json:"principalInfo"`
	ResourceInfo  string   `json:"resourceInfo"`
	RiskLevel     string   `json:"riskLevel"`
	RiskReasons   []string `json:"riskReasons"`
}

// AppConnectionInfo represents a BeyondCorp app connection
type AppConnectionInfo struct {
	Name                string   `json:"name"`
	ProjectID           string   `json:"projectId"`
	Location            string   `json:"location"`
	DisplayName         string   `json:"displayName"`
	State               string   `json:"state"`
	Type                string   `json:"type"`
	ApplicationEndpoint string   `json:"applicationEndpoint"`
	Connectors          []string `json:"connectors"`
	Gateway             string   `json:"gateway"`
	CreateTime          string   `json:"createTime"`
	UpdateTime          string   `json:"updateTime"`
	RiskLevel           string   `json:"riskLevel"`
	RiskReasons         []string `json:"riskReasons"`
}

// ListAppConnectors retrieves all BeyondCorp app connectors
func (s *BeyondCorpService) ListAppConnectors(projectID string) ([]AppConnectorInfo, error) {
	ctx := context.Background()
	var service *beyondcorp.Service
	var err error

	if s.session != nil {
		service, err = beyondcorp.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = beyondcorp.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create BeyondCorp service: %v", err)
	}

	var connectors []AppConnectorInfo

	// List across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := service.Projects.Locations.AppConnectors.List(parent)
	err = req.Pages(ctx, func(page *beyondcorp.GoogleCloudBeyondcorpAppconnectorsV1ListAppConnectorsResponse) error {
		for _, connector := range page.AppConnectors {
			info := s.parseAppConnector(connector, projectID)
			connectors = append(connectors, info)
		}
		return nil
	})
	if err != nil {
		// API might not be enabled
		return connectors, nil
	}

	return connectors, nil
}

// ListAppConnections retrieves all BeyondCorp app connections
func (s *BeyondCorpService) ListAppConnections(projectID string) ([]AppConnectionInfo, error) {
	ctx := context.Background()
	var service *beyondcorp.Service
	var err error

	if s.session != nil {
		service, err = beyondcorp.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = beyondcorp.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create BeyondCorp service: %v", err)
	}

	var connections []AppConnectionInfo

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := service.Projects.Locations.AppConnections.List(parent)
	err = req.Pages(ctx, func(page *beyondcorp.GoogleCloudBeyondcorpAppconnectionsV1ListAppConnectionsResponse) error {
		for _, conn := range page.AppConnections {
			info := s.parseAppConnection(conn, projectID)
			connections = append(connections, info)
		}
		return nil
	})
	if err != nil {
		return connections, nil
	}

	return connections, nil
}

func (s *BeyondCorpService) parseAppConnector(connector *beyondcorp.GoogleCloudBeyondcorpAppconnectorsV1AppConnector, projectID string) AppConnectorInfo {
	info := AppConnectorInfo{
		Name:        extractName(connector.Name),
		ProjectID:   projectID,
		Location:    extractLocation(connector.Name),
		DisplayName: connector.DisplayName,
		State:       connector.State,
		CreateTime:  connector.CreateTime,
		UpdateTime:  connector.UpdateTime,
		RiskReasons: []string{},
	}

	if connector.PrincipalInfo != nil && connector.PrincipalInfo.ServiceAccount != nil {
		info.PrincipalInfo = connector.PrincipalInfo.ServiceAccount.Email
	}

	if connector.ResourceInfo != nil {
		info.ResourceInfo = connector.ResourceInfo.Id
	}

	info.RiskLevel, info.RiskReasons = s.analyzeConnectorRisk(info)

	return info
}

func (s *BeyondCorpService) parseAppConnection(conn *beyondcorp.GoogleCloudBeyondcorpAppconnectionsV1AppConnection, projectID string) AppConnectionInfo {
	info := AppConnectionInfo{
		Name:        extractName(conn.Name),
		ProjectID:   projectID,
		Location:    extractLocation(conn.Name),
		DisplayName: conn.DisplayName,
		State:       conn.State,
		Type:        conn.Type,
		CreateTime:  conn.CreateTime,
		UpdateTime:  conn.UpdateTime,
		RiskReasons: []string{},
	}

	if conn.ApplicationEndpoint != nil {
		info.ApplicationEndpoint = fmt.Sprintf("%s:%d", conn.ApplicationEndpoint.Host, conn.ApplicationEndpoint.Port)
	}

	for _, connector := range conn.Connectors {
		info.Connectors = append(info.Connectors, extractName(connector))
	}

	if conn.Gateway != nil {
		info.Gateway = extractName(conn.Gateway.AppGateway)
	}

	info.RiskLevel, info.RiskReasons = s.analyzeConnectionRisk(info)

	return info
}

func (s *BeyondCorpService) analyzeConnectorRisk(connector AppConnectorInfo) (string, []string) {
	var reasons []string
	score := 0

	if connector.State != "RUNNING" {
		reasons = append(reasons, fmt.Sprintf("Connector not running: %s", connector.State))
		score += 1
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *BeyondCorpService) analyzeConnectionRisk(conn AppConnectionInfo) (string, []string) {
	var reasons []string
	score := 0

	// Connection to sensitive ports
	if strings.Contains(conn.ApplicationEndpoint, ":22") {
		reasons = append(reasons, "Connection to SSH port (22)")
		score += 1
	}
	if strings.Contains(conn.ApplicationEndpoint, ":3389") {
		reasons = append(reasons, "Connection to RDP port (3389)")
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

func extractLocation(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
