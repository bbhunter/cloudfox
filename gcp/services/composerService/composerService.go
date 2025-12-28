package composerservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	composer "google.golang.org/api/composer/v1"
)

type ComposerService struct {
	session *gcpinternal.SafeSession
}

func New() *ComposerService {
	return &ComposerService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *ComposerService {
	return &ComposerService{session: session}
}

// EnvironmentInfo represents a Cloud Composer environment
type EnvironmentInfo struct {
	Name              string   `json:"name"`
	ProjectID         string   `json:"projectId"`
	Location          string   `json:"location"`
	State             string   `json:"state"`
	CreateTime        string   `json:"createTime"`
	UpdateTime        string   `json:"updateTime"`

	// Airflow config
	AirflowURI        string   `json:"airflowUri"`
	DagGcsPrefix      string   `json:"dagGcsPrefix"`
	AirflowVersion    string   `json:"airflowVersion"`
	PythonVersion     string   `json:"pythonVersion"`
	ImageVersion      string   `json:"imageVersion"`

	// Node config
	MachineType       string   `json:"machineType"`
	DiskSizeGb        int64    `json:"diskSizeGb"`
	NodeCount         int64    `json:"nodeCount"`
	Network           string   `json:"network"`
	Subnetwork        string   `json:"subnetwork"`
	ServiceAccount    string   `json:"serviceAccount"`

	// Security config
	PrivateEnvironment bool     `json:"privateEnvironment"`
	WebServerAllowedIPs []string `json:"webServerAllowedIps"`
	EnablePrivateEndpoint bool  `json:"enablePrivateEndpoint"`

	// Security analysis
	RiskLevel         string   `json:"riskLevel"`
	RiskReasons       []string `json:"riskReasons"`
}

// ListEnvironments retrieves all Composer environments in a project
func (s *ComposerService) ListEnvironments(projectID string) ([]EnvironmentInfo, error) {
	ctx := context.Background()
	var service *composer.Service
	var err error

	if s.session != nil {
		service, err = composer.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = composer.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Composer service: %v", err)
	}

	var environments []EnvironmentInfo

	// List environments across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := service.Projects.Locations.Environments.List(parent)
	err = req.Pages(ctx, func(page *composer.ListEnvironmentsResponse) error {
		for _, env := range page.Environments {
			info := s.parseEnvironment(env, projectID)
			environments = append(environments, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list Composer environments: %v", err)
	}

	return environments, nil
}

// parseEnvironment converts a Composer environment to EnvironmentInfo
func (s *ComposerService) parseEnvironment(env *composer.Environment, projectID string) EnvironmentInfo {
	info := EnvironmentInfo{
		Name:        extractName(env.Name),
		ProjectID:   projectID,
		Location:    extractLocation(env.Name),
		State:       env.State,
		CreateTime:  env.CreateTime,
		UpdateTime:  env.UpdateTime,
		RiskReasons: []string{},
	}

	if env.Config != nil {
		// Airflow config
		if env.Config.AirflowUri != "" {
			info.AirflowURI = env.Config.AirflowUri
		}
		info.DagGcsPrefix = env.Config.DagGcsPrefix

		// Software config
		if env.Config.SoftwareConfig != nil {
			info.AirflowVersion = env.Config.SoftwareConfig.AirflowConfigOverrides["core-dags_are_paused_at_creation"]
			info.PythonVersion = env.Config.SoftwareConfig.PythonVersion
			info.ImageVersion = env.Config.SoftwareConfig.ImageVersion
		}

		// Node config
		if env.Config.NodeConfig != nil {
			info.MachineType = env.Config.NodeConfig.MachineType
			info.DiskSizeGb = env.Config.NodeConfig.DiskSizeGb
			info.Network = env.Config.NodeConfig.Network
			info.Subnetwork = env.Config.NodeConfig.Subnetwork
			info.ServiceAccount = env.Config.NodeConfig.ServiceAccount
		}

		info.NodeCount = env.Config.NodeCount

		// Private environment config
		if env.Config.PrivateEnvironmentConfig != nil {
			info.PrivateEnvironment = env.Config.PrivateEnvironmentConfig.EnablePrivateEnvironment
			// EnablePrivateEndpoint is part of PrivateClusterConfig, not PrivateEnvironmentConfig
			if env.Config.PrivateEnvironmentConfig.PrivateClusterConfig != nil {
				info.EnablePrivateEndpoint = env.Config.PrivateEnvironmentConfig.PrivateClusterConfig.EnablePrivateEndpoint
			}
		}

		// Web server network access control
		if env.Config.WebServerNetworkAccessControl != nil {
			for _, cidr := range env.Config.WebServerNetworkAccessControl.AllowedIpRanges {
				info.WebServerAllowedIPs = append(info.WebServerAllowedIPs, cidr.Value)
			}
		}
	}

	// Security analysis
	info.RiskLevel, info.RiskReasons = s.analyzeEnvironmentRisk(info)

	return info
}

// analyzeEnvironmentRisk determines the risk level of a Composer environment
func (s *ComposerService) analyzeEnvironmentRisk(env EnvironmentInfo) (string, []string) {
	var reasons []string
	score := 0

	// Public Airflow UI
	if !env.PrivateEnvironment {
		reasons = append(reasons, "Not using private environment")
		score += 2
	}

	// Public endpoint
	if !env.EnablePrivateEndpoint && env.AirflowURI != "" {
		reasons = append(reasons, "Airflow web server has public endpoint")
		score += 2
	}

	// No IP restrictions or 0.0.0.0/0
	if len(env.WebServerAllowedIPs) == 0 {
		reasons = append(reasons, "No web server IP restrictions")
		score += 1
	} else {
		for _, ip := range env.WebServerAllowedIPs {
			if ip == "0.0.0.0/0" {
				reasons = append(reasons, "Web server allows all IPs (0.0.0.0/0)")
				score += 2
				break
			}
		}
	}

	// Default service account
	if env.ServiceAccount == "" || strings.Contains(env.ServiceAccount, "compute@developer.gserviceaccount.com") {
		reasons = append(reasons, "Uses default Compute Engine service account")
		score += 2
	}

	if score >= 4 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

func extractLocation(fullName string) string {
	parts := strings.Split(fullName, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
