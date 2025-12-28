package serviceagentsservice

import (
	"context"
	"fmt"
	"strings"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
)

type ServiceAgentsService struct{}

func New() *ServiceAgentsService {
	return &ServiceAgentsService{}
}

// ServiceAgentInfo represents a Google-managed service agent
type ServiceAgentInfo struct {
	Email         string   `json:"email"`
	ProjectID     string   `json:"projectId"`
	ServiceName   string   `json:"serviceName"`
	AgentType     string   `json:"agentType"` // compute, gke, cloudbuild, etc.
	Roles         []string `json:"roles"`
	IsCrossProject bool    `json:"isCrossProject"`
	Description   string   `json:"description"`
	RiskLevel     string   `json:"riskLevel"`
	RiskReasons   []string `json:"riskReasons"`
}

// KnownServiceAgents maps service agent patterns to their descriptions
var KnownServiceAgents = map[string]struct {
	Service     string
	Description string
}{
	"@cloudservices.gserviceaccount.com": {
		Service:     "Google APIs",
		Description: "Google APIs Service Agent - manages resources on behalf of Google Cloud services",
	},
	"@compute-system.iam.gserviceaccount.com": {
		Service:     "Compute Engine",
		Description: "Compute Engine Service Agent - manages Compute Engine resources",
	},
	"@container-engine-robot.iam.gserviceaccount.com": {
		Service:     "GKE",
		Description: "Kubernetes Engine Service Agent - manages GKE clusters",
	},
	"@cloudbuild.gserviceaccount.com": {
		Service:     "Cloud Build",
		Description: "Cloud Build Service Account - runs build jobs",
	},
	"@gcp-sa-cloudbuild.iam.gserviceaccount.com": {
		Service:     "Cloud Build",
		Description: "Cloud Build Service Agent - manages Cloud Build resources",
	},
	"@cloudcomposer-accounts.iam.gserviceaccount.com": {
		Service:     "Composer",
		Description: "Cloud Composer Service Agent - manages Airflow environments",
	},
	"@dataflow-service-producer-prod.iam.gserviceaccount.com": {
		Service:     "Dataflow",
		Description: "Dataflow Service Agent - manages Dataflow jobs",
	},
	"@gcp-sa-dataproc.iam.gserviceaccount.com": {
		Service:     "Dataproc",
		Description: "Dataproc Service Agent - manages Dataproc clusters",
	},
	"@gcp-sa-pubsub.iam.gserviceaccount.com": {
		Service:     "Pub/Sub",
		Description: "Pub/Sub Service Agent - manages Pub/Sub resources",
	},
	"@serverless-robot-prod.iam.gserviceaccount.com": {
		Service:     "Cloud Run/Functions",
		Description: "Serverless Service Agent - manages serverless resources",
	},
	"@gcp-sa-cloudscheduler.iam.gserviceaccount.com": {
		Service:     "Cloud Scheduler",
		Description: "Cloud Scheduler Service Agent",
	},
	"@gcp-sa-bigquery.iam.gserviceaccount.com": {
		Service:     "BigQuery",
		Description: "BigQuery Service Agent - manages BigQuery resources",
	},
	"@gcp-sa-artifactregistry.iam.gserviceaccount.com": {
		Service:     "Artifact Registry",
		Description: "Artifact Registry Service Agent",
	},
	"@gcp-sa-secretmanager.iam.gserviceaccount.com": {
		Service:     "Secret Manager",
		Description: "Secret Manager Service Agent",
	},
	"@gcp-sa-firestore.iam.gserviceaccount.com": {
		Service:     "Firestore",
		Description: "Firestore Service Agent",
	},
	"@gcp-sa-cloud-sql.iam.gserviceaccount.com": {
		Service:     "Cloud SQL",
		Description: "Cloud SQL Service Agent",
	},
	"@gcp-sa-logging.iam.gserviceaccount.com": {
		Service:     "Cloud Logging",
		Description: "Cloud Logging Service Agent",
	},
	"@gcp-sa-monitoring.iam.gserviceaccount.com": {
		Service:     "Cloud Monitoring",
		Description: "Cloud Monitoring Service Agent",
	},
}

// GetServiceAgents retrieves all service agents with IAM bindings
func (s *ServiceAgentsService) GetServiceAgents(projectID string) ([]ServiceAgentInfo, error) {
	ctx := context.Background()
	service, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %v", err)
	}

	var agents []ServiceAgentInfo

	// Get IAM policy
	policy, err := service.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy: %v", err)
	}

	// Track which service agents we've seen
	seenAgents := make(map[string]*ServiceAgentInfo)

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if !strings.HasPrefix(member, "serviceAccount:") {
				continue
			}

			email := strings.TrimPrefix(member, "serviceAccount:")

			// Check if it's a service agent
			agentType, description := s.identifyServiceAgent(email)
			if agentType == "" {
				continue // Not a service agent
			}

			// Check for cross-project access
			isCrossProject := !strings.Contains(email, projectID)

			// Add or update agent
			if agent, exists := seenAgents[email]; exists {
				agent.Roles = append(agent.Roles, binding.Role)
			} else {
				agent := &ServiceAgentInfo{
					Email:          email,
					ProjectID:      projectID,
					ServiceName:    agentType,
					AgentType:      agentType,
					Roles:          []string{binding.Role},
					IsCrossProject: isCrossProject,
					Description:    description,
					RiskReasons:    []string{},
				}
				seenAgents[email] = agent
			}
		}
	}

	// Convert to slice and analyze risk
	for _, agent := range seenAgents {
		agent.RiskLevel, agent.RiskReasons = s.analyzeAgentRisk(agent)
		agents = append(agents, *agent)
	}

	return agents, nil
}

func (s *ServiceAgentsService) identifyServiceAgent(email string) (string, string) {
	// Check known patterns
	for suffix, info := range KnownServiceAgents {
		if strings.HasSuffix(email, suffix) {
			return info.Service, info.Description
		}
	}

	// Check for generic service agent patterns
	if strings.Contains(email, "@gcp-sa-") {
		// Extract service name from gcp-sa-{service}
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			saPart := parts[1]
			if strings.HasPrefix(saPart, "gcp-sa-") {
				serviceName := strings.TrimPrefix(saPart, "gcp-sa-")
				serviceName = strings.Split(serviceName, ".")[0]
				return serviceName, fmt.Sprintf("%s Service Agent", serviceName)
			}
		}
	}

	// Check for project-specific service agents
	if strings.Contains(email, "-compute@developer.gserviceaccount.com") {
		return "Compute Engine", "Default Compute Engine service account"
	}

	if strings.Contains(email, "@appspot.gserviceaccount.com") {
		return "App Engine", "App Engine default service account"
	}

	return "", ""
}

func (s *ServiceAgentsService) analyzeAgentRisk(agent *ServiceAgentInfo) (string, []string) {
	var reasons []string
	score := 0

	// Cross-project access is notable
	if agent.IsCrossProject {
		reasons = append(reasons, "Cross-project service agent (from different project)")
		score += 1
	}

	// Check for powerful roles
	for _, role := range agent.Roles {
		if strings.Contains(role, "admin") || strings.Contains(role, "Admin") {
			reasons = append(reasons, fmt.Sprintf("Has admin role: %s", role))
			score += 2
		}
		if role == "roles/owner" || role == "roles/editor" {
			reasons = append(reasons, fmt.Sprintf("Has privileged role: %s", role))
			score += 2
		}
		if strings.Contains(role, "iam.serviceAccountUser") ||
			strings.Contains(role, "iam.serviceAccountTokenCreator") {
			reasons = append(reasons, fmt.Sprintf("Can impersonate service accounts: %s", role))
			score += 2
		}
	}

	// Check for many roles
	if len(agent.Roles) > 5 {
		reasons = append(reasons, fmt.Sprintf("Has many roles (%d)", len(agent.Roles)))
		score += 1
	}

	// Service-specific risks
	if agent.ServiceName == "Cloud Build" {
		reasons = append(reasons, "Cloud Build SA - often has broad permissions for CI/CD")
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

// GetDefaultServiceAccounts returns the default service accounts for a project
func (s *ServiceAgentsService) GetDefaultServiceAccounts(projectID string, projectNumber string) []ServiceAgentInfo {
	var defaults []ServiceAgentInfo

	// Google APIs Service Agent
	defaults = append(defaults, ServiceAgentInfo{
		Email:       fmt.Sprintf("%s@cloudservices.gserviceaccount.com", projectNumber),
		ProjectID:   projectID,
		ServiceName: "Google APIs",
		AgentType:   "Google APIs",
		Description: "Google APIs Service Agent - automatically created, manages resources on behalf of Google Cloud services",
		RiskReasons: []string{"Automatically created with broad permissions"},
		RiskLevel:   "INFO",
	})

	// Compute Engine default SA
	defaults = append(defaults, ServiceAgentInfo{
		Email:       fmt.Sprintf("%s-compute@developer.gserviceaccount.com", projectNumber),
		ProjectID:   projectID,
		ServiceName: "Compute Engine",
		AgentType:   "Compute Engine",
		Description: "Default Compute Engine service account - used by instances without explicit SA",
		RiskReasons: []string{"Default SA often has Editor role - overprivileged"},
		RiskLevel:   "MEDIUM",
	})

	// App Engine default SA
	defaults = append(defaults, ServiceAgentInfo{
		Email:       fmt.Sprintf("%s@appspot.gserviceaccount.com", projectID),
		ProjectID:   projectID,
		ServiceName: "App Engine",
		AgentType:   "App Engine",
		Description: "App Engine default service account",
		RiskReasons: []string{"Default SA often has Editor role"},
		RiskLevel:   "MEDIUM",
	})

	return defaults
}
