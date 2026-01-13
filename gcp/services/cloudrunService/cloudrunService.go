package cloudrunservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	run "google.golang.org/api/run/v2"
)

type CloudRunService struct{}

func New() *CloudRunService {
	return &CloudRunService{}
}

// ServiceInfo holds Cloud Run service details with security-relevant information
type ServiceInfo struct {
	// Basic info
	Name        string
	ProjectID   string
	Region      string
	Description string
	Creator     string
	UpdateTime  string

	// URL and traffic
	URL                     string
	LatestRevision          string
	LatestReadyRevision     string
	TrafficAllOnLatest      bool

	// Security-relevant configuration
	ServiceAccount          string
	IngressSettings         string  // INGRESS_TRAFFIC_ALL, INGRESS_TRAFFIC_INTERNAL_ONLY, INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER
	VPCAccess               string  // VPC Connector or Direct VPC
	VPCEgressSettings       string  // ALL_TRAFFIC, PRIVATE_RANGES_ONLY
	BinaryAuthorizationPolicy string

	// Container configuration
	ContainerImage          string
	ContainerPort           int64
	CPULimit                string
	MemoryLimit             string
	MaxInstances            int64
	MinInstances            int64
	Timeout                 string

	// Environment variables (counts, not values)
	EnvVarCount             int
	SecretEnvVarCount       int
	SecretVolumeCount       int

	// Security analysis
	HardcodedSecrets        []HardcodedSecret // Potential secrets in env vars (not using Secret Manager)
	UsesDefaultSA           bool              // Uses default compute service account

	// Detailed env var and secret info
	EnvVars    []EnvVarInfo    // All environment variables
	SecretRefs []SecretRefInfo // All Secret Manager references

	// IAM
	InvokerMembers          []string
	IsPublic                bool
}

// HardcodedSecret represents a potential secret found in environment variables
type HardcodedSecret struct {
	EnvVarName string
	SecretType string // password, api-key, token, credential, connection-string
}

// EnvVarInfo represents an environment variable configuration
type EnvVarInfo struct {
	Name   string
	Value  string // Direct value (may be empty if using secret ref)
	Source string // "direct", "secret-manager", or "config-map"
	// For Secret Manager references
	SecretName    string
	SecretVersion string
}

// SecretRefInfo represents a Secret Manager reference used by the service
type SecretRefInfo struct {
	EnvVarName    string // The env var name that references this secret
	SecretName    string // Secret Manager secret name
	SecretVersion string // Version (e.g., "latest", "1")
	MountPath     string // For volume mounts, the path where it's mounted
	Type          string // "env" or "volume"
}

// JobInfo holds Cloud Run job details
type JobInfo struct {
	Name            string
	ProjectID       string
	Region          string
	ServiceAccount  string
	ContainerImage  string
	LastExecution   string
	Creator         string
	UpdateTime      string

	// Configuration
	TaskCount       int64
	Parallelism     int64
	MaxRetries      int64
	Timeout         string

	// Environment
	EnvVarCount       int
	SecretEnvVarCount int
	SecretVolumeCount int

	// Security analysis
	HardcodedSecrets []HardcodedSecret
	UsesDefaultSA    bool

	// Detailed env var and secret info
	EnvVars    []EnvVarInfo
	SecretRefs []SecretRefInfo
}

// Services retrieves all Cloud Run services in a project across all regions
func (cs *CloudRunService) Services(projectID string) ([]ServiceInfo, error) {
	ctx := context.Background()

	service, err := run.NewService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "run.googleapis.com")
	}

	var services []ServiceInfo

	// List services across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	call := service.Projects.Locations.Services.List(parent)
	err = call.Pages(ctx, func(page *run.GoogleCloudRunV2ListServicesResponse) error {
		for _, svc := range page.Services {
			info := parseServiceInfo(svc, projectID)

			// Try to get IAM policy
			iamPolicy, iamErr := cs.getServiceIAMPolicy(service, svc.Name)
			if iamErr == nil && iamPolicy != nil {
				info.InvokerMembers, info.IsPublic = parseInvokerBindings(iamPolicy)
			}

			services = append(services, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "run.googleapis.com")
	}

	return services, nil
}

// Jobs retrieves all Cloud Run jobs in a project across all regions
func (cs *CloudRunService) Jobs(projectID string) ([]JobInfo, error) {
	ctx := context.Background()

	service, err := run.NewService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "run.googleapis.com")
	}

	var jobs []JobInfo

	// List jobs across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	call := service.Projects.Locations.Jobs.List(parent)
	err = call.Pages(ctx, func(page *run.GoogleCloudRunV2ListJobsResponse) error {
		for _, job := range page.Jobs {
			info := parseJobInfo(job, projectID)
			jobs = append(jobs, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "run.googleapis.com")
	}

	return jobs, nil
}

// parseServiceInfo extracts relevant information from a Cloud Run service
func parseServiceInfo(svc *run.GoogleCloudRunV2Service, projectID string) ServiceInfo {
	info := ServiceInfo{
		Name:        extractName(svc.Name),
		ProjectID:   projectID,
		Description: svc.Description,
		Creator:     svc.Creator,
		UpdateTime:  svc.UpdateTime,
		URL:         svc.Uri,
	}

	// Extract region from service name
	// Format: projects/{project}/locations/{location}/services/{name}
	parts := strings.Split(svc.Name, "/")
	if len(parts) >= 4 {
		info.Region = parts[3]
	}

	// Ingress settings
	info.IngressSettings = svc.Ingress

	// Latest revision info
	info.LatestRevision = svc.LatestCreatedRevision
	info.LatestReadyRevision = svc.LatestReadyRevision

	// Check if all traffic goes to latest
	for _, traffic := range svc.Traffic {
		if traffic.Type == "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" && traffic.Percent == 100 {
			info.TrafficAllOnLatest = true
			break
		}
	}

	// Binary authorization
	if svc.BinaryAuthorization != nil {
		info.BinaryAuthorizationPolicy = svc.BinaryAuthorization.Policy
		if svc.BinaryAuthorization.UseDefault {
			info.BinaryAuthorizationPolicy = "default"
		}
	}

	// Template configuration (current revision settings)
	if svc.Template != nil {
		info.ServiceAccount = svc.Template.ServiceAccount
		info.Timeout = svc.Template.Timeout

		if svc.Template.Scaling != nil {
			info.MaxInstances = svc.Template.Scaling.MaxInstanceCount
			info.MinInstances = svc.Template.Scaling.MinInstanceCount
		}

		// VPC access configuration
		if svc.Template.VpcAccess != nil {
			info.VPCAccess = svc.Template.VpcAccess.Connector
			info.VPCEgressSettings = svc.Template.VpcAccess.Egress
			if info.VPCAccess == "" && svc.Template.VpcAccess.NetworkInterfaces != nil {
				info.VPCAccess = "Direct VPC"
			}
		}

		// Container configuration
		if len(svc.Template.Containers) > 0 {
			container := svc.Template.Containers[0]
			info.ContainerImage = container.Image

			// Port
			if len(container.Ports) > 0 {
				info.ContainerPort = container.Ports[0].ContainerPort
			}

			// Resources
			if container.Resources != nil {
				if container.Resources.Limits != nil {
					if cpu, ok := container.Resources.Limits["cpu"]; ok {
						info.CPULimit = cpu
					}
					if mem, ok := container.Resources.Limits["memory"]; ok {
						info.MemoryLimit = mem
					}
				}
			}

			// Environment variables
			info.EnvVarCount = len(container.Env)

			// Process each environment variable
			for _, env := range container.Env {
				envInfo := EnvVarInfo{
					Name: env.Name,
				}

				if env.ValueSource != nil && env.ValueSource.SecretKeyRef != nil {
					// Secret Manager reference
					info.SecretEnvVarCount++
					envInfo.Source = "secret-manager"
					envInfo.SecretName = env.ValueSource.SecretKeyRef.Secret
					envInfo.SecretVersion = env.ValueSource.SecretKeyRef.Version

					// Also add to SecretRefs
					info.SecretRefs = append(info.SecretRefs, SecretRefInfo{
						EnvVarName:    env.Name,
						SecretName:    env.ValueSource.SecretKeyRef.Secret,
						SecretVersion: env.ValueSource.SecretKeyRef.Version,
						Type:          "env",
					})
				} else {
					// Direct value
					envInfo.Source = "direct"
					envInfo.Value = env.Value
				}

				info.EnvVars = append(info.EnvVars, envInfo)
			}

			// Count secret volumes
			for _, vol := range container.VolumeMounts {
				// Check if this volume is a secret
				for _, svcVol := range svc.Template.Volumes {
					if svcVol.Name == vol.Name && svcVol.Secret != nil {
						info.SecretVolumeCount++
						info.SecretRefs = append(info.SecretRefs, SecretRefInfo{
							SecretName:    svcVol.Secret.Secret,
							SecretVersion: "latest",
							MountPath:     vol.MountPath,
							Type:          "volume",
						})
						break
					}
				}
			}

			// Detect hardcoded secrets in env vars
			info.HardcodedSecrets = detectHardcodedSecrets(container.Env)
		}

		// Check for default service account
		info.UsesDefaultSA = isDefaultServiceAccount(info.ServiceAccount, projectID)
	}

	return info
}

// parseJobInfo extracts relevant information from a Cloud Run job
func parseJobInfo(job *run.GoogleCloudRunV2Job, projectID string) JobInfo {
	info := JobInfo{
		Name:       extractName(job.Name),
		ProjectID:  projectID,
		Creator:    job.Creator,
		UpdateTime: job.UpdateTime,
	}

	// Extract region from job name
	parts := strings.Split(job.Name, "/")
	if len(parts) >= 4 {
		info.Region = parts[3]
	}

	// Last execution
	if job.LatestCreatedExecution != nil {
		info.LastExecution = job.LatestCreatedExecution.Name
	}

	// Template configuration
	if job.Template != nil {
		info.TaskCount = job.Template.TaskCount
		info.Parallelism = job.Template.Parallelism

		if job.Template.Template != nil {
			info.MaxRetries = job.Template.Template.MaxRetries
			info.Timeout = job.Template.Template.Timeout
			info.ServiceAccount = job.Template.Template.ServiceAccount

			// Container configuration
			if len(job.Template.Template.Containers) > 0 {
				container := job.Template.Template.Containers[0]
				info.ContainerImage = container.Image

				// Environment variables
				info.EnvVarCount = len(container.Env)

				// Process each environment variable
				for _, env := range container.Env {
					envInfo := EnvVarInfo{
						Name: env.Name,
					}

					if env.ValueSource != nil && env.ValueSource.SecretKeyRef != nil {
						// Secret Manager reference
						info.SecretEnvVarCount++
						envInfo.Source = "secret-manager"
						envInfo.SecretName = env.ValueSource.SecretKeyRef.Secret
						envInfo.SecretVersion = env.ValueSource.SecretKeyRef.Version

						// Also add to SecretRefs
						info.SecretRefs = append(info.SecretRefs, SecretRefInfo{
							EnvVarName:    env.Name,
							SecretName:    env.ValueSource.SecretKeyRef.Secret,
							SecretVersion: env.ValueSource.SecretKeyRef.Version,
							Type:          "env",
						})
					} else {
						// Direct value
						envInfo.Source = "direct"
						envInfo.Value = env.Value
					}

					info.EnvVars = append(info.EnvVars, envInfo)
				}

				// Count secret volumes
				for _, vol := range container.VolumeMounts {
					for _, jobVol := range job.Template.Template.Volumes {
						if jobVol.Name == vol.Name && jobVol.Secret != nil {
							info.SecretVolumeCount++
							info.SecretRefs = append(info.SecretRefs, SecretRefInfo{
								SecretName:    jobVol.Secret.Secret,
								SecretVersion: "latest",
								MountPath:     vol.MountPath,
								Type:          "volume",
							})
							break
						}
					}
				}

				// Detect hardcoded secrets in env vars
				info.HardcodedSecrets = detectHardcodedSecrets(container.Env)
			}

			// Check for default service account
			info.UsesDefaultSA = isDefaultServiceAccount(info.ServiceAccount, projectID)
		}
	}

	return info
}

// getServiceIAMPolicy retrieves the IAM policy for a Cloud Run service
func (cs *CloudRunService) getServiceIAMPolicy(service *run.Service, serviceName string) (*run.GoogleIamV1Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Locations.Services.GetIamPolicy(serviceName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// parseInvokerBindings extracts who can invoke the service and checks for public access
func parseInvokerBindings(policy *run.GoogleIamV1Policy) ([]string, bool) {
	var invokers []string
	isPublic := false

	for _, binding := range policy.Bindings {
		// Check for invoker role
		if binding.Role == "roles/run.invoker" {
			invokers = append(invokers, binding.Members...)

			// Check for public access
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					isPublic = true
				}
			}
		}
	}

	return invokers, isPublic
}

// extractName extracts just the resource name from the full resource name
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// secretPatterns maps env var name patterns to secret types
var secretPatterns = map[string]string{
	"PASSWORD":          "password",
	"PASSWD":            "password",
	"SECRET":            "secret",
	"API_KEY":           "api-key",
	"APIKEY":            "api-key",
	"API-KEY":           "api-key",
	"TOKEN":             "token",
	"ACCESS_TOKEN":      "token",
	"AUTH_TOKEN":        "token",
	"BEARER":            "token",
	"CREDENTIAL":        "credential",
	"PRIVATE_KEY":       "credential",
	"PRIVATEKEY":        "credential",
	"CONNECTION_STRING": "connection-string",
	"CONN_STR":          "connection-string",
	"DATABASE_URL":      "connection-string",
	"DB_PASSWORD":       "password",
	"DB_PASS":           "password",
	"MYSQL_PASSWORD":    "password",
	"POSTGRES_PASSWORD": "password",
	"REDIS_PASSWORD":    "password",
	"MONGODB_URI":       "connection-string",
	"AWS_ACCESS_KEY":    "credential",
	"AWS_SECRET":        "credential",
	"AZURE_KEY":         "credential",
	"GCP_KEY":           "credential",
	"ENCRYPTION_KEY":    "credential",
	"SIGNING_KEY":       "credential",
	"JWT_SECRET":        "credential",
	"SESSION_SECRET":    "credential",
	"OAUTH":             "credential",
	"CLIENT_SECRET":     "credential",
}

// detectHardcodedSecrets analyzes env vars to find potential hardcoded secrets
func detectHardcodedSecrets(envVars []*run.GoogleCloudRunV2EnvVar) []HardcodedSecret {
	var secrets []HardcodedSecret

	for _, env := range envVars {
		if env == nil {
			continue
		}

		// Skip if using Secret Manager reference
		if env.ValueSource != nil && env.ValueSource.SecretKeyRef != nil {
			continue
		}

		// Only flag if there's a direct value (not empty)
		if env.Value == "" {
			continue
		}

		envNameUpper := strings.ToUpper(env.Name)

		for pattern, secretType := range secretPatterns {
			if strings.Contains(envNameUpper, pattern) {
				secrets = append(secrets, HardcodedSecret{
					EnvVarName: env.Name,
					SecretType: secretType,
				})
				break
			}
		}
	}

	return secrets
}

// isDefaultServiceAccount checks if the service account is a default compute SA
func isDefaultServiceAccount(sa, projectID string) bool {
	if sa == "" {
		return true // Empty means using default
	}
	// Default compute SA pattern: {project-number}-compute@developer.gserviceaccount.com
	return strings.Contains(sa, "-compute@developer.gserviceaccount.com")
}
