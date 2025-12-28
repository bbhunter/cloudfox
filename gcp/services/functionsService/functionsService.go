package functionsservice

import (
	"context"
	"fmt"
	"strings"

	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
)

type FunctionsService struct{}

func New() *FunctionsService {
	return &FunctionsService{}
}

// FunctionInfo holds Cloud Function details with security-relevant information
type FunctionInfo struct {
	// Basic info
	Name        string
	ProjectID   string
	Region      string
	State       string
	Description string

	// Runtime info
	Runtime        string
	EntryPoint     string
	BuildID        string
	UpdateTime     string

	// Security-relevant configuration
	ServiceAccount       string
	IngressSettings      string  // ALL_TRAFFIC, INTERNAL_ONLY, INTERNAL_AND_GCLB
	VPCConnector         string
	VPCEgressSettings    string  // PRIVATE_RANGES_ONLY, ALL_TRAFFIC
	AllTrafficOnLatest   bool

	// Trigger info
	TriggerType          string  // HTTP, Pub/Sub, Cloud Storage, etc.
	TriggerURL           string  // For HTTP functions
	TriggerEventType     string
	TriggerResource      string

	// Environment variables (sanitized - just names, not values)
	EnvVarCount          int
	SecretEnvVarCount    int
	SecretVolumeCount    int

	// IAM (if retrieved)
	InvokerMembers       []string  // Who can invoke this function
	IsPublic             bool      // allUsers or allAuthenticatedUsers can invoke

	// Pentest-specific fields
	EnvVarNames          []string  // Names of env vars (may hint at secrets)
	SecretEnvVarNames    []string  // Names of secret env vars
	SecretVolumeNames    []string  // Names of secret volumes
	SourceLocation       string    // GCS or repo source location
	SourceType           string    // GCS, Repository
	RiskLevel            string    // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons          []string  // Why it's risky
}

// FunctionSecurityAnalysis contains detailed security analysis for a function
type FunctionSecurityAnalysis struct {
	FunctionName     string   `json:"functionName"`
	ProjectID        string   `json:"projectId"`
	Region           string   `json:"region"`
	ServiceAccount   string   `json:"serviceAccount"`
	IsPublic         bool     `json:"isPublic"`
	TriggerURL       string   `json:"triggerURL"`
	RiskLevel        string   `json:"riskLevel"`
	RiskReasons      []string `json:"riskReasons"`
	ExploitCommands  []string `json:"exploitCommands"`
}

// Functions retrieves all Cloud Functions in a project across all regions
func (fs *FunctionsService) Functions(projectID string) ([]FunctionInfo, error) {
	ctx := context.Background()

	service, err := cloudfunctions.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Functions service: %v", err)
	}

	var functions []FunctionInfo

	// List functions across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	call := service.Projects.Locations.Functions.List(parent)
	err = call.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			info := parseFunctionInfo(fn, projectID)

			// Try to get IAM policy
			iamPolicy, iamErr := fs.getFunctionIAMPolicy(service, fn.Name)
			if iamErr == nil && iamPolicy != nil {
				info.InvokerMembers, info.IsPublic = parseInvokerBindings(iamPolicy)
			}

			functions = append(functions, info)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list functions: %v", err)
	}

	return functions, nil
}

// parseFunctionInfo extracts relevant information from a Cloud Function
func parseFunctionInfo(fn *cloudfunctions.Function, projectID string) FunctionInfo {
	info := FunctionInfo{
		Name:        extractFunctionName(fn.Name),
		ProjectID:   projectID,
		State:       fn.State,
		RiskReasons: []string{},
	}

	// Extract region from function name
	// Format: projects/{project}/locations/{location}/functions/{name}
	parts := strings.Split(fn.Name, "/")
	if len(parts) >= 4 {
		info.Region = parts[3]
	}

	// Build configuration
	if fn.BuildConfig != nil {
		info.Runtime = fn.BuildConfig.Runtime
		info.EntryPoint = fn.BuildConfig.EntryPoint
		info.BuildID = fn.BuildConfig.Build

		// Extract source location (pentest-relevant)
		if fn.BuildConfig.Source != nil {
			if fn.BuildConfig.Source.StorageSource != nil {
				info.SourceType = "GCS"
				info.SourceLocation = fmt.Sprintf("gs://%s/%s",
					fn.BuildConfig.Source.StorageSource.Bucket,
					fn.BuildConfig.Source.StorageSource.Object)
			} else if fn.BuildConfig.Source.RepoSource != nil {
				info.SourceType = "Repository"
				info.SourceLocation = fmt.Sprintf("%s/%s@%s",
					fn.BuildConfig.Source.RepoSource.ProjectId,
					fn.BuildConfig.Source.RepoSource.RepoName,
					fn.BuildConfig.Source.RepoSource.BranchName)
			}
		}
	}

	// Service configuration
	if fn.ServiceConfig != nil {
		info.ServiceAccount = fn.ServiceConfig.ServiceAccountEmail
		info.IngressSettings = fn.ServiceConfig.IngressSettings
		info.VPCConnector = fn.ServiceConfig.VpcConnector
		info.VPCEgressSettings = fn.ServiceConfig.VpcConnectorEgressSettings
		info.AllTrafficOnLatest = fn.ServiceConfig.AllTrafficOnLatestRevision

		// Extract environment variable names (pentest-relevant - may hint at secrets)
		if fn.ServiceConfig.EnvironmentVariables != nil {
			info.EnvVarCount = len(fn.ServiceConfig.EnvironmentVariables)
			for key := range fn.ServiceConfig.EnvironmentVariables {
				info.EnvVarNames = append(info.EnvVarNames, key)
			}
		}

		// Extract secret environment variable names
		if fn.ServiceConfig.SecretEnvironmentVariables != nil {
			info.SecretEnvVarCount = len(fn.ServiceConfig.SecretEnvironmentVariables)
			for _, secret := range fn.ServiceConfig.SecretEnvironmentVariables {
				if secret != nil {
					info.SecretEnvVarNames = append(info.SecretEnvVarNames, secret.Key)
				}
			}
		}

		// Extract secret volume names
		if fn.ServiceConfig.SecretVolumes != nil {
			info.SecretVolumeCount = len(fn.ServiceConfig.SecretVolumes)
			for _, vol := range fn.ServiceConfig.SecretVolumes {
				if vol != nil {
					info.SecretVolumeNames = append(info.SecretVolumeNames, vol.Secret)
				}
			}
		}

		// Get HTTP trigger URL from service config
		info.TriggerURL = fn.ServiceConfig.Uri
	}

	// Event trigger configuration
	if fn.EventTrigger != nil {
		info.TriggerType = "Event"
		info.TriggerEventType = fn.EventTrigger.EventType
		info.TriggerResource = fn.EventTrigger.PubsubTopic
		if info.TriggerResource == "" {
			info.TriggerResource = fn.EventTrigger.Channel
		}
	} else if info.TriggerURL != "" {
		info.TriggerType = "HTTP"
	}

	info.Description = fn.Description
	info.UpdateTime = fn.UpdateTime

	return info
}

// getFunctionIAMPolicy retrieves the IAM policy for a function
func (fs *FunctionsService) getFunctionIAMPolicy(service *cloudfunctions.Service, functionName string) (*cloudfunctions.Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Locations.Functions.GetIamPolicy(functionName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// parseInvokerBindings extracts who can invoke the function and checks for public access
func parseInvokerBindings(policy *cloudfunctions.Policy) ([]string, bool) {
	var invokers []string
	isPublic := false

	for _, binding := range policy.Bindings {
		// Check for invoker roles
		if binding.Role == "roles/cloudfunctions.invoker" ||
		   binding.Role == "roles/run.invoker" {
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

// extractFunctionName extracts just the function name from the full resource name
func extractFunctionName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// AnalyzeFunctionSecurity performs security analysis on a function
func (fs *FunctionsService) AnalyzeFunctionSecurity(fn FunctionInfo) FunctionSecurityAnalysis {
	analysis := FunctionSecurityAnalysis{
		FunctionName:    fn.Name,
		ProjectID:       fn.ProjectID,
		Region:          fn.Region,
		ServiceAccount:  fn.ServiceAccount,
		IsPublic:        fn.IsPublic,
		TriggerURL:      fn.TriggerURL,
		RiskReasons:     []string{},
		ExploitCommands: []string{},
	}

	score := 0

	// Check for public access (CRITICAL)
	if fn.IsPublic {
		analysis.RiskReasons = append(analysis.RiskReasons,
			"Function is publicly accessible (allUsers/allAuthenticatedUsers)")
		if fn.TriggerURL != "" {
			analysis.ExploitCommands = append(analysis.ExploitCommands,
				fmt.Sprintf("# PUBLIC function - direct access:\ncurl -s '%s'", fn.TriggerURL))
		}
		score += 3
	}

	// Check ingress settings
	if fn.IngressSettings == "ALLOW_ALL" || fn.IngressSettings == "ALL_TRAFFIC" {
		analysis.RiskReasons = append(analysis.RiskReasons,
			"Function allows all ingress traffic")
		score += 1
	}

	// Check for default service account (often over-privileged)
	if strings.Contains(fn.ServiceAccount, "-compute@developer.gserviceaccount.com") ||
		strings.Contains(fn.ServiceAccount, "@appspot.gserviceaccount.com") {
		analysis.RiskReasons = append(analysis.RiskReasons,
			"Uses default service account (often has excessive permissions)")
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			fmt.Sprintf("# Check default SA permissions:\ngcloud projects get-iam-policy %s --flatten='bindings[].members' --filter='bindings.members:%s'",
				fn.ProjectID, fn.ServiceAccount))
		score += 2
	}

	// Check for secrets (potential for exfiltration if function is compromised)
	if fn.SecretEnvVarCount > 0 || fn.SecretVolumeCount > 0 {
		analysis.RiskReasons = append(analysis.RiskReasons,
			fmt.Sprintf("Function has access to %d secret env vars and %d secret volumes",
				fn.SecretEnvVarCount, fn.SecretVolumeCount))
		score += 1
	}

	// Check for sensitive env var names
	sensitiveVars := []string{}
	for _, varName := range fn.EnvVarNames {
		if containsSensitiveKeyword(varName) {
			sensitiveVars = append(sensitiveVars, varName)
		}
	}
	if len(sensitiveVars) > 0 {
		analysis.RiskReasons = append(analysis.RiskReasons,
			fmt.Sprintf("Environment variables with sensitive names: %s", strings.Join(sensitiveVars, ", ")))
		score += 1
	}

	// Check VPC connector (lateral movement potential)
	if fn.VPCConnector != "" {
		analysis.RiskReasons = append(analysis.RiskReasons,
			fmt.Sprintf("Function has VPC connector: %s (lateral movement potential)", fn.VPCConnector))
		score += 1
	}

	// Source code access
	if fn.SourceLocation != "" && fn.SourceType == "GCS" {
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			fmt.Sprintf("# Download function source code:\ngsutil cp %s ./function-source.zip && unzip function-source.zip",
				fn.SourceLocation))
	}

	// Add general enumeration commands
	analysis.ExploitCommands = append(analysis.ExploitCommands,
		fmt.Sprintf("# Get function details:\ngcloud functions describe %s --region=%s --project=%s --gen2",
			fn.Name, fn.Region, fn.ProjectID))

	if fn.TriggerType == "HTTP" && fn.TriggerURL != "" {
		analysis.ExploitCommands = append(analysis.ExploitCommands,
			fmt.Sprintf("# Invoke function with auth:\ncurl -s -X POST '%s' -H 'Authorization: Bearer $(gcloud auth print-identity-token)' -H 'Content-Type: application/json' -d '{}'",
				fn.TriggerURL))
	}

	// Determine risk level
	if score >= 4 {
		analysis.RiskLevel = "CRITICAL"
	} else if score >= 3 {
		analysis.RiskLevel = "HIGH"
	} else if score >= 2 {
		analysis.RiskLevel = "MEDIUM"
	} else if score >= 1 {
		analysis.RiskLevel = "LOW"
	} else {
		analysis.RiskLevel = "INFO"
	}

	return analysis
}

// containsSensitiveKeyword checks if a variable name might contain secrets
func containsSensitiveKeyword(name string) bool {
	sensitiveKeywords := []string{
		"SECRET", "PASSWORD", "PASSWD", "PWD",
		"TOKEN", "KEY", "CREDENTIAL", "CRED",
		"AUTH", "API_KEY", "APIKEY", "PRIVATE",
		"DATABASE", "DB_PASS", "MONGO", "MYSQL",
		"POSTGRES", "REDIS", "WEBHOOK", "SLACK",
		"SENDGRID", "STRIPE", "AWS", "AZURE",
	}

	upperName := strings.ToUpper(name)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(upperName, keyword) {
			return true
		}
	}
	return false
}
