package privescservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
)

type PrivescService struct {
	session *gcpinternal.SafeSession
}

func New() *PrivescService {
	return &PrivescService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *PrivescService {
	return &PrivescService{session: session}
}

// PrivescPath represents a privilege escalation opportunity
type PrivescPath struct {
	Principal      string   `json:"principal"`      // Who has this capability
	PrincipalType  string   `json:"principalType"`  // user, serviceAccount, group
	Method         string   `json:"method"`         // The privesc method name
	TargetResource string   `json:"targetResource"` // What resource they can escalate on
	Permissions    []string `json:"permissions"`    // Permissions enabling this
	RiskLevel      string   `json:"riskLevel"`      // CRITICAL, HIGH, MEDIUM
	Description    string   `json:"description"`    // Explanation
	ExploitCommand string   `json:"exploitCommand"` // Command to exploit
	ProjectID      string   `json:"projectId"`
}

// DangerousPermission represents a permission that enables privilege escalation
type DangerousPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`    // SA Impersonation, Key Creation, IAM Modification, etc.
	RiskLevel   string `json:"riskLevel"`   // CRITICAL, HIGH, MEDIUM
	Description string `json:"description"` // What this enables
}

// GetDangerousPermissions returns the list of known dangerous GCP permissions
func GetDangerousPermissions() []DangerousPermission {
	return []DangerousPermission{
		// Service Account Impersonation - CRITICAL
		{Permission: "iam.serviceAccounts.getAccessToken", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Generate access tokens for any SA"},
		{Permission: "iam.serviceAccounts.signBlob", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign blobs as SA (GCS signed URLs)"},
		{Permission: "iam.serviceAccounts.signJwt", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign JWTs as SA (impersonation)"},
		{Permission: "iam.serviceAccounts.implicitDelegation", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Delegate SA identity to others"},

		// Key Creation - CRITICAL
		{Permission: "iam.serviceAccountKeys.create", Category: "Key Creation", RiskLevel: "CRITICAL", Description: "Create persistent SA keys"},
		{Permission: "storage.hmacKeys.create", Category: "Key Creation", RiskLevel: "HIGH", Description: "Create HMAC keys for S3-compatible access"},

		// IAM Modification - CRITICAL
		{Permission: "resourcemanager.projects.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify project-level IAM policy"},
		{Permission: "resourcemanager.folders.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify folder-level IAM policy"},
		{Permission: "resourcemanager.organizations.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify org-level IAM policy"},
		{Permission: "iam.serviceAccounts.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant access to service accounts"},
		{Permission: "iam.roles.update", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Modify custom role permissions"},
		{Permission: "iam.roles.create", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Create new custom roles"},

		// Compute Access - HIGH
		{Permission: "compute.instances.setMetadata", Category: "Compute", RiskLevel: "HIGH", Description: "Modify instance metadata (SSH keys, startup scripts)"},
		{Permission: "compute.instances.setServiceAccount", Category: "Compute", RiskLevel: "HIGH", Description: "Change instance service account"},
		{Permission: "compute.projects.setCommonInstanceMetadata", Category: "Compute", RiskLevel: "HIGH", Description: "Modify project-wide metadata"},
		{Permission: "compute.instances.osLogin", Category: "Compute", RiskLevel: "MEDIUM", Description: "SSH into instances via OS Login"},
		{Permission: "compute.instances.osAdminLogin", Category: "Compute", RiskLevel: "HIGH", Description: "SSH with sudo via OS Login"},

		// Cloud Functions - HIGH
		{Permission: "cloudfunctions.functions.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy functions with SA identity"},
		{Permission: "cloudfunctions.functions.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify function code/SA"},
		{Permission: "cloudfunctions.functions.sourceCodeSet", Category: "Serverless", RiskLevel: "HIGH", Description: "Change function source code"},

		// Cloud Run - HIGH
		{Permission: "run.services.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy services with SA identity"},
		{Permission: "run.services.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify service code/SA"},

		// Cloud Build - HIGH
		{Permission: "cloudbuild.builds.create", Category: "CI/CD", RiskLevel: "HIGH", Description: "Run builds with Cloud Build SA"},
		{Permission: "cloudbuild.builds.update", Category: "CI/CD", RiskLevel: "HIGH", Description: "Modify build configurations"},

		// GKE - HIGH
		{Permission: "container.clusters.getCredentials", Category: "GKE", RiskLevel: "HIGH", Description: "Get GKE cluster credentials"},
		{Permission: "container.pods.exec", Category: "GKE", RiskLevel: "HIGH", Description: "Exec into pods"},
		{Permission: "container.secrets.get", Category: "GKE", RiskLevel: "HIGH", Description: "Read Kubernetes secrets"},

		// Storage - MEDIUM
		{Permission: "storage.buckets.setIamPolicy", Category: "Storage", RiskLevel: "MEDIUM", Description: "Modify bucket access"},
		{Permission: "storage.objects.create", Category: "Storage", RiskLevel: "MEDIUM", Description: "Upload objects to buckets"},

		// Secrets - HIGH
		{Permission: "secretmanager.versions.access", Category: "Secrets", RiskLevel: "HIGH", Description: "Access secret values"},
		{Permission: "secretmanager.secrets.setIamPolicy", Category: "Secrets", RiskLevel: "HIGH", Description: "Grant access to secrets"},

		// Org Policies - HIGH
		{Permission: "orgpolicy.policy.set", Category: "Org Policy", RiskLevel: "HIGH", Description: "Modify organization policies"},

		// Deployment Manager - HIGH
		{Permission: "deploymentmanager.deployments.create", Category: "Deployment", RiskLevel: "HIGH", Description: "Deploy resources with DM SA"},

		// API Keys - MEDIUM
		{Permission: "serviceusage.apiKeys.create", Category: "API Keys", RiskLevel: "MEDIUM", Description: "Create API keys"},

		// Actor permissions
		{Permission: "iam.serviceAccounts.actAs", Category: "SA Usage", RiskLevel: "HIGH", Description: "Use SA for resource creation"},
	}
}

// AnalyzeProjectPrivesc analyzes a project for privilege escalation paths
func (s *PrivescService) AnalyzeProjectPrivesc(projectID string) ([]PrivescPath, error) {
	ctx := context.Background()

	// Get project IAM policy
	var crmService *cloudresourcemanager.Service
	var err error

	if s.session != nil {
		crmService, err = cloudresourcemanager.NewService(ctx, s.session.GetClientOption())
	} else {
		crmService, err = cloudresourcemanager.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create CRM service: %v", err)
	}

	policy, err := crmService.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project IAM policy: %v", err)
	}

	var paths []PrivescPath

	// Get IAM service for role resolution
	var iamService *iam.Service
	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		// Continue without role resolution
		iamService = nil
	}

	// Analyze each binding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}

		// Get permissions for this role
		permissions := s.getRolePermissions(iamService, binding.Role, projectID)

		// Check each member for dangerous permissions
		for _, member := range binding.Members {
			memberPaths := s.analyzePermissionsForPrivesc(member, binding.Role, permissions, projectID)
			paths = append(paths, memberPaths...)
		}
	}

	return paths, nil
}

// getRolePermissions resolves a role to its permissions
func (s *PrivescService) getRolePermissions(iamService *iam.Service, role string, projectID string) []string {
	if iamService == nil {
		return []string{}
	}

	ctx := context.Background()

	// Handle different role types
	var roleInfo *iam.Role
	var err error

	if strings.HasPrefix(role, "roles/") {
		// Predefined role
		roleInfo, err = iamService.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "projects/") {
		// Project custom role
		roleInfo, err = iamService.Projects.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "organizations/") {
		// Org custom role
		roleInfo, err = iamService.Organizations.Roles.Get(role).Do()
	} else {
		// Assume predefined role format
		roleInfo, err = iamService.Roles.Get("roles/" + role).Do()
	}

	if err != nil {
		// Try to query testable permissions as fallback
		return s.getTestablePermissions(ctx, iamService, role, projectID)
	}

	return roleInfo.IncludedPermissions
}

// getTestablePermissions uses QueryTestablePermissions for complex cases
func (s *PrivescService) getTestablePermissions(ctx context.Context, iamService *iam.Service, role string, projectID string) []string {
	// This is a simplified version - in production you'd want more robust handling
	// For now, return known permissions for common roles
	knownRoles := map[string][]string{
		"roles/owner": {
			"iam.serviceAccounts.getAccessToken",
			"iam.serviceAccountKeys.create",
			"resourcemanager.projects.setIamPolicy",
			"compute.instances.setMetadata",
		},
		"roles/editor": {
			"compute.instances.setMetadata",
			"cloudfunctions.functions.create",
			"run.services.create",
		},
		"roles/iam.serviceAccountAdmin": {
			"iam.serviceAccountKeys.create",
			"iam.serviceAccounts.setIamPolicy",
		},
		"roles/iam.serviceAccountKeyAdmin": {
			"iam.serviceAccountKeys.create",
		},
		"roles/iam.serviceAccountTokenCreator": {
			"iam.serviceAccounts.getAccessToken",
			"iam.serviceAccounts.signBlob",
			"iam.serviceAccounts.signJwt",
		},
		"roles/compute.instanceAdmin": {
			"compute.instances.setMetadata",
			"compute.instances.setServiceAccount",
		},
		"roles/cloudfunctions.developer": {
			"cloudfunctions.functions.create",
			"cloudfunctions.functions.update",
		},
		"roles/run.admin": {
			"run.services.create",
			"run.services.update",
		},
		"roles/cloudbuild.builds.editor": {
			"cloudbuild.builds.create",
		},
	}

	if perms, ok := knownRoles[role]; ok {
		return perms
	}

	return []string{}
}

// analyzePermissionsForPrivesc checks if a set of permissions enables privilege escalation
func (s *PrivescService) analyzePermissionsForPrivesc(member, role string, permissions []string, projectID string) []PrivescPath {
	var paths []PrivescPath

	dangerousPerms := GetDangerousPermissions()
	dangerousMap := make(map[string]DangerousPermission)
	for _, dp := range dangerousPerms {
		dangerousMap[dp.Permission] = dp
	}

	// Check for direct dangerous permissions
	foundDangerous := make(map[string]DangerousPermission)
	for _, perm := range permissions {
		if dp, ok := dangerousMap[perm]; ok {
			foundDangerous[perm] = dp
		}
	}

	// Generate privesc paths based on found permissions
	principalType := getPrincipalType(member)
	cleanMember := cleanMemberName(member)

	// SA Token Creation
	if dp, ok := foundDangerous["iam.serviceAccounts.getAccessToken"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SA Token Creation",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can generate access tokens for any service account in the project",
			ExploitCommand: fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID),
			ProjectID:      projectID,
		})
	}

	// SA Key Creation
	if dp, ok := foundDangerous["iam.serviceAccountKeys.create"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "SA Key Creation",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can create persistent keys for any service account",
			ExploitCommand: fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID),
			ProjectID:      projectID,
		})
	}

	// Project IAM Modification
	if dp, ok := foundDangerous["resourcemanager.projects.setIamPolicy"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "Project IAM Modification",
			TargetResource: projectID,
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can modify project IAM policy to grant any role",
			ExploitCommand: fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member=user:attacker@evil.com --role=roles/owner", projectID),
			ProjectID:      projectID,
		})
	}

	// Compute Metadata Modification
	if dp, ok := foundDangerous["compute.instances.setMetadata"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "Compute Metadata Injection",
			TargetResource: "All project instances",
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can inject SSH keys or startup scripts into instances",
			ExploitCommand: "gcloud compute instances add-metadata INSTANCE --metadata=startup-script='#!/bin/bash\\nwhoami > /tmp/pwned'",
			ProjectID:      projectID,
		})
	}

	// Cloud Functions Deployment
	if _, ok := foundDangerous["cloudfunctions.functions.create"]; ok {
		if _, hasActAs := foundDangerous["iam.serviceAccounts.actAs"]; hasActAs {
			paths = append(paths, PrivescPath{
				Principal:      cleanMember,
				PrincipalType:  principalType,
				Method:         "Cloud Functions SA Abuse",
				TargetResource: "Cloud Functions",
				Permissions:    []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"},
				RiskLevel:      "HIGH",
				Description:    "Can deploy functions with privileged service account identity",
				ExploitCommand: "gcloud functions deploy pwned --runtime=python39 --trigger-http --service-account=PRIVILEGED_SA",
				ProjectID:      projectID,
			})
		}
	}

	// Cloud Build
	if dp, ok := foundDangerous["cloudbuild.builds.create"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "Cloud Build SA Abuse",
			TargetResource: "Cloud Build",
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can run builds with Cloud Build service account (often has elevated privileges)",
			ExploitCommand: "gcloud builds submit --config=cloudbuild.yaml .",
			ProjectID:      projectID,
		})
	}

	// GKE Credentials
	if dp, ok := foundDangerous["container.clusters.getCredentials"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "GKE Cluster Access",
			TargetResource: "All project GKE clusters",
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can get credentials for GKE clusters",
			ExploitCommand: "gcloud container clusters get-credentials CLUSTER_NAME --zone=ZONE",
			ProjectID:      projectID,
		})
	}

	// Secret Access
	if dp, ok := foundDangerous["secretmanager.versions.access"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "Secret Access",
			TargetResource: "All project secrets",
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can read secret values from Secret Manager",
			ExploitCommand: "gcloud secrets versions access latest --secret=SECRET_NAME",
			ProjectID:      projectID,
		})
	}

	// SignBlob for GCS Signed URLs
	if dp, ok := foundDangerous["iam.serviceAccounts.signBlob"]; ok {
		paths = append(paths, PrivescPath{
			Principal:      cleanMember,
			PrincipalType:  principalType,
			Method:         "GCS Signed URL Generation",
			TargetResource: "All project service accounts",
			Permissions:    []string{dp.Permission},
			RiskLevel:      dp.RiskLevel,
			Description:    "Can sign blobs as SA to generate GCS signed URLs",
			ExploitCommand: "gsutil signurl -u TARGET_SA@project.iam.gserviceaccount.com gs://bucket/object",
			ProjectID:      projectID,
		})
	}

	return paths
}

// getPrincipalType determines the type of principal from the member string
func getPrincipalType(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	} else if strings.HasPrefix(member, "serviceAccount:") {
		return "serviceAccount"
	} else if strings.HasPrefix(member, "group:") {
		return "group"
	} else if strings.HasPrefix(member, "domain:") {
		return "domain"
	} else if member == "allUsers" {
		return "allUsers"
	} else if member == "allAuthenticatedUsers" {
		return "allAuthenticatedUsers"
	}
	return "unknown"
}

// cleanMemberName removes the prefix from member string
func cleanMemberName(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return member
}
