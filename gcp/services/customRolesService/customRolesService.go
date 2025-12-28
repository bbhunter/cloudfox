package customrolesservice

import (
	"context"
	"fmt"
	"strings"

	iam "google.golang.org/api/iam/v1"
)

type CustomRolesService struct{}

func New() *CustomRolesService {
	return &CustomRolesService{}
}

// CustomRoleInfo represents a custom IAM role
type CustomRoleInfo struct {
	Name                string   `json:"name"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	ProjectID           string   `json:"projectId"`
	Stage               string   `json:"stage"`  // ALPHA, BETA, GA, DEPRECATED
	Deleted             bool     `json:"deleted"`
	IncludedPermissions []string `json:"includedPermissions"`
	PermissionCount     int      `json:"permissionCount"`

	// Security analysis
	RiskLevel           string   `json:"riskLevel"`
	RiskReasons         []string `json:"riskReasons"`
	DangerousPerms      []string `json:"dangerousPermissions"`
	PrivescPerms        []string `json:"privescPermissions"`
}

// RolePermissionAnalysis contains detailed analysis of role permissions
type RolePermissionAnalysis struct {
	RoleName           string            `json:"roleName"`
	ProjectID          string            `json:"projectId"`
	TotalPermissions   int               `json:"totalPermissions"`
	DangerousCount     int               `json:"dangerousCount"`
	PrivescCount       int               `json:"privescCount"`
	PermissionsByType  map[string]int    `json:"permissionsByType"`
	RiskLevel          string            `json:"riskLevel"`
	RiskReasons        []string          `json:"riskReasons"`
	ExploitCommands    []string          `json:"exploitCommands"`
}

// DangerousPermission defines a dangerous permission with its risk category
type DangerousPermission struct {
	Permission  string
	Category    string // privesc, data_exfil, persistence, lateral_movement
	Description string
	RiskLevel   string // CRITICAL, HIGH, MEDIUM
}

// GetDangerousPermissions returns the list of dangerous permissions
func (s *CustomRolesService) GetDangerousPermissions() []DangerousPermission {
	return []DangerousPermission{
		// Privilege Escalation - CRITICAL
		{Permission: "iam.serviceAccountKeys.create", Category: "privesc", Description: "Create SA keys for persistent access", RiskLevel: "CRITICAL"},
		{Permission: "iam.serviceAccountTokenCreator", Category: "privesc", Description: "Generate access tokens for any SA", RiskLevel: "CRITICAL"},
		{Permission: "iam.serviceAccounts.getAccessToken", Category: "privesc", Description: "Get access token for SA", RiskLevel: "CRITICAL"},
		{Permission: "iam.serviceAccounts.signBlob", Category: "privesc", Description: "Sign blobs as SA", RiskLevel: "CRITICAL"},
		{Permission: "iam.serviceAccounts.signJwt", Category: "privesc", Description: "Sign JWTs as SA", RiskLevel: "CRITICAL"},
		{Permission: "iam.serviceAccounts.implicitDelegation", Category: "privesc", Description: "Implicit delegation for SA", RiskLevel: "CRITICAL"},
		{Permission: "iam.serviceAccounts.actAs", Category: "privesc", Description: "Act as service account", RiskLevel: "CRITICAL"},
		{Permission: "resourcemanager.projects.setIamPolicy", Category: "privesc", Description: "Modify project IAM", RiskLevel: "CRITICAL"},
		{Permission: "iam.roles.create", Category: "privesc", Description: "Create custom roles", RiskLevel: "HIGH"},
		{Permission: "iam.roles.update", Category: "privesc", Description: "Modify custom roles", RiskLevel: "HIGH"},
		{Permission: "deploymentmanager.deployments.create", Category: "privesc", Description: "Deploy resources with elevated perms", RiskLevel: "HIGH"},
		{Permission: "cloudfunctions.functions.setIamPolicy", Category: "privesc", Description: "Modify function IAM", RiskLevel: "HIGH"},
		{Permission: "run.services.setIamPolicy", Category: "privesc", Description: "Modify Cloud Run IAM", RiskLevel: "HIGH"},

		// Data Exfiltration - HIGH
		{Permission: "storage.objects.get", Category: "data_exfil", Description: "Read storage objects", RiskLevel: "MEDIUM"},
		{Permission: "storage.objects.list", Category: "data_exfil", Description: "List storage objects", RiskLevel: "LOW"},
		{Permission: "bigquery.tables.getData", Category: "data_exfil", Description: "Read BigQuery data", RiskLevel: "HIGH"},
		{Permission: "secretmanager.versions.access", Category: "data_exfil", Description: "Access secret values", RiskLevel: "CRITICAL"},
		{Permission: "cloudkms.cryptoKeyVersions.useToDecrypt", Category: "data_exfil", Description: "Decrypt with KMS keys", RiskLevel: "HIGH"},

		// Persistence - HIGH
		{Permission: "compute.instances.setMetadata", Category: "persistence", Description: "Modify instance metadata/SSH keys", RiskLevel: "HIGH"},
		{Permission: "compute.projects.setCommonInstanceMetadata", Category: "persistence", Description: "Modify project-wide metadata", RiskLevel: "HIGH"},
		{Permission: "cloudfunctions.functions.create", Category: "persistence", Description: "Create cloud functions", RiskLevel: "MEDIUM"},
		{Permission: "cloudfunctions.functions.update", Category: "persistence", Description: "Update cloud functions", RiskLevel: "MEDIUM"},
		{Permission: "run.services.create", Category: "persistence", Description: "Create Cloud Run services", RiskLevel: "MEDIUM"},
		{Permission: "compute.instances.create", Category: "persistence", Description: "Create compute instances", RiskLevel: "MEDIUM"},

		// Lateral Movement - HIGH
		{Permission: "compute.instances.setServiceAccount", Category: "lateral_movement", Description: "Change instance SA", RiskLevel: "HIGH"},
		{Permission: "container.clusters.getCredentials", Category: "lateral_movement", Description: "Get GKE cluster credentials", RiskLevel: "HIGH"},
		{Permission: "cloudsql.instances.connect", Category: "lateral_movement", Description: "Connect to Cloud SQL", RiskLevel: "MEDIUM"},

		// Organization/Folder level - CRITICAL
		{Permission: "resourcemanager.organizations.setIamPolicy", Category: "privesc", Description: "Modify org-level IAM", RiskLevel: "CRITICAL"},
		{Permission: "resourcemanager.folders.setIamPolicy", Category: "privesc", Description: "Modify folder IAM", RiskLevel: "CRITICAL"},

		// Logging/Audit - HIGH (covering tracks)
		{Permission: "logging.sinks.delete", Category: "persistence", Description: "Delete log sinks", RiskLevel: "HIGH"},
		{Permission: "logging.logs.delete", Category: "persistence", Description: "Delete logs", RiskLevel: "HIGH"},
	}
}

// ListCustomRoles lists all custom roles in a project
func (s *CustomRolesService) ListCustomRoles(projectID string) ([]CustomRoleInfo, error) {
	ctx := context.Background()

	iamService, err := iam.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	var roles []CustomRoleInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	req := iamService.Projects.Roles.List(parent).ShowDeleted(false)
	err = req.Pages(ctx, func(page *iam.ListRolesResponse) error {
		for _, role := range page.Roles {
			// Get full role details including permissions
			roleDetail, err := iamService.Projects.Roles.Get(role.Name).Do()
			if err != nil {
				continue
			}

			info := CustomRoleInfo{
				Name:                extractRoleID(role.Name),
				Title:               role.Title,
				Description:         role.Description,
				ProjectID:           projectID,
				Stage:               role.Stage,
				Deleted:             role.Deleted,
				IncludedPermissions: roleDetail.IncludedPermissions,
				PermissionCount:     len(roleDetail.IncludedPermissions),
				RiskReasons:         []string{},
			}

			// Analyze the role
			info.RiskLevel, info.RiskReasons, info.DangerousPerms, info.PrivescPerms = s.analyzeRole(info)

			roles = append(roles, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list custom roles: %v", err)
	}

	return roles, nil
}

// AnalyzeRoleInDepth performs detailed security analysis on a role
func (s *CustomRolesService) AnalyzeRoleInDepth(role CustomRoleInfo) RolePermissionAnalysis {
	analysis := RolePermissionAnalysis{
		RoleName:          role.Name,
		ProjectID:         role.ProjectID,
		TotalPermissions:  role.PermissionCount,
		PermissionsByType: make(map[string]int),
		RiskReasons:       []string{},
		ExploitCommands:   []string{},
	}

	dangerousPerms := s.GetDangerousPermissions()
	dangerousMap := make(map[string]DangerousPermission)
	for _, dp := range dangerousPerms {
		dangerousMap[dp.Permission] = dp
	}

	// Categorize permissions
	for _, perm := range role.IncludedPermissions {
		// Extract service from permission (e.g., "storage" from "storage.objects.get")
		parts := strings.Split(perm, ".")
		if len(parts) > 0 {
			service := parts[0]
			analysis.PermissionsByType[service]++
		}

		// Check if dangerous
		if dp, found := dangerousMap[perm]; found {
			if dp.Category == "privesc" {
				analysis.PrivescCount++
			}
			analysis.DangerousCount++
			analysis.RiskReasons = append(analysis.RiskReasons,
				fmt.Sprintf("[%s] %s: %s", dp.RiskLevel, perm, dp.Description))
		}
	}

	// Generate exploitation commands based on permissions
	for _, perm := range role.IncludedPermissions {
		switch {
		case strings.Contains(perm, "serviceAccountKeys.create"):
			analysis.ExploitCommands = append(analysis.ExploitCommands,
				fmt.Sprintf("# Create SA key (role has %s):\ngcloud iam service-accounts keys create key.json --iam-account=TARGET_SA@%s.iam.gserviceaccount.com",
					perm, role.ProjectID))
		case strings.Contains(perm, "serviceAccounts.getAccessToken"):
			analysis.ExploitCommands = append(analysis.ExploitCommands,
				fmt.Sprintf("# Get access token (role has %s):\ngcloud auth print-access-token --impersonate-service-account=TARGET_SA@%s.iam.gserviceaccount.com",
					perm, role.ProjectID))
		case strings.Contains(perm, "secretmanager.versions.access"):
			analysis.ExploitCommands = append(analysis.ExploitCommands,
				fmt.Sprintf("# Access secrets (role has %s):\ngcloud secrets versions access latest --secret=SECRET_NAME --project=%s",
					perm, role.ProjectID))
		case strings.Contains(perm, "setIamPolicy"):
			analysis.ExploitCommands = append(analysis.ExploitCommands,
				fmt.Sprintf("# Modify IAM policy (role has %s):\n# This allows privilege escalation by granting yourself additional roles",
					perm))
		}
	}

	// Determine risk level
	if analysis.PrivescCount >= 2 {
		analysis.RiskLevel = "CRITICAL"
	} else if analysis.PrivescCount == 1 || analysis.DangerousCount >= 3 {
		analysis.RiskLevel = "HIGH"
	} else if analysis.DangerousCount >= 1 {
		analysis.RiskLevel = "MEDIUM"
	} else {
		analysis.RiskLevel = "LOW"
	}

	return analysis
}

// analyzeRole performs security analysis on a custom role
func (s *CustomRolesService) analyzeRole(role CustomRoleInfo) (riskLevel string, reasons []string, dangerousPerms []string, privescPerms []string) {
	dangerousPermList := s.GetDangerousPermissions()
	dangerousMap := make(map[string]DangerousPermission)
	for _, dp := range dangerousPermList {
		dangerousMap[dp.Permission] = dp
	}

	score := 0

	for _, perm := range role.IncludedPermissions {
		if dp, found := dangerousMap[perm]; found {
			dangerousPerms = append(dangerousPerms, perm)
			if dp.Category == "privesc" {
				privescPerms = append(privescPerms, perm)
				score += 3
				reasons = append(reasons, fmt.Sprintf("Privesc permission: %s", perm))
			} else if dp.RiskLevel == "CRITICAL" {
				score += 2
				reasons = append(reasons, fmt.Sprintf("Critical permission: %s", perm))
			} else if dp.RiskLevel == "HIGH" {
				score += 1
				reasons = append(reasons, fmt.Sprintf("High-risk permission: %s", perm))
			}
		}

		// Check for wildcard permissions
		if strings.HasSuffix(perm, ".*") || strings.Contains(perm, "All") {
			reasons = append(reasons, fmt.Sprintf("Broad permission: %s", perm))
			score += 1
		}
	}

	// Large number of permissions is a risk indicator
	if role.PermissionCount > 50 {
		reasons = append(reasons, fmt.Sprintf("Large role with %d permissions", role.PermissionCount))
		score += 1
	}

	if score >= 6 {
		riskLevel = "CRITICAL"
	} else if score >= 3 {
		riskLevel = "HIGH"
	} else if score >= 1 {
		riskLevel = "MEDIUM"
	} else {
		riskLevel = "LOW"
	}

	return
}

// extractRoleID extracts the role ID from the full name
func extractRoleID(name string) string {
	// Format: projects/PROJECT_ID/roles/ROLE_ID
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}
