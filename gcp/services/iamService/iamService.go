package iamservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

type IAMService struct {
	session *gcpinternal.SafeSession
}

// New creates a new IAMService (legacy - uses ADC directly)
func New() *IAMService {
	return &IAMService{}
}

// NewWithSession creates an IAMService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *IAMService {
	return &IAMService{session: session}
}

// getClientOption returns the appropriate client option based on session
func (s *IAMService) getClientOption() option.ClientOption {
	if s.session != nil {
		return s.session.GetClientOption()
	}
	return nil
}

// AncestryResource represents a single resource in the project's ancestry.
type AncestryResource struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// IAMCondition represents a parsed IAM condition (conditional access policy)
type IAMCondition struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Expression  string `json:"expression"`
}

// PolicyBindings represents IAM policy bindings.
type PolicyBinding struct {
	Role          string        `json:"role"`
	Members       []string      `json:"members"`
	ResourceID    string        `json:"resourceID"`
	ResourceType  string        `json:"resourceType"`
	PolicyName    string        `json:"policyBindings"`
	Condition     string        `json:"condition"`
	ConditionInfo *IAMCondition `json:"conditionInfo"` // Parsed condition details
	HasCondition  bool          `json:"hasCondition"`  // True if binding has conditions
	IsInherited   bool          `json:"isInherited"`   // True if inherited from folder/org
	InheritedFrom string        `json:"inheritedFrom"` // Source of inheritance (folder/org ID)
}

type PrincipalWithRoles struct {
	Name           string          `json:"name"`
	Type           string          `json:"type"`
	PolicyBindings []PolicyBinding `json:"policyBindings"`
	ResourceID     string          `json:"resourceID"`
	ResourceType   string          `json:"resourceType"`
	// Enhanced fields
	Email          string          `json:"email"`          // Clean email without prefix
	DisplayName    string          `json:"displayName"`    // For service accounts
	Description    string          `json:"description"`    // For service accounts
	Disabled       bool            `json:"disabled"`       // For service accounts
	UniqueID       string          `json:"uniqueId"`       // For service accounts
	HasKeys        bool            `json:"hasKeys"`        // Service account has user-managed keys
	KeyCount       int             `json:"keyCount"`       // Number of user-managed keys
	HasCustomRoles bool            `json:"hasCustomRoles"` // Has any custom roles assigned
	CustomRoles    []string        `json:"customRoles"`    // List of custom role names
}

// ServiceAccountInfo represents detailed info about a service account
type ServiceAccountInfo struct {
	Email            string    `json:"email"`
	Name             string    `json:"name"`             // Full resource name
	ProjectID        string    `json:"projectId"`
	UniqueID         string    `json:"uniqueId"`
	DisplayName      string    `json:"displayName"`
	Description      string    `json:"description"`
	Disabled         bool      `json:"disabled"`
	OAuth2ClientID   string    `json:"oauth2ClientId"`
	// Key information
	HasKeys          bool      `json:"hasKeys"`
	KeyCount         int       `json:"keyCount"`
	Keys             []ServiceAccountKeyInfo `json:"keys"`
	// Role information
	Roles            []string  `json:"roles"`
	HasCustomRoles   bool      `json:"hasCustomRoles"`
	CustomRoles      []string  `json:"customRoles"`
	HasHighPrivilege bool      `json:"hasHighPrivilege"`
	HighPrivRoles    []string  `json:"highPrivRoles"`
	// Pentest: Impersonation information
	CanBeImpersonatedBy    []string `json:"canBeImpersonatedBy"`    // Principals who can impersonate this SA
	CanCreateKeysBy        []string `json:"canCreateKeysBy"`        // Principals who can create keys for this SA
	CanGetAccessTokenBy    []string `json:"canGetAccessTokenBy"`    // Principals with getAccessToken
	CanSignBlobBy          []string `json:"canSignBlobBy"`          // Principals with signBlob
	CanSignJwtBy           []string `json:"canSignJwtBy"`           // Principals with signJwt
	HasImpersonationRisk   bool     `json:"hasImpersonationRisk"`   // True if any impersonation path exists
	ImpersonationRiskLevel string   `json:"impersonationRiskLevel"` // CRITICAL, HIGH, MEDIUM, LOW
}

// SAImpersonationInfo represents who can impersonate/abuse a service account
type SAImpersonationInfo struct {
	ServiceAccount      string   `json:"serviceAccount"`
	ProjectID           string   `json:"projectId"`
	TokenCreators       []string `json:"tokenCreators"`       // iam.serviceAccounts.getAccessToken
	KeyCreators         []string `json:"keyCreators"`         // iam.serviceAccountKeys.create
	SignBlobUsers       []string `json:"signBlobUsers"`       // iam.serviceAccounts.signBlob
	SignJwtUsers        []string `json:"signJwtUsers"`        // iam.serviceAccounts.signJwt
	ImplicitDelegators  []string `json:"implicitDelegators"`  // iam.serviceAccounts.implicitDelegation
	ActAsUsers          []string `json:"actAsUsers"`          // iam.serviceAccounts.actAs
	SAAdmins            []string `json:"saAdmins"`            // iam.serviceAccounts.* (full admin)
	RiskLevel           string   `json:"riskLevel"`
	RiskReasons         []string `json:"riskReasons"`
}

// ServiceAccountKeyInfo represents a service account key
type ServiceAccountKeyInfo struct {
	Name           string    `json:"name"`
	KeyAlgorithm   string    `json:"keyAlgorithm"`
	KeyOrigin      string    `json:"keyOrigin"`      // GOOGLE_PROVIDED or USER_PROVIDED
	KeyType        string    `json:"keyType"`        // USER_MANAGED or SYSTEM_MANAGED
	ValidAfter     time.Time `json:"validAfter"`
	ValidBefore    time.Time `json:"validBefore"`
	Disabled       bool      `json:"disabled"`
}

// CustomRole represents a custom IAM role
type CustomRole struct {
	Name                string   `json:"name"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	IncludedPermissions []string `json:"includedPermissions"`
	Stage               string   `json:"stage"`          // ALPHA, BETA, GA, DEPRECATED, DISABLED
	Deleted             bool     `json:"deleted"`
	Etag                string   `json:"etag"`
	ProjectID           string   `json:"projectId"`      // Empty if org-level
	OrgID               string   `json:"orgId"`          // Empty if project-level
	IsProjectLevel      bool     `json:"isProjectLevel"`
	PermissionCount     int      `json:"permissionCount"`
}

// GroupMember represents a member of a Google Group
type GroupMember struct {
	Email      string `json:"email"`
	Type       string `json:"type"`       // USER, SERVICE_ACCOUNT, GROUP (nested)
	Role       string `json:"role"`       // OWNER, MANAGER, MEMBER
	Status     string `json:"status"`     // ACTIVE, SUSPENDED, etc.
	IsExternal bool   `json:"isExternal"` // External to the organization
}

// GroupInfo represents a Google Group (for tracking group memberships)
type GroupInfo struct {
	Email         string        `json:"email"`
	DisplayName   string        `json:"displayName"`
	Description   string        `json:"description"`
	Roles         []string      `json:"roles"`         // Roles assigned to this group
	ProjectID     string        `json:"projectId"`
	Members       []GroupMember `json:"members"`       // Direct members of this group
	NestedGroups  []string      `json:"nestedGroups"`  // Groups that are members of this group
	MemberCount   int           `json:"memberCount"`   // Total direct members
	HasNestedGroups bool        `json:"hasNestedGroups"`
	MembershipEnumerated bool   `json:"membershipEnumerated"` // Whether we successfully enumerated members
}

// CombinedIAMData holds all IAM-related data for a project
type CombinedIAMData struct {
	Principals       []PrincipalWithRoles  `json:"principals"`
	ServiceAccounts  []ServiceAccountInfo  `json:"serviceAccounts"`
	CustomRoles      []CustomRole          `json:"customRoles"`
	Groups           []GroupInfo           `json:"groups"`
	InheritedRoles   []PolicyBinding       `json:"inheritedRoles"`
}

var logger internal.Logger

func (s *IAMService) projectAncestry(projectID string) ([]AncestryResource, error) {
	ctx := context.Background()
	var projectsClient *resourcemanager.ProjectsClient
	var foldersClient *resourcemanager.FoldersClient
	var err error

	if s.session != nil {
		projectsClient, err = resourcemanager.NewProjectsClient(ctx, s.session.GetClientOption())
	} else {
		projectsClient, err = resourcemanager.NewProjectsClient(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create projects client: %v", err)
	}
	defer projectsClient.Close()

	if s.session != nil {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx, s.session.GetClientOption())
	} else {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create folders client: %v", err)
	}
	defer foldersClient.Close()

	resourceID := "projects/" + projectID
	var ancestry []AncestryResource

	for {
		if strings.HasPrefix(resourceID, "organizations/") {
			ancestry = append(ancestry, AncestryResource{Type: "organization", Id: strings.TrimPrefix(resourceID, "organizations/")})
			break
		} else if strings.HasPrefix(resourceID, "folders/") {
			resp, err := foldersClient.GetFolder(ctx, &resourcemanagerpb.GetFolderRequest{Name: resourceID})
			if err != nil {
				logger.ErrorM(fmt.Sprintf("failed to access folder %s, %v", resourceID, err), globals.GCP_IAM_MODULE_NAME)
				break // Stop processing further if a folder is inaccessible
			}
			ancestry = append(ancestry, AncestryResource{Type: "folder", Id: strings.TrimPrefix(resp.Name, "folders/")})
			resourceID = resp.Parent
		} else if strings.HasPrefix(resourceID, "projects/") {
			resp, err := projectsClient.GetProject(ctx, &resourcemanagerpb.GetProjectRequest{Name: resourceID})
			if err != nil {
				logger.ErrorM(fmt.Sprintf("failed to access project %s, %v", resourceID, err), globals.GCP_IAM_MODULE_NAME)
				return nil, fmt.Errorf("failed to get project: %v", err)
			}
			ancestry = append(ancestry, AncestryResource{Type: "project", Id: strings.TrimPrefix(resp.Name, "projects/")})
			resourceID = resp.Parent
		} else {
			return nil, fmt.Errorf("unknown resource type for: %s", resourceID)
		}
	}

	// Reverse the slice as we've built it from child to ancestor
	for i, j := 0, len(ancestry)-1; i < j; i, j = i+1, j-1 {
		ancestry[i], ancestry[j] = ancestry[j], ancestry[i]
	}

	return ancestry, nil
}

// Policies fetches IAM policy for a given resource and all policies in resource ancestry
func (s *IAMService) Policies(resourceID string, resourceType string) ([]PolicyBinding, error) {
	ctx := context.Background()
	var client *resourcemanager.ProjectsClient
	var err error

	if s.session != nil {
		client, err = resourcemanager.NewProjectsClient(ctx, s.session.GetClientOption())
	} else {
		client, err = resourcemanager.NewProjectsClient(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("resourcemanager.NewProjectsClient: %v", err)
	}
	defer client.Close()

	var resourceName string
	switch resourceType {
	case "project":
		resourceName = "projects/" + resourceID
	case "folder":
		resourceName = "folders/" + resourceID
	case "organization":
		resourceName = "organizations/" + resourceID
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	req := &iampb.GetIamPolicyRequest{
		Resource: resourceName,
	}

	// Fetch the IAM policy for the resource
	policy, err := client.GetIamPolicy(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("client.GetIamPolicy: %v", err)
	}

	// Assemble the policy bindings
	var policyBindings []PolicyBinding
	for _, binding := range policy.Bindings {
		policyBinding := PolicyBinding{
			Role:         binding.Role,
			Members:      binding.Members,
			ResourceID:   resourceID,
			ResourceType: resourceType,
			Condition:    binding.Condition.String(),
			PolicyName:   resourceName + "_policyBindings",
		}
		policyBindings = append(policyBindings, policyBinding)
	}

	return policyBindings, nil
}

func determinePrincipalType(member string) string {
	switch {
	case strings.HasPrefix(member, "user:"):
		return "User"
	case strings.HasPrefix(member, "serviceAccount:"):
		return "ServiceAccount"
	case strings.HasPrefix(member, "group:"):
		return "Group"
	case strings.HasPrefix(member, "domain:"):
		return "Domain"
	case member == "allUsers":
		return "PUBLIC"
	case member == "allAuthenticatedUsers":
		return "ALL_AUTHENTICATED"
	case strings.HasPrefix(member, "deleted:"):
		return "Deleted"
	case strings.HasPrefix(member, "projectOwner:"):
		return "ProjectOwner"
	case strings.HasPrefix(member, "projectEditor:"):
		return "ProjectEditor"
	case strings.HasPrefix(member, "projectViewer:"):
		return "ProjectViewer"
	case strings.HasPrefix(member, "principal:"):
		return "WorkloadIdentity"
	case strings.HasPrefix(member, "principalSet:"):
		return "WorkloadIdentityPool"
	default:
		return "Unknown"
	}
}

// extractEmail extracts the clean email/identifier from a member string
func extractEmail(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return member
}

// isCustomRole checks if a role is a custom role
func isCustomRole(role string) bool {
	return strings.HasPrefix(role, "projects/") || strings.HasPrefix(role, "organizations/")
}

func (s *IAMService) PrincipalsWithRoles(resourceID string, resourceType string) ([]PrincipalWithRoles, error) {
	policyBindings, err := s.Policies(resourceID, resourceType)
	if err != nil {
		return nil, err
	}

	principalMap := make(map[string]*PrincipalWithRoles)
	for _, pb := range policyBindings {
		for _, member := range pb.Members {
			principalType := determinePrincipalType(member)
			if principal, ok := principalMap[member]; ok {
				principal.PolicyBindings = append(principal.PolicyBindings, pb)
				// Track custom roles
				if isCustomRole(pb.Role) && !contains(principal.CustomRoles, pb.Role) {
					principal.CustomRoles = append(principal.CustomRoles, pb.Role)
					principal.HasCustomRoles = true
				}
			} else {
				customRoles := []string{}
				hasCustomRoles := false
				if isCustomRole(pb.Role) {
					customRoles = append(customRoles, pb.Role)
					hasCustomRoles = true
				}
				principalMap[member] = &PrincipalWithRoles{
					Name:           member,
					Type:           principalType,
					Email:          extractEmail(member),
					PolicyBindings: []PolicyBinding{pb},
					ResourceID:     resourceID,
					ResourceType:   resourceType,
					HasCustomRoles: hasCustomRoles,
					CustomRoles:    customRoles,
				}
			}
		}
	}

	var principals []PrincipalWithRoles
	for _, principal := range principalMap {
		principals = append(principals, *principal)
	}

	return principals, nil
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ServiceAccounts retrieves all service accounts in a project with detailed info
func (s *IAMService) ServiceAccounts(projectID string) ([]ServiceAccountInfo, error) {
	ctx := context.Background()
	var iamService *iam.Service
	var err error

	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	var serviceAccounts []ServiceAccountInfo

	// List all service accounts in the project
	req := iamService.Projects.ServiceAccounts.List("projects/" + projectID)
	err = req.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, sa := range page.Accounts {
			saInfo := ServiceAccountInfo{
				Email:          sa.Email,
				Name:           sa.Name,
				ProjectID:      projectID,
				UniqueID:       sa.UniqueId,
				DisplayName:    sa.DisplayName,
				Description:    sa.Description,
				Disabled:       sa.Disabled,
				OAuth2ClientID: sa.Oauth2ClientId,
			}

			// Get keys for this service account
			keys, err := s.getServiceAccountKeys(ctx, iamService, sa.Name)
			if err != nil {
				// Log but don't fail - we might not have permission
				logger.InfoM(fmt.Sprintf("Could not list keys for %s: %v", sa.Email, err), globals.GCP_IAM_MODULE_NAME)
			} else {
				saInfo.Keys = keys
				// Count user-managed keys only
				userManagedCount := 0
				for _, key := range keys {
					if key.KeyType == "USER_MANAGED" {
						userManagedCount++
					}
				}
				saInfo.KeyCount = userManagedCount
				saInfo.HasKeys = userManagedCount > 0
			}

			serviceAccounts = append(serviceAccounts, saInfo)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %v", err)
	}

	return serviceAccounts, nil
}

// getServiceAccountKeys retrieves keys for a service account
func (s *IAMService) getServiceAccountKeys(ctx context.Context, iamService *iam.Service, saName string) ([]ServiceAccountKeyInfo, error) {
	var keys []ServiceAccountKeyInfo

	resp, err := iamService.Projects.ServiceAccounts.Keys.List(saName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, key := range resp.Keys {
		keyInfo := ServiceAccountKeyInfo{
			Name:         key.Name,
			KeyAlgorithm: key.KeyAlgorithm,
			KeyOrigin:    key.KeyOrigin,
			KeyType:      key.KeyType,
			Disabled:     key.Disabled,
		}

		// Parse timestamps
		if key.ValidAfterTime != "" {
			if t, err := time.Parse(time.RFC3339, key.ValidAfterTime); err == nil {
				keyInfo.ValidAfter = t
			}
		}
		if key.ValidBeforeTime != "" {
			if t, err := time.Parse(time.RFC3339, key.ValidBeforeTime); err == nil {
				keyInfo.ValidBefore = t
			}
		}

		keys = append(keys, keyInfo)
	}

	return keys, nil
}

// CustomRoles retrieves all custom roles in a project
func (s *IAMService) CustomRoles(projectID string) ([]CustomRole, error) {
	ctx := context.Background()
	var iamService *iam.Service
	var err error

	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	var customRoles []CustomRole

	// List project-level custom roles
	req := iamService.Projects.Roles.List("projects/" + projectID)
	req.ShowDeleted(true) // Include deleted roles for security awareness
	err = req.Pages(ctx, func(page *iam.ListRolesResponse) error {
		for _, role := range page.Roles {
			customRole := CustomRole{
				Name:                role.Name,
				Title:               role.Title,
				Description:         role.Description,
				IncludedPermissions: role.IncludedPermissions,
				Stage:               role.Stage,
				Deleted:             role.Deleted,
				Etag:                role.Etag,
				ProjectID:           projectID,
				IsProjectLevel:      true,
				PermissionCount:     len(role.IncludedPermissions),
			}
			customRoles = append(customRoles, customRole)
		}
		return nil
	})
	if err != nil {
		// Don't fail completely - we might just not have access to list roles
		logger.InfoM(fmt.Sprintf("Could not list custom roles for project %s: %v", projectID, err), globals.GCP_IAM_MODULE_NAME)
	}

	return customRoles, nil
}

// PoliciesWithInheritance fetches IAM policies including inherited ones from folders and organization
func (s *IAMService) PoliciesWithInheritance(projectID string) ([]PolicyBinding, error) {
	ctx := context.Background()

	// Get project's ancestry
	ancestry, err := s.projectAncestry(projectID)
	if err != nil {
		// If we can't get ancestry, just return project-level policies
		logger.InfoM(fmt.Sprintf("Could not get ancestry for project %s, returning project-level policies only: %v", projectID, err), globals.GCP_IAM_MODULE_NAME)
		return s.Policies(projectID, "project")
	}

	var allBindings []PolicyBinding

	// Get policies for each resource in the ancestry (org -> folders -> project)
	for _, resource := range ancestry {
		bindings, err := s.getPoliciesForResource(ctx, resource.Id, resource.Type)
		if err != nil {
			logger.InfoM(fmt.Sprintf("Could not get policies for %s/%s: %v", resource.Type, resource.Id, err), globals.GCP_IAM_MODULE_NAME)
			continue
		}

		// Mark inherited bindings
		for i := range bindings {
			if resource.Type != "project" || resource.Id != projectID {
				bindings[i].IsInherited = true
				bindings[i].InheritedFrom = fmt.Sprintf("%s/%s", resource.Type, resource.Id)
			}
		}

		allBindings = append(allBindings, bindings...)
	}

	return allBindings, nil
}

// getPoliciesForResource fetches policies for a specific resource using the appropriate client
func (s *IAMService) getPoliciesForResource(ctx context.Context, resourceID string, resourceType string) ([]PolicyBinding, error) {
	var resourceName string

	switch resourceType {
	case "project":
		var client *resourcemanager.ProjectsClient
		var err error
		if s.session != nil {
			client, err = resourcemanager.NewProjectsClient(ctx, s.session.GetClientOption())
		} else {
			client, err = resourcemanager.NewProjectsClient(ctx)
		}
		if err != nil {
			return nil, err
		}
		defer client.Close()

		resourceName = "projects/" + resourceID
		policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resourceName})
		if err != nil {
			return nil, err
		}
		return convertPolicyToBindings(policy, resourceID, resourceType, resourceName), nil

	case "folder":
		var client *resourcemanager.FoldersClient
		var err error
		if s.session != nil {
			client, err = resourcemanager.NewFoldersClient(ctx, s.session.GetClientOption())
		} else {
			client, err = resourcemanager.NewFoldersClient(ctx)
		}
		if err != nil {
			return nil, err
		}
		defer client.Close()

		resourceName = "folders/" + resourceID
		policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resourceName})
		if err != nil {
			return nil, err
		}
		return convertPolicyToBindings(policy, resourceID, resourceType, resourceName), nil

	case "organization":
		var client *resourcemanager.OrganizationsClient
		var err error
		if s.session != nil {
			client, err = resourcemanager.NewOrganizationsClient(ctx, s.session.GetClientOption())
		} else {
			client, err = resourcemanager.NewOrganizationsClient(ctx)
		}
		if err != nil {
			return nil, err
		}
		defer client.Close()

		resourceName = "organizations/" + resourceID
		policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resourceName})
		if err != nil {
			return nil, err
		}
		return convertPolicyToBindings(policy, resourceID, resourceType, resourceName), nil

	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}
}

// convertPolicyToBindings converts an IAM policy to PolicyBinding slice
func convertPolicyToBindings(policy *iampb.Policy, resourceID, resourceType, resourceName string) []PolicyBinding {
	var bindings []PolicyBinding
	for _, binding := range policy.Bindings {
		pb := PolicyBinding{
			Role:         binding.Role,
			Members:      binding.Members,
			ResourceID:   resourceID,
			ResourceType: resourceType,
			PolicyName:   resourceName + "_policyBindings",
		}

		// Parse condition if present
		if binding.Condition != nil {
			pb.Condition = binding.Condition.String()
			pb.HasCondition = true
			pb.ConditionInfo = &IAMCondition{
				Title:       binding.Condition.Title,
				Description: binding.Condition.Description,
				Expression:  binding.Condition.Expression,
			}
		}

		bindings = append(bindings, pb)
	}
	return bindings
}

// CombinedIAM retrieves all IAM-related data for a project
func (s *IAMService) CombinedIAM(projectID string) (CombinedIAMData, error) {
	var data CombinedIAMData

	// Get principals with roles (includes inheritance tracking)
	principals, err := s.PrincipalsWithRolesEnhanced(projectID)
	if err != nil {
		return data, fmt.Errorf("failed to get principals: %v", err)
	}
	data.Principals = principals

	// Get service accounts with details
	serviceAccounts, err := s.ServiceAccounts(projectID)
	if err != nil {
		// Don't fail completely
		logger.InfoM(fmt.Sprintf("Could not get service accounts: %v", err), globals.GCP_IAM_MODULE_NAME)
	} else {
		data.ServiceAccounts = serviceAccounts
	}

	// Get custom roles
	customRoles, err := s.CustomRoles(projectID)
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not get custom roles: %v", err), globals.GCP_IAM_MODULE_NAME)
	} else {
		data.CustomRoles = customRoles
	}

	// Extract groups from principals
	var groups []GroupInfo
	groupMap := make(map[string]*GroupInfo)
	for _, p := range principals {
		if p.Type == "Group" {
			if _, exists := groupMap[p.Email]; !exists {
				groupMap[p.Email] = &GroupInfo{
					Email:     p.Email,
					ProjectID: projectID,
					Roles:     []string{},
				}
			}
			for _, binding := range p.PolicyBindings {
				groupMap[p.Email].Roles = append(groupMap[p.Email].Roles, binding.Role)
			}
		}
	}
	for _, g := range groupMap {
		groups = append(groups, *g)
	}
	data.Groups = groups

	return data, nil
}

// PrincipalsWithRolesEnhanced gets principals with roles including inheritance info
func (s *IAMService) PrincipalsWithRolesEnhanced(projectID string) ([]PrincipalWithRoles, error) {
	policyBindings, err := s.PoliciesWithInheritance(projectID)
	if err != nil {
		return nil, err
	}

	principalMap := make(map[string]*PrincipalWithRoles)
	for _, pb := range policyBindings {
		for _, member := range pb.Members {
			principalType := determinePrincipalType(member)
			// Create a binding copy for this principal
			principalBinding := PolicyBinding{
				Role:          pb.Role,
				Members:       []string{member},
				ResourceID:    pb.ResourceID,
				ResourceType:  pb.ResourceType,
				Condition:     pb.Condition,
				PolicyName:    pb.PolicyName,
				IsInherited:   pb.IsInherited,
				InheritedFrom: pb.InheritedFrom,
			}

			if principal, ok := principalMap[member]; ok {
				principal.PolicyBindings = append(principal.PolicyBindings, principalBinding)
				// Track custom roles
				if isCustomRole(pb.Role) && !contains(principal.CustomRoles, pb.Role) {
					principal.CustomRoles = append(principal.CustomRoles, pb.Role)
					principal.HasCustomRoles = true
				}
			} else {
				customRoles := []string{}
				hasCustomRoles := false
				if isCustomRole(pb.Role) {
					customRoles = append(customRoles, pb.Role)
					hasCustomRoles = true
				}
				principalMap[member] = &PrincipalWithRoles{
					Name:           member,
					Type:           principalType,
					Email:          extractEmail(member),
					PolicyBindings: []PolicyBinding{principalBinding},
					ResourceID:     projectID,
					ResourceType:   "project",
					HasCustomRoles: hasCustomRoles,
					CustomRoles:    customRoles,
				}
			}
		}
	}

	var principals []PrincipalWithRoles
	for _, principal := range principalMap {
		principals = append(principals, *principal)
	}

	return principals, nil
}

// GetMemberType returns the member type for display purposes
func GetMemberType(member string) string {
	return determinePrincipalType(member)
}

// PermissionEntry represents a single permission with its source information
type PermissionEntry struct {
	Permission    string `json:"permission"`
	Role          string `json:"role"`
	RoleType      string `json:"roleType"`      // "predefined", "custom", "basic"
	ResourceID    string `json:"resourceId"`
	ResourceType  string `json:"resourceType"`
	IsInherited   bool   `json:"isInherited"`
	InheritedFrom string `json:"inheritedFrom"`
	HasCondition  bool   `json:"hasCondition"`
	Condition     string `json:"condition"`
}

// EntityPermissions represents all permissions for an entity
type EntityPermissions struct {
	Entity       string            `json:"entity"`
	EntityType   string            `json:"entityType"`
	Email        string            `json:"email"`
	ProjectID    string            `json:"projectId"`
	Permissions  []PermissionEntry `json:"permissions"`
	Roles        []string          `json:"roles"`
	TotalPerms   int               `json:"totalPerms"`
	UniquePerms  int               `json:"uniquePerms"`
}

// RolePermissions caches role to permissions mapping
var rolePermissionsCache = make(map[string][]string)

// GetRolePermissions retrieves the permissions for a given role
func (s *IAMService) GetRolePermissions(ctx context.Context, roleName string) ([]string, error) {
	// Check cache first
	if perms, ok := rolePermissionsCache[roleName]; ok {
		return perms, nil
	}

	var iamService *iam.Service
	var err error
	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	var permissions []string

	// Handle different role types
	if strings.HasPrefix(roleName, "roles/") {
		// Predefined role
		role, err := iamService.Roles.Get(roleName).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("failed to get role %s: %v", roleName, err)
		}
		permissions = role.IncludedPermissions
	} else if strings.HasPrefix(roleName, "projects/") {
		// Project-level custom role
		role, err := iamService.Projects.Roles.Get(roleName).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("failed to get custom role %s: %v", roleName, err)
		}
		permissions = role.IncludedPermissions
	} else if strings.HasPrefix(roleName, "organizations/") {
		// Organization-level custom role
		role, err := iamService.Organizations.Roles.Get(roleName).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("failed to get org custom role %s: %v", roleName, err)
		}
		permissions = role.IncludedPermissions
	}

	// Cache the result
	rolePermissionsCache[roleName] = permissions
	return permissions, nil
}

// GetRoleType determines the type of role
func GetRoleType(roleName string) string {
	switch {
	case strings.HasPrefix(roleName, "roles/owner") || strings.HasPrefix(roleName, "roles/editor") || strings.HasPrefix(roleName, "roles/viewer"):
		return "basic"
	case strings.HasPrefix(roleName, "projects/") || strings.HasPrefix(roleName, "organizations/"):
		return "custom"
	default:
		return "predefined"
	}
}

// GetEntityPermissions retrieves all permissions for a specific entity
func (s *IAMService) GetEntityPermissions(ctx context.Context, projectID string, entity string) (*EntityPermissions, error) {
	// Get all bindings with inheritance
	bindings, err := s.PoliciesWithInheritance(projectID)
	if err != nil {
		return nil, err
	}

	entityPerms := &EntityPermissions{
		Entity:      entity,
		EntityType:  determinePrincipalType(entity),
		Email:       extractEmail(entity),
		ProjectID:   projectID,
		Permissions: []PermissionEntry{},
		Roles:       []string{},
	}

	// Track unique permissions
	uniquePerms := make(map[string]bool)
	rolesSet := make(map[string]bool)

	// Process each binding
	for _, binding := range bindings {
		// Check if this entity is in the binding
		found := false
		for _, member := range binding.Members {
			if member == entity {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		// Track the role
		if !rolesSet[binding.Role] {
			rolesSet[binding.Role] = true
			entityPerms.Roles = append(entityPerms.Roles, binding.Role)
		}

		// Get permissions for this role
		permissions, err := s.GetRolePermissions(ctx, binding.Role)
		if err != nil {
			logger.InfoM(fmt.Sprintf("Could not get permissions for role %s: %v", binding.Role, err), globals.GCP_IAM_MODULE_NAME)
			continue
		}

		// Create permission entries
		for _, perm := range permissions {
			permEntry := PermissionEntry{
				Permission:    perm,
				Role:          binding.Role,
				RoleType:      GetRoleType(binding.Role),
				ResourceID:    binding.ResourceID,
				ResourceType:  binding.ResourceType,
				IsInherited:   binding.IsInherited,
				InheritedFrom: binding.InheritedFrom,
				HasCondition:  binding.HasCondition,
			}
			if binding.ConditionInfo != nil {
				permEntry.Condition = binding.ConditionInfo.Title
			}

			entityPerms.Permissions = append(entityPerms.Permissions, permEntry)

			if !uniquePerms[perm] {
				uniquePerms[perm] = true
			}
		}
	}

	entityPerms.TotalPerms = len(entityPerms.Permissions)
	entityPerms.UniquePerms = len(uniquePerms)

	return entityPerms, nil
}

// GetAllEntityPermissions retrieves permissions for all entities in a project
func (s *IAMService) GetAllEntityPermissions(projectID string) ([]EntityPermissions, error) {
	ctx := context.Background()

	// Get all principals
	principals, err := s.PrincipalsWithRolesEnhanced(projectID)
	if err != nil {
		return nil, err
	}

	var allPerms []EntityPermissions

	for _, principal := range principals {
		entityPerms, err := s.GetEntityPermissions(ctx, projectID, principal.Name)
		if err != nil {
			logger.InfoM(fmt.Sprintf("Could not get permissions for %s: %v", principal.Name, err), globals.GCP_IAM_MODULE_NAME)
			continue
		}
		allPerms = append(allPerms, *entityPerms)
	}

	return allPerms, nil
}

// GetGroupMembership retrieves members of a Google Group using Cloud Identity API
// Requires cloudidentity.groups.readonly or cloudidentity.groups scope
func (s *IAMService) GetGroupMembership(ctx context.Context, groupEmail string) (*GroupInfo, error) {
	var ciService *cloudidentity.Service
	var err error
	if s.session != nil {
		ciService, err = cloudidentity.NewService(ctx, s.session.GetClientOption())
	} else {
		ciService, err = cloudidentity.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Identity service: %v", err)
	}

	groupInfo := &GroupInfo{
		Email:   groupEmail,
		Members: []GroupMember{},
	}

	// First, look up the group to get its resource name
	// Cloud Identity uses groups/{group_id} format
	lookupReq := ciService.Groups.Lookup()
	lookupReq.GroupKeyId(groupEmail)

	lookupResp, err := lookupReq.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to lookup group %s: %v", groupEmail, err)
	}

	groupName := lookupResp.Name

	// Get group details
	group, err := ciService.Groups.Get(groupName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get group details for %s: %v", groupEmail, err)
	}

	groupInfo.DisplayName = group.DisplayName
	groupInfo.Description = group.Description

	// List memberships
	membershipsReq := ciService.Groups.Memberships.List(groupName)
	err = membershipsReq.Pages(ctx, func(page *cloudidentity.ListMembershipsResponse) error {
		for _, membership := range page.Memberships {
			member := GroupMember{
				Role: membership.Roles[0].Name, // OWNER, MANAGER, MEMBER
			}

			// Get member details from preferredMemberKey
			if membership.PreferredMemberKey != nil {
				member.Email = membership.PreferredMemberKey.Id
			}

			// Determine member type
			if membership.Type == "GROUP" {
				member.Type = "GROUP"
				groupInfo.NestedGroups = append(groupInfo.NestedGroups, member.Email)
				groupInfo.HasNestedGroups = true
			} else if strings.HasSuffix(member.Email, ".iam.gserviceaccount.com") {
				member.Type = "SERVICE_ACCOUNT"
			} else {
				member.Type = "USER"
			}

			groupInfo.Members = append(groupInfo.Members, member)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships for group %s: %v", groupEmail, err)
	}

	groupInfo.MemberCount = len(groupInfo.Members)
	groupInfo.MembershipEnumerated = true

	return groupInfo, nil
}

// GetGroupMemberships retrieves members for all groups found in IAM bindings
func (s *IAMService) GetGroupMemberships(ctx context.Context, groups []GroupInfo) []GroupInfo {
	var enrichedGroups []GroupInfo

	for _, group := range groups {
		enrichedGroup, err := s.GetGroupMembership(ctx, group.Email)
		if err != nil {
			// Log but don't fail - Cloud Identity API access is often restricted
			logger.InfoM(fmt.Sprintf("Could not enumerate membership for group %s: %v", group.Email, err), globals.GCP_IAM_MODULE_NAME)
			// Keep the original group info without membership
			group.MembershipEnumerated = false
			enrichedGroups = append(enrichedGroups, group)
			continue
		}
		// Preserve the roles from the original group
		enrichedGroup.Roles = group.Roles
		enrichedGroup.ProjectID = group.ProjectID
		enrichedGroups = append(enrichedGroups, *enrichedGroup)
	}

	return enrichedGroups
}

// ExpandGroupPermissions expands permissions to include inherited permissions from group membership
// This creates permission entries for group members based on the group's permissions
func (s *IAMService) ExpandGroupPermissions(ctx context.Context, projectID string, entityPerms []EntityPermissions) ([]EntityPermissions, error) {
	// Find all groups in the entity permissions
	groupPermsMap := make(map[string]*EntityPermissions)
	for i := range entityPerms {
		if entityPerms[i].EntityType == "Group" {
			groupPermsMap[entityPerms[i].Entity] = &entityPerms[i]
		}
	}

	if len(groupPermsMap) == 0 {
		return entityPerms, nil
	}

	// Try to enumerate group memberships
	var groupInfos []GroupInfo
	for groupEmail := range groupPermsMap {
		groupInfos = append(groupInfos, GroupInfo{Email: groupEmail, ProjectID: projectID})
	}

	enrichedGroups := s.GetGroupMemberships(ctx, groupInfos)

	// Create a map of member to their inherited permissions from groups
	memberInheritedPerms := make(map[string][]PermissionEntry)

	for _, group := range enrichedGroups {
		if !group.MembershipEnumerated {
			continue
		}

		groupPerms := groupPermsMap["group:"+group.Email]
		if groupPerms == nil {
			continue
		}

		// For each member of the group, add the group's permissions as inherited
		for _, member := range group.Members {
			memberKey := ""
			switch member.Type {
			case "USER":
				memberKey = "user:" + member.Email
			case "SERVICE_ACCOUNT":
				memberKey = "serviceAccount:" + member.Email
			case "GROUP":
				memberKey = "group:" + member.Email
			}

			if memberKey == "" {
				continue
			}

			// Create inherited permission entries
			for _, perm := range groupPerms.Permissions {
				inheritedPerm := PermissionEntry{
					Permission:    perm.Permission,
					Role:          perm.Role,
					RoleType:      perm.RoleType,
					ResourceID:    perm.ResourceID,
					ResourceType:  perm.ResourceType,
					IsInherited:   true,
					InheritedFrom: fmt.Sprintf("group:%s", group.Email),
					HasCondition:  perm.HasCondition,
					Condition:     perm.Condition,
				}
				memberInheritedPerms[memberKey] = append(memberInheritedPerms[memberKey], inheritedPerm)
			}
		}
	}

	// Add inherited permissions to existing entities or create new ones
	entityMap := make(map[string]*EntityPermissions)
	for i := range entityPerms {
		entityMap[entityPerms[i].Entity] = &entityPerms[i]
	}

	for memberKey, inheritedPerms := range memberInheritedPerms {
		if existing, ok := entityMap[memberKey]; ok {
			// Add inherited permissions to existing entity
			existing.Permissions = append(existing.Permissions, inheritedPerms...)
			existing.TotalPerms = len(existing.Permissions)
			// Recalculate unique perms
			uniquePerms := make(map[string]bool)
			for _, p := range existing.Permissions {
				uniquePerms[p.Permission] = true
			}
			existing.UniquePerms = len(uniquePerms)
		} else {
			// Create new entity entry for this group member
			newEntity := EntityPermissions{
				Entity:      memberKey,
				EntityType:  determinePrincipalType(memberKey),
				Email:       extractEmail(memberKey),
				ProjectID:   projectID,
				Permissions: inheritedPerms,
				Roles:       []string{}, // Roles are inherited via group
				TotalPerms:  len(inheritedPerms),
			}
			// Calculate unique perms
			uniquePerms := make(map[string]bool)
			for _, p := range inheritedPerms {
				uniquePerms[p.Permission] = true
			}
			newEntity.UniquePerms = len(uniquePerms)
			entityPerms = append(entityPerms, newEntity)
		}
	}

	return entityPerms, nil
}

// GetAllEntityPermissionsWithGroupExpansion retrieves permissions with group membership expansion
func (s *IAMService) GetAllEntityPermissionsWithGroupExpansion(projectID string) ([]EntityPermissions, []GroupInfo, error) {
	ctx := context.Background()

	// Get base permissions
	entityPerms, err := s.GetAllEntityPermissions(projectID)
	if err != nil {
		return nil, nil, err
	}

	// Find groups
	var groups []GroupInfo
	for _, ep := range entityPerms {
		if ep.EntityType == "Group" {
			groups = append(groups, GroupInfo{
				Email:     ep.Email,
				ProjectID: projectID,
				Roles:     ep.Roles,
			})
		}
	}

	// Try to enumerate group memberships
	enrichedGroups := s.GetGroupMemberships(ctx, groups)

	// Expand permissions based on group membership
	expandedPerms, err := s.ExpandGroupPermissions(ctx, projectID, entityPerms)
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not expand group permissions: %v", err), globals.GCP_IAM_MODULE_NAME)
		return entityPerms, enrichedGroups, nil
	}

	return expandedPerms, enrichedGroups, nil
}

// ============================================================================
// PENTEST: Service Account Impersonation Analysis
// ============================================================================

// Dangerous permissions for SA impersonation/abuse
var saImpersonationPermissions = map[string]string{
	"iam.serviceAccounts.getAccessToken":     "tokenCreator",
	"iam.serviceAccountKeys.create":          "keyCreator",
	"iam.serviceAccounts.signBlob":           "signBlob",
	"iam.serviceAccounts.signJwt":            "signJwt",
	"iam.serviceAccounts.implicitDelegation": "implicitDelegation",
	"iam.serviceAccounts.actAs":              "actAs",
}

// GetServiceAccountIAMPolicy gets the IAM policy for a specific service account
func (s *IAMService) GetServiceAccountIAMPolicy(ctx context.Context, saEmail string, projectID string) (*SAImpersonationInfo, error) {
	var iamService *iam.Service
	var err error

	if s.session != nil {
		iamService, err = iam.NewService(ctx, s.session.GetClientOption())
	} else {
		iamService, err = iam.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	saResource := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)

	policy, err := iamService.Projects.ServiceAccounts.GetIamPolicy(saResource).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy for SA %s: %v", saEmail, err)
	}

	info := &SAImpersonationInfo{
		ServiceAccount: saEmail,
		ProjectID:      projectID,
		RiskReasons:    []string{},
	}

	// Analyze each binding
	for _, binding := range policy.Bindings {
		role := binding.Role
		members := binding.Members

		// Check for specific dangerous roles
		switch role {
		case "roles/iam.serviceAccountTokenCreator":
			info.TokenCreators = append(info.TokenCreators, members...)
		case "roles/iam.serviceAccountKeyAdmin":
			info.KeyCreators = append(info.KeyCreators, members...)
			info.SAAdmins = append(info.SAAdmins, members...)
		case "roles/iam.serviceAccountAdmin":
			info.SAAdmins = append(info.SAAdmins, members...)
			info.TokenCreators = append(info.TokenCreators, members...)
			info.KeyCreators = append(info.KeyCreators, members...)
		case "roles/iam.serviceAccountUser":
			info.ActAsUsers = append(info.ActAsUsers, members...)
		case "roles/owner", "roles/editor":
			// These grant broad SA access
			info.SAAdmins = append(info.SAAdmins, members...)
		}
	}

	// Calculate risk level
	info.RiskLevel, info.RiskReasons = calculateSAImpersonationRisk(info)

	return info, nil
}

// GetAllServiceAccountImpersonation analyzes impersonation risks for all SAs in a project
func (s *IAMService) GetAllServiceAccountImpersonation(projectID string) ([]SAImpersonationInfo, error) {
	ctx := context.Background()

	// Get all service accounts
	serviceAccounts, err := s.ServiceAccounts(projectID)
	if err != nil {
		return nil, err
	}

	var results []SAImpersonationInfo

	for _, sa := range serviceAccounts {
		info, err := s.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
		if err != nil {
			// Log but don't fail - we might not have permission
			logger.InfoM(fmt.Sprintf("Could not get IAM policy for SA %s: %v", sa.Email, err), globals.GCP_IAM_MODULE_NAME)
			continue
		}
		results = append(results, *info)
	}

	return results, nil
}

// ServiceAccountsWithImpersonation returns service accounts with impersonation analysis
func (s *IAMService) ServiceAccountsWithImpersonation(projectID string) ([]ServiceAccountInfo, error) {
	ctx := context.Background()

	// Get base service account info
	serviceAccounts, err := s.ServiceAccounts(projectID)
	if err != nil {
		return nil, err
	}

	// Enrich with impersonation info
	for i := range serviceAccounts {
		sa := &serviceAccounts[i]

		info, err := s.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
		if err != nil {
			// Log but continue
			continue
		}

		// Populate impersonation fields
		sa.CanGetAccessTokenBy = info.TokenCreators
		sa.CanCreateKeysBy = info.KeyCreators
		sa.CanSignBlobBy = info.SignBlobUsers
		sa.CanSignJwtBy = info.SignJwtUsers

		// Combine all impersonation paths
		allImpersonators := make(map[string]bool)
		for _, m := range info.TokenCreators {
			allImpersonators[m] = true
		}
		for _, m := range info.KeyCreators {
			allImpersonators[m] = true
		}
		for _, m := range info.SignBlobUsers {
			allImpersonators[m] = true
		}
		for _, m := range info.SignJwtUsers {
			allImpersonators[m] = true
		}
		for _, m := range info.SAAdmins {
			allImpersonators[m] = true
		}

		for m := range allImpersonators {
			sa.CanBeImpersonatedBy = append(sa.CanBeImpersonatedBy, m)
		}

		sa.HasImpersonationRisk = len(sa.CanBeImpersonatedBy) > 0
		sa.ImpersonationRiskLevel = info.RiskLevel
	}

	return serviceAccounts, nil
}

func calculateSAImpersonationRisk(info *SAImpersonationInfo) (string, []string) {
	var reasons []string
	score := 0

	// Token creators are critical - direct impersonation
	if len(info.TokenCreators) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d principal(s) can get access tokens (impersonate)", len(info.TokenCreators)))
		score += 3

		// Check for public access
		for _, m := range info.TokenCreators {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				reasons = append(reasons, "PUBLIC can impersonate this SA!")
				score += 5
			}
		}
	}

	// Key creators are critical - persistent access
	if len(info.KeyCreators) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d principal(s) can create keys (persistent access)", len(info.KeyCreators)))
		score += 3

		for _, m := range info.KeyCreators {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				reasons = append(reasons, "PUBLIC can create keys for this SA!")
				score += 5
			}
		}
	}

	// SignBlob/SignJwt - can forge tokens
	if len(info.SignBlobUsers) > 0 || len(info.SignJwtUsers) > 0 {
		reasons = append(reasons, "Principals can sign blobs/JWTs (token forgery)")
		score += 2
	}

	// SA Admins
	if len(info.SAAdmins) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d SA admin(s)", len(info.SAAdmins)))
		score += 1
	}

	// ActAs users (needed for attaching SA to resources)
	if len(info.ActAsUsers) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d principal(s) can actAs this SA", len(info.ActAsUsers)))
		score += 1
	}

	if score >= 5 {
		return "CRITICAL", reasons
	} else if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}
