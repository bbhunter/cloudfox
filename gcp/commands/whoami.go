package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	OAuthService "github.com/BishopFox/cloudfox/gcp/services/oauthService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	cloudidentity "google.golang.org/api/cloudidentity/v1"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	crmv3 "google.golang.org/api/cloudresourcemanager/v3"
)

// Flags for whoami command
var whoamiExtended bool
var whoamiGroups []string
var whoamiGroupsFile string

var GCPWhoAmICommand = &cobra.Command{
	Use:     globals.GCP_WHOAMI_MODULE_NAME,
	Aliases: []string{"identity", "me"},
	Short:   "Display identity context for the authenticated GCP user/service account",
	Long: `Display identity context for the authenticated GCP user/service account.

Default output:
- Current identity details (email, type)
- Organization and folder context
- Effective role bindings across projects (with inheritance source)

With --extended flag (adds):
- Service accounts that can be impersonated
- Privilege escalation opportunities
- Exploitation commands

With --groups flag:
- Provide known group email addresses when group enumeration is permission denied
- Role bindings from these groups will be included in the output
- Use comma-separated list: --groups=group1@domain.com,group2@domain.com

With --groupslist flag:
- Import groups from a file (one group per line)
- Same behavior as --groups but reads from file
- Example: --groupslist=groups.txt`,
	Run: runGCPWhoAmICommand,
}

func init() {
	GCPWhoAmICommand.Flags().BoolVarP(&whoamiExtended, "extended", "e", false, "Enable extended enumeration (impersonation targets, privilege escalation paths)")
	GCPWhoAmICommand.Flags().StringSliceVarP(&whoamiGroups, "groups", "g", []string{}, "Comma-separated list of known group email addresses (used when group enumeration is permission denied)")
	GCPWhoAmICommand.Flags().StringVar(&whoamiGroupsFile, "groupslist", "", "Path to file containing group email addresses (one per line)")
}

// ------------------------------
// Data Structures
// ------------------------------

type IdentityContext struct {
	Email             string
	Type              string // "user" or "serviceAccount"
	UniqueID          string
	ProjectIDs        []string      // Keep for backward compatibility
	Projects          []ProjectInfo // New: stores project ID and display name
	Organizations     []OrgInfo
	Folders           []FolderInfo
	Groups            []GroupMembership // Groups the identity is a member of
	GroupsEnumerated  bool              // Whether group enumeration was successful
	GroupsProvided    []string          // Groups provided via --groups flag
	GroupsMismatch    bool              // True if provided groups differ from enumerated
}

type ProjectInfo struct {
	ProjectID   string
	DisplayName string
}

type OrgInfo struct {
	Name        string
	DisplayName string
	OrgID       string
}

type FolderInfo struct {
	Name        string
	DisplayName string
	Parent      string
}

type GroupMembership struct {
	GroupID     string // e.g., "groups/abc123"
	Email       string // e.g., "security-team@example.com"
	DisplayName string // e.g., "Security Team"
	Source      string // "enumerated" or "provided"
}

type RoleBinding struct {
	Role            string
	Scope           string // "organization", "folder", "project"
	ScopeID         string
	ScopeName       string // Display name of the scope resource
	Inherited       bool
	Condition       string
	InheritedFrom   string // Source of binding: "direct", group email, or parent resource
	MemberType      string // "user", "serviceAccount", "group"
}

type ImpersonationTarget struct {
	ServiceAccount string
	ProjectID      string
	CanImpersonate bool
	CanCreateKeys  bool
	CanActAs       bool
}

type PrivilegeEscalationPath struct {
	Name        string
	Description string
	Command     string
}

// ------------------------------
// Module Struct
// ------------------------------
type WhoAmIModule struct {
	gcpinternal.BaseGCPModule

	Identity             IdentityContext
	RoleBindings         []RoleBinding
	ImpersonationTargets []ImpersonationTarget
	PrivEscPaths         []PrivilegeEscalationPath
	DangerousPermissions []string
	LootMap              map[string]*internal.LootFile
	Extended             bool
	ProvidedGroups       []string // Groups provided via --groups flag
	mu                   sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type WhoAmIOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o WhoAmIOutput) TableFiles() []internal.TableFile { return o.Table }
func (o WhoAmIOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPWhoAmICommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_WHOAMI_MODULE_NAME)
	if err != nil {
		return
	}

	// Combine groups from --groups flag and --groupslist file
	allGroups := whoamiGroups
	if whoamiGroupsFile != "" {
		fileGroups := internal.LoadFileLinesIntoArray(whoamiGroupsFile)
		allGroups = append(allGroups, fileGroups...)
	}

	// Create module instance
	module := &WhoAmIModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		RoleBindings:         []RoleBinding{},
		ImpersonationTargets: []ImpersonationTarget{},
		PrivEscPaths:         []PrivilegeEscalationPath{},
		DangerousPermissions: []string{},
		LootMap:              make(map[string]*internal.LootFile),
		Extended:             whoamiExtended,
		ProvidedGroups:       allGroups,
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *WhoAmIModule) Execute(ctx context.Context, logger internal.Logger) {
	if m.Extended {
		logger.InfoM("Gathering comprehensive identity context (extended mode)...", globals.GCP_WHOAMI_MODULE_NAME)
	} else {
		logger.InfoM("Gathering identity context...", globals.GCP_WHOAMI_MODULE_NAME)
	}

	// Step 1: Get current identity
	oauthService := OAuthService.NewOAuthService()
	principal, err := oauthService.WhoAmI()
	if err != nil {
		parsedErr := gcpinternal.ParseGCPError(err, "oauth2.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not retrieve token info")
		return
	}

	m.Identity = IdentityContext{
		Email:      principal.Email,
		ProjectIDs: m.ProjectIDs,
	}

	// Determine identity type
	if strings.HasSuffix(principal.Email, ".gserviceaccount.com") {
		m.Identity.Type = "serviceAccount"
	} else {
		m.Identity.Type = "user"
	}

	logger.InfoM(fmt.Sprintf("Authenticated as: %s (%s)", m.Identity.Email, m.Identity.Type), globals.GCP_WHOAMI_MODULE_NAME)

	// Step 2: Get organization context (always run)
	m.getOrganizationContext(ctx, logger)

	// Step 3: Get group memberships for the current identity
	m.getGroupMemberships(ctx, logger)

	// Step 4: Get role bindings across projects (always run)
	m.getRoleBindings(ctx, logger)

	// Extended mode: Additional enumeration
	if m.Extended {
		// Step 4: Find impersonation targets
		m.findImpersonationTargets(ctx, logger)

		// Step 5: Identify privilege escalation paths
		m.identifyPrivEscPaths(ctx, logger)
	}

	// Step 6: Generate loot
	m.generateLoot()

	// Write output
	m.writeOutput(ctx, logger)
}

// getOrganizationContext retrieves organization and folder hierarchy
func (m *WhoAmIModule) getOrganizationContext(ctx context.Context, logger internal.Logger) {
	// Create resource manager clients
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not create Cloud Resource Manager client")
		return
	}

	// Create v3 client for fetching folder details
	crmv3Service, err := crmv3.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not create Cloud Resource Manager v3 client")
		// Continue without v3, we just won't get display names for folders
	}

	// Get project ancestry for each project
	for _, projectID := range m.ProjectIDs {
		// Fetch project details to get display name
		projectInfo := ProjectInfo{
			ProjectID: projectID,
		}
		project, err := crmService.Projects.Get(projectID).Do()
		if err == nil && project != nil {
			projectInfo.DisplayName = project.Name
		}
		m.Identity.Projects = append(m.Identity.Projects, projectInfo)

		// Get ancestry
		resp, err := crmService.Projects.GetAncestry(projectID, &cloudresourcemanager.GetAncestryRequest{}).Do()
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
				fmt.Sprintf("Could not get ancestry for project %s", projectID))
			continue
		}

		for _, ancestor := range resp.Ancestor {
			switch ancestor.ResourceId.Type {
			case "organization":
				orgInfo := OrgInfo{
					OrgID: ancestor.ResourceId.Id,
					Name:  fmt.Sprintf("organizations/%s", ancestor.ResourceId.Id),
				}
				// Try to get display name for organization
				org, err := crmService.Organizations.Get(orgInfo.Name).Do()
				if err == nil && org != nil {
					orgInfo.DisplayName = org.DisplayName
				}
				// Check if already added
				exists := false
				for _, o := range m.Identity.Organizations {
					if o.OrgID == orgInfo.OrgID {
						exists = true
						break
					}
				}
				if !exists {
					m.Identity.Organizations = append(m.Identity.Organizations, orgInfo)
				}
			case "folder":
				folderName := fmt.Sprintf("folders/%s", ancestor.ResourceId.Id)
				folderInfo := FolderInfo{
					Name: folderName,
				}
				// Try to get display name for folder using v3 API
				if crmv3Service != nil {
					folder, err := crmv3Service.Folders.Get(folderName).Do()
					if err == nil && folder != nil {
						folderInfo.DisplayName = folder.DisplayName
						folderInfo.Parent = folder.Parent
					}
				}
				// Check if already added
				exists := false
				for _, f := range m.Identity.Folders {
					if f.Name == folderInfo.Name {
						exists = true
						break
					}
				}
				if !exists {
					m.Identity.Folders = append(m.Identity.Folders, folderInfo)
				}
			}
		}
	}

	if len(m.Identity.Organizations) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d organization(s), %d folder(s)", len(m.Identity.Organizations), len(m.Identity.Folders)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// normalizeGroupEmail ensures group has full email format
// If group doesn't contain @, tries to infer domain from identity email
func (m *WhoAmIModule) normalizeGroupEmail(group string) string {
	if strings.Contains(group, "@") {
		return group
	}

	// Try to infer domain from identity email
	if m.Identity.Email != "" && strings.Contains(m.Identity.Email, "@") {
		parts := strings.SplitN(m.Identity.Email, "@", 2)
		if len(parts) == 2 {
			return group + "@" + parts[1]
		}
	}

	// Return as-is if we can't infer domain
	return group
}

// getGroupMemberships retrieves the groups that the current identity is a member of
func (m *WhoAmIModule) getGroupMemberships(ctx context.Context, logger internal.Logger) {
	// Normalize provided groups to full email format
	var normalizedGroups []string
	for _, group := range m.ProvidedGroups {
		normalizedGroups = append(normalizedGroups, m.normalizeGroupEmail(group))
	}
	m.ProvidedGroups = normalizedGroups

	// Store provided groups
	m.Identity.GroupsProvided = m.ProvidedGroups

	// Only applicable for user identities (not service accounts)
	if m.Identity.Type != "user" {
		m.Identity.GroupsEnumerated = true // N/A for service accounts
		// If groups were provided for a service account, add them as provided
		if len(m.ProvidedGroups) > 0 {
			for _, groupEmail := range m.ProvidedGroups {
				m.Identity.Groups = append(m.Identity.Groups, GroupMembership{
					Email:  groupEmail,
					Source: "provided",
				})
			}
			logger.InfoM(fmt.Sprintf("Using %d provided group(s) for service account", len(m.ProvidedGroups)), globals.GCP_WHOAMI_MODULE_NAME)
		}
		return
	}

	ciService, err := cloudidentity.NewService(ctx)
	if err != nil {
		m.CommandCounter.Error++
		parsedErr := gcpinternal.ParseGCPError(err, "cloudidentity.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not create Cloud Identity client")
		// GroupsEnumerated stays false - use provided groups if available
		m.useProvidedGroups(logger)
		return
	}

	// Search for groups that the user is a direct member of
	// The parent must be "groups/-" to search across all groups
	query := fmt.Sprintf("member_key_id == '%s'", m.Identity.Email)
	resp, err := ciService.Groups.Memberships.SearchDirectGroups("groups/-").Query(query).Do()
	if err != nil {
		m.CommandCounter.Error++
		parsedErr := gcpinternal.ParseGCPError(err, "cloudidentity.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, globals.GCP_WHOAMI_MODULE_NAME,
			"Could not fetch group memberships")
		// GroupsEnumerated stays false - use provided groups if available
		m.useProvidedGroups(logger)
		return
	}

	// Successfully enumerated groups
	m.Identity.GroupsEnumerated = true

	var enumeratedEmails []string
	for _, membership := range resp.Memberships {
		group := GroupMembership{
			GroupID:     membership.Group,
			DisplayName: membership.DisplayName,
			Source:      "enumerated",
		}
		if membership.GroupKey != nil {
			group.Email = membership.GroupKey.Id
			enumeratedEmails = append(enumeratedEmails, strings.ToLower(membership.GroupKey.Id))
		}
		m.Identity.Groups = append(m.Identity.Groups, group)
	}

	// Check for mismatch with provided groups
	if len(m.ProvidedGroups) > 0 {
		m.checkGroupMismatch(enumeratedEmails, logger)
	}

	if len(m.Identity.Groups) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d group membership(s)", len(m.Identity.Groups)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// useProvidedGroups adds provided groups when enumeration fails
func (m *WhoAmIModule) useProvidedGroups(logger internal.Logger) {
	if len(m.ProvidedGroups) > 0 {
		for _, groupEmail := range m.ProvidedGroups {
			m.Identity.Groups = append(m.Identity.Groups, GroupMembership{
				Email:  groupEmail,
				Source: "provided",
			})
		}
		logger.InfoM(fmt.Sprintf("Using %d provided group(s) (enumeration failed)", len(m.ProvidedGroups)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// checkGroupMismatch compares provided groups with enumerated groups
func (m *WhoAmIModule) checkGroupMismatch(enumeratedEmails []string, logger internal.Logger) {
	enumeratedSet := make(map[string]bool)
	for _, email := range enumeratedEmails {
		enumeratedSet[strings.ToLower(email)] = true
	}

	providedSet := make(map[string]bool)
	for _, email := range m.ProvidedGroups {
		providedSet[strings.ToLower(email)] = true
	}

	// Check for provided groups not in enumerated
	var notInEnumerated []string
	for _, email := range m.ProvidedGroups {
		if !enumeratedSet[strings.ToLower(email)] {
			notInEnumerated = append(notInEnumerated, email)
		}
	}

	// Check for enumerated groups not in provided
	var notInProvided []string
	for _, email := range enumeratedEmails {
		if !providedSet[strings.ToLower(email)] {
			notInProvided = append(notInProvided, email)
		}
	}

	if len(notInEnumerated) > 0 || len(notInProvided) > 0 {
		m.Identity.GroupsMismatch = true
		if len(notInEnumerated) > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Provided groups not found in enumerated: %s", strings.Join(notInEnumerated, ", ")), globals.GCP_WHOAMI_MODULE_NAME)
		}
		if len(notInProvided) > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Enumerated groups not in provided list: %s", strings.Join(notInProvided, ", ")), globals.GCP_WHOAMI_MODULE_NAME)
		}
	}
}

// getRoleBindings retrieves IAM role bindings for the current identity
func (m *WhoAmIModule) getRoleBindings(ctx context.Context, logger internal.Logger) {
	iamService := IAMService.New()

	// Determine the member format for current identity
	var memberPrefix string
	if m.Identity.Type == "serviceAccount" {
		memberPrefix = "serviceAccount:"
	} else {
		memberPrefix = "user:"
	}
	fullMember := memberPrefix + m.Identity.Email

	// Build list of group members to check
	groupMembers := make(map[string]string) // group:email -> email for display
	for _, group := range m.Identity.Groups {
		if group.Email != "" {
			groupMembers["group:"+group.Email] = group.Email
		}
	}

	// Get role bindings from each project
	for _, projectID := range m.ProjectIDs {
		// Use PrincipalsWithRolesEnhanced which includes inheritance
		principals, err := iamService.PrincipalsWithRolesEnhanced(projectID)
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_WHOAMI_MODULE_NAME,
				fmt.Sprintf("Could not get IAM bindings for project %s", projectID))
			continue
		}

		// Find bindings for the current identity (direct)
		for _, principal := range principals {
			if principal.Name == fullMember || principal.Email == m.Identity.Email {
				for _, binding := range principal.PolicyBindings {
					rb := RoleBinding{
						Role:          binding.Role,
						Scope:         binding.ResourceType,
						ScopeID:       binding.ResourceID,
						Inherited:     binding.IsInherited,
						InheritedFrom: "direct",
						MemberType:    m.Identity.Type,
					}
					if binding.HasCondition && binding.ConditionInfo != nil {
						rb.Condition = binding.ConditionInfo.Title
					}
					// Set inherited source if from parent resource
					if binding.IsInherited && binding.InheritedFrom != "" {
						rb.InheritedFrom = binding.InheritedFrom
					}

					// Check for dangerous permissions
					if isDangerousRole(binding.Role) {
						m.DangerousPermissions = append(m.DangerousPermissions, fmt.Sprintf("%s on %s", binding.Role, binding.ResourceID))
					}

					m.mu.Lock()
					m.RoleBindings = append(m.RoleBindings, rb)
					m.mu.Unlock()
				}
			}

			// Check for group-based bindings
			if groupEmail, ok := groupMembers[principal.Name]; ok {
				for _, binding := range principal.PolicyBindings {
					rb := RoleBinding{
						Role:          binding.Role,
						Scope:         binding.ResourceType,
						ScopeID:       binding.ResourceID,
						Inherited:     binding.IsInherited,
						InheritedFrom: fmt.Sprintf("group:%s", groupEmail),
						MemberType:    "group",
					}
					if binding.HasCondition && binding.ConditionInfo != nil {
						rb.Condition = binding.ConditionInfo.Title
					}

					// Check for dangerous permissions
					if isDangerousRole(binding.Role) {
						m.DangerousPermissions = append(m.DangerousPermissions, fmt.Sprintf("%s on %s (via group %s)", binding.Role, binding.ResourceID, groupEmail))
					}

					m.mu.Lock()
					m.RoleBindings = append(m.RoleBindings, rb)
					m.mu.Unlock()
				}
			}
		}
	}

	directCount := 0
	groupCount := 0
	for _, rb := range m.RoleBindings {
		if rb.MemberType == "group" {
			groupCount++
		} else {
			directCount++
		}
	}

	if groupCount > 0 {
		logger.InfoM(fmt.Sprintf("Found %d role binding(s) (%d direct, %d via groups)", len(m.RoleBindings), directCount, groupCount), globals.GCP_WHOAMI_MODULE_NAME)
	} else {
		logger.InfoM(fmt.Sprintf("Found %d role binding(s) for current identity", len(m.RoleBindings)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// findImpersonationTargets identifies service accounts that can be impersonated
func (m *WhoAmIModule) findImpersonationTargets(ctx context.Context, logger internal.Logger) {
	iamService := IAMService.New()

	// Determine the member format for current identity
	var memberPrefix string
	if m.Identity.Type == "serviceAccount" {
		memberPrefix = "serviceAccount:"
	} else {
		memberPrefix = "user:"
	}
	fullMember := memberPrefix + m.Identity.Email

	for _, projectID := range m.ProjectIDs {
		// Get all service accounts in the project
		serviceAccounts, err := iamService.ServiceAccounts(projectID)
		if err != nil {
			continue
		}

		for _, sa := range serviceAccounts {
			// Check if current identity can impersonate this SA using GetServiceAccountIAMPolicy
			impersonationInfo, err := iamService.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
			if err != nil {
				continue
			}

			// Check if current identity is in the token creators or key creators list
			canImpersonate := false
			canCreateKeys := false
			canActAs := false

			for _, tc := range impersonationInfo.TokenCreators {
				if tc == fullMember || tc == m.Identity.Email || tc == "allUsers" || tc == "allAuthenticatedUsers" {
					canImpersonate = true
					break
				}
			}

			for _, kc := range impersonationInfo.KeyCreators {
				if kc == fullMember || kc == m.Identity.Email || kc == "allUsers" || kc == "allAuthenticatedUsers" {
					canCreateKeys = true
					break
				}
			}

			for _, aa := range impersonationInfo.ActAsUsers {
				if aa == fullMember || aa == m.Identity.Email || aa == "allUsers" || aa == "allAuthenticatedUsers" {
					canActAs = true
					break
				}
			}

			if canImpersonate || canCreateKeys || canActAs {
				target := ImpersonationTarget{
					ServiceAccount: sa.Email,
					ProjectID:      projectID,
					CanImpersonate: canImpersonate,
					CanCreateKeys:  canCreateKeys,
					CanActAs:       canActAs,
				}
				m.ImpersonationTargets = append(m.ImpersonationTargets, target)
			}
		}
	}

	if len(m.ImpersonationTargets) > 0 {
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d service account(s) that can be impersonated", len(m.ImpersonationTargets)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// identifyPrivEscPaths identifies privilege escalation paths based on current permissions
func (m *WhoAmIModule) identifyPrivEscPaths(ctx context.Context, logger internal.Logger) {
	// Check for privilege escalation opportunities based on role bindings
	for _, rb := range m.RoleBindings {
		paths := getPrivEscPathsForRole(rb.Role, rb.ScopeID)
		m.PrivEscPaths = append(m.PrivEscPaths, paths...)
	}

	// Check impersonation-based privilege escalation
	for _, target := range m.ImpersonationTargets {
		if target.CanImpersonate {
			path := PrivilegeEscalationPath{
				Name:        fmt.Sprintf("Impersonate %s", target.ServiceAccount),
				Description: "Can generate access tokens for this service account",
				Command:     fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", target.ServiceAccount),
			}
			m.PrivEscPaths = append(m.PrivEscPaths, path)
		}

		if target.CanCreateKeys {
			path := PrivilegeEscalationPath{
				Name:        fmt.Sprintf("Create key for %s", target.ServiceAccount),
				Description: "Can create persistent service account keys",
				Command:     fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", target.ServiceAccount),
			}
			m.PrivEscPaths = append(m.PrivEscPaths, path)
		}
	}

	if len(m.PrivEscPaths) > 0 {
		logger.InfoM(fmt.Sprintf("[PRIVESC] Found %d privilege escalation path(s)", len(m.PrivEscPaths)), globals.GCP_WHOAMI_MODULE_NAME)
	}
}

// isDangerousRole checks if a role is considered dangerous
func isDangerousRole(role string) bool {
	dangerousRoles := []string{
		"roles/owner",
		"roles/editor",
		"roles/iam.securityAdmin",
		"roles/iam.serviceAccountAdmin",
		"roles/iam.serviceAccountKeyAdmin",
		"roles/iam.serviceAccountTokenCreator",
		"roles/resourcemanager.organizationAdmin",
		"roles/resourcemanager.folderAdmin",
		"roles/resourcemanager.projectIamAdmin",
		"roles/cloudfunctions.admin",
		"roles/compute.admin",
		"roles/container.admin",
		"roles/storage.admin",
	}

	for _, dr := range dangerousRoles {
		if role == dr {
			return true
		}
	}
	return false
}

// getPrivEscPathsForRole returns privilege escalation paths for a given role
func getPrivEscPathsForRole(role, projectID string) []PrivilegeEscalationPath {
	var paths []PrivilegeEscalationPath

	switch role {
	case "roles/iam.serviceAccountTokenCreator":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Token Creator - Impersonate any SA",
			Description: "Can generate access tokens for any service account in the project",
			Command:     fmt.Sprintf("gcloud iam service-accounts list --project=%s", projectID),
		})
	case "roles/iam.serviceAccountKeyAdmin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Key Admin - Create persistent keys",
			Description: "Can create service account keys for any SA",
			Command:     fmt.Sprintf("gcloud iam service-accounts list --project=%s", projectID),
		})
	case "roles/cloudfunctions.admin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Cloud Functions Admin - Code Execution",
			Description: "Can deploy Cloud Functions with SA permissions",
			Command:     "gcloud functions deploy malicious-function --runtime=python39 --trigger-http --service-account=<target-sa>",
		})
	case "roles/compute.admin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Compute Admin - Metadata Injection",
			Description: "Can add startup scripts with SA access",
			Command:     "gcloud compute instances add-metadata <instance> --metadata=startup-script='curl -H \"Metadata-Flavor: Google\" http://metadata/...'",
		})
	case "roles/container.admin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Container Admin - Pod Deployment",
			Description: "Can deploy pods with service account access",
			Command:     fmt.Sprintf("gcloud container clusters get-credentials <cluster> --project=%s", projectID),
		})
	case "roles/owner", "roles/editor":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Owner/Editor - Full Project Access",
			Description: "Has full control over project resources",
			Command:     fmt.Sprintf("gcloud projects get-iam-policy %s", projectID),
		})
	}

	return paths
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *WhoAmIModule) initializeLootFiles() {
	// Note: whoami-context and whoami-permissions loot files removed as redundant
	// The same information is already saved to table/csv/json files

	// Extended mode loot files - these contain actionable commands
	if m.Extended {
		m.LootMap["whoami-impersonation"] = &internal.LootFile{
			Name:     "whoami-impersonation",
			Contents: "# Service Account Impersonation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
		}
		m.LootMap["whoami-privesc"] = &internal.LootFile{
			Name:     "whoami-privesc",
			Contents: "# Privilege Escalation Paths\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
		}
	}
}

func (m *WhoAmIModule) generateLoot() {
	// Note: Context and permissions info is already saved to table/csv/json files
	// Only generate loot files for extended mode (actionable commands)

	// Extended mode loot
	if m.Extended {
		// Impersonation loot
		for _, target := range m.ImpersonationTargets {
			m.LootMap["whoami-impersonation"].Contents += fmt.Sprintf(
				"# Service Account: %s\n"+
					"# Project: %s\n",
				target.ServiceAccount,
				target.ProjectID,
			)
			if target.CanImpersonate {
				m.LootMap["whoami-impersonation"].Contents += fmt.Sprintf(
					"gcloud auth print-access-token --impersonate-service-account=%s\n",
					target.ServiceAccount,
				)
			}
			if target.CanCreateKeys {
				m.LootMap["whoami-impersonation"].Contents += fmt.Sprintf(
					"gcloud iam service-accounts keys create key.json --iam-account=%s\n",
					target.ServiceAccount,
				)
			}
			m.LootMap["whoami-impersonation"].Contents += "\n"
		}

		// Privilege escalation loot
		for _, path := range m.PrivEscPaths {
			m.LootMap["whoami-privesc"].Contents += fmt.Sprintf(
				"## %s\n"+
					"# %s\n"+
					"%s\n\n",
				path.Name,
				path.Description,
				path.Command,
			)
		}
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *WhoAmIModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Determine output mode based on hierarchy availability
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *WhoAmIModule) buildTables() []internal.TableFile {
	// Identity table
	identityHeader := []string{
		"Property",
		"Value",
	}

	identityBody := [][]string{
		{"Email", m.Identity.Email},
		{"Type", m.Identity.Type},
	}

	// Add project details (expanded)
	for i, proj := range m.Identity.Projects {
		label := "Project"
		if len(m.Identity.Projects) > 1 {
			label = fmt.Sprintf("Project %d", i+1)
		}
		if proj.DisplayName != "" {
			identityBody = append(identityBody, []string{label, fmt.Sprintf("%s (%s)", proj.DisplayName, proj.ProjectID)})
		} else {
			identityBody = append(identityBody, []string{label, proj.ProjectID})
		}
	}
	if len(m.Identity.Projects) == 0 {
		identityBody = append(identityBody, []string{"Projects", "0"})
	}

	// Add organization details (expanded)
	for i, org := range m.Identity.Organizations {
		label := "Organization"
		if len(m.Identity.Organizations) > 1 {
			label = fmt.Sprintf("Organization %d", i+1)
		}
		if org.DisplayName != "" {
			identityBody = append(identityBody, []string{label, fmt.Sprintf("%s (%s)", org.DisplayName, org.OrgID)})
		} else {
			identityBody = append(identityBody, []string{label, org.OrgID})
		}
	}
	if len(m.Identity.Organizations) == 0 {
		identityBody = append(identityBody, []string{"Organizations", "0"})
	}

	// Add folder details (expanded)
	for i, folder := range m.Identity.Folders {
		label := "Folder"
		if len(m.Identity.Folders) > 1 {
			label = fmt.Sprintf("Folder %d", i+1)
		}
		folderID := strings.TrimPrefix(folder.Name, "folders/")
		if folder.DisplayName != "" {
			identityBody = append(identityBody, []string{label, fmt.Sprintf("%s (%s)", folder.DisplayName, folderID)})
		} else {
			identityBody = append(identityBody, []string{label, folderID})
		}
	}
	if len(m.Identity.Folders) == 0 {
		identityBody = append(identityBody, []string{"Folders", "0"})
	}

	// Add group membership details (expanded)
	for i, group := range m.Identity.Groups {
		label := "Group"
		if len(m.Identity.Groups) > 1 {
			label = fmt.Sprintf("Group %d", i+1)
		}

		// Build display value with source indicator
		var displayValue string
		if group.DisplayName != "" && group.Email != "" {
			displayValue = fmt.Sprintf("%s (%s)", group.DisplayName, group.Email)
		} else if group.Email != "" {
			displayValue = group.Email
		} else if group.DisplayName != "" {
			displayValue = group.DisplayName
		} else {
			displayValue = group.GroupID
		}

		// Add source indicator
		if group.Source == "provided" {
			displayValue += " (provided)"
		} else if group.Source == "enumerated" && m.Identity.GroupsMismatch {
			displayValue += " (enumerated)"
		}

		identityBody = append(identityBody, []string{label, displayValue})
	}
	if len(m.Identity.Groups) == 0 {
		if m.Identity.GroupsEnumerated {
			identityBody = append(identityBody, []string{"Groups", "0"})
		} else {
			identityBody = append(identityBody, []string{"Groups", "Unknown (permission denied)"})
		}
	}

	// Add role binding details (expanded)
	for i, rb := range m.RoleBindings {
		label := "Role Binding"
		if len(m.RoleBindings) > 1 {
			label = fmt.Sprintf("Role Binding %d", i+1)
		}
		// Format: Role -> Scope (ScopeID)
		scopeDisplay := rb.ScopeID
		if rb.ScopeName != "" {
			scopeDisplay = fmt.Sprintf("%s (%s)", rb.ScopeName, rb.ScopeID)
		}

		// Build source/inheritance info
		sourceStr := ""
		if rb.InheritedFrom != "" && rb.InheritedFrom != "direct" {
			if strings.HasPrefix(rb.InheritedFrom, "group:") {
				// Group-based binding
				sourceStr = fmt.Sprintf(" [via %s]", rb.InheritedFrom)
			} else {
				// Inherited from parent resource (folder/org)
				sourceStr = fmt.Sprintf(" [inherited from %s]", rb.InheritedFrom)
			}
		} else if rb.InheritedFrom == "direct" {
			sourceStr = " [direct]"
		}

		identityBody = append(identityBody, []string{label, fmt.Sprintf("%s on %s/%s%s", rb.Role, rb.Scope, scopeDisplay, sourceStr)})
	}
	if len(m.RoleBindings) == 0 {
		identityBody = append(identityBody, []string{"Role Bindings", "0"})
	}

	// Add extended info to identity table
	if m.Extended {
		identityBody = append(identityBody, []string{"Impersonation Targets", fmt.Sprintf("%d", len(m.ImpersonationTargets))})
		identityBody = append(identityBody, []string{"Privilege Escalation Paths", fmt.Sprintf("%d", len(m.PrivEscPaths))})
	}

	// Role bindings table
	rolesHeader := []string{
		"Role",
		"Scope",
		"Scope ID",
		"Source",
	}

	var rolesBody [][]string
	for _, rb := range m.RoleBindings {
		source := rb.InheritedFrom
		if source == "" {
			source = "direct"
		}
		rolesBody = append(rolesBody, []string{
			rb.Role,
			rb.Scope,
			rb.ScopeID,
			source,
		})
	}

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "whoami-identity",
			Header: identityHeader,
			Body:   identityBody,
		},
	}

	if len(rolesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "whoami-roles",
			Header: rolesHeader,
			Body:   rolesBody,
		})
	}

	// Extended mode tables
	if m.Extended {
		// Impersonation targets table
		if len(m.ImpersonationTargets) > 0 {
			impersonationHeader := []string{
				"Service Account",
				"Project",
				"Can Impersonate",
				"Can Create Keys",
				"Can ActAs",
			}

			var impersonationBody [][]string
			for _, target := range m.ImpersonationTargets {
				impersonationBody = append(impersonationBody, []string{
					target.ServiceAccount,
					target.ProjectID,
					whoamiBoolToYesNo(target.CanImpersonate),
					whoamiBoolToYesNo(target.CanCreateKeys),
					whoamiBoolToYesNo(target.CanActAs),
				})
			}

			tables = append(tables, internal.TableFile{
				Name:   "whoami-impersonation",
				Header: impersonationHeader,
				Body:   impersonationBody,
			})
		}

		// Privilege escalation table
		if len(m.PrivEscPaths) > 0 {
			privescHeader := []string{
				"Path Name",
				"Description",
				"Command",
			}

			var privescBody [][]string
			for _, path := range m.PrivEscPaths {
				privescBody = append(privescBody, []string{
					path.Name,
					path.Description,
					path.Command,
				})
			}

			tables = append(tables, internal.TableFile{
				Name:   "whoami-privesc",
				Header: privescHeader,
				Body:   privescBody,
			})
		}
	}

	return tables
}

func (m *WhoAmIModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		// Include loot files that have content and aren't just header comments
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *WhoAmIModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// For whoami, output at org level since it's account-level data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := WhoAmIOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output location - prefer org-level, fall back to project-level
	orgID := ""
	if len(m.Identity.Organizations) > 0 {
		orgID = m.Identity.Organizations[0].OrgID
	} else if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	if orgID != "" {
		// Place at org level
		outputData.OrgLevelData[orgID] = output
	} else if len(m.ProjectIDs) > 0 {
		// Fall back to first project level if no org discovered
		outputData.ProjectLevelData[m.ProjectIDs[0]] = output
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_WHOAMI_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *WhoAmIModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	output := WhoAmIOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Write output
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_WHOAMI_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// whoamiBoolToYesNo converts a boolean to "Yes" or "No"
func whoamiBoolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
