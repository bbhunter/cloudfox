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

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
)

// Flag for extended enumeration
var whoamiExtended bool

var GCPWhoAmICommand = &cobra.Command{
	Use:     globals.GCP_WHOAMI_MODULE_NAME,
	Aliases: []string{"identity", "me"},
	Short:   "Display identity context for the authenticated GCP user/service account",
	Long: `Display identity context for the authenticated GCP user/service account.

Default output:
- Current identity details (email, type)
- Organization and folder context
- Effective role bindings across projects

With --extended flag (adds):
- Service accounts that can be impersonated
- Privilege escalation opportunities
- Exploitation commands`,
	Run: runGCPWhoAmICommand,
}

func init() {
	GCPWhoAmICommand.Flags().BoolVarP(&whoamiExtended, "extended", "e", false, "Enable extended enumeration (impersonation targets, privilege escalation paths)")
}

// ------------------------------
// Data Structures
// ------------------------------

type IdentityContext struct {
	Email         string
	Type          string // "user" or "serviceAccount"
	UniqueID      string
	ProjectIDs    []string
	Organizations []OrgInfo
	Folders       []FolderInfo
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

type RoleBinding struct {
	Role      string
	Scope     string // "organization", "folder", "project"
	ScopeID   string
	Inherited bool
	Condition string
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
	Risk        string // CRITICAL, HIGH, MEDIUM
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

	// Create module instance
	module := &WhoAmIModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		RoleBindings:         []RoleBinding{},
		ImpersonationTargets: []ImpersonationTarget{},
		PrivEscPaths:         []PrivilegeEscalationPath{},
		DangerousPermissions: []string{},
		LootMap:              make(map[string]*internal.LootFile),
		Extended:             whoamiExtended,
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
		logger.ErrorM(fmt.Sprintf("Error retrieving token info: %v", err), globals.GCP_WHOAMI_MODULE_NAME)
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

	// Step 3: Get role bindings across projects (always run)
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
	// Create resource manager client
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error creating CRM client: %v", err), globals.GCP_WHOAMI_MODULE_NAME)
		}
		return
	}

	// Get project ancestry for each project
	for _, projectID := range m.ProjectIDs {
		resp, err := crmService.Projects.GetAncestry(projectID, &cloudresourcemanager.GetAncestryRequest{}).Do()
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error getting ancestry for project %s: %v", projectID, err), globals.GCP_WHOAMI_MODULE_NAME)
			}
			continue
		}

		for _, ancestor := range resp.Ancestor {
			switch ancestor.ResourceId.Type {
			case "organization":
				orgInfo := OrgInfo{
					OrgID: ancestor.ResourceId.Id,
					Name:  fmt.Sprintf("organizations/%s", ancestor.ResourceId.Id),
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
				folderInfo := FolderInfo{
					Name: fmt.Sprintf("folders/%s", ancestor.ResourceId.Id),
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

	// Get role bindings from each project
	for _, projectID := range m.ProjectIDs {
		// Use PrincipalsWithRolesEnhanced which includes inheritance
		principals, err := iamService.PrincipalsWithRolesEnhanced(projectID)
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error getting IAM bindings for project %s: %v", projectID, err), globals.GCP_WHOAMI_MODULE_NAME)
			}
			continue
		}

		// Find bindings for the current identity
		for _, principal := range principals {
			if principal.Name == fullMember || principal.Email == m.Identity.Email {
				for _, binding := range principal.PolicyBindings {
					rb := RoleBinding{
						Role:      binding.Role,
						Scope:     binding.ResourceType,
						ScopeID:   binding.ResourceID,
						Inherited: binding.IsInherited,
					}
					if binding.HasCondition && binding.ConditionInfo != nil {
						rb.Condition = binding.ConditionInfo.Title
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
		}
	}

	logger.InfoM(fmt.Sprintf("Found %d role binding(s) for current identity", len(m.RoleBindings)), globals.GCP_WHOAMI_MODULE_NAME)
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
				Risk:        "HIGH",
				Command:     fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", target.ServiceAccount),
			}
			m.PrivEscPaths = append(m.PrivEscPaths, path)
		}

		if target.CanCreateKeys {
			path := PrivilegeEscalationPath{
				Name:        fmt.Sprintf("Create key for %s", target.ServiceAccount),
				Description: "Can create persistent service account keys",
				Risk:        "CRITICAL",
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
			Risk:        "CRITICAL",
			Command:     fmt.Sprintf("gcloud iam service-accounts list --project=%s", projectID),
		})
	case "roles/iam.serviceAccountKeyAdmin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Key Admin - Create persistent keys",
			Description: "Can create service account keys for any SA",
			Risk:        "CRITICAL",
			Command:     fmt.Sprintf("gcloud iam service-accounts list --project=%s", projectID),
		})
	case "roles/cloudfunctions.admin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Cloud Functions Admin - Code Execution",
			Description: "Can deploy Cloud Functions with SA permissions",
			Risk:        "HIGH",
			Command:     "gcloud functions deploy malicious-function --runtime=python39 --trigger-http --service-account=<target-sa>",
		})
	case "roles/compute.admin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Compute Admin - Metadata Injection",
			Description: "Can add startup scripts with SA access",
			Risk:        "HIGH",
			Command:     "gcloud compute instances add-metadata <instance> --metadata=startup-script='curl -H \"Metadata-Flavor: Google\" http://metadata/...'",
		})
	case "roles/container.admin":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Container Admin - Pod Deployment",
			Description: "Can deploy pods with service account access",
			Risk:        "HIGH",
			Command:     fmt.Sprintf("gcloud container clusters get-credentials <cluster> --project=%s", projectID),
		})
	case "roles/owner", "roles/editor":
		paths = append(paths, PrivilegeEscalationPath{
			Name:        "Owner/Editor - Full Project Access",
			Description: "Has full control over project resources",
			Risk:        "CRITICAL",
			Command:     fmt.Sprintf("gcloud projects get-iam-policy %s", projectID),
		})
	}

	return paths
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *WhoAmIModule) initializeLootFiles() {
	m.LootMap["whoami-context"] = &internal.LootFile{
		Name:     "whoami-context",
		Contents: "# GCP Identity Context\n# Generated by CloudFox\n\n",
	}
	m.LootMap["whoami-permissions"] = &internal.LootFile{
		Name:     "whoami-permissions",
		Contents: "# Current Identity Permissions\n# Generated by CloudFox\n\n",
	}

	// Extended mode loot files
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
	// Context loot
	m.LootMap["whoami-context"].Contents += fmt.Sprintf(
		"Identity: %s\n"+
			"Type: %s\n"+
			"Projects: %s\n"+
			"Organizations: %d\n"+
			"Folders: %d\n\n",
		m.Identity.Email,
		m.Identity.Type,
		strings.Join(m.Identity.ProjectIDs, ", "),
		len(m.Identity.Organizations),
		len(m.Identity.Folders),
	)

	// Permissions loot
	for _, rb := range m.RoleBindings {
		m.LootMap["whoami-permissions"].Contents += fmt.Sprintf(
			"%s on %s/%s\n",
			rb.Role,
			rb.Scope,
			rb.ScopeID,
		)
	}

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
				"## %s [%s]\n"+
					"# %s\n"+
					"%s\n\n",
				path.Name,
				path.Risk,
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
	// Identity table
	identityHeader := []string{
		"Property",
		"Value",
	}

	identityBody := [][]string{
		{"Email", m.Identity.Email},
		{"Type", m.Identity.Type},
		{"Projects", strings.Join(m.Identity.ProjectIDs, ", ")},
		{"Organizations", fmt.Sprintf("%d", len(m.Identity.Organizations))},
		{"Folders", fmt.Sprintf("%d", len(m.Identity.Folders))},
		{"Role Bindings", fmt.Sprintf("%d", len(m.RoleBindings))},
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
	}

	var rolesBody [][]string
	for _, rb := range m.RoleBindings {
		rolesBody = append(rolesBody, []string{
			rb.Role,
			rb.Scope,
			rb.ScopeID,
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
				"Risk",
				"Description",
				"Command",
			}

			var privescBody [][]string
			for _, path := range m.PrivEscPaths {
				privescBody = append(privescBody, []string{
					path.Name,
					path.Risk,
					path.Description,
					truncateString(path.Command, 50),
				})
			}

			tables = append(tables, internal.TableFile{
				Name:   "whoami-privesc",
				Header: privescHeader,
				Body:   privescBody,
			})
		}
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

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
