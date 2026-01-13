package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPermissionsCommand = &cobra.Command{
	Use:     globals.GCP_PERMISSIONS_MODULE_NAME,
	Aliases: []string{"perms", "privs"},
	Short:   "Enumerate ALL permissions for each IAM entity with full inheritance explosion",
	Long: `Enumerate ALL permissions for each IAM entity with complete inheritance explosion.

This module provides COMPLETE permission visibility by:
- Enumerating organization-level IAM bindings (top of hierarchy)
- Enumerating folder-level IAM bindings (inherited to child resources)
- Enumerating project-level IAM bindings (resource-specific)
- EXPLODING every role into its individual permissions (one line per permission)
- Tracking the exact inheritance source for each permission
- Expanding group memberships to show inherited permissions
- Identifying cross-project access patterns
- Flagging dangerous/privesc permissions

Output: Single unified table with one row per permission entry.`,
	Run: runGCPPermissionsCommand,
}

// High-privilege permission prefixes that should be flagged
var highPrivilegePermissionPrefixes = []string{
	"iam.serviceAccounts.actAs",
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccounts.getOpenIdToken",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccountKeys.create",
	"iam.roles.create",
	"iam.roles.update",
	"resourcemanager.projects.setIamPolicy",
	"resourcemanager.folders.setIamPolicy",
	"resourcemanager.organizations.setIamPolicy",
	"compute.instances.setMetadata",
	"compute.instances.setServiceAccount",
	"compute.projects.setCommonInstanceMetadata",
	"storage.buckets.setIamPolicy",
	"storage.objects.setIamPolicy",
	"cloudfunctions.functions.setIamPolicy",
	"run.services.setIamPolicy",
	"secretmanager.secrets.setIamPolicy",
	"deploymentmanager.deployments.create",
	"cloudbuild.builds.create",
	"container.clusters.getCredentials",
	"orgpolicy.policy.set",
}

// ExplodedPermission represents a single permission entry with full context
type ExplodedPermission struct {
	Entity            string
	EntityType        string
	EntityEmail       string
	Permission        string
	Role              string
	RoleType          string
	ResourceScope     string
	ResourceScopeType string
	ResourceScopeID   string
	ResourceScopeName string
	InheritedFrom     string
	IsInherited       bool
	HasCondition      bool
	Condition         string
	ConditionTitle    string
	EffectiveProject  string
	ProjectName       string
	IsCrossProject    bool
	SourceProject     string
	IsHighPrivilege   bool
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type PermissionsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	ExplodedPerms     []ExplodedPermission
	EntityPermissions []IAMService.EntityPermissions
	GroupInfos        []IAMService.GroupInfo
	OrgBindings       []IAMService.PolicyBinding
	FolderBindings    map[string][]IAMService.PolicyBinding
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex

	// Organization info for output path
	OrgIDs   []string
	OrgNames map[string]string
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type PermissionsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PermissionsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PermissionsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPPermissionsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PERMISSIONS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PermissionsModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ExplodedPerms:     []ExplodedPermission{},
		EntityPermissions: []IAMService.EntityPermissions{},
		GroupInfos:        []IAMService.GroupInfo{},
		OrgBindings:       []IAMService.PolicyBinding{},
		FolderBindings:    make(map[string][]IAMService.PolicyBinding),
		LootMap:           make(map[string]*internal.LootFile),
		OrgIDs:            []string{},
		OrgNames:          make(map[string]string),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *PermissionsModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Enumerating ALL permissions with full inheritance explosion...", globals.GCP_PERMISSIONS_MODULE_NAME)
	logger.InfoM("This includes organization, folder, and project-level bindings", globals.GCP_PERMISSIONS_MODULE_NAME)

	// First, try to enumerate organization-level bindings
	m.enumerateOrganizationBindings(ctx, logger)

	// Run project enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_PERMISSIONS_MODULE_NAME, m.processProject)

	if len(m.ExplodedPerms) == 0 {
		logger.InfoM("No permissions found", globals.GCP_PERMISSIONS_MODULE_NAME)
		return
	}

	// Count statistics
	uniqueEntities := make(map[string]bool)
	uniquePerms := make(map[string]bool)
	inheritedCount := 0
	crossProjectCount := 0
	highPrivCount := 0

	for _, ep := range m.ExplodedPerms {
		uniqueEntities[ep.Entity] = true
		uniquePerms[ep.Permission] = true
		if ep.IsInherited {
			inheritedCount++
		}
		if ep.IsCrossProject {
			crossProjectCount++
		}
		if ep.IsHighPrivilege {
			highPrivCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Exploded %d total permission entries for %d entities",
		len(m.ExplodedPerms), len(uniqueEntities)), globals.GCP_PERMISSIONS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Unique permissions: %d | Inherited: %d | Cross-project: %d | High-privilege: %d",
		len(uniquePerms), inheritedCount, crossProjectCount, highPrivCount), globals.GCP_PERMISSIONS_MODULE_NAME)

	if len(m.GroupInfos) > 0 {
		groupsEnumerated := 0
		for _, gi := range m.GroupInfos {
			if gi.MembershipEnumerated {
				groupsEnumerated++
			}
		}
		logger.InfoM(fmt.Sprintf("Found %d group(s), enumerated membership for %d", len(m.GroupInfos), groupsEnumerated), globals.GCP_PERMISSIONS_MODULE_NAME)

		unenumeratedGroups := len(m.GroupInfos) - groupsEnumerated
		if unenumeratedGroups > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Could not enumerate membership for %d group(s) - permissions inherited via these groups are NOT visible!", unenumeratedGroups), globals.GCP_PERMISSIONS_MODULE_NAME)
		}
	}

	m.writeOutput(ctx, logger)
}

// enumerateOrganizationBindings tries to get organization-level IAM bindings
func (m *PermissionsModule) enumerateOrganizationBindings(ctx context.Context, logger internal.Logger) {
	orgsSvc := orgsservice.New()

	if len(m.ProjectIDs) > 0 {
		iamSvc := IAMService.New()

		bindings, err := iamSvc.PoliciesWithInheritance(m.ProjectIDs[0])
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not get inherited policies: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
			}
			return
		}

		for _, binding := range bindings {
			if binding.ResourceType == "organization" {
				m.mu.Lock()
				m.OrgBindings = append(m.OrgBindings, binding)
				// Track org IDs
				if !contains(m.OrgIDs, binding.ResourceID) {
					m.OrgIDs = append(m.OrgIDs, binding.ResourceID)
					m.OrgNames[binding.ResourceID] = binding.ResourceID // Use ID as name for now
				}
				m.mu.Unlock()
			} else if binding.ResourceType == "folder" {
				m.mu.Lock()
				m.FolderBindings[binding.ResourceID] = append(m.FolderBindings[binding.ResourceID], binding)
				m.mu.Unlock()
			}
		}

		if len(m.OrgBindings) > 0 {
			logger.InfoM(fmt.Sprintf("Found %d organization-level IAM binding(s)", len(m.OrgBindings)), globals.GCP_PERMISSIONS_MODULE_NAME)
		}

		totalFolderBindings := 0
		for _, bindings := range m.FolderBindings {
			totalFolderBindings += len(bindings)
		}
		if totalFolderBindings > 0 {
			logger.InfoM(fmt.Sprintf("Found %d folder-level IAM binding(s) across %d folder(s)", totalFolderBindings, len(m.FolderBindings)), globals.GCP_PERMISSIONS_MODULE_NAME)
		}
	}

	_ = orgsSvc
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *PermissionsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating permissions in project: %s", projectID), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	iamService := IAMService.New()
	entityPerms, groupInfos, err := iamService.GetAllEntityPermissionsWithGroupExpansion(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PERMISSIONS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate permissions in project %s", projectID))
		return
	}

	var explodedPerms []ExplodedPermission
	for _, ep := range entityPerms {
		for _, perm := range ep.Permissions {
			isHighPriv := isHighPrivilegePermission(perm.Permission)

			exploded := ExplodedPermission{
				Entity:            ep.Entity,
				EntityType:        ep.EntityType,
				EntityEmail:       ep.Email,
				Permission:        perm.Permission,
				Role:              perm.Role,
				RoleType:          perm.RoleType,
				ResourceScope:     fmt.Sprintf("%s/%s", perm.ResourceType, perm.ResourceID),
				ResourceScopeType: perm.ResourceType,
				ResourceScopeID:   perm.ResourceID,
				ResourceScopeName: m.getScopeName(perm.ResourceType, perm.ResourceID),
				IsInherited:       perm.IsInherited,
				InheritedFrom:     perm.InheritedFrom,
				HasCondition:      perm.HasCondition,
				Condition:         perm.Condition,
				EffectiveProject:  projectID,
				ProjectName:       m.GetProjectName(projectID),
				IsHighPrivilege:   isHighPriv,
			}

			// Parse condition title if present
			if perm.HasCondition && perm.Condition != "" {
				exploded.ConditionTitle = parseConditionTitle(perm.Condition)
			}

			// Detect cross-project access
			if ep.EntityType == "ServiceAccount" {
				parts := strings.Split(ep.Email, "@")
				if len(parts) == 2 {
					saParts := strings.Split(parts[1], ".")
					if len(saParts) >= 1 {
						saProject := saParts[0]
						if saProject != projectID {
							exploded.IsCrossProject = true
							exploded.SourceProject = saProject
						}
					}
				}
			}

			explodedPerms = append(explodedPerms, exploded)
		}
	}

	m.mu.Lock()
	m.ExplodedPerms = append(m.ExplodedPerms, explodedPerms...)
	m.EntityPermissions = append(m.EntityPermissions, entityPerms...)
	m.GroupInfos = append(m.GroupInfos, groupInfos...)

	// Generate loot
	for _, ep := range entityPerms {
		m.addEntityToLoot(ep)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Exploded %d permission entries in project %s", len(explodedPerms), projectID), globals.GCP_PERMISSIONS_MODULE_NAME)
	}
}

func (m *PermissionsModule) getScopeName(scopeType, scopeID string) string {
	switch scopeType {
	case "project":
		return m.GetProjectName(scopeID)
	case "organization":
		if name, ok := m.OrgNames[scopeID]; ok {
			return name
		}
		return scopeID
	case "folder":
		return scopeID // Could be enhanced to lookup folder names
	default:
		return scopeID
	}
}

func parseConditionTitle(condition string) string {
	// Try to extract title from condition if it looks like a struct
	if strings.Contains(condition, "title:") {
		parts := strings.Split(condition, "title:")
		if len(parts) > 1 {
			titlePart := strings.TrimSpace(parts[1])
			if idx := strings.Index(titlePart, " "); idx > 0 {
				return titlePart[:idx]
			}
			return titlePart
		}
	}
	return ""
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *PermissionsModule) initializeLootFiles() {
	m.LootMap["permissions-commands"] = &internal.LootFile{
		Name:     "permissions-commands",
		Contents: "# GCP Permissions Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *PermissionsModule) addEntityToLoot(ep IAMService.EntityPermissions) {
	// Only add service accounts with high-privilege permissions
	hasHighPriv := false
	var highPrivPerms []string

	for _, perm := range ep.Permissions {
		if isHighPrivilegePermission(perm.Permission) {
			hasHighPriv = true
			highPrivPerms = append(highPrivPerms, perm.Permission)
		}
	}

	if ep.EntityType == "ServiceAccount" {
		if hasHighPriv {
			m.LootMap["permissions-commands"].Contents += fmt.Sprintf(
				"# Service Account: %s [HIGH PRIVILEGE]\n"+
					"# High-privilege permissions: %s\n"+
					"# Roles: %s\n",
				ep.Email,
				strings.Join(highPrivPerms, ", "),
				strings.Join(ep.Roles, ", "),
			)
		} else {
			m.LootMap["permissions-commands"].Contents += fmt.Sprintf(
				"# Service Account: %s\n"+
					"# Roles: %s\n",
				ep.Email,
				strings.Join(ep.Roles, ", "),
			)
		}

		m.LootMap["permissions-commands"].Contents += fmt.Sprintf(
			"gcloud iam service-accounts describe %s --project=%s\n"+
				"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n"+
				"gcloud iam service-accounts get-iam-policy %s --project=%s\n"+
				"gcloud iam service-accounts keys create ./key.json --iam-account=%s --project=%s\n"+
				"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
			ep.Email, ep.ProjectID,
			ep.Email, ep.ProjectID,
			ep.Email, ep.ProjectID,
			ep.Email, ep.ProjectID,
			ep.Email,
		)
	}
}

// isHighPrivilegePermission checks if a permission is considered high-privilege
func isHighPrivilegePermission(permission string) bool {
	for _, prefix := range highPrivilegePermissionPrefixes {
		if strings.HasPrefix(permission, prefix) {
			return true
		}
	}
	return false
}

// PermFederatedIdentityInfo contains parsed information about a federated identity
type PermFederatedIdentityInfo struct {
	IsFederated  bool
	ProviderType string // AWS, GitHub, GitLab, OIDC, SAML, Azure, etc.
	PoolName     string
	Subject      string
	Attribute    string
}

// parsePermFederatedIdentity detects and parses federated identity principals
func parsePermFederatedIdentity(identity string) PermFederatedIdentityInfo {
	info := PermFederatedIdentityInfo{}

	// Check for principal:// or principalSet:// format
	if !strings.HasPrefix(identity, "principal://") && !strings.HasPrefix(identity, "principalSet://") {
		return info
	}

	info.IsFederated = true

	// Extract pool name if present
	if strings.Contains(identity, "workloadIdentityPools/") {
		parts := strings.Split(identity, "workloadIdentityPools/")
		if len(parts) > 1 {
			poolParts := strings.Split(parts[1], "/")
			if len(poolParts) > 0 {
				info.PoolName = poolParts[0]
			}
		}
	}

	// Detect provider type based on common patterns
	identityLower := strings.ToLower(identity)

	switch {
	case strings.Contains(identityLower, "aws") || strings.Contains(identityLower, "amazon"):
		info.ProviderType = "AWS"
	case strings.Contains(identityLower, "github"):
		info.ProviderType = "GitHub"
	case strings.Contains(identityLower, "gitlab"):
		info.ProviderType = "GitLab"
	case strings.Contains(identityLower, "azure") || strings.Contains(identityLower, "microsoft"):
		info.ProviderType = "Azure"
	case strings.Contains(identityLower, "okta"):
		info.ProviderType = "Okta"
	case strings.Contains(identityLower, "bitbucket"):
		info.ProviderType = "Bitbucket"
	case strings.Contains(identityLower, "circleci"):
		info.ProviderType = "CircleCI"
	case strings.Contains(identity, "attribute."):
		info.ProviderType = "OIDC"
	default:
		info.ProviderType = "Federated"
	}

	// Extract subject if present
	// Format: .../subject/{subject}
	if strings.Contains(identity, "/subject/") {
		parts := strings.Split(identity, "/subject/")
		if len(parts) > 1 {
			info.Subject = parts[1]
		}
	}

	// Extract attribute and value if present
	// Format: .../attribute.{attr}/{value}
	if strings.Contains(identity, "/attribute.") {
		parts := strings.Split(identity, "/attribute.")
		if len(parts) > 1 {
			attrParts := strings.Split(parts[1], "/")
			if len(attrParts) >= 1 {
				info.Attribute = attrParts[0]
			}
			if len(attrParts) >= 2 {
				// The value is the specific identity (e.g., repo name)
				info.Subject = attrParts[1]
			}
		}
	}

	return info
}

// formatPermFederatedInfo formats federated identity info for display
func formatPermFederatedInfo(info PermFederatedIdentityInfo) string {
	if !info.IsFederated {
		return "-"
	}

	result := info.ProviderType

	// Show subject (specific identity like repo/workflow) if available
	if info.Subject != "" {
		result += ": " + info.Subject
	} else if info.Attribute != "" {
		result += " [" + info.Attribute + "]"
	}

	// Add pool name in parentheses
	if info.PoolName != "" {
		result += " (pool: " + info.PoolName + ")"
	}

	return result
}

// formatCondition formats a condition for display
func formatPermissionCondition(hasCondition bool, condition, conditionTitle string) string {
	if !hasCondition {
		return "No"
	}

	if conditionTitle != "" {
		return conditionTitle
	}

	// Parse common patterns
	if strings.Contains(condition, "request.time") {
		return "[time-limited]"
	}
	if strings.Contains(condition, "resource.name") {
		return "[resource-scoped]"
	}
	if strings.Contains(condition, "origin.ip") || strings.Contains(condition, "request.origin") {
		return "[IP-restricted]"
	}
	if strings.Contains(condition, "device") {
		return "[device-policy]"
	}

	return "Yes"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PermissionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Single unified table with all permissions
	header := []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Entity Type",
		"Identity",
		"Permission",
		"Role",
		"Custom Role",
		"Inherited",
		"Inherited From",
		"Condition",
		"Cross-Project",
		"High Privilege",
		"Federated",
	}

	var body [][]string
	for _, ep := range m.ExplodedPerms {
		isCustom := "No"
		if ep.RoleType == "custom" || strings.HasPrefix(ep.Role, "projects/") || strings.HasPrefix(ep.Role, "organizations/") {
			isCustom = "Yes"
		}

		inherited := "No"
		if ep.IsInherited {
			inherited = "Yes"
		}

		inheritedFrom := "-"
		if ep.IsInherited && ep.InheritedFrom != "" {
			inheritedFrom = ep.InheritedFrom
		}

		condition := formatPermissionCondition(ep.HasCondition, ep.Condition, ep.ConditionTitle)

		crossProject := "No"
		if ep.IsCrossProject {
			crossProject = fmt.Sprintf("Yes (from %s)", ep.SourceProject)
		}

		highPriv := "No"
		if ep.IsHighPrivilege {
			highPriv = "Yes"
		}

		// Check for federated identity
		federated := formatPermFederatedInfo(parsePermFederatedIdentity(ep.EntityEmail))

		body = append(body, []string{
			ep.ResourceScopeType,
			ep.ResourceScopeID,
			ep.ResourceScopeName,
			ep.EntityType,
			ep.EntityEmail,
			ep.Permission,
			ep.Role,
			isCustom,
			inherited,
			inheritedFrom,
			condition,
			crossProject,
			highPriv,
			federated,
		})
	}

	// Sort by scope type (org first, then folder, then project), then entity, then permission
	scopeOrder := map[string]int{"organization": 0, "folder": 1, "project": 2}
	sort.Slice(body, func(i, j int) bool {
		if body[i][0] != body[j][0] {
			return scopeOrder[body[i][0]] < scopeOrder[body[j][0]]
		}
		if body[i][4] != body[j][4] {
			return body[i][4] < body[j][4]
		}
		return body[i][5] < body[j][5]
	})

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	tables := []internal.TableFile{
		{
			Name:   "permissions",
			Header: header,
			Body:   body,
		},
	}

	// Log findings
	highPrivCount := 0
	crossProjectCount := 0
	for _, ep := range m.ExplodedPerms {
		if ep.IsHighPrivilege {
			highPrivCount++
		}
		if ep.IsCrossProject {
			crossProjectCount++
		}
	}

	if highPrivCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d high-privilege permission entries!", highPrivCount), globals.GCP_PERMISSIONS_MODULE_NAME)
	}
	if crossProjectCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d cross-project permission entries!", crossProjectCount), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	output := PermissionsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output scope - use org if available, otherwise fall back to project
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
