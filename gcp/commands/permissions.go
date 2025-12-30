package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	privescservice "github.com/BishopFox/cloudfox/gcp/services/privescService"
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

Output Tables:
1. permissions-exploded: ONE ROW PER PERMISSION with full context
2. permissions-summary: Entity summary with permission counts
3. permissions-by-scope: Permissions grouped by resource scope (org/folder/project)
4. permissions-dangerous: Privesc-relevant permissions
5. permissions-cross-project: Permissions granting cross-project access

Each permission row includes:
- Entity (user/SA/group)
- Permission name
- Role that grants this permission
- Resource scope (organization/folder/project ID)
- Inheritance source (where the binding was defined)
- Condition (if any IAM conditions apply)

This is a comprehensive enumeration - expect longer execution times for large organizations.`,
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
	Entity            string // Full entity identifier (e.g., user:foo@example.com)
	EntityType        string // User, ServiceAccount, Group, etc.
	EntityEmail       string // Clean email without prefix
	Permission        string // Individual permission name
	Role              string // Role that grants this permission
	RoleType          string // predefined, custom, basic
	ResourceScope     string // Full resource path (organizations/123, folders/456, projects/xyz)
	ResourceScopeType string // organization, folder, project
	ResourceScopeID   string // Just the ID portion
	InheritedFrom     string // Where the binding was defined (if different from scope)
	IsInherited       bool   // True if permission comes from a higher level
	HasCondition      bool   // True if IAM condition applies
	Condition         string // Condition expression if any
	EffectiveProject  string // The project this permission is effective in
	ProjectName       string // Display name of the effective project
	IsCrossProject    bool   // True if entity is from different project
	SourceProject     string // Entity's home project (for cross-project detection)
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
	OrgBindings       []IAMService.PolicyBinding // Organization-level bindings
	FolderBindings    map[string][]IAMService.PolicyBinding // Folder ID -> bindings
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex
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
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PERMISSIONS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &PermissionsModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ExplodedPerms:     []ExplodedPermission{},
		EntityPermissions: []IAMService.EntityPermissions{},
		GroupInfos:        []IAMService.GroupInfo{},
		OrgBindings:       []IAMService.PolicyBinding{},
		FolderBindings:    make(map[string][]IAMService.PolicyBinding),
		LootMap:           make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
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

	// Check results
	if len(m.ExplodedPerms) == 0 {
		logger.InfoM("No permissions found", globals.GCP_PERMISSIONS_MODULE_NAME)
		return
	}

	// Count statistics
	uniqueEntities := make(map[string]bool)
	uniquePerms := make(map[string]bool)
	inheritedCount := 0
	crossProjectCount := 0
	dangerousCount := 0

	for _, ep := range m.ExplodedPerms {
		uniqueEntities[ep.Entity] = true
		uniquePerms[ep.Permission] = true
		if ep.IsInherited {
			inheritedCount++
		}
		if ep.IsCrossProject {
			crossProjectCount++
		}
		if getDangerousPermissionInfo(ep.Permission) != nil {
			dangerousCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Exploded %d total permission entries for %d entities",
		len(m.ExplodedPerms), len(uniqueEntities)), globals.GCP_PERMISSIONS_MODULE_NAME)
	logger.InfoM(fmt.Sprintf("Unique permissions: %d | Inherited: %d | Cross-project: %d | Dangerous: %d",
		len(uniquePerms), inheritedCount, crossProjectCount, dangerousCount), globals.GCP_PERMISSIONS_MODULE_NAME)

	if len(m.GroupInfos) > 0 {
		groupsEnumerated := 0
		for _, gi := range m.GroupInfos {
			if gi.MembershipEnumerated {
				groupsEnumerated++
			}
		}
		logger.InfoM(fmt.Sprintf("Found %d group(s), enumerated membership for %d", len(m.GroupInfos), groupsEnumerated), globals.GCP_PERMISSIONS_MODULE_NAME)

		// Warn about blindspot if we couldn't enumerate some groups
		unenumeratedGroups := len(m.GroupInfos) - groupsEnumerated
		if unenumeratedGroups > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Could not enumerate membership for %d group(s) - permissions inherited via these groups are NOT visible!", unenumeratedGroups), globals.GCP_PERMISSIONS_MODULE_NAME)
		}
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// enumerateOrganizationBindings tries to get organization-level IAM bindings
func (m *PermissionsModule) enumerateOrganizationBindings(ctx context.Context, logger internal.Logger) {
	// Try to discover the organization
	orgsSvc := orgsservice.New()

	// Use SearchProjects to find organizations from project ancestry
	if len(m.ProjectIDs) > 0 {
		iamSvc := IAMService.New()

		// Try to get org bindings via the first project's ancestry
		bindings, err := iamSvc.PoliciesWithInheritance(m.ProjectIDs[0])
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.InfoM(fmt.Sprintf("Could not get inherited policies: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
			}
			return
		}

		// Extract org and folder bindings
		for _, binding := range bindings {
			if binding.ResourceType == "organization" {
				m.mu.Lock()
				m.OrgBindings = append(m.OrgBindings, binding)
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

	_ = orgsSvc // silence unused warning if not used
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *PermissionsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating permissions in project: %s", projectID), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	// Create service and fetch permissions with group expansion
	iamService := IAMService.New()
	entityPerms, groupInfos, err := iamService.GetAllEntityPermissionsWithGroupExpansion(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating permissions in project %s: %v", projectID, err), globals.GCP_PERMISSIONS_MODULE_NAME)
		}
		return
	}

	// Explode permissions - create one entry per permission
	var explodedPerms []ExplodedPermission
	for _, ep := range entityPerms {
		for _, perm := range ep.Permissions {
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
				IsInherited:       perm.IsInherited,
				InheritedFrom:     perm.InheritedFrom,
				HasCondition:      perm.HasCondition,
				Condition:         perm.Condition,
				EffectiveProject:  projectID,
				ProjectName:       m.GetProjectName(projectID),
			}

			// Detect cross-project access
			if ep.EntityType == "ServiceAccount" {
				// Extract project from SA email (format: sa-name@project-id.iam.gserviceaccount.com)
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

	// Thread-safe append
	m.mu.Lock()
	m.ExplodedPerms = append(m.ExplodedPerms, explodedPerms...)
	m.EntityPermissions = append(m.EntityPermissions, entityPerms...)
	m.GroupInfos = append(m.GroupInfos, groupInfos...)

	// Generate loot for each entity
	for _, ep := range entityPerms {
		m.addEntityToLoot(ep)
	}

	// Generate loot for group memberships
	for _, gi := range groupInfos {
		m.addGroupToLoot(gi)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Exploded %d permission entries in project %s", len(explodedPerms), projectID), globals.GCP_PERMISSIONS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *PermissionsModule) initializeLootFiles() {
	m.LootMap["permissions-all"] = &internal.LootFile{
		Name:     "permissions-all",
		Contents: "# GCP Entity Permissions (All)\n# Generated by CloudFox\n# Format: Entity | Permission | Role | Scope | Inherited | Condition\n\n",
	}
	m.LootMap["permissions-high-privilege"] = &internal.LootFile{
		Name:     "permissions-high-privilege",
		Contents: "# GCP High-Privilege Permissions\n# Generated by CloudFox\n# These permissions can lead to privilege escalation\n\n",
	}
	m.LootMap["permissions-by-entity"] = &internal.LootFile{
		Name:     "permissions-by-entity",
		Contents: "# GCP Permissions Grouped by Entity\n# Generated by CloudFox\n\n",
	}
	m.LootMap["permissions-inherited"] = &internal.LootFile{
		Name:     "permissions-inherited",
		Contents: "# GCP Inherited Permissions\n# Generated by CloudFox\n# These permissions are inherited from folders or organization\n\n",
	}
	m.LootMap["permissions-conditional"] = &internal.LootFile{
		Name:     "permissions-conditional",
		Contents: "# GCP Conditional Permissions\n# Generated by CloudFox\n# These permissions have IAM conditions (conditional access)\n\n",
	}
	m.LootMap["group-memberships"] = &internal.LootFile{
		Name:     "group-memberships",
		Contents: "# GCP Group Memberships\n# Generated by CloudFox\n# Shows group members including nested groups\n\n",
	}
	m.LootMap["groups-unenumerated"] = &internal.LootFile{
		Name:     "groups-unenumerated",
		Contents: "# GCP Groups - Membership NOT Enumerated (BLINDSPOT)\n# Generated by CloudFox\n# These groups have IAM permissions but membership could not be enumerated\n# Members of these groups inherit permissions that are NOT visible in other output\n# Requires Cloud Identity API access to enumerate\n\n",
	}
	// Pentest-focused loot files
	m.LootMap["permissions-dangerous"] = &internal.LootFile{
		Name:     "permissions-dangerous",
		Contents: "# GCP Dangerous Permissions (Privesc Risk)\n# Generated by CloudFox\n# These permissions can lead to privilege escalation\n\n",
	}
	m.LootMap["permissions-dangerous-by-category"] = &internal.LootFile{
		Name:     "permissions-dangerous-by-category",
		Contents: "# GCP Dangerous Permissions by Category\n# Generated by CloudFox\n\n",
	}
	m.LootMap["permissions-cross-project"] = &internal.LootFile{
		Name:     "permissions-cross-project",
		Contents: "# GCP Cross-Project Permissions\n# Generated by CloudFox\n# Service accounts with access to projects outside their home project\n\n",
	}
	m.LootMap["permissions-org-level"] = &internal.LootFile{
		Name:     "permissions-org-level",
		Contents: "# GCP Organization-Level Permissions\n# Generated by CloudFox\n# These permissions are inherited by ALL projects in the organization\n\n",
	}
}

func (m *PermissionsModule) addEntityToLoot(ep IAMService.EntityPermissions) {
	// Permissions by entity
	m.LootMap["permissions-by-entity"].Contents += fmt.Sprintf(
		"# Entity: %s (Type: %s)\n"+
			"# Project: %s\n"+
			"# Roles: %s\n"+
			"# Total Permissions: %d (Unique: %d)\n",
		ep.Email, ep.EntityType,
		ep.ProjectID,
		strings.Join(ep.Roles, ", "),
		ep.TotalPerms, ep.UniquePerms,
	)

	// Sort permissions for consistent output
	sortedPerms := make([]IAMService.PermissionEntry, len(ep.Permissions))
	copy(sortedPerms, ep.Permissions)
	sort.Slice(sortedPerms, func(i, j int) bool {
		return sortedPerms[i].Permission < sortedPerms[j].Permission
	})

	for _, perm := range sortedPerms {
		inherited := ""
		if perm.IsInherited {
			inherited = fmt.Sprintf(" [inherited from %s]", perm.InheritedFrom)
		}
		condition := ""
		if perm.HasCondition {
			condition = fmt.Sprintf(" [condition: %s]", perm.Condition)
		}

		m.LootMap["permissions-by-entity"].Contents += fmt.Sprintf(
			"  %s (via %s)%s%s\n",
			perm.Permission, perm.Role, inherited, condition,
		)

		// All permissions
		m.LootMap["permissions-all"].Contents += fmt.Sprintf(
			"%s | %s | %s | %s/%s | %v | %s\n",
			ep.Email, perm.Permission, perm.Role, perm.ResourceType, perm.ResourceID, perm.IsInherited, perm.Condition,
		)

		// High privilege permissions
		if isHighPrivilegePermission(perm.Permission) {
			m.LootMap["permissions-high-privilege"].Contents += fmt.Sprintf(
				"# Entity: %s (Type: %s)\n"+
					"# Permission: %s\n"+
					"# Role: %s (%s)\n"+
					"# Resource: %s/%s%s%s\n\n",
				ep.Email, ep.EntityType,
				perm.Permission,
				perm.Role, perm.RoleType,
				perm.ResourceType, perm.ResourceID, inherited, condition,
			)
		}

		// Dangerous permissions with detailed categorization
		if dpInfo := getDangerousPermissionInfo(perm.Permission); dpInfo != nil {
			m.LootMap["permissions-dangerous"].Contents += fmt.Sprintf(
				"## [%s] %s\n"+
					"## Entity: %s (%s)\n"+
					"## Permission: %s\n"+
					"## Category: %s\n"+
					"## Description: %s\n"+
					"## Role: %s\n"+
					"## Project: %s%s%s\n\n",
				dpInfo.RiskLevel, dpInfo.Category,
				ep.Email, ep.EntityType,
				dpInfo.Permission,
				dpInfo.Category,
				dpInfo.Description,
				perm.Role,
				perm.ResourceID, inherited, condition,
			)

			m.LootMap["permissions-dangerous-by-category"].Contents += fmt.Sprintf(
				"[%s] %s | %s | %s | %s | %s\n",
				dpInfo.RiskLevel, dpInfo.Category, ep.Email, dpInfo.Permission, dpInfo.Description, perm.ResourceID,
			)
		}

		// Inherited permissions
		if perm.IsInherited {
			m.LootMap["permissions-inherited"].Contents += fmt.Sprintf(
				"%s | %s | %s | %s\n",
				ep.Email, perm.Permission, perm.Role, perm.InheritedFrom,
			)
		}

		// Conditional permissions
		if perm.HasCondition {
			m.LootMap["permissions-conditional"].Contents += fmt.Sprintf(
				"%s | %s | %s | %s\n",
				ep.Email, perm.Permission, perm.Role, perm.Condition,
			)
		}

		// Organization-level permissions
		if perm.ResourceType == "organization" {
			m.LootMap["permissions-org-level"].Contents += fmt.Sprintf(
				"%s | %s | %s | %s\n",
				ep.Email, perm.Permission, perm.Role, perm.ResourceID,
			)
		}
	}
	m.LootMap["permissions-by-entity"].Contents += "\n"
}

// addGroupToLoot adds group membership information to loot files
func (m *PermissionsModule) addGroupToLoot(gi IAMService.GroupInfo) {
	enumStatus := "not enumerated"
	if gi.MembershipEnumerated {
		enumStatus = "enumerated"
	}

	m.LootMap["group-memberships"].Contents += fmt.Sprintf(
		"# Group: %s\n"+
			"# Display Name: %s\n"+
			"# Project: %s\n"+
			"# Member Count: %d\n"+
			"# Has Nested Groups: %v\n"+
			"# Membership Status: %s\n"+
			"# Roles: %s\n",
		gi.Email,
		gi.DisplayName,
		gi.ProjectID,
		gi.MemberCount,
		gi.HasNestedGroups,
		enumStatus,
		strings.Join(gi.Roles, ", "),
	)

	if gi.MembershipEnumerated && len(gi.Members) > 0 {
		m.LootMap["group-memberships"].Contents += "# Members:\n"
		for _, member := range gi.Members {
			m.LootMap["group-memberships"].Contents += fmt.Sprintf(
				"  - %s (Type: %s, Role: %s)\n",
				member.Email, member.Type, member.Role,
			)
		}
	}

	if gi.HasNestedGroups && len(gi.NestedGroups) > 0 {
		m.LootMap["group-memberships"].Contents += "# Nested Groups:\n"
		for _, nested := range gi.NestedGroups {
			m.LootMap["group-memberships"].Contents += fmt.Sprintf("  - %s\n", nested)
		}
	}

	m.LootMap["group-memberships"].Contents += "\n"

	// Track unenumerated groups as a blindspot
	if !gi.MembershipEnumerated {
		m.LootMap["groups-unenumerated"].Contents += fmt.Sprintf(
			"# BLINDSPOT: Group %s\n"+
				"# Project: %s\n"+
				"# Roles assigned to this group: %s\n"+
				"# Members of this group inherit these roles but are NOT visible!\n\n",
			gi.Email,
			gi.ProjectID,
			strings.Join(gi.Roles, ", "),
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

// DangerousPermissionInfo contains detailed info about a dangerous permission
type DangerousPermissionInfo struct {
	Permission  string
	Category    string
	RiskLevel   string
	Description string
}

// getDangerousPermissionInfo returns detailed info if permission is dangerous, nil otherwise
func getDangerousPermissionInfo(permission string) *DangerousPermissionInfo {
	dangerousPerms := privescservice.GetDangerousPermissions()
	for _, dp := range dangerousPerms {
		if permission == dp.Permission {
			return &DangerousPermissionInfo{
				Permission:  dp.Permission,
				Category:    dp.Category,
				RiskLevel:   dp.RiskLevel,
				Description: dp.Description,
			}
		}
	}
	return nil
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PermissionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// ========================================
	// TABLE 1: EXPLODED PERMISSIONS (Main table - one row per permission)
	// ========================================
	explodedHeader := []string{
		"Entity",
		"Type",
		"Permission",
		"Role",
		"Role Type",
		"Resource Scope",
		"Scope Type",
		"Scope ID",
		"Inherited",
		"Inherited From",
		"Condition",
		"Effective Project",
		"Project Name",
		"Cross-Project",
	}

	var explodedBody [][]string
	for _, ep := range m.ExplodedPerms {
		inherited := ""
		if ep.IsInherited {
			inherited = "✓"
		}
		crossProject := ""
		if ep.IsCrossProject {
			crossProject = fmt.Sprintf("✓ (from %s)", ep.SourceProject)
		}
		condition := ""
		if ep.HasCondition {
			condition = ep.Condition
		}

		explodedBody = append(explodedBody, []string{
			ep.EntityEmail,
			ep.EntityType,
			ep.Permission,
			ep.Role,
			ep.RoleType,
			ep.ResourceScope,
			ep.ResourceScopeType,
			ep.ResourceScopeID,
			inherited,
			ep.InheritedFrom,
			condition,
			ep.EffectiveProject,
			ep.ProjectName,
			crossProject,
		})
	}

	// Sort by entity, then by permission for consistent output
	sort.Slice(explodedBody, func(i, j int) bool {
		if explodedBody[i][0] != explodedBody[j][0] {
			return explodedBody[i][0] < explodedBody[j][0]
		}
		return explodedBody[i][2] < explodedBody[j][2]
	})

	// ========================================
	// TABLE 2: Entity summary table
	// ========================================
	summaryHeader := []string{
		"Entity",
		"Type",
		"Total Perms",
		"Unique Perms",
		"Roles",
		"High Priv",
		"Dangerous",
		"Inherited",
		"Conditional",
		"Projects",
		"Cross-Project",
	}

	// Aggregate by entity
	entityStats := make(map[string]*struct {
		entityType      string
		totalPerms      int
		uniquePerms     map[string]bool
		roles           map[string]bool
		highPriv        int
		dangerous       int
		inherited       int
		conditional     int
		projects        map[string]bool
		crossProject    int
	})

	for _, ep := range m.ExplodedPerms {
		if entityStats[ep.Entity] == nil {
			entityStats[ep.Entity] = &struct {
				entityType      string
				totalPerms      int
				uniquePerms     map[string]bool
				roles           map[string]bool
				highPriv        int
				dangerous       int
				inherited       int
				conditional     int
				projects        map[string]bool
				crossProject    int
			}{
				entityType:  ep.EntityType,
				uniquePerms: make(map[string]bool),
				roles:       make(map[string]bool),
				projects:    make(map[string]bool),
			}
		}
		stats := entityStats[ep.Entity]
		stats.totalPerms++
		stats.uniquePerms[ep.Permission] = true
		stats.roles[ep.Role] = true
		stats.projects[ep.EffectiveProject] = true
		if isHighPrivilegePermission(ep.Permission) {
			stats.highPriv++
		}
		if getDangerousPermissionInfo(ep.Permission) != nil {
			stats.dangerous++
		}
		if ep.IsInherited {
			stats.inherited++
		}
		if ep.HasCondition {
			stats.conditional++
		}
		if ep.IsCrossProject {
			stats.crossProject++
		}
	}

	var summaryBody [][]string
	for entity, stats := range entityStats {
		crossProjectStr := ""
		if stats.crossProject > 0 {
			crossProjectStr = fmt.Sprintf("✓ (%d)", stats.crossProject)
		}
		summaryBody = append(summaryBody, []string{
			extractEmailFromEntity(entity),
			stats.entityType,
			fmt.Sprintf("%d", stats.totalPerms),
			fmt.Sprintf("%d", len(stats.uniquePerms)),
			fmt.Sprintf("%d", len(stats.roles)),
			fmt.Sprintf("%d", stats.highPriv),
			fmt.Sprintf("%d", stats.dangerous),
			fmt.Sprintf("%d", stats.inherited),
			fmt.Sprintf("%d", stats.conditional),
			fmt.Sprintf("%d", len(stats.projects)),
			crossProjectStr,
		})
	}

	// Sort by dangerous count descending
	sort.Slice(summaryBody, func(i, j int) bool {
		di := 0
		dj := 0
		fmt.Sscanf(summaryBody[i][6], "%d", &di)
		fmt.Sscanf(summaryBody[j][6], "%d", &dj)
		return di > dj
	})

	// ========================================
	// TABLE 3: Permissions by Scope (org/folder/project)
	// ========================================
	scopeHeader := []string{
		"Scope Type",
		"Scope ID",
		"Entity",
		"Type",
		"Permission",
		"Role",
		"Inherited From",
		"Condition",
	}

	var scopeBody [][]string
	for _, ep := range m.ExplodedPerms {
		scopeBody = append(scopeBody, []string{
			ep.ResourceScopeType,
			ep.ResourceScopeID,
			ep.EntityEmail,
			ep.EntityType,
			ep.Permission,
			ep.Role,
			ep.InheritedFrom,
			ep.Condition,
		})
	}

	// Sort by scope type (org first, then folder, then project), then scope ID
	scopeOrder := map[string]int{"organization": 0, "folder": 1, "project": 2}
	sort.Slice(scopeBody, func(i, j int) bool {
		if scopeBody[i][0] != scopeBody[j][0] {
			return scopeOrder[scopeBody[i][0]] < scopeOrder[scopeBody[j][0]]
		}
		return scopeBody[i][1] < scopeBody[j][1]
	})

	// ========================================
	// TABLE 4: Dangerous permissions table
	// ========================================
	dangerousHeader := []string{
		"Risk",
		"Category",
		"Entity",
		"Type",
		"Permission",
		"Description",
		"Role",
		"Scope",
		"Inherited",
		"Effective Project",
		"Project Name",
	}

	var dangerousBody [][]string
	criticalCount := 0
	for _, ep := range m.ExplodedPerms {
		if dpInfo := getDangerousPermissionInfo(ep.Permission); dpInfo != nil {
			inherited := ""
			if ep.IsInherited {
				inherited = ep.InheritedFrom
			}
			dangerousBody = append(dangerousBody, []string{
				dpInfo.RiskLevel,
				dpInfo.Category,
				ep.EntityEmail,
				ep.EntityType,
				dpInfo.Permission,
				dpInfo.Description,
				ep.Role,
				ep.ResourceScope,
				inherited,
				ep.EffectiveProject,
				ep.ProjectName,
			})
			if dpInfo.RiskLevel == "CRITICAL" {
				criticalCount++
			}
		}
	}

	// Sort by risk level
	riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.Slice(dangerousBody, func(i, j int) bool {
		return riskOrder[dangerousBody[i][0]] < riskOrder[dangerousBody[j][0]]
	})

	// ========================================
	// TABLE 5: Cross-project permissions
	// ========================================
	crossProjectHeader := []string{
		"Entity",
		"Type",
		"Source Project",
		"Target Project",
		"Target Project Name",
		"Permission",
		"Role",
		"Inherited",
	}

	var crossProjectBody [][]string
	for _, ep := range m.ExplodedPerms {
		if ep.IsCrossProject {
			inherited := ""
			if ep.IsInherited {
				inherited = ep.InheritedFrom
			}
			crossProjectBody = append(crossProjectBody, []string{
				ep.EntityEmail,
				ep.EntityType,
				ep.SourceProject,
				ep.EffectiveProject,
				ep.ProjectName,
				ep.Permission,
				ep.Role,
				inherited,
			})
		}
	}

	// ========================================
	// TABLE 6: High privilege permissions table
	// ========================================
	highPrivHeader := []string{
		"Entity",
		"Type",
		"Permission",
		"Role",
		"Scope",
		"Inherited",
		"Condition",
		"Effective Project",
		"Project Name",
	}

	var highPrivBody [][]string
	for _, ep := range m.ExplodedPerms {
		if isHighPrivilegePermission(ep.Permission) {
			inherited := ""
			if ep.IsInherited {
				inherited = ep.InheritedFrom
			}
			condition := ""
			if ep.HasCondition {
				condition = ep.Condition
			}

			highPrivBody = append(highPrivBody, []string{
				ep.EntityEmail,
				ep.EntityType,
				ep.Permission,
				ep.Role,
				ep.ResourceScope,
				inherited,
				condition,
				ep.EffectiveProject,
				ep.ProjectName,
			})
		}
	}

	// ========================================
	// TABLE 7: Group membership table
	// ========================================
	groupHeader := []string{
		"Group Email",
		"Display Name",
		"Member Count",
		"Nested Groups",
		"Enumerated",
		"Roles",
		"Project Name",
		"Project ID",
	}

	var groupBody [][]string
	for _, gi := range m.GroupInfos {
		enumStatus := "No"
		if gi.MembershipEnumerated {
			enumStatus = "Yes"
		}
		nestedGroups := ""
		if gi.HasNestedGroups {
			nestedGroups = fmt.Sprintf("%d", len(gi.NestedGroups))
		}

		groupBody = append(groupBody, []string{
			gi.Email,
			gi.DisplayName,
			fmt.Sprintf("%d", gi.MemberCount),
			nestedGroups,
			enumStatus,
			fmt.Sprintf("%d", len(gi.Roles)),
			m.GetProjectName(gi.ProjectID),
			gi.ProjectID,
		})
	}

	// ========================================
	// TABLE 8: Group members detail table
	// ========================================
	groupMembersHeader := []string{
		"Group Email",
		"Member Email",
		"Member Type",
		"Role in Group",
		"Project Name",
		"Project ID",
	}

	var groupMembersBody [][]string
	for _, gi := range m.GroupInfos {
		if gi.MembershipEnumerated {
			for _, member := range gi.Members {
				groupMembersBody = append(groupMembersBody, []string{
					gi.Email,
					member.Email,
					member.Type,
					member.Role,
					m.GetProjectName(gi.ProjectID),
					gi.ProjectID,
				})
			}
		}
	}

	// ========================================
	// TABLE 9: Inherited permissions table
	// ========================================
	inheritedHeader := []string{
		"Entity",
		"Type",
		"Permission",
		"Role",
		"Inherited From",
		"Scope Type",
		"Effective Project",
		"Project Name",
	}

	var inheritedBody [][]string
	for _, ep := range m.ExplodedPerms {
		if ep.IsInherited {
			inheritedBody = append(inheritedBody, []string{
				ep.EntityEmail,
				ep.EntityType,
				ep.Permission,
				ep.Role,
				ep.InheritedFrom,
				ep.ResourceScopeType,
				ep.EffectiveProject,
				ep.ProjectName,
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

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "permissions-exploded",
			Header: explodedHeader,
			Body:   explodedBody,
		},
		{
			Name:   "permissions-summary",
			Header: summaryHeader,
			Body:   summaryBody,
		},
	}

	// Add scope table
	if len(scopeBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-by-scope",
			Header: scopeHeader,
			Body:   scopeBody,
		})
	}

	// Add dangerous permissions table (pentest-focused)
	if len(dangerousBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-dangerous",
			Header: dangerousHeader,
			Body:   dangerousBody,
		})
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d dangerous permission entries (%d CRITICAL) - privesc risk!", len(dangerousBody), criticalCount), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	// Add cross-project table
	if len(crossProjectBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-cross-project",
			Header: crossProjectHeader,
			Body:   crossProjectBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d cross-project permission entries!", len(crossProjectBody)), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	// Add high privilege table if there are any
	if len(highPrivBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-high-privilege",
			Header: highPrivHeader,
			Body:   highPrivBody,
		})
	}

	// Add inherited permissions table
	if len(inheritedBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-inherited",
			Header: inheritedHeader,
			Body:   inheritedBody,
		})
	}

	// Add group summary table if there are any groups
	if len(groupBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-groups",
			Header: groupHeader,
			Body:   groupBody,
		})
	}

	// Add group members detail table if there are enumerated members
	if len(groupMembersBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-group-members",
			Header: groupMembersHeader,
			Body:   groupMembersBody,
		})
	}

	output := PermissionsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scopeNames using GetProjectName
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	// Write output using HandleOutputSmart with scope support
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",           // scopeType
		m.ProjectIDs,        // scopeIdentifiers
		scopeNames,          // scopeNames
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// extractEmailFromEntity extracts the email portion from an entity string like "user:foo@example.com"
func extractEmailFromEntity(entity string) string {
	parts := strings.SplitN(entity, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return entity
}
