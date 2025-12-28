package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	privescservice "github.com/BishopFox/cloudfox/gcp/services/privescService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPermissionsCommand = &cobra.Command{
	Use:     globals.GCP_PERMISSIONS_MODULE_NAME,
	Aliases: []string{"perms", "privs"},
	Short:   "Enumerate all permissions for each IAM entity with detailed source information",
	Long: `Enumerate all permissions for each IAM entity (user, service account, group, etc.) with detailed source information.

Features:
- Lists every permission for each entity line by line
- Shows the role that granted each permission
- Identifies if permissions are inherited from folders/organization
- Shows conditional access restrictions on permissions
- Distinguishes between predefined, custom, and basic roles
- Summarizes total and unique permission counts per entity
- Identifies high-privilege permissions (iam.*, resourcemanager.*, etc.)
- Enumerates group memberships using Cloud Identity API (when accessible)
- Expands permissions to include inherited permissions from group membership
- Identifies nested groups (groups that are members of other groups)
- Generates loot files for exploitation and further analysis

This is a comprehensive permission enumeration - expect longer execution times for projects with many entities.
Note: Group membership enumeration requires Cloud Identity API access (cloudidentity.groups.readonly scope).`,
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

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type PermissionsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	EntityPermissions []IAMService.EntityPermissions
	GroupInfos        []IAMService.GroupInfo
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
		EntityPermissions: []IAMService.EntityPermissions{},
		GroupInfos:        []IAMService.GroupInfo{},
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
	logger.InfoM("Enumerating permissions for all entities with group expansion (this may take a while)...", globals.GCP_PERMISSIONS_MODULE_NAME)

	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_PERMISSIONS_MODULE_NAME, m.processProject)

	// Check results
	if len(m.EntityPermissions) == 0 {
		logger.InfoM("No entity permissions found", globals.GCP_PERMISSIONS_MODULE_NAME)
		return
	}

	// Count total permissions and group membership stats
	totalPerms := 0
	groupsEnumerated := 0
	for _, ep := range m.EntityPermissions {
		totalPerms += ep.TotalPerms
	}
	for _, gi := range m.GroupInfos {
		if gi.MembershipEnumerated {
			groupsEnumerated++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d entity(ies) with %d total permission entries",
		len(m.EntityPermissions), totalPerms), globals.GCP_PERMISSIONS_MODULE_NAME)

	if len(m.GroupInfos) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d group(s), enumerated membership for %d", len(m.GroupInfos), groupsEnumerated), globals.GCP_PERMISSIONS_MODULE_NAME)

		// Warn about blindspot if we couldn't enumerate some groups
		unenumeratedGroups := len(m.GroupInfos) - groupsEnumerated
		if unenumeratedGroups > 0 {
			logger.InfoM(fmt.Sprintf("[WARNING] Could not enumerate membership for %d group(s) - permissions inherited via these groups are NOT visible!", unenumeratedGroups), globals.GCP_PERMISSIONS_MODULE_NAME)
			logger.InfoM("[WARNING] Group members may have elevated privileges not shown in this output. Consider enabling Cloud Identity API access.", globals.GCP_PERMISSIONS_MODULE_NAME)
		}
	}

	// Write output
	m.writeOutput(ctx, logger)
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

	// Thread-safe append
	m.mu.Lock()
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
		logger.InfoM(fmt.Sprintf("Found %d entity(ies) with permissions in project %s", len(entityPerms), projectID), globals.GCP_PERMISSIONS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *PermissionsModule) initializeLootFiles() {
	m.LootMap["permissions-all"] = &internal.LootFile{
		Name:     "permissions-all",
		Contents: "# GCP Entity Permissions (All)\n# Generated by CloudFox\n# Format: Entity | Permission | Role | Inherited | Condition\n\n",
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
			"%s | %s | %s | %v | %s\n",
			ep.Email, perm.Permission, perm.Role, perm.IsInherited, perm.Condition,
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
	// Entity summary table
	summaryHeader := []string{
		"Entity",
		"Type",
		"Roles",
		"Total Perms",
		"Unique Perms",
		"High Priv",
		"Inherited",
		"Conditional",
		"Project",
	}

	var summaryBody [][]string
	highPrivEntities := 0
	for _, ep := range m.EntityPermissions {
		highPrivCount := 0
		inheritedCount := 0
		conditionalCount := 0
		for _, perm := range ep.Permissions {
			if isHighPrivilegePermission(perm.Permission) {
				highPrivCount++
			}
			if perm.IsInherited {
				inheritedCount++
			}
			if perm.HasCondition {
				conditionalCount++
			}
		}

		if highPrivCount > 0 {
			highPrivEntities++
		}

		summaryBody = append(summaryBody, []string{
			ep.Email,
			ep.EntityType,
			fmt.Sprintf("%d", len(ep.Roles)),
			fmt.Sprintf("%d", ep.TotalPerms),
			fmt.Sprintf("%d", ep.UniquePerms),
			fmt.Sprintf("%d", highPrivCount),
			fmt.Sprintf("%d", inheritedCount),
			fmt.Sprintf("%d", conditionalCount),
			ep.ProjectID,
		})
	}

	// Detailed permissions table (one row per permission)
	detailHeader := []string{
		"Entity",
		"Type",
		"Permission",
		"Role",
		"Role Type",
		"Inherited",
		"Source",
		"Condition",
		"Project",
	}

	var detailBody [][]string
	for _, ep := range m.EntityPermissions {
		for _, perm := range ep.Permissions {
			inherited := ""
			source := perm.ResourceType
			if perm.IsInherited {
				inherited = "✓"
				source = perm.InheritedFrom
			}

			condition := ""
			if perm.HasCondition {
				condition = perm.Condition
			}

			detailBody = append(detailBody, []string{
				ep.Email,
				ep.EntityType,
				perm.Permission,
				perm.Role,
				perm.RoleType,
				inherited,
				source,
				condition,
				perm.ResourceID,
			})
		}
	}

	// High privilege permissions table
	highPrivHeader := []string{
		"Entity",
		"Type",
		"Permission",
		"Role",
		"Inherited",
		"Condition",
		"Project",
	}

	var highPrivBody [][]string
	for _, ep := range m.EntityPermissions {
		for _, perm := range ep.Permissions {
			if isHighPrivilegePermission(perm.Permission) {
				inherited := ""
				if perm.IsInherited {
					inherited = perm.InheritedFrom
				}
				condition := ""
				if perm.HasCondition {
					condition = perm.Condition
				}

				highPrivBody = append(highPrivBody, []string{
					ep.Email,
					ep.EntityType,
					perm.Permission,
					perm.Role,
					inherited,
					condition,
					perm.ResourceID,
				})
			}
		}
	}

	// Dangerous permissions table with categories (pentest-focused)
	dangerousHeader := []string{
		"Risk",
		"Category",
		"Entity",
		"Type",
		"Permission",
		"Description",
		"Role",
		"Project",
	}

	var dangerousBody [][]string
	criticalCount := 0
	for _, ep := range m.EntityPermissions {
		for _, perm := range ep.Permissions {
			if dpInfo := getDangerousPermissionInfo(perm.Permission); dpInfo != nil {
				dangerousBody = append(dangerousBody, []string{
					dpInfo.RiskLevel,
					dpInfo.Category,
					ep.Email,
					ep.EntityType,
					dpInfo.Permission,
					dpInfo.Description,
					perm.Role,
					perm.ResourceID,
				})
				if dpInfo.RiskLevel == "CRITICAL" {
					criticalCount++
				}
			}
		}
	}

	// Group membership table
	groupHeader := []string{
		"Group Email",
		"Display Name",
		"Member Count",
		"Nested Groups",
		"Enumerated",
		"Roles",
		"Project",
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
			gi.ProjectID,
		})
	}

	// Group members detail table
	groupMembersHeader := []string{
		"Group Email",
		"Member Email",
		"Member Type",
		"Role in Group",
		"Project",
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
					gi.ProjectID,
				})
			}
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
			Name:   "permissions-summary",
			Header: summaryHeader,
			Body:   summaryBody,
		},
	}

	// Add high privilege table if there are any
	if len(highPrivBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-high-privilege",
			Header: highPrivHeader,
			Body:   highPrivBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d entity(ies) with high-privilege permissions!", highPrivEntities), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	// Add dangerous permissions table (pentest-focused)
	if len(dangerousBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-dangerous",
			Header: dangerousHeader,
			Body:   dangerousBody,
		})
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d dangerous permission(s) (%d CRITICAL) - privesc risk!", len(dangerousBody), criticalCount), globals.GCP_PERMISSIONS_MODULE_NAME)
	}

	// Add detailed table (can be large)
	if len(detailBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "permissions-detail",
			Header: detailHeader,
			Body:   detailBody,
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

	// Write output using HandleOutputSmart with scope support
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",           // scopeType
		m.ProjectIDs,        // scopeIdentifiers
		m.ProjectIDs,        // scopeNames (same as IDs for GCP projects)
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PERMISSIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
