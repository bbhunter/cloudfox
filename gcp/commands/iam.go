package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPIAMCommand = &cobra.Command{
	Use:     globals.GCP_IAM_MODULE_NAME,
	Aliases: []string{"roles", "permissions"},
	Short:   "Enumerate GCP IAM principals, service accounts, groups, and custom roles",
	Long: `Enumerate GCP IAM principals and their role bindings with security-focused analysis.

Features:
- Lists all IAM principals (users, service accounts, groups, domains)
- Shows role assignments per principal with inheritance tracking
- Enumerates service accounts with key information
- Lists custom roles with their permissions
- Identifies groups and their role assignments
- Detects high-privilege roles and public access
- Shows inherited roles from folders and organization
- Generates gcloud commands for privilege escalation testing`,
	Run: runGCPIAMCommand,
}

// High-privilege roles that should be flagged
var highPrivilegeRoles = map[string]bool{
	// Owner/Editor
	"roles/owner":  true,
	"roles/editor": true,
	// IAM Admin roles
	"roles/iam.securityAdmin":              true,
	"roles/iam.serviceAccountAdmin":        true,
	"roles/iam.serviceAccountKeyAdmin":     true,
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.serviceAccountUser":         true,
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.roleAdmin":                  true,
	// Resource Manager roles
	"roles/resourcemanager.projectIamAdmin":    true,
	"roles/resourcemanager.folderAdmin":        true,
	"roles/resourcemanager.folderIamAdmin":     true,
	"roles/resourcemanager.organizationAdmin":  true,
	// Compute roles
	"roles/compute.admin":         true,
	"roles/compute.instanceAdmin": true,
	"roles/compute.osAdminLogin":  true,
	// Storage roles
	"roles/storage.admin": true,
	// Functions/Run roles
	"roles/cloudfunctions.admin":   true,
	"roles/cloudfunctions.developer": true,
	"roles/run.admin":              true,
	"roles/run.developer":          true,
	// Secret Manager
	"roles/secretmanager.admin": true,
	// Container/Kubernetes
	"roles/container.admin":        true,
	"roles/container.clusterAdmin": true,
	// BigQuery
	"roles/bigquery.admin": true,
	// Deployment Manager
	"roles/deploymentmanager.editor": true,
	// Cloud Build
	"roles/cloudbuild.builds.editor": true,
	// Service Usage
	"roles/serviceusage.serviceUsageAdmin": true,
	// Org Policy
	"roles/orgpolicy.policyAdmin": true,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type IAMModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Principals      []IAMService.PrincipalWithRoles
	ServiceAccounts []IAMService.ServiceAccountInfo
	CustomRoles     []IAMService.CustomRole
	Groups          []IAMService.GroupInfo
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type IAMOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o IAMOutput) TableFiles() []internal.TableFile { return o.Table }
func (o IAMOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPIAMCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_IAM_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &IAMModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		Principals:      []IAMService.PrincipalWithRoles{},
		ServiceAccounts: []IAMService.ServiceAccountInfo{},
		CustomRoles:     []IAMService.CustomRole{},
		Groups:          []IAMService.GroupInfo{},
		LootMap:         make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *IAMModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_IAM_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Principals) == 0 {
		logger.InfoM("No IAM principals found", globals.GCP_IAM_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d principal(s), %d service account(s), %d custom role(s), %d group(s)",
		len(m.Principals), len(m.ServiceAccounts), len(m.CustomRoles), len(m.Groups)), globals.GCP_IAM_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *IAMModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating IAM in project: %s", projectID), globals.GCP_IAM_MODULE_NAME)
	}

	// Create service and fetch combined IAM data
	iamService := IAMService.New()
	iamData, err := iamService.CombinedIAM(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating IAM in project %s: %v", projectID, err), globals.GCP_IAM_MODULE_NAME)
		}
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Principals = append(m.Principals, iamData.Principals...)
	m.ServiceAccounts = append(m.ServiceAccounts, iamData.ServiceAccounts...)
	m.CustomRoles = append(m.CustomRoles, iamData.CustomRoles...)
	m.Groups = append(m.Groups, iamData.Groups...)

	// Generate loot for each principal
	for _, principal := range iamData.Principals {
		m.addPrincipalToLoot(principal, projectID)
	}

	// Generate loot for service accounts
	for _, sa := range iamData.ServiceAccounts {
		m.addServiceAccountToLoot(sa, projectID)
	}

	// Generate loot for custom roles
	for _, role := range iamData.CustomRoles {
		m.addCustomRoleToLoot(role)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d principal(s), %d SA(s), %d custom role(s), %d group(s) in project %s",
			len(iamData.Principals), len(iamData.ServiceAccounts), len(iamData.CustomRoles), len(iamData.Groups), projectID), globals.GCP_IAM_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *IAMModule) initializeLootFiles() {
	m.LootMap["iam-gcloud-commands"] = &internal.LootFile{
		Name:     "iam-gcloud-commands",
		Contents: "# GCP IAM Enumeration Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["iam-high-privilege"] = &internal.LootFile{
		Name:     "iam-high-privilege",
		Contents: "# GCP High-Privilege Principals\n# Generated by CloudFox\n# These principals have elevated permissions\n\n",
	}
	m.LootMap["iam-service-accounts"] = &internal.LootFile{
		Name:     "iam-service-accounts",
		Contents: "# GCP Service Account Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["iam-privilege-escalation"] = &internal.LootFile{
		Name:     "iam-privilege-escalation",
		Contents: "# GCP Privilege Escalation Paths\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["iam-custom-roles"] = &internal.LootFile{
		Name:     "iam-custom-roles",
		Contents: "# GCP Custom Roles\n# Generated by CloudFox\n# Review these for overly permissive custom roles\n\n",
	}
	m.LootMap["iam-service-account-keys"] = &internal.LootFile{
		Name:     "iam-service-account-keys",
		Contents: "# GCP Service Account Keys\n# Generated by CloudFox\n# User-managed keys are potential security risks\n\n",
	}
	m.LootMap["iam-groups"] = &internal.LootFile{
		Name:     "iam-groups",
		Contents: "# GCP Groups with IAM Permissions\n# Generated by CloudFox\n# Consider reviewing group membership for high-privilege roles\n\n",
	}
	m.LootMap["iam-inherited-roles"] = &internal.LootFile{
		Name:     "iam-inherited-roles",
		Contents: "# GCP Inherited IAM Roles\n# Generated by CloudFox\n# These roles are inherited from folders or organization\n\n",
	}
}

func (m *IAMModule) addPrincipalToLoot(principal IAMService.PrincipalWithRoles, projectID string) {
	hasHighPrivilege := false
	var highPrivRoles []string
	var inheritedRoles []string

	for _, binding := range principal.PolicyBindings {
		if highPrivilegeRoles[binding.Role] {
			hasHighPrivilege = true
			highPrivRoles = append(highPrivRoles, binding.Role)
		}
		if binding.IsInherited {
			inheritedRoles = append(inheritedRoles, fmt.Sprintf("%s (from %s)", binding.Role, binding.InheritedFrom))
		}
	}

	// Track inherited roles
	if len(inheritedRoles) > 0 {
		m.LootMap["iam-inherited-roles"].Contents += fmt.Sprintf(
			"# Principal: %s (Type: %s)\n"+
				"# Inherited Roles:\n",
			principal.Name, principal.Type,
		)
		for _, role := range inheritedRoles {
			m.LootMap["iam-inherited-roles"].Contents += fmt.Sprintf("  - %s\n", role)
		}
		m.LootMap["iam-inherited-roles"].Contents += "\n"
	}

	// Track groups
	if principal.Type == "Group" {
		var roles []string
		for _, binding := range principal.PolicyBindings {
			roles = append(roles, binding.Role)
		}
		hasHighPriv := ""
		if hasHighPrivilege {
			hasHighPriv = " [HIGH PRIVILEGE]"
		}
		m.LootMap["iam-groups"].Contents += fmt.Sprintf(
			"# Group: %s%s\n"+
				"# Project: %s\n"+
				"# Roles: %s\n"+
				"# Enumerate group membership (requires Admin SDK):\n"+
				"# gcloud identity groups memberships list --group-email=%s\n\n",
			principal.Email, hasHighPriv,
			projectID,
			strings.Join(roles, ", "),
			principal.Email,
		)
	}

	// gcloud commands for enumeration
	if principal.Type == "ServiceAccount" {
		saEmail := strings.TrimPrefix(principal.Name, "serviceAccount:")
		m.LootMap["iam-gcloud-commands"].Contents += fmt.Sprintf(
			"# Service Account: %s\n"+
				"gcloud iam service-accounts describe %s --project=%s\n"+
				"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n"+
				"gcloud iam service-accounts get-iam-policy %s --project=%s\n\n",
			saEmail,
			saEmail, projectID,
			saEmail, projectID,
			saEmail, projectID,
		)

		// Service account exploitation commands
		m.LootMap["iam-service-accounts"].Contents += fmt.Sprintf(
			"# Service Account: %s\n"+
				"# Create a key for this service account:\n"+
				"gcloud iam service-accounts keys create ./key.json --iam-account=%s --project=%s\n"+
				"# Generate access token:\n"+
				"gcloud auth print-access-token --impersonate-service-account=%s\n"+
				"# Generate ID token:\n"+
				"gcloud auth print-identity-token --impersonate-service-account=%s\n\n",
			saEmail,
			saEmail, projectID,
			saEmail,
			saEmail,
		)
	}

	// High privilege principals
	if hasHighPrivilege {
		m.LootMap["iam-high-privilege"].Contents += fmt.Sprintf(
			"# Principal: %s (Type: %s)\n"+
				"# High-Privilege Roles: %s\n"+
				"# Resource: %s/%s\n",
			principal.Name, principal.Type,
			strings.Join(highPrivRoles, ", "),
			principal.ResourceType, principal.ResourceID,
		)
		if principal.HasCustomRoles {
			m.LootMap["iam-high-privilege"].Contents += fmt.Sprintf(
				"# Custom Roles: %s\n", strings.Join(principal.CustomRoles, ", "))
		}
		m.LootMap["iam-high-privilege"].Contents += "\n"

		// Privilege escalation paths
		if principal.Type == "ServiceAccount" {
			saEmail := strings.TrimPrefix(principal.Name, "serviceAccount:")
			m.LootMap["iam-privilege-escalation"].Contents += fmt.Sprintf(
				"# Service Account: %s has high privileges\n"+
					"# Roles: %s\n"+
					"# Potential privilege escalation via service account key creation:\n"+
					"gcloud iam service-accounts keys create ./key.json --iam-account=%s\n"+
					"# Then authenticate:\n"+
					"gcloud auth activate-service-account %s --key-file=./key.json\n\n",
				saEmail,
				strings.Join(highPrivRoles, ", "),
				saEmail,
				saEmail,
			)
		}
	}
}

// addServiceAccountToLoot adds detailed service account info to loot
func (m *IAMModule) addServiceAccountToLoot(sa IAMService.ServiceAccountInfo, projectID string) {
	// Service accounts with user-managed keys
	if sa.HasKeys {
		m.LootMap["iam-service-account-keys"].Contents += fmt.Sprintf(
			"# Service Account: %s\n"+
				"# Project: %s\n"+
				"# User-Managed Keys: %d\n"+
				"# Disabled: %v\n"+
				"# List keys:\n"+
				"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n\n",
			sa.Email,
			projectID,
			sa.KeyCount,
			sa.Disabled,
			sa.Email, projectID,
		)
	}
}

// addCustomRoleToLoot adds custom role info to loot
func (m *IAMModule) addCustomRoleToLoot(role IAMService.CustomRole) {
	deletedStr := ""
	if role.Deleted {
		deletedStr = " [DELETED]"
	}
	m.LootMap["iam-custom-roles"].Contents += fmt.Sprintf(
		"# Role: %s%s\n"+
			"# Title: %s\n"+
			"# Stage: %s\n"+
			"# Permissions: %d\n"+
			"# Description: %s\n"+
			"# View role details:\n"+
			"gcloud iam roles describe %s --project=%s\n\n",
		role.Name, deletedStr,
		role.Title,
		role.Stage,
		role.PermissionCount,
		role.Description,
		extractRoleName(role.Name), role.ProjectID,
	)
}

// extractRoleName extracts the role name from full path
func extractRoleName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *IAMModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main principals table with security columns
	principalHeader := []string{
		"Principal",
		"Type",
		"Role",
		"High Priv",
		"Custom Role",
		"Inherited",
		"Condition",
		"Source",
		"Project Name",
		"Project",
	}

	var principalBody [][]string
	publicAccessFound := false
	conditionsFound := false
	for _, principal := range m.Principals {
		for _, binding := range principal.PolicyBindings {
			isHighPriv := ""
			if highPrivilegeRoles[binding.Role] {
				isHighPriv = "YES"
			}

			isCustom := ""
			if strings.HasPrefix(binding.Role, "projects/") || strings.HasPrefix(binding.Role, "organizations/") {
				isCustom = "✓"
			}

			inherited := ""
			source := binding.ResourceType
			if binding.IsInherited {
				inherited = "✓"
				source = binding.InheritedFrom
			}

			// Check for conditions (conditional access)
			condition := ""
			if binding.HasCondition {
				conditionsFound = true
				if binding.ConditionInfo != nil && binding.ConditionInfo.Title != "" {
					condition = binding.ConditionInfo.Title
				} else {
					condition = "✓"
				}
			}

			// Check for public access
			if principal.Type == "PUBLIC" || principal.Type == "ALL_AUTHENTICATED" {
				publicAccessFound = true
			}

			principalBody = append(principalBody, []string{
				principal.Email,
				principal.Type,
				binding.Role,
				isHighPriv,
				isCustom,
				inherited,
				condition,
				source,
				m.GetProjectName(binding.ResourceID),
				binding.ResourceID,
			})
		}
	}

	// Service accounts table
	saHeader := []string{
		"Email",
		"Display Name",
		"Disabled",
		"Has Keys",
		"Key Count",
		"Project Name",
		"Project",
	}

	var saBody [][]string
	saWithKeys := 0
	for _, sa := range m.ServiceAccounts {
		disabled := ""
		if sa.Disabled {
			disabled = "✓"
		}
		hasKeys := ""
		if sa.HasKeys {
			hasKeys = "YES"
			saWithKeys++
		}

		saBody = append(saBody, []string{
			sa.Email,
			sa.DisplayName,
			disabled,
			hasKeys,
			fmt.Sprintf("%d", sa.KeyCount),
			m.GetProjectName(sa.ProjectID),
			sa.ProjectID,
		})
	}

	// Custom roles table
	customRoleHeader := []string{
		"Role Name",
		"Title",
		"Stage",
		"Permissions",
		"Deleted",
		"Project Name",
		"Project",
	}

	var customRoleBody [][]string
	for _, role := range m.CustomRoles {
		deleted := ""
		if role.Deleted {
			deleted = "✓"
		}

		customRoleBody = append(customRoleBody, []string{
			extractRoleName(role.Name),
			role.Title,
			role.Stage,
			fmt.Sprintf("%d", role.PermissionCount),
			deleted,
			m.GetProjectName(role.ProjectID),
			role.ProjectID,
		})
	}

	// Groups table
	groupHeader := []string{
		"Group Email",
		"Role Count",
		"High Privilege",
		"Project Name",
		"Project",
	}

	var groupBody [][]string
	for _, group := range m.Groups {
		hasHighPriv := ""
		for _, role := range group.Roles {
			if highPrivilegeRoles[role] {
				hasHighPriv = "YES"
				break
			}
		}

		groupBody = append(groupBody, []string{
			group.Email,
			fmt.Sprintf("%d", len(group.Roles)),
			hasHighPriv,
			m.GetProjectName(group.ProjectID),
			group.ProjectID,
		})
	}

	// High privilege principals table
	highPrivHeader := []string{
		"Principal",
		"Type",
		"High Priv Roles",
		"Custom Roles",
		"Project Name",
		"Project",
	}

	var highPrivBody [][]string
	highPrivSet := make(map[string]bool)
	for _, principal := range m.Principals {
		var highPrivRoles []string
		for _, binding := range principal.PolicyBindings {
			if highPrivilegeRoles[binding.Role] {
				highPrivRoles = append(highPrivRoles, binding.Role)
			}
		}
		if len(highPrivRoles) > 0 && !highPrivSet[principal.Name] {
			highPrivSet[principal.Name] = true
			customRolesStr := ""
			if principal.HasCustomRoles {
				customRolesStr = strings.Join(principal.CustomRoles, ", ")
			}
			highPrivBody = append(highPrivBody, []string{
				principal.Email,
				principal.Type,
				strings.Join(highPrivRoles, ", "),
				customRolesStr,
				m.GetProjectName(principal.ResourceID),
				principal.ResourceID,
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
			Name:   "iam-principals",
			Header: principalHeader,
			Body:   principalBody,
		},
	}

	// Add service accounts table if there are any
	if len(saBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "iam-service-accounts",
			Header: saHeader,
			Body:   saBody,
		})
	}

	// Add custom roles table if there are any
	if len(customRoleBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "iam-custom-roles",
			Header: customRoleHeader,
			Body:   customRoleBody,
		})
	}

	// Add groups table if there are any
	if len(groupBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "iam-groups",
			Header: groupHeader,
			Body:   groupBody,
		})
	}

	// Add high privilege principals table if there are any
	if len(highPrivBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "iam-high-privilege",
			Header: highPrivHeader,
			Body:   highPrivBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d principal(s) with high-privilege roles!", len(highPrivBody)), globals.GCP_IAM_MODULE_NAME)
	}

	// Conditional bindings table
	conditionsHeader := []string{
		"Principal",
		"Type",
		"Role",
		"Condition Title",
		"Condition Expression",
		"Project Name",
		"Project",
	}

	var conditionsBody [][]string
	for _, principal := range m.Principals {
		for _, binding := range principal.PolicyBindings {
			if binding.HasCondition && binding.ConditionInfo != nil {
				conditionsBody = append(conditionsBody, []string{
					principal.Email,
					principal.Type,
					binding.Role,
					binding.ConditionInfo.Title,
					truncateString(binding.ConditionInfo.Expression, 80),
					m.GetProjectName(binding.ResourceID),
					binding.ResourceID,
				})
			}
		}
	}

	// Add conditional bindings table if there are any
	if len(conditionsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "iam-conditions",
			Header: conditionsHeader,
			Body:   conditionsBody,
		})
	}

	// Log warnings for security findings
	if publicAccessFound {
		logger.InfoM("[FINDING] Public access (allUsers/allAuthenticatedUsers) detected in IAM bindings!", globals.GCP_IAM_MODULE_NAME)
	}
	if saWithKeys > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d service account(s) with user-managed keys!", saWithKeys), globals.GCP_IAM_MODULE_NAME)
	}
	if conditionsFound {
		logger.InfoM(fmt.Sprintf("[INFO] Found %d conditional IAM binding(s)", len(conditionsBody)), globals.GCP_IAM_MODULE_NAME)
	}

	output := IAMOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",    // scopeType
		m.ProjectIDs, // scopeIdentifiers
		scopeNames,   // scopeNames
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_IAM_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
