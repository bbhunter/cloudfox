package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPIAMCommand = &cobra.Command{
	Use:     globals.GCP_IAM_MODULE_NAME,
	Aliases: []string{"roles"},
	Short:   "Enumerate GCP IAM principals across organizations, folders, and projects",
	Long: `Enumerate GCP IAM principals and their role bindings across the entire hierarchy.

Features:
- Enumerates IAM bindings at organization, folder, and project levels
- Shows role assignments per principal with scope information
- Enumerates service accounts with key information
- Lists custom roles with their permissions
- Identifies groups and their role assignments
- Detects high-privilege roles and public access
- Shows conditional IAM policies with details
- Attempts to retrieve MFA status for users (requires Admin SDK)
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
	"roles/resourcemanager.projectIamAdmin":   true,
	"roles/resourcemanager.folderAdmin":       true,
	"roles/resourcemanager.folderIamAdmin":    true,
	"roles/resourcemanager.organizationAdmin": true,
	// Compute roles
	"roles/compute.admin":         true,
	"roles/compute.instanceAdmin": true,
	"roles/compute.osAdminLogin":  true,
	// Storage roles
	"roles/storage.admin": true,
	// Functions/Run roles
	"roles/cloudfunctions.admin":     true,
	"roles/cloudfunctions.developer": true,
	"roles/run.admin":                true,
	"roles/run.developer":            true,
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

	// Module-specific fields - using enhanced data
	ScopeBindings   []IAMService.ScopeBinding
	ServiceAccounts []IAMService.ServiceAccountInfo
	CustomRoles     []IAMService.CustomRole
	Groups          []IAMService.GroupInfo
	MFAStatus       map[string]*IAMService.MFAStatus
	LootMap         map[string]*internal.LootFile
	AttackPathCache *gcpinternal.AttackPathCache
	mu              sync.Mutex

	// Member to groups mapping (email -> list of group emails)
	MemberToGroups map[string][]string

	// Organization info for output path
	OrgIDs   []string
	OrgNames map[string]string
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
		ScopeBindings:   []IAMService.ScopeBinding{},
		ServiceAccounts: []IAMService.ServiceAccountInfo{},
		CustomRoles:     []IAMService.CustomRole{},
		Groups:          []IAMService.GroupInfo{},
		MFAStatus:       make(map[string]*IAMService.MFAStatus),
		LootMap:         make(map[string]*internal.LootFile),
		MemberToGroups:  make(map[string][]string),
		OrgIDs:          []string{},
		OrgNames:        make(map[string]string),
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
	// Get attack path cache from context (populated by all-checks or attack path analysis)
	m.AttackPathCache = gcpinternal.GetAttackPathCacheFromContext(ctx)

	// If no context cache, try loading from disk cache
	if m.AttackPathCache == nil || !m.AttackPathCache.IsPopulated() {
		diskCache, metadata, err := gcpinternal.LoadAttackPathCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			logger.InfoM(fmt.Sprintf("Using attack path cache from disk (created: %s)",
				metadata.CreatedAt.Format("2006-01-02 15:04:05")), globals.GCP_IAM_MODULE_NAME)
			m.AttackPathCache = diskCache
		}
	}

	logger.InfoM("Enumerating IAM across organizations, folders, and projects...", globals.GCP_IAM_MODULE_NAME)

	// Use the enhanced IAM enumeration
	iamService := IAMService.New()
	iamData, err := iamService.CombinedIAMEnhanced(ctx, m.ProjectIDs, m.ProjectNames)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_IAM_MODULE_NAME, "Failed to enumerate IAM")
		return
	}

	m.ScopeBindings = iamData.ScopeBindings
	m.ServiceAccounts = iamData.ServiceAccounts
	m.CustomRoles = iamData.CustomRoles
	m.Groups = iamData.Groups
	m.MFAStatus = iamData.MFAStatus

	// Try to enumerate group memberships to build reverse lookup
	enrichedGroups := iamService.GetGroupMemberships(ctx, m.Groups)
	m.Groups = enrichedGroups

	// Build member-to-groups reverse mapping
	for _, group := range enrichedGroups {
		if group.MembershipEnumerated {
			for _, member := range group.Members {
				if member.Email != "" {
					m.MemberToGroups[member.Email] = append(m.MemberToGroups[member.Email], group.Email)
				}
			}
		}
	}

	// Generate loot
	m.generateLoot()

	// Count scopes and track org IDs
	orgCount, folderCount, projectCount := 0, 0, 0
	scopeSeen := make(map[string]bool)
	for _, sb := range m.ScopeBindings {
		key := sb.ScopeType + ":" + sb.ScopeID
		if !scopeSeen[key] {
			scopeSeen[key] = true
			switch sb.ScopeType {
			case "organization":
				orgCount++
				m.OrgIDs = append(m.OrgIDs, sb.ScopeID)
				m.OrgNames[sb.ScopeID] = sb.ScopeName
			case "folder":
				folderCount++
			case "project":
				projectCount++
			}
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d binding(s) across %d org(s), %d folder(s), %d project(s); %d SA(s), %d custom role(s), %d group(s)",
		len(m.ScopeBindings), orgCount, folderCount, projectCount,
		len(m.ServiceAccounts), len(m.CustomRoles), len(m.Groups)), globals.GCP_IAM_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *IAMModule) initializeLootFiles() {
	m.LootMap["iam-commands"] = &internal.LootFile{
		Name:     "iam-commands",
		Contents: "# GCP IAM Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["iam-enumeration"] = &internal.LootFile{
		Name:     "iam-enumeration",
		Contents: "# GCP IAM Enumeration Commands\n# Generated by CloudFox\n# Use these commands to enumerate roles and permissions for identities\n\n",
	}
}

func (m *IAMModule) generateLoot() {
	// Track unique service accounts we've seen
	sasSeen := make(map[string]bool)

	for _, sb := range m.ScopeBindings {
		if sb.MemberType != "ServiceAccount" {
			continue
		}
		if sasSeen[sb.MemberEmail] {
			continue
		}
		sasSeen[sb.MemberEmail] = true

		// Check for high privilege roles
		isHighPriv := highPrivilegeRoles[sb.Role]

		if isHighPriv {
			m.LootMap["iam-commands"].Contents += fmt.Sprintf(
				"# Service Account: %s [HIGH PRIVILEGE] (%s)\n",
				sb.MemberEmail, sb.Role,
			)
		} else {
			m.LootMap["iam-commands"].Contents += fmt.Sprintf(
				"# Service Account: %s\n",
				sb.MemberEmail,
			)
		}

		// Use project scope if available, otherwise use first project
		projectID := sb.ScopeID
		if sb.ScopeType != "project" && len(m.ProjectIDs) > 0 {
			projectID = m.ProjectIDs[0]
		}

		m.LootMap["iam-commands"].Contents += fmt.Sprintf(
			"gcloud iam service-accounts describe %s --project=%s\n"+
				"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n"+
				"gcloud iam service-accounts get-iam-policy %s --project=%s\n"+
				"gcloud iam service-accounts keys create ./key.json --iam-account=%s --project=%s\n"+
				"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
			sb.MemberEmail, projectID,
			sb.MemberEmail, projectID,
			sb.MemberEmail, projectID,
			sb.MemberEmail, projectID,
			sb.MemberEmail,
		)
	}

	// Add service accounts with keys
	for _, sa := range m.ServiceAccounts {
		if sa.HasKeys {
			m.LootMap["iam-commands"].Contents += fmt.Sprintf(
				"# Service Account with Keys: %s (Keys: %d)\n"+
					"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n\n",
				sa.Email, sa.KeyCount, sa.Email, sa.ProjectID,
			)
		}
	}

	// Add custom roles
	for _, role := range m.CustomRoles {
		m.LootMap["iam-commands"].Contents += fmt.Sprintf(
			"# Custom Role: %s (%d permissions)\n"+
				"gcloud iam roles describe %s --project=%s\n\n",
			role.Title, role.PermissionCount,
			extractRoleName(role.Name), role.ProjectID,
		)
	}

	// Generate IAM enumeration commands
	m.generateEnumerationLoot()
}

func (m *IAMModule) generateEnumerationLoot() {
	loot := m.LootMap["iam-enumeration"]

	// Add organization-level enumeration commands
	for _, orgID := range m.OrgIDs {
		orgName := m.OrgNames[orgID]
		loot.Contents += fmt.Sprintf("# =====================================================\n")
		loot.Contents += fmt.Sprintf("# Organization: %s (%s)\n", orgName, orgID)
		loot.Contents += fmt.Sprintf("# =====================================================\n\n")

		loot.Contents += fmt.Sprintf("# List all IAM bindings for organization\n")
		loot.Contents += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json\n\n", orgID)

		loot.Contents += fmt.Sprintf("# List all roles assigned at organization level\n")
		loot.Contents += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json | jq -r '.bindings[].role' | sort -u\n\n", orgID)

		loot.Contents += fmt.Sprintf("# List all members with their roles at organization level\n")
		loot.Contents += fmt.Sprintf("gcloud organizations get-iam-policy %s --format=json | jq -r '.bindings[] | \"\\(.role): \\(.members[])\"'\n\n", orgID)
	}

	// Track unique identities for enumeration commands
	identitiesSeen := make(map[string]bool)
	type identityInfo struct {
		email      string
		memberType string
		roles      []string
		scopes     []string
	}
	identities := make(map[string]*identityInfo)

	// Collect all unique identities and their roles/scopes
	for _, sb := range m.ScopeBindings {
		if sb.MemberEmail == "" {
			continue
		}
		key := sb.MemberEmail
		if !identitiesSeen[key] {
			identitiesSeen[key] = true
			identities[key] = &identityInfo{
				email:      sb.MemberEmail,
				memberType: sb.MemberType,
				roles:      []string{},
				scopes:     []string{},
			}
		}
		identities[key].roles = append(identities[key].roles, sb.Role)
		scopeKey := fmt.Sprintf("%s:%s", sb.ScopeType, sb.ScopeID)
		// Check if scope already exists
		found := false
		for _, s := range identities[key].scopes {
			if s == scopeKey {
				found = true
				break
			}
		}
		if !found {
			identities[key].scopes = append(identities[key].scopes, scopeKey)
		}
	}

	// Add project-level enumeration commands
	for _, projectID := range m.ProjectIDs {
		projectName := m.GetProjectName(projectID)
		loot.Contents += fmt.Sprintf("# =====================================================\n")
		loot.Contents += fmt.Sprintf("# Project: %s (%s)\n", projectName, projectID)
		loot.Contents += fmt.Sprintf("# =====================================================\n\n")

		loot.Contents += fmt.Sprintf("# List all IAM bindings for project\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json\n\n", projectID)

		loot.Contents += fmt.Sprintf("# List all roles assigned at project level\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[].role' | sort -u\n\n", projectID)

		loot.Contents += fmt.Sprintf("# List all members with their roles at project level\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | \"\\(.role): \\(.members[])\"'\n\n", projectID)

		loot.Contents += fmt.Sprintf("# Find all roles for a specific user (replace USER_EMAIL)\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"USER_EMAIL\")) | .role'\n\n", projectID)

		loot.Contents += fmt.Sprintf("# Find all roles for a specific service account (replace SA_EMAIL)\n")
		loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"SA_EMAIL\")) | .role'\n\n", projectID)

		loot.Contents += fmt.Sprintf("# List all service accounts in project\n")
		loot.Contents += fmt.Sprintf("gcloud iam service-accounts list --project=%s --format=json\n\n", projectID)

		loot.Contents += fmt.Sprintf("# List all custom roles in project\n")
		loot.Contents += fmt.Sprintf("gcloud iam roles list --project=%s --format=json\n\n", projectID)
	}

	// Add identity-specific enumeration commands
	loot.Contents += fmt.Sprintf("# =====================================================\n")
	loot.Contents += fmt.Sprintf("# Identity-Specific Enumeration Commands\n")
	loot.Contents += fmt.Sprintf("# =====================================================\n\n")

	for email, info := range identities {
		if info.memberType == "ServiceAccount" {
			loot.Contents += fmt.Sprintf("# Service Account: %s\n", email)
			// Extract project from SA email
			saProject := ""
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				saParts := strings.Split(parts[1], ".")
				if len(saParts) >= 1 {
					saProject = saParts[0]
				}
			}
			if saProject != "" {
				loot.Contents += fmt.Sprintf("# Find all roles for this service account across all projects\n")
				for _, projectID := range m.ProjectIDs {
					loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"%s\")) | .role'\n", projectID, email)
				}
				loot.Contents += "\n"
			}
		} else if info.memberType == "User" {
			loot.Contents += fmt.Sprintf("# User: %s\n", email)
			loot.Contents += fmt.Sprintf("# Find all roles for this user across all projects\n")
			for _, projectID := range m.ProjectIDs {
				loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"%s\")) | .role'\n", projectID, email)
			}
			loot.Contents += "\n"
		} else if info.memberType == "Group" {
			loot.Contents += fmt.Sprintf("# Group: %s\n", email)
			loot.Contents += fmt.Sprintf("# Find all roles for this group across all projects\n")
			for _, projectID := range m.ProjectIDs {
				loot.Contents += fmt.Sprintf("gcloud projects get-iam-policy %s --format=json | jq -r '.bindings[] | select(.members[] | contains(\"%s\")) | .role'\n", projectID, email)
			}
			loot.Contents += "\n"
		}
	}
}

// extractRoleName extracts the role name from full path
func extractRoleName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// FederatedIdentityInfo contains parsed information about a federated identity
type FederatedIdentityInfo struct {
	IsFederated  bool
	ProviderType string // AWS, GitHub, GitLab, OIDC, SAML, Azure, etc.
	PoolName     string
	Subject      string
	Attribute    string
}

// parseFederatedIdentity detects and parses federated identity principals
// Federated identities use principal:// or principalSet:// format
func parseFederatedIdentity(identity string) FederatedIdentityInfo {
	info := FederatedIdentityInfo{}

	// Check for principal:// or principalSet:// format
	if !strings.HasPrefix(identity, "principal://") && !strings.HasPrefix(identity, "principalSet://") {
		return info
	}

	info.IsFederated = true

	// Parse the principal URL
	// Format: principal://iam.googleapis.com/projects/{project}/locations/global/workloadIdentityPools/{pool}/subject/{subject}
	// Or: principalSet://iam.googleapis.com/projects/{project}/locations/global/workloadIdentityPools/{pool}/attribute.{attr}/{value}

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

	// Detect provider type based on common patterns in pool names and attributes
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
		// Has OIDC attributes but unknown provider
		info.ProviderType = "OIDC"
	case strings.Contains(identity, "/subject/"):
		// Has subject but unknown provider type
		info.ProviderType = "Federated"
	default:
		info.ProviderType = "Federated"
	}

	// Extract subject if present
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

// formatFederatedInfo formats federated identity info for display
func formatFederatedInfo(info FederatedIdentityInfo) string {
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
func formatCondition(condInfo *IAMService.IAMCondition) string {
	if condInfo == nil {
		return "No"
	}

	// Build a meaningful condition summary
	parts := []string{}

	if condInfo.Title != "" {
		parts = append(parts, condInfo.Title)
	}

	// Parse common condition patterns from expression
	expr := condInfo.Expression
	if expr != "" {
		// Check for time-based conditions
		if strings.Contains(expr, "request.time") {
			if strings.Contains(expr, "timestamp") {
				parts = append(parts, "[time-limited]")
			}
		}
		// Check for resource-based conditions
		if strings.Contains(expr, "resource.name") {
			parts = append(parts, "[resource-scoped]")
		}
		// Check for IP-based conditions
		if strings.Contains(expr, "origin.ip") || strings.Contains(expr, "request.origin") {
			parts = append(parts, "[IP-restricted]")
		}
		// Check for device policy
		if strings.Contains(expr, "device") {
			parts = append(parts, "[device-policy]")
		}
	}

	if len(parts) == 0 {
		return "Yes"
	}

	return strings.Join(parts, " ")
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *IAMModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *IAMModule) buildTables() []internal.TableFile {
	// New table structure with Scope Type/ID/Name
	header := []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Entry Type",
		"Identity",
		"Role",
		"High Privilege",
		"Custom Role",
		"Has Keys",
		"Condition",
		"MFA",
		"Groups",
		"Federated",
		"SA Attack Paths",
	}

	var body [][]string

	// Add scope bindings (one row per binding)
	for _, sb := range m.ScopeBindings {
		isHighPriv := "No"
		if highPrivilegeRoles[sb.Role] {
			isHighPriv = "Yes"
		}

		isCustom := "No"
		if sb.IsCustom {
			isCustom = "Yes"
		}

		// Format condition
		condition := "No"
		if sb.HasCondition {
			condition = formatCondition(sb.ConditionInfo)
		}

		// Get MFA status
		mfa := "-"
		if sb.MemberType == "User" {
			if status, ok := m.MFAStatus[sb.MemberEmail]; ok {
				if status.Error != "" {
					mfa = "Unknown"
				} else if status.HasMFA {
					mfa = "Yes"
				} else {
					mfa = "No"
				}
			}
		} else if sb.MemberType == "ServiceAccount" {
			mfa = "N/A"
		}

		// Get groups this member belongs to
		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sb.MemberEmail]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		// Check for federated identity
		federated := formatFederatedInfo(parseFederatedIdentity(sb.MemberEmail))

		// Check attack paths for service account principals
		attackPaths := "-"
		if sb.MemberType == "ServiceAccount" {
			if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
				attackPaths = m.AttackPathCache.GetAttackSummary(sb.MemberEmail)
			} else {
				attackPaths = "run --attack-paths"
			}
		}

		body = append(body, []string{
			sb.ScopeType,
			sb.ScopeID,
			sb.ScopeName,
			sb.MemberType,
			sb.MemberEmail,
			sb.Role,
			isHighPriv,
			isCustom,
			"-",
			condition,
			mfa,
			groups,
			federated,
			attackPaths,
		})
	}

	// Add service accounts
	for _, sa := range m.ServiceAccounts {
		hasKeys := "No"
		if sa.HasKeys {
			hasKeys = "Yes"
		}

		disabled := ""
		if sa.Disabled {
			disabled = " (disabled)"
		}

		// Get groups this SA belongs to
		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sa.Email]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		// Check attack paths for this service account
		attackPaths := "-"
		if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
			attackPaths = m.AttackPathCache.GetAttackSummary(sa.Email)
		} else {
			attackPaths = "run --attack-paths"
		}

		body = append(body, []string{
			"project",
			sa.ProjectID,
			m.GetProjectName(sa.ProjectID),
			"ServiceAccountInfo",
			sa.Email + disabled,
			sa.DisplayName,
			"-",
			"-",
			hasKeys,
			"-",
			"N/A",
			groups,
			"-", // Service accounts are not federated identities
			attackPaths,
		})
	}

	// Add custom roles
	for _, role := range m.CustomRoles {
		deleted := ""
		if role.Deleted {
			deleted = " (deleted)"
		}

		body = append(body, []string{
			"project",
			role.ProjectID,
			m.GetProjectName(role.ProjectID),
			"CustomRole",
			extractRoleName(role.Name) + deleted,
			fmt.Sprintf("%s (%d permissions)", role.Title, role.PermissionCount),
			"-",
			"Yes",
			"-",
			"-",
			"-",
			"-",
			"-", // Custom roles are not federated identities
			"-", // Custom roles don't have attack paths
		})
	}

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "iam",
			Header: header,
			Body:   body,
		},
	}

	return tables
}

func (m *IAMModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *IAMModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Determine org ID - prefer discovered orgs, fall back to hierarchy
	orgID := ""
	if len(m.OrgIDs) > 0 {
		orgID = m.OrgIDs[0]
	} else if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		tables := m.buildTables()
		lootFiles := m.collectLootFiles()
		outputData.OrgLevelData[orgID] = IAMOutput{Table: tables, Loot: lootFiles}

		// DUAL OUTPUT: Filtered per-project output
		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			if len(projectTables) > 0 && len(projectTables[0].Body) > 0 {
				outputData.ProjectLevelData[projectID] = IAMOutput{Table: projectTables, Loot: nil}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		tables := m.buildTables()
		lootFiles := m.collectLootFiles()
		outputData.ProjectLevelData[m.ProjectIDs[0]] = IAMOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_IAM_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// buildTablesForProject builds tables filtered to only include data for a specific project
func (m *IAMModule) buildTablesForProject(projectID string) []internal.TableFile {
	header := []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Member Type",
		"Member",
		"Role",
		"High Privilege",
		"Custom Role",
		"Has Keys",
		"Condition",
		"MFA",
		"Groups",
		"Federated",
		"SA Attack Paths",
	}

	var body [][]string

	// Add scope bindings for this project only
	for _, sb := range m.ScopeBindings {
		if sb.ScopeType != "project" || sb.ScopeID != projectID {
			continue
		}

		isHighPriv := "No"
		if highPrivilegeRoles[sb.Role] {
			isHighPriv = "Yes"
		}

		isCustom := "No"
		if sb.IsCustom {
			isCustom = "Yes"
		}

		condition := "No"
		if sb.HasCondition {
			condition = formatCondition(sb.ConditionInfo)
		}

		mfa := "-"
		if sb.MemberType == "User" {
			if status, ok := m.MFAStatus[sb.MemberEmail]; ok {
				if status.Error != "" {
					mfa = "Unknown"
				} else if status.HasMFA {
					mfa = "Yes"
				} else {
					mfa = "No"
				}
			}
		} else if sb.MemberType == "ServiceAccount" {
			mfa = "N/A"
		}

		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sb.MemberEmail]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		federated := formatFederatedInfo(parseFederatedIdentity(sb.MemberEmail))

		// Check attack paths for service account principals
		attackPaths := "-"
		if sb.MemberType == "ServiceAccount" {
			if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
				attackPaths = m.AttackPathCache.GetAttackSummary(sb.MemberEmail)
			} else {
				attackPaths = "run --attack-paths"
			}
		}

		body = append(body, []string{
			sb.ScopeType,
			sb.ScopeID,
			sb.ScopeName,
			sb.MemberType,
			sb.MemberEmail,
			sb.Role,
			isHighPriv,
			isCustom,
			"-",
			condition,
			mfa,
			groups,
			federated,
			attackPaths,
		})
	}

	// Add service accounts for this project only
	for _, sa := range m.ServiceAccounts {
		if sa.ProjectID != projectID {
			continue
		}

		hasKeys := "No"
		if sa.HasKeys {
			hasKeys = "Yes"
		}

		disabled := ""
		if sa.Disabled {
			disabled = " (disabled)"
		}

		groups := "-"
		if memberGroups, ok := m.MemberToGroups[sa.Email]; ok && len(memberGroups) > 0 {
			groups = strings.Join(memberGroups, ", ")
		}

		// Check attack paths for this service account
		attackPaths := "-"
		if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
			attackPaths = m.AttackPathCache.GetAttackSummary(sa.Email)
		} else {
			attackPaths = "run --attack-paths"
		}

		body = append(body, []string{
			"project",
			sa.ProjectID,
			m.GetProjectName(sa.ProjectID),
			"ServiceAccountInfo",
			sa.Email + disabled,
			sa.DisplayName,
			"-",
			"-",
			hasKeys,
			"-",
			"N/A",
			groups,
			"-",
			attackPaths,
		})
	}

	// Add custom roles for this project only
	for _, role := range m.CustomRoles {
		if role.ProjectID != projectID {
			continue
		}

		deleted := ""
		if role.Deleted {
			deleted = " (deleted)"
		}

		body = append(body, []string{
			"project",
			role.ProjectID,
			m.GetProjectName(role.ProjectID),
			"CustomRole",
			extractRoleName(role.Name) + deleted,
			fmt.Sprintf("%s (%d permissions)", role.Title, role.PermissionCount),
			"-",
			"Yes",
			"-",
			"-",
			"-",
			"-",
			"-",
			"-", // Custom roles don't have attack paths
		})
	}

	if len(body) == 0 {
		return nil
	}

	return []internal.TableFile{
		{
			Name:   "iam",
			Header: header,
			Body:   body,
		},
	}
}

func (m *IAMModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildTables()
	lootFiles := m.collectLootFiles()

	// Count security findings for logging
	publicAccessFound := false
	saWithKeys := 0
	highPrivCount := 0

	for _, sb := range m.ScopeBindings {
		if highPrivilegeRoles[sb.Role] {
			highPrivCount++
		}
		if sb.MemberType == "PUBLIC" || sb.MemberType == "ALL_AUTHENTICATED" {
			publicAccessFound = true
		}
	}

	for _, sa := range m.ServiceAccounts {
		if sa.HasKeys {
			saWithKeys++
		}
	}

	// Log warnings for security findings
	if publicAccessFound {
		logger.InfoM("[FINDING] Public access (allUsers/allAuthenticatedUsers) detected in IAM bindings!", globals.GCP_IAM_MODULE_NAME)
	}
	if saWithKeys > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d service account(s) with user-managed keys!", saWithKeys), globals.GCP_IAM_MODULE_NAME)
	}
	if highPrivCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d high-privilege role binding(s)!", highPrivCount), globals.GCP_IAM_MODULE_NAME)
	}

	output := IAMOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Determine output scope - use org if available, otherwise fall back to project
	var scopeType string
	var scopeIdentifiers []string
	var scopeNames []string

	if len(m.OrgIDs) > 0 {
		// Use organization scope with [O] prefix format
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
		// Fall back to project scope
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_IAM_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
