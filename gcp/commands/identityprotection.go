package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
)

// Module name constant
const GCP_IDENTITYPROTECTION_MODULE_NAME string = "identity-protection"

var GCPIdentityProtectionCommand = &cobra.Command{
	Use:     GCP_IDENTITYPROTECTION_MODULE_NAME,
	Aliases: []string{"identity", "risky-identities", "iam-risk"},
	Short:   "Risk-based identity analysis and suspicious activity detection",
	Long: `Analyze IAM identities for security risks, unused permissions, and policy recommendations.

Features:
- Identifies risky IAM bindings (overly permissive roles)
- Detects unused permissions and over-provisioned identities
- Analyzes service account key age and rotation status
- Identifies external identities with access
- Detects domain-wide delegation configurations
- Provides policy recommendations for least privilege
- Maps identity attack surface

Risk Categories:
- CRITICAL: Owner/Editor roles, domain-wide delegation, allUsers access
- HIGH: Primitive roles, external identity access, old service account keys
- MEDIUM: Broad permissions, unused high-privilege roles
- LOW: Minor policy improvements recommended

Requires appropriate IAM permissions:
- roles/iam.securityReviewer
- roles/resourcemanager.organizationViewer`,
	Run: runGCPIdentityProtectionCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type RiskyBinding struct {
	Principal     string
	Role          string
	Resource      string
	ResourceType  string
	ProjectID     string
	RiskLevel     string
	RiskReason    string
	Recommendation string
	BindingType   string // user, serviceAccount, group, domain, allUsers, allAuthenticatedUsers
}

type UnusedPermission struct {
	Principal        string
	Role             string
	Resource         string
	ProjectID        string
	LastUsed         string
	DaysSinceUse     int
	Recommendation   string
	PermissionCount  int
}

type ServiceAccountRisk struct {
	Email            string
	ProjectID        string
	DisplayName      string
	KeyCount         int
	OldestKeyAge     int // days
	HasUserManagedKey bool
	DomainWideDelegation bool
	RiskLevel        string
	RiskReasons      []string
	Recommendations  []string
}

type ExternalIdentity struct {
	Principal    string
	IdentityType string // external-user, external-sa, external-domain
	Domain       string
	Roles        []string
	Resources    []string
	ProjectID    string
	RiskLevel    string
	Details      string
}

type IdentityRisk struct {
	RiskType     string
	Severity     string
	AffectedCount int
	Description  string
	Mitigation   string
}

// ------------------------------
// Module Struct
// ------------------------------
type IdentityProtectionModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	RiskyBindings      []RiskyBinding
	UnusedPermissions  []UnusedPermission
	ServiceAccountRisks []ServiceAccountRisk
	ExternalIdentities []ExternalIdentity
	IdentityRisks      []IdentityRisk
	LootMap            map[string]*internal.LootFile
	mu                 sync.Mutex

	// Tracking
	projectDomains map[string]string // project -> org domain
	allUsersCount  int
	allAuthCount   int
	ownerCount     int
	editorCount    int
	externalCount  int
}

// ------------------------------
// Output Struct
// ------------------------------
type IdentityProtectionOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o IdentityProtectionOutput) TableFiles() []internal.TableFile { return o.Table }
func (o IdentityProtectionOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPIdentityProtectionCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_IDENTITYPROTECTION_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &IdentityProtectionModule{
		BaseGCPModule:       gcpinternal.NewBaseGCPModule(cmdCtx),
		RiskyBindings:       []RiskyBinding{},
		UnusedPermissions:   []UnusedPermission{},
		ServiceAccountRisks: []ServiceAccountRisk{},
		ExternalIdentities:  []ExternalIdentity{},
		IdentityRisks:       []IdentityRisk{},
		LootMap:             make(map[string]*internal.LootFile),
		projectDomains:      make(map[string]string),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *IdentityProtectionModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing identity risks and policy recommendations...", GCP_IDENTITYPROTECTION_MODULE_NAME)

	// Create service clients
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Resource Manager service: %v", err), GCP_IDENTITYPROTECTION_MODULE_NAME)
		return
	}

	iamService, err := iam.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create IAM service: %v", err), GCP_IDENTITYPROTECTION_MODULE_NAME)
		return
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, crmService, iamService, logger)
		}(projectID)
	}
	wg.Wait()

	// Analyze and summarize risks
	m.summarizeRisks(logger)

	// Check results
	totalRisks := len(m.RiskyBindings) + len(m.ServiceAccountRisks) + len(m.ExternalIdentities)
	if totalRisks == 0 {
		logger.InfoM("No identity risks found", GCP_IDENTITYPROTECTION_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d risky binding(s), %d service account risk(s), %d external identity(ies)",
		len(m.RiskyBindings), len(m.ServiceAccountRisks), len(m.ExternalIdentities)), GCP_IDENTITYPROTECTION_MODULE_NAME)

	if m.allUsersCount > 0 || m.allAuthCount > 0 {
		logger.InfoM(fmt.Sprintf("[CRITICAL] Found %d allUsers and %d allAuthenticatedUsers bindings!",
			m.allUsersCount, m.allAuthCount), GCP_IDENTITYPROTECTION_MODULE_NAME)
	}

	if m.ownerCount > 0 || m.editorCount > 0 {
		logger.InfoM(fmt.Sprintf("[HIGH] Found %d Owner and %d Editor role bindings",
			m.ownerCount, m.editorCount), GCP_IDENTITYPROTECTION_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *IdentityProtectionModule) processProject(ctx context.Context, projectID string, crmService *cloudresourcemanager.Service, iamService *iam.Service, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing identities for project: %s", projectID), GCP_IDENTITYPROTECTION_MODULE_NAME)
	}

	// Analyze IAM policy bindings
	m.analyzeIAMPolicy(ctx, projectID, crmService, logger)

	// Analyze service accounts
	m.analyzeServiceAccounts(ctx, projectID, iamService, logger)
}

func (m *IdentityProtectionModule) analyzeIAMPolicy(ctx context.Context, projectID string, crmService *cloudresourcemanager.Service, logger internal.Logger) {
	// Get IAM policy for the project
	policy, err := crmService.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting IAM policy for project %s: %v", projectID, err), GCP_IDENTITYPROTECTION_MODULE_NAME)
		}
		return
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			m.analyzeBinding(member, binding.Role, projectID, "project", logger)
		}
	}
}

func (m *IdentityProtectionModule) analyzeBinding(member, role, projectID, resourceType string, logger internal.Logger) {
	riskLevel := "LOW"
	riskReason := ""
	recommendation := ""
	bindingType := m.getBindingType(member)

	// Check for allUsers/allAuthenticatedUsers (CRITICAL)
	if member == "allUsers" {
		riskLevel = "CRITICAL"
		riskReason = "Public access: allUsers grants access to anyone on the internet"
		recommendation = "Remove allUsers binding immediately unless intentionally public"
		m.mu.Lock()
		m.allUsersCount++
		m.mu.Unlock()
	} else if member == "allAuthenticatedUsers" {
		riskLevel = "CRITICAL"
		riskReason = "Any Google account: allAuthenticatedUsers grants access to any authenticated Google user"
		recommendation = "Replace with specific users/groups or use IAM Conditions"
		m.mu.Lock()
		m.allAuthCount++
		m.mu.Unlock()
	}

	// Check for Owner/Editor roles (HIGH)
	if strings.Contains(role, "roles/owner") {
		if riskLevel != "CRITICAL" {
			riskLevel = "HIGH"
		}
		riskReason = "Owner role: Full administrative access including IAM management"
		recommendation = "Replace with specific roles following least privilege principle"
		m.mu.Lock()
		m.ownerCount++
		m.mu.Unlock()
	} else if strings.Contains(role, "roles/editor") {
		if riskLevel != "CRITICAL" {
			riskLevel = "HIGH"
		}
		riskReason = "Editor role: Broad modify access to most resources"
		recommendation = "Replace with specific roles for required services only"
		m.mu.Lock()
		m.editorCount++
		m.mu.Unlock()
	}

	// Check for other high-risk roles
	highRiskRoles := map[string]string{
		"roles/iam.securityAdmin":           "Can manage all IAM policies",
		"roles/iam.serviceAccountAdmin":     "Can create/delete service accounts",
		"roles/iam.serviceAccountKeyAdmin":  "Can create service account keys",
		"roles/iam.serviceAccountTokenCreator": "Can impersonate service accounts",
		"roles/resourcemanager.projectIamAdmin": "Can manage project IAM policies",
		"roles/cloudfunctions.admin":        "Can deploy functions with any SA",
		"roles/compute.admin":               "Full compute access including SSH",
		"roles/storage.admin":               "Full storage access",
	}

	if reason, isHighRisk := highRiskRoles[role]; isHighRisk {
		if riskLevel == "LOW" {
			riskLevel = "MEDIUM"
			riskReason = reason
			recommendation = "Review if this level of access is necessary"
		}
	}

	// Check for external identities
	if m.isExternalIdentity(member, projectID) {
		if riskLevel == "LOW" {
			riskLevel = "MEDIUM"
		}
		riskReason += "; External identity with access"
		m.mu.Lock()
		m.externalCount++

		// Track external identity
		domain := m.extractDomain(member)
		external := ExternalIdentity{
			Principal:    member,
			IdentityType: bindingType,
			Domain:       domain,
			Roles:        []string{role},
			Resources:    []string{projectID},
			ProjectID:    projectID,
			RiskLevel:    riskLevel,
			Details:      fmt.Sprintf("External %s with %s role", bindingType, role),
		}
		m.ExternalIdentities = append(m.ExternalIdentities, external)
		m.mu.Unlock()
	}

	// Only track if there's a risk
	if riskLevel != "LOW" || m.isHighPrivilegeRole(role) {
		risky := RiskyBinding{
			Principal:      member,
			Role:           role,
			Resource:       projectID,
			ResourceType:   resourceType,
			ProjectID:      projectID,
			RiskLevel:      riskLevel,
			RiskReason:     riskReason,
			Recommendation: recommendation,
			BindingType:    bindingType,
		}

		m.mu.Lock()
		m.RiskyBindings = append(m.RiskyBindings, risky)
		m.addRiskyBindingToLoot(risky)
		m.mu.Unlock()
	}
}

func (m *IdentityProtectionModule) analyzeServiceAccounts(ctx context.Context, projectID string, iamService *iam.Service, logger internal.Logger) {
	// List service accounts
	saList, err := iamService.Projects.ServiceAccounts.List(fmt.Sprintf("projects/%s", projectID)).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing service accounts for project %s: %v", projectID, err), GCP_IDENTITYPROTECTION_MODULE_NAME)
		}
		return
	}

	for _, sa := range saList.Accounts {
		saRisk := ServiceAccountRisk{
			Email:       sa.Email,
			ProjectID:   projectID,
			DisplayName: sa.DisplayName,
			RiskLevel:   "LOW",
			RiskReasons: []string{},
			Recommendations: []string{},
		}

		// Check for domain-wide delegation
		if sa.Oauth2ClientId != "" {
			// Service account has OAuth client ID, may have domain-wide delegation
			saRisk.DomainWideDelegation = true
			saRisk.RiskLevel = "CRITICAL"
			saRisk.RiskReasons = append(saRisk.RiskReasons, "Domain-wide delegation enabled - can impersonate any user in the domain")
			saRisk.Recommendations = append(saRisk.Recommendations, "Review and restrict domain-wide delegation scopes")
		}

		// List service account keys
		keysResp, err := iamService.Projects.ServiceAccounts.Keys.List(fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, sa.Email)).Do()
		if err == nil {
			userManagedKeys := 0
			var oldestKeyAge int

			for _, key := range keysResp.Keys {
				if key.KeyType == "USER_MANAGED" {
					userManagedKeys++
					saRisk.HasUserManagedKey = true

					// Check key age
					validAfter, err := time.Parse(time.RFC3339, key.ValidAfterTime)
					if err == nil {
						keyAge := int(time.Since(validAfter).Hours() / 24)
						if keyAge > oldestKeyAge {
							oldestKeyAge = keyAge
						}
					}
				}
			}

			saRisk.KeyCount = userManagedKeys
			saRisk.OldestKeyAge = oldestKeyAge

			if userManagedKeys > 0 {
				if saRisk.RiskLevel == "LOW" {
					saRisk.RiskLevel = "MEDIUM"
				}
				saRisk.RiskReasons = append(saRisk.RiskReasons, fmt.Sprintf("%d user-managed key(s) exist", userManagedKeys))
				saRisk.Recommendations = append(saRisk.Recommendations, "Use workload identity or short-lived tokens instead of keys")
			}

			if oldestKeyAge > 90 {
				if saRisk.RiskLevel == "LOW" || saRisk.RiskLevel == "MEDIUM" {
					saRisk.RiskLevel = "HIGH"
				}
				saRisk.RiskReasons = append(saRisk.RiskReasons, fmt.Sprintf("Oldest key is %d days old (>90 days)", oldestKeyAge))
				saRisk.Recommendations = append(saRisk.Recommendations, "Rotate service account keys - keys should be rotated every 90 days")
			}
		}

		// Check for default compute service account
		if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") {
			saRisk.RiskReasons = append(saRisk.RiskReasons, "Default Compute Engine service account - often over-privileged")
			saRisk.Recommendations = append(saRisk.Recommendations, "Create custom service accounts with minimal permissions")
		}

		// Check for App Engine default service account
		if strings.Contains(sa.Email, "@appspot.gserviceaccount.com") {
			saRisk.RiskReasons = append(saRisk.RiskReasons, "App Engine default service account")
			saRisk.Recommendations = append(saRisk.Recommendations, "Review App Engine service account permissions")
		}

		// Only add if there are risks
		if len(saRisk.RiskReasons) > 0 {
			m.mu.Lock()
			m.ServiceAccountRisks = append(m.ServiceAccountRisks, saRisk)
			m.addServiceAccountRiskToLoot(saRisk)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Risk Analysis
// ------------------------------
func (m *IdentityProtectionModule) summarizeRisks(logger internal.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Summarize allUsers/allAuthenticatedUsers
	if m.allUsersCount > 0 {
		m.IdentityRisks = append(m.IdentityRisks, IdentityRisk{
			RiskType:      "public-access",
			Severity:      "CRITICAL",
			AffectedCount: m.allUsersCount,
			Description:   "Resources accessible to anyone on the internet",
			Mitigation:    "Remove allUsers bindings unless resource is intentionally public",
		})
	}

	if m.allAuthCount > 0 {
		m.IdentityRisks = append(m.IdentityRisks, IdentityRisk{
			RiskType:      "all-authenticated-users",
			Severity:      "CRITICAL",
			AffectedCount: m.allAuthCount,
			Description:   "Resources accessible to any Google account holder",
			Mitigation:    "Replace with specific users/groups or domain restrictions",
		})
	}

	// Summarize Owner/Editor roles
	if m.ownerCount > 0 {
		m.IdentityRisks = append(m.IdentityRisks, IdentityRisk{
			RiskType:      "owner-role",
			Severity:      "HIGH",
			AffectedCount: m.ownerCount,
			Description:   "Owner role grants full administrative access",
			Mitigation:    "Use specific admin roles instead of Owner",
		})
	}

	if m.editorCount > 0 {
		m.IdentityRisks = append(m.IdentityRisks, IdentityRisk{
			RiskType:      "editor-role",
			Severity:      "HIGH",
			AffectedCount: m.editorCount,
			Description:   "Editor role grants broad modify access",
			Mitigation:    "Replace with service-specific roles",
		})
	}

	// Summarize external access
	if m.externalCount > 0 {
		m.IdentityRisks = append(m.IdentityRisks, IdentityRisk{
			RiskType:      "external-access",
			Severity:      "MEDIUM",
			AffectedCount: m.externalCount,
			Description:   "External identities have access to resources",
			Mitigation:    "Review and document external access requirements",
		})
	}

	// Count domain-wide delegation
	dwdCount := 0
	for _, sa := range m.ServiceAccountRisks {
		if sa.DomainWideDelegation {
			dwdCount++
		}
	}
	if dwdCount > 0 {
		m.IdentityRisks = append(m.IdentityRisks, IdentityRisk{
			RiskType:      "domain-wide-delegation",
			Severity:      "CRITICAL",
			AffectedCount: dwdCount,
			Description:   "Service accounts with domain-wide delegation can impersonate any domain user",
			Mitigation:    "Restrict delegation scopes to minimum required",
		})
	}

	// Count old keys
	oldKeyCount := 0
	for _, sa := range m.ServiceAccountRisks {
		if sa.OldestKeyAge > 90 {
			oldKeyCount++
		}
	}
	if oldKeyCount > 0 {
		m.IdentityRisks = append(m.IdentityRisks, IdentityRisk{
			RiskType:      "old-service-account-keys",
			Severity:      "HIGH",
			AffectedCount: oldKeyCount,
			Description:   "Service account keys older than 90 days",
			Mitigation:    "Implement key rotation policy or use workload identity",
		})
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func (m *IdentityProtectionModule) getBindingType(member string) string {
	switch {
	case member == "allUsers":
		return "allUsers"
	case member == "allAuthenticatedUsers":
		return "allAuthenticatedUsers"
	case strings.HasPrefix(member, "user:"):
		return "user"
	case strings.HasPrefix(member, "serviceAccount:"):
		return "serviceAccount"
	case strings.HasPrefix(member, "group:"):
		return "group"
	case strings.HasPrefix(member, "domain:"):
		return "domain"
	default:
		return "unknown"
	}
}

func (m *IdentityProtectionModule) isExternalIdentity(member, projectID string) bool {
	// Extract domain from member
	domain := m.extractDomain(member)
	if domain == "" {
		return false
	}

	// Check if it's a GCP service account in same project
	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		// Extract project from SA email
		parts := strings.Split(domain, ".")
		if len(parts) > 0 {
			saProject := parts[0]
			if saProject == projectID {
				return false
			}
		}
		return true // External service account
	}

	// Check against known internal domains (would need org domain)
	// For now, consider external if not a GCP service account
	return !strings.Contains(domain, "gserviceaccount.com")
}

func (m *IdentityProtectionModule) extractDomain(member string) string {
	// Remove prefix
	parts := strings.SplitN(member, ":", 2)
	if len(parts) != 2 {
		return ""
	}

	email := parts[1]
	emailParts := strings.Split(email, "@")
	if len(emailParts) != 2 {
		return ""
	}

	return emailParts[1]
}

func (m *IdentityProtectionModule) isHighPrivilegeRole(role string) bool {
	highPrivRoles := []string{
		"roles/owner",
		"roles/editor",
		"roles/iam.securityAdmin",
		"roles/iam.serviceAccountAdmin",
		"roles/iam.serviceAccountKeyAdmin",
		"roles/iam.serviceAccountTokenCreator",
		"roles/resourcemanager.projectIamAdmin",
		"roles/resourcemanager.organizationAdmin",
		"roles/compute.admin",
		"roles/storage.admin",
		"roles/bigquery.admin",
		"roles/cloudsql.admin",
		"roles/cloudfunctions.admin",
		"roles/run.admin",
		"roles/container.admin",
	}

	for _, r := range highPrivRoles {
		if role == r {
			return true
		}
	}
	return false
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *IdentityProtectionModule) initializeLootFiles() {
	m.LootMap["risky-accounts"] = &internal.LootFile{
		Name:     "risky-accounts",
		Contents: "# Risky IAM Bindings\n# Generated by CloudFox\n# Review and remediate these bindings!\n\n",
	}
	m.LootMap["unused-permissions"] = &internal.LootFile{
		Name:     "unused-permissions",
		Contents: "# Unused/Over-provisioned Permissions\n# Generated by CloudFox\n\n",
	}
	m.LootMap["remediation-commands"] = &internal.LootFile{
		Name:     "remediation-commands",
		Contents: "# IAM Remediation Commands\n# Generated by CloudFox\n# Review before executing!\n\n",
	}
	m.LootMap["external-access"] = &internal.LootFile{
		Name:     "external-access",
		Contents: "# External Identity Access\n# Generated by CloudFox\n\n",
	}
	m.LootMap["service-account-risks"] = &internal.LootFile{
		Name:     "service-account-risks",
		Contents: "# Service Account Security Risks\n# Generated by CloudFox\n\n",
	}
}

func (m *IdentityProtectionModule) addRiskyBindingToLoot(binding RiskyBinding) {
	m.LootMap["risky-accounts"].Contents += fmt.Sprintf(
		"## %s [%s]\n"+
			"Role: %s\n"+
			"Resource: %s\n"+
			"Risk: %s\n"+
			"Recommendation: %s\n\n",
		binding.Principal,
		binding.RiskLevel,
		binding.Role,
		binding.Resource,
		binding.RiskReason,
		binding.Recommendation,
	)

	// Add remediation command
	if binding.RiskLevel == "CRITICAL" || binding.RiskLevel == "HIGH" {
		m.LootMap["remediation-commands"].Contents += fmt.Sprintf(
			"# Remove %s binding for %s\n"+
				"gcloud projects remove-iam-policy-binding %s \\\n"+
				"  --member=\"%s\" \\\n"+
				"  --role=\"%s\"\n\n",
			binding.RiskLevel, binding.Principal,
			binding.ProjectID,
			binding.Principal,
			binding.Role,
		)
	}

	// Track external access
	if binding.BindingType == "user" || binding.BindingType == "serviceAccount" {
		domain := m.extractDomain(binding.Principal)
		if domain != "" && !strings.Contains(domain, "gserviceaccount.com") {
			m.LootMap["external-access"].Contents += fmt.Sprintf(
				"%s (%s) - %s on %s\n",
				binding.Principal, domain, binding.Role, binding.Resource,
			)
		}
	}
}

func (m *IdentityProtectionModule) addServiceAccountRiskToLoot(saRisk ServiceAccountRisk) {
	m.LootMap["service-account-risks"].Contents += fmt.Sprintf(
		"## %s [%s]\n"+
			"Project: %s\n"+
			"Display Name: %s\n"+
			"User-Managed Keys: %d\n"+
			"Oldest Key Age: %d days\n"+
			"Domain-Wide Delegation: %t\n"+
			"Risks:\n",
		saRisk.Email,
		saRisk.RiskLevel,
		saRisk.ProjectID,
		saRisk.DisplayName,
		saRisk.KeyCount,
		saRisk.OldestKeyAge,
		saRisk.DomainWideDelegation,
	)

	for _, reason := range saRisk.RiskReasons {
		m.LootMap["service-account-risks"].Contents += fmt.Sprintf("  - %s\n", reason)
	}

	m.LootMap["service-account-risks"].Contents += "Recommendations:\n"
	for _, rec := range saRisk.Recommendations {
		m.LootMap["service-account-risks"].Contents += fmt.Sprintf("  - %s\n", rec)
	}
	m.LootMap["service-account-risks"].Contents += "\n"

	// Add key rotation commands
	if saRisk.OldestKeyAge > 90 {
		m.LootMap["remediation-commands"].Contents += fmt.Sprintf(
			"# Rotate keys for %s (oldest key: %d days)\n"+
				"# List keys:\n"+
				"gcloud iam service-accounts keys list --iam-account=%s\n"+
				"# Delete old key:\n"+
				"# gcloud iam service-accounts keys delete KEY_ID --iam-account=%s\n\n",
			saRisk.Email, saRisk.OldestKeyAge,
			saRisk.Email,
			saRisk.Email,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *IdentityProtectionModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort risky bindings by risk level
	sort.Slice(m.RiskyBindings, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		return riskOrder[m.RiskyBindings[i].RiskLevel] < riskOrder[m.RiskyBindings[j].RiskLevel]
	})

	// Risky Bindings table
	bindingsHeader := []string{
		"Principal",
		"Role",
		"Resource",
		"Risk Level",
		"Type",
		"Risk Reason",
	}

	var bindingsBody [][]string
	for _, b := range m.RiskyBindings {
		bindingsBody = append(bindingsBody, []string{
			truncateString(b.Principal, 40),
			truncateString(b.Role, 35),
			b.Resource,
			b.RiskLevel,
			b.BindingType,
			truncateString(b.RiskReason, 40),
		})
	}

	// Service Account Risks table
	saRisksHeader := []string{
		"Service Account",
		"Project Name",
		"Project ID",
		"Risk Level",
		"Keys",
		"Key Age",
		"DWD",
		"Risks",
	}

	var saRisksBody [][]string
	for _, sa := range m.ServiceAccountRisks {
		dwd := "No"
		if sa.DomainWideDelegation {
			dwd = "Yes"
		}

		saRisksBody = append(saRisksBody, []string{
			truncateString(sa.Email, 40),
			m.GetProjectName(sa.ProjectID),
			sa.ProjectID,
			sa.RiskLevel,
			fmt.Sprintf("%d", sa.KeyCount),
			fmt.Sprintf("%d days", sa.OldestKeyAge),
			dwd,
			truncateString(strings.Join(sa.RiskReasons, "; "), 40),
		})
	}

	// External Identities table
	externalHeader := []string{
		"Identity",
		"Type",
		"Domain",
		"Project Name",
		"Project ID",
		"Risk Level",
		"Details",
	}

	var externalBody [][]string
	for _, e := range m.ExternalIdentities {
		externalBody = append(externalBody, []string{
			truncateString(e.Principal, 40),
			e.IdentityType,
			e.Domain,
			m.GetProjectName(e.ProjectID),
			e.ProjectID,
			e.RiskLevel,
			truncateString(e.Details, 40),
		})
	}

	// Risk Summary table
	summaryHeader := []string{
		"Risk Type",
		"Severity",
		"Affected",
		"Description",
	}

	var summaryBody [][]string
	for _, r := range m.IdentityRisks {
		summaryBody = append(summaryBody, []string{
			r.RiskType,
			r.Severity,
			fmt.Sprintf("%d", r.AffectedCount),
			truncateString(r.Description, 50),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	tables := []internal.TableFile{}

	if len(bindingsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "risky-bindings",
			Header: bindingsHeader,
			Body:   bindingsBody,
		})
	}

	if len(saRisksBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "service-account-risks",
			Header: saRisksHeader,
			Body:   saRisksBody,
		})
	}

	if len(externalBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "external-identities",
			Header: externalHeader,
			Body:   externalBody,
		})
	}

	if len(summaryBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "identity-risks",
			Header: summaryHeader,
			Body:   summaryBody,
		})
	}

	output := IdentityProtectionOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scope names using project names
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	// Write output
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		scopeNames,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_IDENTITYPROTECTION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
