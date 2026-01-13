package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPServiceAccountsCommand = &cobra.Command{
	Use:     globals.GCP_SERVICEACCOUNTS_MODULE_NAME,
	Aliases: []string{"sa", "sas", "service-accounts"},
	Short:   "Enumerate GCP service accounts with security analysis",
	Long: `Enumerate GCP service accounts with detailed security analysis.

Features:
- Lists all service accounts with metadata
- Analyzes user-managed keys (age, expiration)
- Identifies default service accounts (Compute, App Engine, etc.)
- Detects disabled service accounts
- Flags service accounts without key rotation
- Identifies impersonation opportunities`,
	Run: runGCPServiceAccountsCommand,
}

// ServiceAccountAnalysis extends ServiceAccountInfo with security analysis
type ServiceAccountAnalysis struct {
	IAMService.ServiceAccountInfo
	IsDefaultSA       bool
	DefaultSAType     string // "compute", "appengine", "cloudbuild", etc.
	OldestKeyAge      int    // Days
	HasExpiredKeys    bool
	HasOldKeys        bool // Keys older than 90 days
	// Pentest: Impersonation analysis
	ImpersonationInfo *IAMService.SAImpersonationInfo
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type ServiceAccountsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	ServiceAccounts []ServiceAccountAnalysis
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type ServiceAccountsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ServiceAccountsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ServiceAccountsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPServiceAccountsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &ServiceAccountsModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		ServiceAccounts: []ServiceAccountAnalysis{},
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
func (m *ServiceAccountsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_SERVICEACCOUNTS_MODULE_NAME, m.processProject)

	// Check results
	if len(m.ServiceAccounts) == 0 {
		logger.InfoM("No service accounts found", globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
		return
	}

	// Count findings
	withKeys := 0
	defaultSAs := 0
	impersonatable := 0
	for _, sa := range m.ServiceAccounts {
		if sa.HasKeys {
			withKeys++
		}
		if sa.IsDefaultSA {
			defaultSAs++
		}
		if sa.ImpersonationInfo != nil && (len(sa.ImpersonationInfo.TokenCreators) > 0 || len(sa.ImpersonationInfo.KeyCreators) > 0) {
			impersonatable++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d service account(s) (%d with keys, %d default, %d impersonatable)",
		len(m.ServiceAccounts), withKeys, defaultSAs, impersonatable), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *ServiceAccountsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating service accounts in project: %s", projectID), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}

	// Create service and fetch service accounts with impersonation analysis
	iamService := IAMService.New()
	serviceAccounts, err := iamService.ServiceAccountsWithImpersonation(projectID)
	if err != nil {
		// Fallback to basic enumeration if impersonation analysis fails
		serviceAccounts, err = iamService.ServiceAccounts(projectID)
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, globals.GCP_SERVICEACCOUNTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate service accounts in project %s", projectID))
			return
		}
	}

	// Get impersonation info for each SA
	impersonationMap := make(map[string]*IAMService.SAImpersonationInfo)
	impersonationInfos, err := iamService.GetAllServiceAccountImpersonation(projectID)
	if err == nil {
		for i := range impersonationInfos {
			impersonationMap[impersonationInfos[i].ServiceAccount] = &impersonationInfos[i]
		}
	}

	// Analyze each service account
	var analyzedSAs []ServiceAccountAnalysis
	for _, sa := range serviceAccounts {
		analyzed := m.analyzeServiceAccount(sa, projectID)
		// Attach impersonation info if available
		if info, ok := impersonationMap[sa.Email]; ok {
			analyzed.ImpersonationInfo = info
		}
		analyzedSAs = append(analyzedSAs, analyzed)
	}

	// Thread-safe append
	m.mu.Lock()
	m.ServiceAccounts = append(m.ServiceAccounts, analyzedSAs...)

	// Generate loot for each service account
	for _, sa := range analyzedSAs {
		m.addServiceAccountToLoot(sa, projectID)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d service account(s) in project %s", len(analyzedSAs), projectID), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}
}

// analyzeServiceAccount performs security analysis on a service account
func (m *ServiceAccountsModule) analyzeServiceAccount(sa IAMService.ServiceAccountInfo, projectID string) ServiceAccountAnalysis {
	analyzed := ServiceAccountAnalysis{
		ServiceAccountInfo: sa,
	}

	// Check if it's a default service account
	analyzed.IsDefaultSA, analyzed.DefaultSAType = isDefaultServiceAccount(sa.Email, projectID)

	// Analyze keys
	if len(sa.Keys) > 0 {
		now := time.Now()
		oldestAge := 0

		for _, key := range sa.Keys {
			if key.KeyType == "USER_MANAGED" {
				// Calculate key age
				keyAge := int(now.Sub(key.ValidAfter).Hours() / 24)
				if keyAge > oldestAge {
					oldestAge = keyAge
				}

				// Check for expired keys
				if !key.ValidBefore.IsZero() && now.After(key.ValidBefore) {
					analyzed.HasExpiredKeys = true
				}

				// Check for old keys (> 90 days)
				if keyAge > 90 {
					analyzed.HasOldKeys = true
				}
			}
		}

		analyzed.OldestKeyAge = oldestAge
	}

	return analyzed
}

// isDefaultServiceAccount checks if a service account is a GCP default service account
func isDefaultServiceAccount(email, projectID string) (bool, string) {
	// Compute Engine default service account
	if strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") {
		return true, "Compute Engine"
	}

	// App Engine default service account
	if strings.HasSuffix(email, "@appspot.gserviceaccount.com") {
		return true, "App Engine"
	}

	// Cloud Build service account
	if strings.Contains(email, "@cloudbuild.gserviceaccount.com") {
		return true, "Cloud Build"
	}

	// Cloud Functions service account (project-id@appspot.gserviceaccount.com)
	if email == fmt.Sprintf("%s@appspot.gserviceaccount.com", projectID) {
		return true, "App Engine/Functions"
	}

	// Dataflow service account
	if strings.Contains(email, "-compute@developer.gserviceaccount.com") {
		// This is also used by Dataflow
		return true, "Compute/Dataflow"
	}

	// GKE service account
	if strings.Contains(email, "@container-engine-robot.iam.gserviceaccount.com") {
		return true, "GKE"
	}

	// Cloud SQL service account
	if strings.Contains(email, "@gcp-sa-cloud-sql.iam.gserviceaccount.com") {
		return true, "Cloud SQL"
	}

	// Pub/Sub service account
	if strings.Contains(email, "@gcp-sa-pubsub.iam.gserviceaccount.com") {
		return true, "Pub/Sub"
	}

	// Firebase service accounts
	if strings.Contains(email, "@firebase.iam.gserviceaccount.com") {
		return true, "Firebase"
	}

	// Google APIs service account
	if strings.Contains(email, "@cloudservices.gserviceaccount.com") {
		return true, "Google APIs"
	}

	return false, ""
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ServiceAccountsModule) initializeLootFiles() {
	m.LootMap["serviceaccounts-commands"] = &internal.LootFile{
		Name:     "serviceaccounts-commands",
		Contents: "# Service Account Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *ServiceAccountsModule) addServiceAccountToLoot(sa ServiceAccountAnalysis, projectID string) {
	keyFileName := strings.Split(sa.Email, "@")[0]

	m.LootMap["serviceaccounts-commands"].Contents += fmt.Sprintf(
		"# ==========================================\n"+
			"# SERVICE ACCOUNT: %s\n"+
			"# ==========================================\n"+
			"# Project: %s\n"+
			"# Display Name: %s\n"+
			"# Disabled: %v\n",
		sa.Email,
		projectID,
		sa.DisplayName,
		sa.Disabled,
	)

	// Add impersonation info if available
	if sa.ImpersonationInfo != nil {
		if len(sa.ImpersonationInfo.TokenCreators) > 0 {
			m.LootMap["serviceaccounts-commands"].Contents += fmt.Sprintf("# Token Creators: %s\n", strings.Join(sa.ImpersonationInfo.TokenCreators, ", "))
		}
		if len(sa.ImpersonationInfo.KeyCreators) > 0 {
			m.LootMap["serviceaccounts-commands"].Contents += fmt.Sprintf("# Key Creators: %s\n", strings.Join(sa.ImpersonationInfo.KeyCreators, ", "))
		}
		if len(sa.ImpersonationInfo.ActAsUsers) > 0 {
			m.LootMap["serviceaccounts-commands"].Contents += fmt.Sprintf("# ActAs Users: %s\n", strings.Join(sa.ImpersonationInfo.ActAsUsers, ", "))
		}
	}

	m.LootMap["serviceaccounts-commands"].Contents += fmt.Sprintf(
		"\n# Impersonation commands:\n"+
			"gcloud auth print-access-token --impersonate-service-account=%s\n"+
			"gcloud auth print-identity-token --impersonate-service-account=%s\n\n"+
			"# Key creation commands:\n"+
			"gcloud iam service-accounts keys create %s-key.json --iam-account=%s --project=%s\n"+
			"gcloud auth activate-service-account --key-file=%s-key.json\n\n"+
			"# Describe service account:\n"+
			"gcloud iam service-accounts describe %s --project=%s\n\n"+
			"# Get IAM policy for this service account:\n"+
			"gcloud iam service-accounts get-iam-policy %s --project=%s\n\n",
		sa.Email,
		sa.Email,
		keyFileName,
		sa.Email,
		projectID,
		keyFileName,
		sa.Email,
		projectID,
		sa.Email,
		projectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ServiceAccountsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Service accounts table - one row per IAM binding (impersonation permission)
	saHeader := []string{
		"Project Name",
		"Project ID",
		"Email",
		"Display Name",
		"Disabled",
		"Default SA",
		"DWD",
		"Key Count",
		"IAM Role",
		"IAM Member",
	}

	var saBody [][]string
	for _, sa := range m.ServiceAccounts {
		disabled := "No"
		if sa.Disabled {
			disabled = "Yes"
		}

		defaultSA := "-"
		if sa.IsDefaultSA {
			defaultSA = sa.DefaultSAType
		}

		// Check if DWD is enabled
		dwd := "No"
		if sa.OAuth2ClientID != "" {
			dwd = "Yes"
		}

		// Count user-managed keys
		keyCount := "-"
		userKeyCount := 0
		for _, key := range sa.Keys {
			if key.KeyType == "USER_MANAGED" {
				userKeyCount++
			}
		}
		if userKeyCount > 0 {
			keyCount = fmt.Sprintf("%d", userKeyCount)
		}

		// Build IAM bindings from impersonation info
		// One row per IAM binding (member + role type)
		hasBindings := false
		if sa.ImpersonationInfo != nil {
			// Token creators can get access tokens
			for _, member := range sa.ImpersonationInfo.TokenCreators {
				email := extractEmailFromMember(member)
				if email != sa.Email { // Skip self-reference
					hasBindings = true
					saBody = append(saBody, []string{
						m.GetProjectName(sa.ProjectID),
						sa.ProjectID,
						sa.Email,
						sa.DisplayName,
						disabled,
						defaultSA,
						dwd,
						keyCount,
						"TokenCreator",
						member,
					})
				}
			}
			// Key creators can create keys
			for _, member := range sa.ImpersonationInfo.KeyCreators {
				email := extractEmailFromMember(member)
				if email != sa.Email { // Skip self-reference
					hasBindings = true
					saBody = append(saBody, []string{
						m.GetProjectName(sa.ProjectID),
						sa.ProjectID,
						sa.Email,
						sa.DisplayName,
						disabled,
						defaultSA,
						dwd,
						keyCount,
						"KeyAdmin",
						member,
					})
				}
			}
			// ActAs users can impersonate
			for _, member := range sa.ImpersonationInfo.ActAsUsers {
				email := extractEmailFromMember(member)
				if email != sa.Email { // Skip self-reference
					hasBindings = true
					saBody = append(saBody, []string{
						m.GetProjectName(sa.ProjectID),
						sa.ProjectID,
						sa.Email,
						sa.DisplayName,
						disabled,
						defaultSA,
						dwd,
						keyCount,
						"ActAs",
						member,
					})
				}
			}
			// SA Admins have full control
			for _, member := range sa.ImpersonationInfo.SAAdmins {
				email := extractEmailFromMember(member)
				if email != sa.Email { // Skip self-reference
					hasBindings = true
					saBody = append(saBody, []string{
						m.GetProjectName(sa.ProjectID),
						sa.ProjectID,
						sa.Email,
						sa.DisplayName,
						disabled,
						defaultSA,
						dwd,
						keyCount,
						"SAAdmin",
						member,
					})
				}
			}
			// SignBlob users
			for _, member := range sa.ImpersonationInfo.SignBlobUsers {
				email := extractEmailFromMember(member)
				if email != sa.Email { // Skip self-reference
					hasBindings = true
					saBody = append(saBody, []string{
						m.GetProjectName(sa.ProjectID),
						sa.ProjectID,
						sa.Email,
						sa.DisplayName,
						disabled,
						defaultSA,
						dwd,
						keyCount,
						"SignBlob",
						member,
					})
				}
			}
			// SignJwt users
			for _, member := range sa.ImpersonationInfo.SignJwtUsers {
				email := extractEmailFromMember(member)
				if email != sa.Email { // Skip self-reference
					hasBindings = true
					saBody = append(saBody, []string{
						m.GetProjectName(sa.ProjectID),
						sa.ProjectID,
						sa.Email,
						sa.DisplayName,
						disabled,
						defaultSA,
						dwd,
						keyCount,
						"SignJwt",
						member,
					})
				}
			}
		}

		// If no IAM bindings, still show the SA with empty IAM columns
		if !hasBindings {
			saBody = append(saBody, []string{
				m.GetProjectName(sa.ProjectID),
				sa.ProjectID,
				sa.Email,
				sa.DisplayName,
				disabled,
				defaultSA,
				dwd,
				keyCount,
				"-",
				"-",
			})
		}
	}

	// Collect loot files (only non-empty ones)
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables - just one table now
	tables := []internal.TableFile{
		{
			Name:   "serviceaccounts",
			Header: saHeader,
			Body:   saBody,
		},
	}

	output := ServiceAccountsOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// extractEmailFromMember extracts the email/identity from an IAM member string
// e.g., "user:alice@example.com" -> "alice@example.com"
// e.g., "serviceAccount:sa@project.iam.gserviceaccount.com" -> "sa@project.iam..."
func extractEmailFromMember(member string) string {
	if idx := strings.Index(member, ":"); idx != -1 {
		return member[idx+1:]
	}
	return member
}
