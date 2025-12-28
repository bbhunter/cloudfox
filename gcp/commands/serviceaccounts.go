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
- Shows service account roles and permissions
- Identifies cross-project service account bindings
- Generates exploitation commands for penetration testing`,
	Run: runGCPServiceAccountsCommand,
}

// ServiceAccountAnalysis extends ServiceAccountInfo with security analysis
type ServiceAccountAnalysis struct {
	IAMService.ServiceAccountInfo
	IsDefaultSA       bool
	DefaultSAType     string // "compute", "appengine", "cloudbuild", etc.
	OldestKeyAge      int    // Days
	HasExpiredKeys    bool
	HasOldKeys        bool   // Keys older than 90 days
	KeyAgeWarning     string
	RiskLevel         string // HIGH, MEDIUM, LOW
	RiskReasons       []string
	ImpersonationCmds []string
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
	highRisk := 0
	defaultSAs := 0
	for _, sa := range m.ServiceAccounts {
		if sa.HasKeys {
			withKeys++
		}
		if sa.RiskLevel == "HIGH" {
			highRisk++
		}
		if sa.IsDefaultSA {
			defaultSAs++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d service account(s) (%d with keys, %d high-risk, %d default)",
		len(m.ServiceAccounts), withKeys, highRisk, defaultSAs), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)

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
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error enumerating service accounts in project %s: %v", projectID, err), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
			}
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
		RiskReasons:        []string{},
		ImpersonationCmds:  []string{},
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
		if oldestAge > 365 {
			analyzed.KeyAgeWarning = fmt.Sprintf("%d days (>1 year)", oldestAge)
		} else if oldestAge > 90 {
			analyzed.KeyAgeWarning = fmt.Sprintf("%d days (>90 days)", oldestAge)
		}
	}

	// Generate impersonation commands
	analyzed.ImpersonationCmds = []string{
		fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", sa.Email),
		fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", sa.Email),
	}

	// Determine risk level
	analyzed.RiskLevel, analyzed.RiskReasons = determineServiceAccountRisk(analyzed)

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

	// Cloud Run service account (uses compute default)
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

// determineServiceAccountRisk determines the risk level of a service account
func determineServiceAccountRisk(sa ServiceAccountAnalysis) (string, []string) {
	var reasons []string
	score := 0

	// High-risk indicators
	if sa.HasKeys && sa.OldestKeyAge > 365 {
		reasons = append(reasons, "Key older than 1 year without rotation")
		score += 3
	} else if sa.HasKeys && sa.OldestKeyAge > 90 {
		reasons = append(reasons, "Key older than 90 days")
		score += 2
	}

	if sa.HasExpiredKeys {
		reasons = append(reasons, "Has expired keys (cleanup needed)")
		score += 1
	}

	if sa.HasKeys && sa.KeyCount > 2 {
		reasons = append(reasons, fmt.Sprintf("Multiple user-managed keys (%d)", sa.KeyCount))
		score += 1
	}

	if sa.IsDefaultSA && sa.HasKeys {
		reasons = append(reasons, fmt.Sprintf("Default SA (%s) with user-managed keys", sa.DefaultSAType))
		score += 2
	}

	if sa.Disabled && sa.HasKeys {
		reasons = append(reasons, "Disabled SA with active keys")
		score += 2
	}

	// Determine risk level
	if score >= 4 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}

	return "INFO", reasons
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ServiceAccountsModule) initializeLootFiles() {
	m.LootMap["sa-impersonation-commands"] = &internal.LootFile{
		Name:     "sa-impersonation-commands",
		Contents: "# Service Account Impersonation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["sa-key-creation-commands"] = &internal.LootFile{
		Name:     "sa-key-creation-commands",
		Contents: "# Service Account Key Creation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["sa-high-risk"] = &internal.LootFile{
		Name:     "sa-high-risk",
		Contents: "# High-Risk Service Accounts\n# Generated by CloudFox\n\n",
	}
	m.LootMap["sa-old-keys"] = &internal.LootFile{
		Name:     "sa-old-keys",
		Contents: "# Service Accounts with Old Keys (>90 days)\n# Generated by CloudFox\n# Consider rotating these keys\n\n",
	}
	m.LootMap["sa-default-accounts"] = &internal.LootFile{
		Name:     "sa-default-accounts",
		Contents: "# Default Service Accounts\n# Generated by CloudFox\n# These often have broad permissions\n\n",
	}
	m.LootMap["sa-all-emails"] = &internal.LootFile{
		Name:     "sa-all-emails",
		Contents: "",
	}
	// Pentest: Impersonation-specific loot
	m.LootMap["sa-impersonatable"] = &internal.LootFile{
		Name:     "sa-impersonatable",
		Contents: "# Service Accounts That Can Be Impersonated\n# Generated by CloudFox\n# These SAs have principals who can impersonate them\n\n",
	}
	m.LootMap["sa-token-creators"] = &internal.LootFile{
		Name:     "sa-token-creators",
		Contents: "# Principals Who Can Create Access Tokens (Impersonate)\n# Generated by CloudFox\n# Permission: iam.serviceAccounts.getAccessToken\n\n",
	}
	m.LootMap["sa-key-creators"] = &internal.LootFile{
		Name:     "sa-key-creators",
		Contents: "# Principals Who Can Create SA Keys (Persistent Access)\n# Generated by CloudFox\n# Permission: iam.serviceAccountKeys.create\n\n",
	}
	m.LootMap["sa-privesc-commands"] = &internal.LootFile{
		Name:     "sa-privesc-commands",
		Contents: "# Service Account Privilege Escalation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *ServiceAccountsModule) addServiceAccountToLoot(sa ServiceAccountAnalysis, projectID string) {
	// All service account emails
	m.LootMap["sa-all-emails"].Contents += sa.Email + "\n"

	// Impersonation commands
	m.LootMap["sa-impersonation-commands"].Contents += fmt.Sprintf(
		"# Service Account: %s\n"+
			"# Project: %s\n"+
			"gcloud auth print-access-token --impersonate-service-account=%s\n"+
			"gcloud auth print-identity-token --impersonate-service-account=%s\n\n",
		sa.Email,
		projectID,
		sa.Email,
		sa.Email,
	)

	// Key creation commands
	m.LootMap["sa-key-creation-commands"].Contents += fmt.Sprintf(
		"# Service Account: %s\n"+
			"gcloud iam service-accounts keys create %s-key.json --iam-account=%s --project=%s\n\n",
		sa.Email,
		strings.Split(sa.Email, "@")[0],
		sa.Email,
		projectID,
	)

	// High-risk service accounts
	if sa.RiskLevel == "HIGH" {
		m.LootMap["sa-high-risk"].Contents += fmt.Sprintf(
			"# Service Account: %s\n"+
				"# Project: %s\n"+
				"# Risk Level: %s\n"+
				"# Reasons:\n",
			sa.Email,
			projectID,
			sa.RiskLevel,
		)
		for _, reason := range sa.RiskReasons {
			m.LootMap["sa-high-risk"].Contents += fmt.Sprintf("  - %s\n", reason)
		}
		m.LootMap["sa-high-risk"].Contents += "\n"
	}

	// Old keys
	if sa.HasOldKeys {
		m.LootMap["sa-old-keys"].Contents += fmt.Sprintf(
			"# Service Account: %s\n"+
				"# Project: %s\n"+
				"# Oldest Key Age: %d days\n"+
				"# List keys:\n"+
				"gcloud iam service-accounts keys list --iam-account=%s --project=%s\n\n",
			sa.Email,
			projectID,
			sa.OldestKeyAge,
			sa.Email,
			projectID,
		)
	}

	// Default service accounts
	if sa.IsDefaultSA {
		keysInfo := "No user-managed keys"
		if sa.HasKeys {
			keysInfo = fmt.Sprintf("%d user-managed key(s)", sa.KeyCount)
		}
		m.LootMap["sa-default-accounts"].Contents += fmt.Sprintf(
			"# Service Account: %s\n"+
				"# Type: %s default\n"+
				"# Project: %s\n"+
				"# Keys: %s\n"+
				"# Get IAM policy:\n"+
				"gcloud iam service-accounts get-iam-policy %s --project=%s\n\n",
			sa.Email,
			sa.DefaultSAType,
			projectID,
			keysInfo,
			sa.Email,
			projectID,
		)
	}

	// Pentest: Impersonation loot
	if sa.ImpersonationInfo != nil {
		info := sa.ImpersonationInfo

		// SAs that can be impersonated
		if len(info.TokenCreators) > 0 || len(info.KeyCreators) > 0 || len(info.SAAdmins) > 0 {
			m.LootMap["sa-impersonatable"].Contents += fmt.Sprintf(
				"## Service Account: %s\n"+
					"## Project: %s\n"+
					"## Risk Level: %s\n",
				sa.Email,
				projectID,
				info.RiskLevel,
			)
			if len(info.TokenCreators) > 0 {
				m.LootMap["sa-impersonatable"].Contents += "# Token Creators (can impersonate):\n"
				for _, tc := range info.TokenCreators {
					m.LootMap["sa-impersonatable"].Contents += fmt.Sprintf("  - %s\n", tc)
				}
			}
			if len(info.KeyCreators) > 0 {
				m.LootMap["sa-impersonatable"].Contents += "# Key Creators (persistent access):\n"
				for _, kc := range info.KeyCreators {
					m.LootMap["sa-impersonatable"].Contents += fmt.Sprintf("  - %s\n", kc)
				}
			}
			m.LootMap["sa-impersonatable"].Contents += "\n"
		}

		// Token creators loot
		if len(info.TokenCreators) > 0 {
			for _, tc := range info.TokenCreators {
				m.LootMap["sa-token-creators"].Contents += fmt.Sprintf(
					"# %s can impersonate %s\n"+
						"# As %s, run:\n"+
						"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
					tc, sa.Email, tc, sa.Email,
				)
			}
		}

		// Key creators loot
		if len(info.KeyCreators) > 0 {
			for _, kc := range info.KeyCreators {
				m.LootMap["sa-key-creators"].Contents += fmt.Sprintf(
					"# %s can create keys for %s\n"+
						"# As %s, run:\n"+
						"gcloud iam service-accounts keys create key.json --iam-account=%s\n\n",
					kc, sa.Email, kc, sa.Email,
				)
			}
		}

		// Privesc commands
		if info.RiskLevel == "CRITICAL" || info.RiskLevel == "HIGH" {
			m.LootMap["sa-privesc-commands"].Contents += fmt.Sprintf(
				"## Target SA: %s (Risk: %s)\n"+
					"## Project: %s\n",
				sa.Email,
				info.RiskLevel,
				projectID,
			)
			for _, reason := range info.RiskReasons {
				m.LootMap["sa-privesc-commands"].Contents += fmt.Sprintf("# %s\n", reason)
			}
			m.LootMap["sa-privesc-commands"].Contents += fmt.Sprintf(
				"\n# Step 1: Impersonate the SA\n"+
					"gcloud auth print-access-token --impersonate-service-account=%s\n\n"+
					"# Step 2: Or create a persistent key\n"+
					"gcloud iam service-accounts keys create %s-key.json --iam-account=%s\n\n"+
					"# Step 3: Activate the key\n"+
					"gcloud auth activate-service-account --key-file=%s-key.json\n\n",
				sa.Email,
				strings.Split(sa.Email, "@")[0],
				sa.Email,
				strings.Split(sa.Email, "@")[0],
			)
		}
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ServiceAccountsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main service accounts table
	saHeader := []string{
		"Email",
		"Display Name",
		"Project",
		"Disabled",
		"Default SA",
		"Keys",
		"Key Age",
		"Risk",
	}

	var saBody [][]string
	for _, sa := range m.ServiceAccounts {
		disabled := ""
		if sa.Disabled {
			disabled = "YES"
		}

		defaultSA := ""
		if sa.IsDefaultSA {
			defaultSA = sa.DefaultSAType
		}

		keys := "-"
		if sa.HasKeys {
			keys = fmt.Sprintf("%d", sa.KeyCount)
		}

		keyAge := "-"
		if sa.OldestKeyAge > 0 {
			keyAge = fmt.Sprintf("%dd", sa.OldestKeyAge)
		}

		saBody = append(saBody, []string{
			sa.Email,
			sa.DisplayName,
			sa.ProjectID,
			disabled,
			defaultSA,
			keys,
			keyAge,
			sa.RiskLevel,
		})
	}

	// Service accounts with keys table
	keysHeader := []string{
		"Service Account",
		"Project",
		"Key Count",
		"Oldest Key Age",
		"Has Old Keys",
		"Has Expired",
		"Risk",
	}

	var keysBody [][]string
	for _, sa := range m.ServiceAccounts {
		if sa.HasKeys {
			hasOld := ""
			if sa.HasOldKeys {
				hasOld = "YES"
			}
			hasExpired := ""
			if sa.HasExpiredKeys {
				hasExpired = "YES"
			}

			keysBody = append(keysBody, []string{
				sa.Email,
				sa.ProjectID,
				fmt.Sprintf("%d", sa.KeyCount),
				fmt.Sprintf("%d days", sa.OldestKeyAge),
				hasOld,
				hasExpired,
				sa.RiskLevel,
			})
		}
	}

	// High-risk service accounts table
	highRiskHeader := []string{
		"Service Account",
		"Project",
		"Risk Level",
		"Risk Reasons",
	}

	var highRiskBody [][]string
	for _, sa := range m.ServiceAccounts {
		if sa.RiskLevel == "HIGH" || sa.RiskLevel == "MEDIUM" {
			highRiskBody = append(highRiskBody, []string{
				sa.Email,
				sa.ProjectID,
				sa.RiskLevel,
				strings.Join(sa.RiskReasons, "; "),
			})
		}
	}

	// Default service accounts table
	defaultHeader := []string{
		"Service Account",
		"Project",
		"Type",
		"Has Keys",
		"Disabled",
	}

	var defaultBody [][]string
	for _, sa := range m.ServiceAccounts {
		if sa.IsDefaultSA {
			hasKeys := "No"
			if sa.HasKeys {
				hasKeys = fmt.Sprintf("Yes (%d)", sa.KeyCount)
			}
			disabled := "No"
			if sa.Disabled {
				disabled = "Yes"
			}

			defaultBody = append(defaultBody, []string{
				sa.Email,
				sa.ProjectID,
				sa.DefaultSAType,
				hasKeys,
				disabled,
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
			Name:   "serviceaccounts",
			Header: saHeader,
			Body:   saBody,
		},
	}

	// Add keys table if there are any
	if len(keysBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "serviceaccounts-keys",
			Header: keysHeader,
			Body:   keysBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d service account(s) with user-managed keys", len(keysBody)), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}

	// Add high-risk table if there are any
	if len(highRiskBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "serviceaccounts-high-risk",
			Header: highRiskHeader,
			Body:   highRiskBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d high/medium risk service account(s)", len(highRiskBody)), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}

	// Add default service accounts table if there are any
	if len(defaultBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "serviceaccounts-default",
			Header: defaultHeader,
			Body:   defaultBody,
		})
	}

	// Pentest: Impersonation table
	impersonationHeader := []string{
		"Service Account",
		"Project",
		"Token Creators",
		"Key Creators",
		"ActAs Users",
		"Risk",
	}

	var impersonationBody [][]string
	impersonatableCount := 0
	for _, sa := range m.ServiceAccounts {
		if sa.ImpersonationInfo != nil {
			info := sa.ImpersonationInfo
			if len(info.TokenCreators) > 0 || len(info.KeyCreators) > 0 || len(info.ActAsUsers) > 0 {
				impersonatableCount++
				tokenCreators := "-"
				if len(info.TokenCreators) > 0 {
					tokenCreators = fmt.Sprintf("%d", len(info.TokenCreators))
				}
				keyCreators := "-"
				if len(info.KeyCreators) > 0 {
					keyCreators = fmt.Sprintf("%d", len(info.KeyCreators))
				}
				actAsUsers := "-"
				if len(info.ActAsUsers) > 0 {
					actAsUsers = fmt.Sprintf("%d", len(info.ActAsUsers))
				}

				impersonationBody = append(impersonationBody, []string{
					sa.Email,
					sa.ProjectID,
					tokenCreators,
					keyCreators,
					actAsUsers,
					info.RiskLevel,
				})
			}
		}
	}

	if len(impersonationBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "serviceaccounts-impersonation",
			Header: impersonationHeader,
			Body:   impersonationBody,
		})
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d service account(s) with impersonation risks", impersonatableCount), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
	}

	output := ServiceAccountsOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SERVICEACCOUNTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
