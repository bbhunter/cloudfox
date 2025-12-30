package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	domainwidedelegationservice "github.com/BishopFox/cloudfox/gcp/services/domainWideDelegationService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPDomainWideDelegationCommand = &cobra.Command{
	Use:     globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME,
	Aliases: []string{"dwd", "delegation", "workspace-delegation"},
	Short:   "Find service accounts with Domain-Wide Delegation to Google Workspace",
	Long: `Find service accounts configured for Domain-Wide Delegation (DWD).

Domain-Wide Delegation allows a service account to impersonate any user in a
Google Workspace domain. This is EXTREMELY powerful and a high-value target.

With DWD + a service account key, an attacker can:
- Read any user's Gmail
- Access any user's Google Drive
- View any user's Calendar
- Enumerate all users and groups via Admin Directory API
- Send emails as any user
- And much more depending on authorized scopes

Detection Method:
- Service accounts with OAuth2 Client ID set have DWD enabled
- The actual authorized scopes are configured in Google Admin Console
- We check for naming patterns that suggest DWD purpose

To Exploit:
1. Obtain a key for the DWD service account
2. Identify a target user email in the Workspace domain
3. Generate tokens with the target user as 'subject'
4. Access Workspace APIs as that user

Note: Scopes must be authorized in Admin Console > Security > API Controls`,
	Run: runGCPDomainWideDelegationCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type DomainWideDelegationModule struct {
	gcpinternal.BaseGCPModule

	DWDAccounts []domainwidedelegationservice.DWDServiceAccount
	LootMap     map[string]*internal.LootFile
	mu          sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type DomainWideDelegationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DomainWideDelegationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DomainWideDelegationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDomainWideDelegationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DomainWideDelegationModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		DWDAccounts:   []domainwidedelegationservice.DWDServiceAccount{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DomainWideDelegationModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME, m.processProject)

	if len(m.DWDAccounts) == 0 {
		logger.InfoM("No Domain-Wide Delegation service accounts found", globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
		return
	}

	// Count confirmed DWD accounts
	confirmedDWD := 0
	criticalCount := 0
	for _, account := range m.DWDAccounts {
		if account.DWDEnabled {
			confirmedDWD++
		}
		if account.RiskLevel == "CRITICAL" {
			criticalCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d potential DWD service account(s) (%d confirmed)", len(m.DWDAccounts), confirmedDWD), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)

	if criticalCount > 0 {
		logger.InfoM(fmt.Sprintf("[CRITICAL] %d DWD accounts with keys - can impersonate Workspace users!", criticalCount), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DomainWideDelegationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking DWD service accounts in project: %s", projectID), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}

	svc := domainwidedelegationservice.New()
	accounts, err := svc.GetDWDServiceAccounts(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error checking project %s: %v", projectID, err), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
		}
		return
	}

	m.mu.Lock()
	m.DWDAccounts = append(m.DWDAccounts, accounts...)

	for _, account := range accounts {
		m.addAccountToLoot(account)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS && len(accounts) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d DWD account(s) in project %s", len(accounts), projectID), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DomainWideDelegationModule) initializeLootFiles() {
	m.LootMap["dwd-accounts"] = &internal.LootFile{
		Name:     "dwd-accounts",
		Contents: "# Domain-Wide Delegation Service Accounts\n# Generated by CloudFox\n\n",
	}
	m.LootMap["dwd-critical"] = &internal.LootFile{
		Name:     "dwd-critical",
		Contents: "# CRITICAL: DWD Accounts with Keys\n# Generated by CloudFox\n# These can impersonate any Google Workspace user!\n\n",
	}
	m.LootMap["dwd-exploit-commands"] = &internal.LootFile{
		Name:     "dwd-exploit-commands",
		Contents: "# DWD Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *DomainWideDelegationModule) addAccountToLoot(account domainwidedelegationservice.DWDServiceAccount) {
	// All DWD accounts
	m.LootMap["dwd-accounts"].Contents += fmt.Sprintf(
		"## [%s] %s\n"+
			"## Project: %s\n"+
			"## DWD Enabled: %v\n"+
			"## OAuth2 Client ID: %s\n"+
			"## Has Keys: %v (Count: %d)\n",
		account.RiskLevel, account.Email,
		account.ProjectID,
		account.DWDEnabled,
		account.OAuth2ClientID,
		account.HasKeys, account.KeyCount,
	)
	for _, reason := range account.RiskReasons {
		m.LootMap["dwd-accounts"].Contents += fmt.Sprintf("##   - %s\n", reason)
	}
	m.LootMap["dwd-accounts"].Contents += "\n"

	// Critical accounts
	if account.RiskLevel == "CRITICAL" {
		m.LootMap["dwd-critical"].Contents += fmt.Sprintf(
			"## [CRITICAL] %s\n"+
				"## Project: %s\n"+
				"## OAuth2 Client ID: %s\n"+
				"## Keys: %d user-managed key(s)\n"+
				"##\n"+
				"## This service account can impersonate ANY user in the Workspace domain!\n"+
				"## To exploit:\n"+
				"## 1. Create/download a key for this SA\n"+
				"## 2. Use the key with a target user email as 'subject'\n"+
				"## 3. Access Gmail, Drive, Calendar, etc. as that user\n\n",
			account.Email,
			account.ProjectID,
			account.OAuth2ClientID,
			account.KeyCount,
		)
	}

	// Exploit commands
	if len(account.ExploitCommands) > 0 {
		m.LootMap["dwd-exploit-commands"].Contents += fmt.Sprintf(
			"## [%s] %s\n",
			account.RiskLevel, account.Email,
		)
		for _, cmd := range account.ExploitCommands {
			m.LootMap["dwd-exploit-commands"].Contents += cmd + "\n"
		}
		m.LootMap["dwd-exploit-commands"].Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *DomainWideDelegationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main table
	header := []string{
		"Risk",
		"Email",
		"DWD Enabled",
		"OAuth2 Client ID",
		"Keys",
		"Project Name",
		"Project",
	}

	var body [][]string
	for _, account := range m.DWDAccounts {
		dwdStatus := "No"
		if account.DWDEnabled {
			dwdStatus = "YES"
		}

		clientID := account.OAuth2ClientID
		if clientID == "" {
			clientID = "-"
		} else if len(clientID) > 20 {
			clientID = clientID[:20] + "..."
		}

		keysDisplay := "-"
		if account.HasKeys {
			keysDisplay = fmt.Sprintf("%d key(s)", account.KeyCount)
		}

		// Shorten email for display
		email := account.Email
		if len(email) > 40 {
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				email = parts[0][:15] + "...@" + parts[1]
			}
		}

		body = append(body, []string{
			account.RiskLevel,
			email,
			dwdStatus,
			clientID,
			keysDisplay,
			m.GetProjectName(account.ProjectID),
			account.ProjectID,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	tables := []internal.TableFile{
		{
			Name:   "domain-wide-delegation",
			Header: header,
			Body:   body,
		},
	}

	output := DomainWideDelegationOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_DOMAINWIDEDELEGATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
