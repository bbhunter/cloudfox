package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	apikeysservice "github.com/BishopFox/cloudfox/gcp/services/apikeysService"
	hmacservice "github.com/BishopFox/cloudfox/gcp/services/hmacService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPKeysCommand = &cobra.Command{
	Use:     globals.GCP_KEYS_MODULE_NAME,
	Aliases: []string{"credentials", "creds", "access-keys"},
	Short:   "Enumerate all GCP keys (SA keys, HMAC keys, API keys)",
	Long: `Enumerate all types of GCP keys and credentials.

Key Types:
- SA Keys: Service account RSA keys for OAuth 2.0 authentication
- HMAC Keys: S3-compatible access keys for Cloud Storage
- API Keys: Project-level keys for API access (Maps, Translation, etc.)

Features:
- Unified view of all credential types
- Shows key age and expiration status
- Identifies Google-managed vs user-managed keys
- Generates exploitation commands for penetration testing`,
	Run: runGCPKeysCommand,
}

// UnifiedKeyInfo represents a key from any source
type UnifiedKeyInfo struct {
	ProjectID    string
	KeyType      string // "SA Key", "HMAC", "API Key"
	KeyID        string
	Owner        string // Email for SA/HMAC, "Project-level" for API keys
	DisplayName  string
	Origin       string // "Google Managed", "User Managed", "Service Account", "User", "-"
	Algorithm    string // Key algorithm (e.g., "KEY_ALG_RSA_2048")
	State        string // "ACTIVE", "INACTIVE", "DELETED", "DISABLED"
	CreateTime   time.Time
	ExpireTime   time.Time
	Expired      bool
	DWDEnabled   bool   // For SA keys - whether the SA has Domain-Wide Delegation enabled
	Restrictions string // For API keys only
	KeyString    string // For API keys only (if accessible)
}

type KeysModule struct {
	gcpinternal.BaseGCPModule
	Keys    []UnifiedKeyInfo
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

type KeysOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o KeysOutput) TableFiles() []internal.TableFile { return o.Table }
func (o KeysOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPKeysCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_KEYS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &KeysModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Keys:          []UnifiedKeyInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *KeysModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_KEYS_MODULE_NAME, m.processProject)

	if len(m.Keys) == 0 {
		logger.InfoM("No keys found", globals.GCP_KEYS_MODULE_NAME)
		return
	}

	// Count by type
	saKeyCount := 0
	hmacKeyCount := 0
	apiKeyCount := 0
	userManagedCount := 0

	for _, key := range m.Keys {
		switch key.KeyType {
		case "SA Key":
			saKeyCount++
			if key.Origin == "User Managed" {
				userManagedCount++
			}
		case "HMAC":
			hmacKeyCount++
		case "API Key":
			apiKeyCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d key(s) (%d SA keys [%d user-managed], %d HMAC keys, %d API keys)",
		len(m.Keys), saKeyCount, userManagedCount, hmacKeyCount, apiKeyCount), globals.GCP_KEYS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *KeysModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating keys in project: %s", projectID), globals.GCP_KEYS_MODULE_NAME)
	}

	var projectKeys []UnifiedKeyInfo

	// 1. Enumerate Service Account Keys
	iamService := IAMService.New()
	serviceAccounts, err := iamService.ServiceAccounts(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KEYS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate service accounts in project %s", projectID))
	} else {
		for _, sa := range serviceAccounts {
			// Check if DWD is enabled (OAuth2ClientID is set)
			dwdEnabled := sa.OAuth2ClientID != ""

			for _, key := range sa.Keys {
				// Extract key ID from full name
				keyID := key.Name
				if parts := strings.Split(key.Name, "/"); len(parts) > 0 {
					keyID = parts[len(parts)-1]
				}

				origin := "Google Managed"
				if key.KeyType == "USER_MANAGED" {
					origin = "User Managed"
				}

				state := "ACTIVE"
				if key.Disabled {
					state = "DISABLED"
				}

				expired := false
				if !key.ValidBefore.IsZero() && time.Now().After(key.ValidBefore) {
					expired = true
				}

				projectKeys = append(projectKeys, UnifiedKeyInfo{
					ProjectID:   projectID,
					KeyType:     "SA Key",
					KeyID:       keyID,
					Owner:       sa.Email,
					DisplayName: sa.DisplayName,
					Origin:      origin,
					Algorithm:   key.KeyAlgorithm,
					State:       state,
					CreateTime:  key.ValidAfter,
					ExpireTime:  key.ValidBefore,
					Expired:     expired,
					DWDEnabled:  dwdEnabled,
				})
			}
		}
	}

	// 2. Enumerate HMAC Keys
	hmacService := hmacservice.New()
	hmacKeys, err := hmacService.ListHMACKeys(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KEYS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate HMAC keys in project %s", projectID))
	} else {
		for _, key := range hmacKeys {
			origin := "Service Account"
			// Note: User HMAC keys are not enumerable via API, so all we see are SA keys

			projectKeys = append(projectKeys, UnifiedKeyInfo{
				ProjectID:   projectID,
				KeyType:     "HMAC",
				KeyID:       key.AccessID,
				Owner:       key.ServiceAccountEmail,
				DisplayName: "",
				Origin:      origin,
				State:       key.State,
				CreateTime:  key.TimeCreated,
				Expired:     false, // HMAC keys don't expire
			})
		}
	}

	// 3. Enumerate API Keys
	apiKeysService := apikeysservice.New()
	apiKeys, err := apiKeysService.ListAPIKeysWithKeyStrings(projectID)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_KEYS_MODULE_NAME,
			fmt.Sprintf("Could not enumerate API keys in project %s", projectID))
	} else {
		for _, key := range apiKeys {
			// Extract key ID from full name
			keyID := key.UID
			if keyID == "" {
				if parts := strings.Split(key.Name, "/"); len(parts) > 0 {
					keyID = parts[len(parts)-1]
				}
			}

			state := "ACTIVE"
			if !key.DeleteTime.IsZero() {
				state = "DELETED"
			}

			restrictions := "None"
			if key.HasRestrictions {
				restrictions = key.RestrictionType
				if len(key.AllowedAPIs) > 0 {
					restrictions = fmt.Sprintf("%s (APIs: %d)", key.RestrictionType, len(key.AllowedAPIs))
				}
			}

			projectKeys = append(projectKeys, UnifiedKeyInfo{
				ProjectID:    projectID,
				KeyType:      "API Key",
				KeyID:        keyID,
				Owner:        "Project-level",
				DisplayName:  key.DisplayName,
				Origin:       "-",
				State:        state,
				CreateTime:   key.CreateTime,
				Expired:      false, // API keys don't expire
				Restrictions: restrictions,
				KeyString:    key.KeyString,
			})
		}
	}

	// Thread-safe append
	m.mu.Lock()
	m.Keys = append(m.Keys, projectKeys...)
	for _, key := range projectKeys {
		m.addKeyToLoot(key)
	}
	m.mu.Unlock()
}

func (m *KeysModule) initializeLootFiles() {
	m.LootMap["keys-hmac-s3-commands"] = &internal.LootFile{
		Name:     "keys-hmac-s3-commands",
		Contents: "# HMAC S3-Compatible Access Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["keys-apikey-test-commands"] = &internal.LootFile{
		Name:     "keys-apikey-test-commands",
		Contents: "# API Key Test Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *KeysModule) addKeyToLoot(key UnifiedKeyInfo) {
	switch key.KeyType {
	case "HMAC":
		if key.State == "ACTIVE" {
			m.LootMap["keys-hmac-s3-commands"].Contents += fmt.Sprintf(
				"# HMAC Key: %s\n"+
					"# Service Account: %s\n"+
					"# Project: %s\n\n"+
					"# Configure AWS CLI with HMAC credentials:\n"+
					"aws configure set aws_access_key_id %s\n"+
					"aws configure set aws_secret_access_key <SECRET_KEY_HERE>\n\n"+
					"# List buckets via S3-compatible endpoint:\n"+
					"aws --endpoint-url https://storage.googleapis.com s3 ls\n\n",
				key.KeyID,
				key.Owner,
				key.ProjectID,
				key.KeyID,
			)
		}

	case "API Key":
		if key.KeyString != "" {
			m.LootMap["keys-apikey-test-commands"].Contents += fmt.Sprintf(
				"# API Key: %s (%s)\n"+
					"# Project: %s\n"+
					"# Restrictions: %s\n\n"+
					"# Test API access:\n"+
					"curl -H 'X-Goog-Api-Key: %s' 'https://maps.googleapis.com/maps/api/geocode/json?address=test'\n"+
					"curl -H 'X-Goog-Api-Key: %s' 'https://translation.googleapis.com/language/translate/v2?q=Hello&target=es'\n\n",
				key.KeyID,
				key.DisplayName,
				key.ProjectID,
				key.Restrictions,
				key.KeyString,
				key.KeyString,
			)
		}
	}
}

func (m *KeysModule) writeOutput(ctx context.Context, logger internal.Logger) {
	header := []string{
		"Project ID",
		"Project Name",
		"Key Type",
		"Key ID",
		"Owner",
		"Origin",
		"Algorithm",
		"State",
		"Created",
		"Expires",
		"DWD",
		"Restrictions",
	}

	var body [][]string
	for _, key := range m.Keys {
		created := "-"
		if !key.CreateTime.IsZero() {
			created = key.CreateTime.Format("2006-01-02")
		}

		expires := "-"
		if !key.ExpireTime.IsZero() {
			// Check for "never expires" (year 9999)
			if key.ExpireTime.Year() >= 9999 {
				expires = "Never"
			} else {
				expires = key.ExpireTime.Format("2006-01-02")
			}
		}

		dwd := "-"
		if key.KeyType == "SA Key" {
			if key.DWDEnabled {
				dwd = "Yes"
			} else {
				dwd = "No"
			}
		}

		restrictions := "-"
		if key.KeyType == "API Key" {
			restrictions = key.Restrictions
		}

		algorithm := key.Algorithm
		if algorithm == "" {
			algorithm = "-"
		}

		body = append(body, []string{
			key.ProjectID,
			m.GetProjectName(key.ProjectID),
			key.KeyType,
			key.KeyID,
			key.Owner,
			key.Origin,
			algorithm,
			key.State,
			created,
			expires,
			dwd,
			restrictions,
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
			Name:   "keys",
			Header: header,
			Body:   body,
		},
	}

	output := KeysOutput{Table: tables, Loot: lootFiles}

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
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_KEYS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
