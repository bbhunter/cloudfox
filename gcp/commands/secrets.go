package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	SecretsService "github.com/BishopFox/cloudfox/gcp/services/secretsService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPSecretsCommand = &cobra.Command{
	Use:     globals.GCP_SECRETS_MODULE_NAME,
	Aliases: []string{"secretmanager", "sm"},
	Short:   "Enumerate GCP Secret Manager secrets with security configuration",
	Long: `Enumerate GCP Secret Manager secrets across projects with security-relevant details.

Features:
- Lists all secrets with metadata and security configuration
- Shows encryption type (Google-managed vs CMEK)
- Shows replication configuration (automatic vs user-managed)
- Shows expiration and rotation settings
- Enumerates IAM policies per secret
- Generates gcloud commands for secret access
- Generates exploitation commands for secret extraction

Security Columns:
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)
- Replication: "automatic" or "user-managed" with locations
- Rotation: Whether automatic rotation is enabled
- Expiration: Whether the secret has an expiration time/TTL
- VersionDestroyTTL: Delayed destruction period for old versions`,
	Run: runGCPSecretsCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type SecretsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Secrets []SecretsService.SecretInfo
	LootMap map[string]*internal.LootFile
	client  *secretmanager.Client
	mu      sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type SecretsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SecretsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SecretsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPSecretsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_SECRETS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create Secret Manager client
	client, err := secretmanager.NewClient(cmdCtx.Ctx)
	if err != nil {
		cmdCtx.Logger.ErrorM(fmt.Sprintf("Failed to create Secret Manager client: %v", err), globals.GCP_SECRETS_MODULE_NAME)
		return
	}
	defer client.Close()

	// Create module instance
	module := &SecretsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Secrets:       []SecretsService.SecretInfo{},
		LootMap:       make(map[string]*internal.LootFile),
		client:        client,
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *SecretsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_SECRETS_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Secrets) == 0 {
		logger.InfoM("No secrets found", globals.GCP_SECRETS_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d secret(s)", len(m.Secrets)), globals.GCP_SECRETS_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *SecretsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating secrets in project: %s", projectID), globals.GCP_SECRETS_MODULE_NAME)
	}

	// Create service and fetch secrets
	ss := SecretsService.New(m.client)
	secrets, err := ss.Secrets(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating secrets in project %s: %v", projectID, err), globals.GCP_SECRETS_MODULE_NAME)
		}
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Secrets = append(m.Secrets, secrets...)

	// Generate loot for each secret
	for _, secret := range secrets {
		m.addSecretToLoot(secret)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d secret(s) in project %s", len(secrets), projectID), globals.GCP_SECRETS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *SecretsModule) initializeLootFiles() {
	m.LootMap["secrets-gcloud-commands"] = &internal.LootFile{
		Name:     "secrets-gcloud-commands",
		Contents: "# GCP Secret Manager Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["secrets-access-commands"] = &internal.LootFile{
		Name:     "secrets-access-commands",
		Contents: "# GCP Secret Access Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["secrets-exploitation"] = &internal.LootFile{
		Name:     "secrets-exploitation",
		Contents: "# GCP Secret Extraction Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["secrets-iam-bindings"] = &internal.LootFile{
		Name:     "secrets-iam-bindings",
		Contents: "# GCP Secret IAM Bindings\n# Generated by CloudFox\n\n",
	}
	m.LootMap["secrets-no-rotation"] = &internal.LootFile{
		Name:     "secrets-no-rotation",
		Contents: "# Secrets WITHOUT Rotation\n# Generated by CloudFox\n# These secrets may contain stale credentials\n\n",
	}
	m.LootMap["secrets-with-rotation"] = &internal.LootFile{
		Name:     "secrets-with-rotation",
		Contents: "# Secrets WITH Rotation Configured\n# Generated by CloudFox\n\n",
	}
	m.LootMap["secrets-google-managed"] = &internal.LootFile{
		Name:     "secrets-google-managed",
		Contents: "# Secrets Using Google-Managed Encryption\n# Generated by CloudFox\n# Consider CMEK for compliance requirements\n\n",
	}
	m.LootMap["secrets-cmek"] = &internal.LootFile{
		Name:     "secrets-cmek",
		Contents: "# Secrets Using CMEK (Customer-Managed Encryption Keys)\n# Generated by CloudFox\n\n",
	}
	m.LootMap["secrets-security-recommendations"] = &internal.LootFile{
		Name:     "secrets-security-recommendations",
		Contents: "# Secret Manager Security Recommendations\n# Generated by CloudFox\n# Remediation commands for security issues\n\n",
	}
	m.LootMap["secrets-public-access"] = &internal.LootFile{
		Name:     "secrets-public-access",
		Contents: "# Secrets with PUBLIC Access\n# Generated by CloudFox\n# CRITICAL: These secrets are accessible by anyone!\n\n",
	}
}

func (m *SecretsModule) addSecretToLoot(secret SecretsService.SecretInfo) {
	// Extract secret name from full path
	secretName := getSecretShortName(secret.Name)

	// gcloud commands for enumeration
	m.LootMap["secrets-gcloud-commands"].Contents += fmt.Sprintf(
		"# Secret: %s (Project: %s)\n"+
			"# Encryption: %s, Replication: %s, Rotation: %s\n"+
			"gcloud secrets describe %s --project=%s\n"+
			"gcloud secrets versions list %s --project=%s\n"+
			"gcloud secrets get-iam-policy %s --project=%s\n\n",
		secretName, secret.ProjectID,
		secret.EncryptionType, secret.ReplicationType, secret.Rotation,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
	)

	// Secret access commands
	m.LootMap["secrets-access-commands"].Contents += fmt.Sprintf(
		"# Secret: %s\n"+
			"# Access latest version:\n"+
			"gcloud secrets versions access latest --secret=%s --project=%s\n"+
			"# Access specific version:\n"+
			"gcloud secrets versions access 1 --secret=%s --project=%s\n\n",
		secretName,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
	)

	// Exploitation commands
	m.LootMap["secrets-exploitation"].Contents += fmt.Sprintf(
		"# Secret: %s (Project: %s)\n"+
			"# Download all versions:\n"+
			"for v in $(gcloud secrets versions list %s --project=%s --format='value(name)'); do\n"+
			"  echo \"=== Version $v ===\"\n"+
			"  gcloud secrets versions access $v --secret=%s --project=%s\n"+
			"done\n\n"+
			"# Add a new version (requires write access):\n"+
			"echo -n 'new-secret-value' | gcloud secrets versions add %s --project=%s --data-file=-\n\n",
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
		secretName, secret.ProjectID,
	)

	// IAM bindings
	if len(secret.IAMBindings) > 0 {
		m.LootMap["secrets-iam-bindings"].Contents += fmt.Sprintf(
			"# Secret: %s (Project: %s)\n",
			secretName, secret.ProjectID,
		)
		for _, binding := range secret.IAMBindings {
			m.LootMap["secrets-iam-bindings"].Contents += fmt.Sprintf(
				"# Role: %s\n#   Members: %s\n",
				binding.Role,
				strings.Join(binding.Members, ", "),
			)
		}
		m.LootMap["secrets-iam-bindings"].Contents += "\n"
	}

	// Rotation status
	if secret.Rotation == "disabled" {
		m.LootMap["secrets-no-rotation"].Contents += fmt.Sprintf(
			"# SECRET: %s (Project: %s)\n"+
				"# Encryption: %s\n"+
				"# Created: %s\n"+
				"# Enable rotation:\n"+
				"gcloud secrets update %s \\\n"+
				"  --rotation-period=90d \\\n"+
				"  --next-rotation-time=$(date -u -d '+1 day' +%%Y-%%m-%%dT%%H:%%M:%%SZ) \\\n"+
				"  --project=%s\n\n",
			secretName, secret.ProjectID,
			secret.EncryptionType,
			secret.CreationTime,
			secretName, secret.ProjectID,
		)
	} else {
		nextRotation := secret.NextRotationTime
		if nextRotation == "" {
			nextRotation = "Not scheduled"
		}
		rotationPeriod := secret.RotationPeriod
		if rotationPeriod == "" {
			rotationPeriod = "Not set"
		}
		m.LootMap["secrets-with-rotation"].Contents += fmt.Sprintf(
			"# SECRET: %s (Project: %s)\n"+
				"# Rotation Period: %s\n"+
				"# Next Rotation: %s\n\n",
			secretName, secret.ProjectID,
			rotationPeriod,
			nextRotation,
		)
	}

	// Encryption type
	if secret.EncryptionType == "Google-managed" {
		m.LootMap["secrets-google-managed"].Contents += fmt.Sprintf(
			"# SECRET: %s (Project: %s)\n"+
				"# Encryption: Google-managed\n"+
				"# NOTE: CMEK must be set at secret creation time\n\n",
			secretName, secret.ProjectID,
		)
	} else if secret.EncryptionType == "CMEK" {
		kmsKey := secret.KMSKeyName
		if kmsKey == "" {
			kmsKey = "Unknown"
		}
		m.LootMap["secrets-cmek"].Contents += fmt.Sprintf(
			"# SECRET: %s (Project: %s)\n"+
				"# Encryption: CMEK\n"+
				"# KMS Key: %s\n\n",
			secretName, secret.ProjectID, kmsKey,
		)
	}

	// Check for public access
	for _, binding := range secret.IAMBindings {
		for _, member := range binding.Members {
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				m.LootMap["secrets-public-access"].Contents += fmt.Sprintf(
					"# CRITICAL: Secret with PUBLIC access!\n"+
						"# SECRET: %s (Project: %s)\n"+
						"# Role: %s, Member: %s\n"+
						"# Remove public access:\n"+
						"gcloud secrets remove-iam-policy-binding %s \\\n"+
						"  --member='%s' \\\n"+
						"  --role='%s' \\\n"+
						"  --project=%s\n\n",
					secretName, secret.ProjectID,
					binding.Role, member,
					secretName, member, binding.Role, secret.ProjectID,
				)
			}
		}
	}

	// Security recommendations
	m.addSecretSecurityRecommendations(secret, secretName)
}

// addSecretSecurityRecommendations adds remediation commands for secret security issues
func (m *SecretsModule) addSecretSecurityRecommendations(secret SecretsService.SecretInfo, secretName string) {
	hasRecommendations := false
	recommendations := fmt.Sprintf(
		"# SECRET: %s (Project: %s)\n",
		secretName, secret.ProjectID,
	)

	// No rotation
	if secret.Rotation == "disabled" {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Rotation not configured\n"+
				"gcloud secrets update %s \\\n"+
				"  --rotation-period=90d \\\n"+
				"  --next-rotation-time=$(date -u -d '+1 day' +%%Y-%%m-%%dT%%H:%%M:%%SZ) \\\n"+
				"  --project=%s\n\n",
			secretName, secret.ProjectID,
		)
	}

	// No version destroy TTL
	if secret.VersionDestroyTTL == "" {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: No version destroy TTL (old versions deleted immediately)\n"+
				"# Consider adding a delay for recovery:\n"+
				"gcloud secrets update %s \\\n"+
				"  --version-destroy-ttl=86400s \\\n"+
				"  --project=%s\n\n",
			secretName, secret.ProjectID,
		)
	}

	// Check for overly permissive IAM
	for _, binding := range secret.IAMBindings {
		for _, member := range binding.Members {
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				hasRecommendations = true
				recommendations += fmt.Sprintf(
					"# Issue: PUBLIC access (member: %s)\n"+
						"gcloud secrets remove-iam-policy-binding %s \\\n"+
						"  --member='%s' \\\n"+
						"  --role='%s' \\\n"+
						"  --project=%s\n\n",
					member, secretName, member, binding.Role, secret.ProjectID,
				)
			}
		}
	}

	if hasRecommendations {
		m.LootMap["secrets-security-recommendations"].Contents += recommendations + "\n"
	}
}

// ------------------------------
// Helper functions
// ------------------------------

// getSecretShortName extracts the short name from a full secret resource path
func getSecretShortName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// getSecretMemberType extracts the member type from a GCP IAM member string
func getSecretMemberType(member string) string {
	switch {
	case member == "allUsers":
		return "PUBLIC"
	case member == "allAuthenticatedUsers":
		return "ALL_AUTHENTICATED"
	case strings.HasPrefix(member, "user:"):
		return "User"
	case strings.HasPrefix(member, "serviceAccount:"):
		return "ServiceAccount"
	case strings.HasPrefix(member, "group:"):
		return "Group"
	case strings.HasPrefix(member, "domain:"):
		return "Domain"
	case strings.HasPrefix(member, "projectOwner:"):
		return "ProjectOwner"
	case strings.HasPrefix(member, "projectEditor:"):
		return "ProjectEditor"
	case strings.HasPrefix(member, "projectViewer:"):
		return "ProjectViewer"
	case strings.HasPrefix(member, "deleted:"):
		return "Deleted"
	default:
		return "Unknown"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *SecretsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main table with security-relevant columns
	header := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Encryption",
		"Replication",
		"Rotation",
		"Expiration",
		"VersionDestroyTTL",
		"Created",
	}

	var body [][]string
	for _, secret := range m.Secrets {
		secretName := getSecretShortName(secret.Name)

		// Format expiration
		expiration := "-"
		if secret.HasExpiration {
			if secret.ExpireTime != "" {
				expiration = secret.ExpireTime
			} else if secret.TTL != "" {
				expiration = "TTL: " + secret.TTL
			}
		}

		// Format version destroy TTL
		versionDestroyTTL := "-"
		if secret.VersionDestroyTTL != "" {
			versionDestroyTTL = secret.VersionDestroyTTL
		}

		body = append(body, []string{
			m.GetProjectName(secret.ProjectID),
			secret.ProjectID,
			secretName,
			secret.EncryptionType,
			secret.ReplicationType,
			secret.Rotation,
			expiration,
			versionDestroyTTL,
			secret.CreationTime,
		})
	}

	// Detailed IAM table - one row per member
	iamHeader := []string{
		"Secret",
		"Project Name",
		"Project ID",
		"Role",
		"Member Type",
		"Member",
	}

	var iamBody [][]string
	for _, secret := range m.Secrets {
		secretName := getSecretShortName(secret.Name)
		for _, binding := range secret.IAMBindings {
			for _, member := range binding.Members {
				memberType := getSecretMemberType(member)
				iamBody = append(iamBody, []string{
					secretName,
					m.GetProjectName(secret.ProjectID),
					secret.ProjectID,
					binding.Role,
					memberType,
					member,
				})
			}
		}
	}

	// Security configuration table
	securityHeader := []string{
		"Secret",
		"Project Name",
		"Project ID",
		"Rotation",
		"Next Rotation",
		"Rotation Period",
		"Encrypt",
		"KMS Key",
		"Destroy TTL",
	}

	var securityBody [][]string
	for _, secret := range m.Secrets {
		secretName := getSecretShortName(secret.Name)
		nextRotation := secret.NextRotationTime
		if nextRotation == "" {
			nextRotation = "-"
		}
		rotationPeriod := secret.RotationPeriod
		if rotationPeriod == "" {
			rotationPeriod = "-"
		}
		kmsKey := secret.KMSKeyName
		if kmsKey == "" {
			kmsKey = "-"
		} else {
			// Truncate long key names
			parts := strings.Split(kmsKey, "/")
			if len(parts) > 0 {
				kmsKey = parts[len(parts)-1]
			}
		}
		destroyTTL := secret.VersionDestroyTTL
		if destroyTTL == "" {
			destroyTTL = "-"
		}
		securityBody = append(securityBody, []string{
			secretName,
			m.GetProjectName(secret.ProjectID),
			secret.ProjectID,
			secret.Rotation,
			nextRotation,
			rotationPeriod,
			secret.EncryptionType,
			kmsKey,
			destroyTTL,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{
		{
			Name:   globals.GCP_SECRETS_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	// Add IAM table if there are bindings
	if len(iamBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "secrets-iam",
			Header: iamHeader,
			Body:   iamBody,
		})
	}

	// Always add security config table
	tableFiles = append(tableFiles, internal.TableFile{
		Name:   "secrets-security-config",
		Header: securityHeader,
		Body:   securityBody,
	})

	output := SecretsOutput{
		Table: tableFiles,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SECRETS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
