package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	KMSService "github.com/BishopFox/cloudfox/gcp/services/kmsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPKMSCommand = &cobra.Command{
	Use:     globals.GCP_KMS_MODULE_NAME,
	Aliases: []string{"keys", "crypto"},
	Short:   "Enumerate Cloud KMS key rings and crypto keys with security analysis",
	Long: `Enumerate Cloud KMS key rings and crypto keys across projects with security-relevant details.

Features:
- Lists all KMS key rings and crypto keys
- Shows key purpose (encryption, signing, MAC)
- Identifies protection level (software, HSM, external)
- Shows rotation configuration and status
- Detects public key access via IAM
- Generates gcloud commands for key operations

Security Columns:
- Purpose: ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC
- Protection: SOFTWARE, HSM, EXTERNAL, EXTERNAL_VPC
- Rotation: Key rotation period and next rotation time
- PublicDecrypt: Whether allUsers/allAuthenticatedUsers can decrypt

Attack Surface:
- Public decrypt access allows unauthorized data access
- Keys without rotation may be compromised long-term
- HSM vs software protection affects key extraction risk
- External keys indicate third-party key management`,
	Run: runGCPKMSCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type KMSModule struct {
	gcpinternal.BaseGCPModule

	KeyRings   []KMSService.KeyRingInfo
	CryptoKeys []KMSService.CryptoKeyInfo
	LootMap    map[string]*internal.LootFile
	mu         sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type KMSOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o KMSOutput) TableFiles() []internal.TableFile { return o.Table }
func (o KMSOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPKMSCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_KMS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &KMSModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		KeyRings:      []KMSService.KeyRingInfo{},
		CryptoKeys:    []KMSService.CryptoKeyInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *KMSModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_KMS_MODULE_NAME, m.processProject)

	if len(m.CryptoKeys) == 0 {
		logger.InfoM("No KMS keys found", globals.GCP_KMS_MODULE_NAME)
		return
	}

	// Count security-relevant metrics
	hsmCount := 0
	publicDecryptCount := 0
	noRotationCount := 0
	for _, key := range m.CryptoKeys {
		if key.ProtectionLevel == "HSM" {
			hsmCount++
		}
		if key.IsPublicDecrypt {
			publicDecryptCount++
		}
		if key.RotationPeriod == "" && key.Purpose == "ENCRYPT_DECRYPT" {
			noRotationCount++
		}
	}

	msg := fmt.Sprintf("Found %d key ring(s), %d key(s)", len(m.KeyRings), len(m.CryptoKeys))
	if hsmCount > 0 {
		msg += fmt.Sprintf(" [%d HSM]", hsmCount)
	}
	if publicDecryptCount > 0 {
		msg += fmt.Sprintf(" [%d PUBLIC DECRYPT!]", publicDecryptCount)
	}
	logger.SuccessM(msg, globals.GCP_KMS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *KMSModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating KMS in project: %s", projectID), globals.GCP_KMS_MODULE_NAME)
	}

	ks := KMSService.New()

	// Get key rings
	keyRings, err := ks.KeyRings(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating KMS key rings in project %s: %v", projectID, err), globals.GCP_KMS_MODULE_NAME)
		}
		return
	}

	m.mu.Lock()
	m.KeyRings = append(m.KeyRings, keyRings...)
	m.mu.Unlock()

	// Get crypto keys
	keys, err := ks.CryptoKeys(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating KMS keys in project %s: %v", projectID, err), globals.GCP_KMS_MODULE_NAME)
		}
	} else {
		m.mu.Lock()
		m.CryptoKeys = append(m.CryptoKeys, keys...)
		for _, key := range keys {
			m.addKeyToLoot(key)
		}
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d key ring(s), %d key(s) in project %s", len(keyRings), len(keys), projectID), globals.GCP_KMS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *KMSModule) initializeLootFiles() {
	m.LootMap["kms-gcloud-commands"] = &internal.LootFile{
		Name:     "kms-gcloud-commands",
		Contents: "# KMS gcloud Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["kms-public-access"] = &internal.LootFile{
		Name:     "kms-public-access",
		Contents: "# PUBLIC KMS Key Access\n# Generated by CloudFox\n# These keys have public encrypt/decrypt access!\n\n",
	}
	m.LootMap["kms-exploitation"] = &internal.LootFile{
		Name:     "kms-exploitation",
		Contents: "# KMS Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["kms-no-rotation"] = &internal.LootFile{
		Name:     "kms-no-rotation",
		Contents: "# KMS Keys Without Rotation\n# Generated by CloudFox\n# These encryption keys have no rotation configured\n\n",
	}
}

func (m *KMSModule) addKeyToLoot(key KMSService.CryptoKeyInfo) {
	keyPath := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		key.ProjectID, key.Location, key.KeyRing, key.Name)

	// gcloud commands
	m.LootMap["kms-gcloud-commands"].Contents += fmt.Sprintf(
		"# Key: %s (Project: %s, KeyRing: %s)\n"+
			"gcloud kms keys describe %s --keyring=%s --location=%s --project=%s\n"+
			"gcloud kms keys get-iam-policy %s --keyring=%s --location=%s --project=%s\n"+
			"gcloud kms keys versions list --key=%s --keyring=%s --location=%s --project=%s\n\n",
		key.Name, key.ProjectID, key.KeyRing,
		key.Name, key.KeyRing, key.Location, key.ProjectID,
		key.Name, key.KeyRing, key.Location, key.ProjectID,
		key.Name, key.KeyRing, key.Location, key.ProjectID,
	)

	// Public access
	if key.IsPublicEncrypt || key.IsPublicDecrypt {
		m.LootMap["kms-public-access"].Contents += fmt.Sprintf(
			"# KEY: %s\n"+
				"# Project: %s, Location: %s, KeyRing: %s\n"+
				"# Purpose: %s, Protection: %s\n"+
				"# Public Encrypt: %v\n"+
				"# Public Decrypt: %v\n\n",
			key.Name,
			key.ProjectID, key.Location, key.KeyRing,
			key.Purpose, key.ProtectionLevel,
			key.IsPublicEncrypt,
			key.IsPublicDecrypt,
		)
	}

	// Keys without rotation (only for symmetric encryption keys)
	if key.RotationPeriod == "" && key.Purpose == "ENCRYPT_DECRYPT" {
		m.LootMap["kms-no-rotation"].Contents += fmt.Sprintf(
			"# KEY: %s\n"+
				"# Project: %s, Location: %s, KeyRing: %s\n"+
				"# Purpose: %s, Protection: %s\n"+
				"# Created: %s\n\n",
			key.Name,
			key.ProjectID, key.Location, key.KeyRing,
			key.Purpose, key.ProtectionLevel,
			key.CreateTime,
		)
	}

	// Exploitation commands
	m.LootMap["kms-exploitation"].Contents += fmt.Sprintf(
		"# Key: %s (Project: %s)\n"+
			"# Purpose: %s, Protection: %s\n"+
			"# Path: %s\n\n",
		key.Name, key.ProjectID,
		key.Purpose, key.ProtectionLevel,
		keyPath,
	)

	switch key.Purpose {
	case "ENCRYPT_DECRYPT":
		m.LootMap["kms-exploitation"].Contents += fmt.Sprintf(
			"# Encrypt data (if you have cloudkms.cryptoKeyVersions.useToEncrypt):\n"+
				"echo -n 'secret data' | gcloud kms encrypt --key=%s --keyring=%s --location=%s --project=%s --plaintext-file=- --ciphertext-file=encrypted.bin\n\n"+
				"# Decrypt data (if you have cloudkms.cryptoKeyVersions.useToDecrypt):\n"+
				"gcloud kms decrypt --key=%s --keyring=%s --location=%s --project=%s --ciphertext-file=encrypted.bin --plaintext-file=-\n\n",
			key.Name, key.KeyRing, key.Location, key.ProjectID,
			key.Name, key.KeyRing, key.Location, key.ProjectID,
		)
	case "ASYMMETRIC_SIGN":
		m.LootMap["kms-exploitation"].Contents += fmt.Sprintf(
			"# Sign data (if you have cloudkms.cryptoKeyVersions.useToSign):\n"+
				"gcloud kms asymmetric-sign --key=%s --keyring=%s --location=%s --project=%s --version=1 --digest-algorithm=sha256 --input-file=data.txt --signature-file=signature.bin\n\n"+
				"# Get public key:\n"+
				"gcloud kms keys versions get-public-key 1 --key=%s --keyring=%s --location=%s --project=%s\n\n",
			key.Name, key.KeyRing, key.Location, key.ProjectID,
			key.Name, key.KeyRing, key.Location, key.ProjectID,
		)
	case "ASYMMETRIC_DECRYPT":
		m.LootMap["kms-exploitation"].Contents += fmt.Sprintf(
			"# Decrypt data (if you have cloudkms.cryptoKeyVersions.useToDecrypt):\n"+
				"gcloud kms asymmetric-decrypt --key=%s --keyring=%s --location=%s --project=%s --version=1 --ciphertext-file=encrypted.bin --plaintext-file=-\n\n"+
				"# Get public key:\n"+
				"gcloud kms keys versions get-public-key 1 --key=%s --keyring=%s --location=%s --project=%s\n\n",
			key.Name, key.KeyRing, key.Location, key.ProjectID,
			key.Name, key.KeyRing, key.Location, key.ProjectID,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *KMSModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Crypto keys table
	keysHeader := []string{
		"Project ID",
		"Key Name",
		"Key Ring",
		"Location",
		"Purpose",
		"Protection",
		"Version",
		"State",
		"Rotation",
		"Public Decrypt",
	}

	var keysBody [][]string
	for _, key := range m.CryptoKeys {
		// Format rotation
		rotation := "-"
		if key.RotationPeriod != "" {
			rotation = formatDuration(key.RotationPeriod)
		}

		// Format public decrypt
		publicDecrypt := "No"
		if key.IsPublicDecrypt {
			publicDecrypt = "YES!"
		}

		// Format protection level
		protection := key.ProtectionLevel
		if protection == "" {
			protection = "SOFTWARE"
		}

		keysBody = append(keysBody, []string{
			key.ProjectID,
			key.Name,
			key.KeyRing,
			key.Location,
			formatPurpose(key.Purpose),
			protection,
			key.PrimaryVersion,
			key.PrimaryState,
			rotation,
			publicDecrypt,
		})
	}

	// Key rings table (summary)
	keyRingsHeader := []string{
		"Project ID",
		"Key Ring",
		"Location",
		"Key Count",
	}

	var keyRingsBody [][]string
	for _, kr := range m.KeyRings {
		keyRingsBody = append(keyRingsBody, []string{
			kr.ProjectID,
			kr.Name,
			kr.Location,
			fmt.Sprintf("%d", kr.KeyCount),
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
	tableFiles := []internal.TableFile{}

	if len(keysBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_KMS_MODULE_NAME + "-keys",
			Header: keysHeader,
			Body:   keysBody,
		})
	}

	if len(keyRingsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_KMS_MODULE_NAME + "-keyrings",
			Header: keyRingsHeader,
			Body:   keyRingsBody,
		})
	}

	output := KMSOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_KMS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// formatPurpose formats key purpose for display
func formatPurpose(purpose string) string {
	switch purpose {
	case "ENCRYPT_DECRYPT":
		return "Symmetric"
	case "ASYMMETRIC_SIGN":
		return "Sign"
	case "ASYMMETRIC_DECRYPT":
		return "Asymm Decrypt"
	case "MAC":
		return "MAC"
	default:
		return purpose
	}
}

// formatDuration formats a duration string for display
func formatDuration(duration string) string {
	// Duration is in format like "7776000s" (90 days)
	duration = strings.TrimSuffix(duration, "s")
	if duration == "" {
		return "-"
	}

	// Parse seconds
	var seconds int64
	fmt.Sscanf(duration, "%d", &seconds)

	if seconds == 0 {
		return "-"
	}

	days := seconds / 86400
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}

	hours := seconds / 3600
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}

	return fmt.Sprintf("%ds", seconds)
}
