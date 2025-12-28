package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPInstancesCommand = &cobra.Command{
	Use:     globals.GCP_INSTANCES_MODULE_NAME,
	Aliases: []string{"vms", "compute"},
	Short:   "Enumerate GCP Compute Engine instances with security configuration",
	Long: `Enumerate GCP Compute Engine instances across projects with security-relevant details.

Features:
- Lists all instances with network and security configuration
- Shows attached service accounts and their scopes
- Identifies instances with default service accounts or broad scopes
- Shows Shielded VM, Secure Boot, and Confidential VM status
- Shows OS Login and serial port configuration
- Shows disk encryption type (Google-managed vs CMEK/CSEK)
- Generates gcloud commands for instance access
- Generates exploitation commands (SSH, serial console, metadata)

Security Columns:
- ExternalIP: Instances with external IPs are internet-accessible
- DefaultSA: Uses default compute service account (security risk)
- BroadScopes: Has cloud-platform or other broad OAuth scopes
- CanIPForward: Can forward packets (potential for lateral movement)
- OSLogin: OS Login enabled (recommended for access control)
- SerialPort: Serial port access enabled (security risk if exposed)
- ShieldedVM: Shielded VM features enabled
- SecureBoot: Secure Boot enabled (prevents rootkits)
- Encryption: Boot disk encryption type`,
	Run: runGCPInstancesCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type InstancesModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Instances       []ComputeEngineService.ComputeEngineInfo
	ProjectMetadata map[string]*ComputeEngineService.ProjectMetadataInfo // projectID -> metadata
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type InstancesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o InstancesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o InstancesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPInstancesCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_INSTANCES_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &InstancesModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		Instances:       []ComputeEngineService.ComputeEngineInfo{},
		ProjectMetadata: make(map[string]*ComputeEngineService.ProjectMetadataInfo),
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
func (m *InstancesModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_INSTANCES_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Instances) == 0 {
		logger.InfoM("No instances found", globals.GCP_INSTANCES_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d instance(s)", len(m.Instances)), globals.GCP_INSTANCES_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *InstancesModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating instances in project: %s", projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}

	// Create service and fetch instances with project metadata
	ces := ComputeEngineService.New()
	instances, projectMeta, err := ces.InstancesWithMetadata(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating instances in project %s: %v", projectID, err), globals.GCP_INSTANCES_MODULE_NAME)
		}
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Instances = append(m.Instances, instances...)
	m.ProjectMetadata[projectID] = projectMeta

	// Generate loot for each instance
	for _, instance := range instances {
		m.addInstanceToLoot(instance)
	}

	// Add project metadata to loot
	m.addProjectMetadataToLoot(projectMeta)
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d instance(s) in project %s", len(instances), projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *InstancesModule) initializeLootFiles() {
	m.LootMap["instances-gcloud-commands"] = &internal.LootFile{
		Name:     "instances-gcloud-commands",
		Contents: "# GCP Compute Engine Instance Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["instances-ssh-commands"] = &internal.LootFile{
		Name:     "instances-ssh-commands",
		Contents: "# GCP Instance SSH Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["instances-exploitation"] = &internal.LootFile{
		Name:     "instances-exploitation",
		Contents: "# GCP Instance Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["instances-metadata"] = &internal.LootFile{
		Name:     "instances-metadata",
		Contents: "# GCP Instance Metadata Access Commands\n# Generated by CloudFox\n\n",
	}
	// New pentest-focused loot files
	m.LootMap["instances-startup-scripts"] = &internal.LootFile{
		Name:     "instances-startup-scripts",
		Contents: "# GCP Instance Startup Scripts\n# Generated by CloudFox\n# May contain credentials, API keys, or sensitive configuration\n\n",
	}
	m.LootMap["instances-ssh-keys"] = &internal.LootFile{
		Name:     "instances-ssh-keys",
		Contents: "# GCP Instance SSH Keys\n# Generated by CloudFox\n# Format: user:key-type KEY comment\n\n",
	}
	m.LootMap["instances-project-metadata"] = &internal.LootFile{
		Name:     "instances-project-metadata",
		Contents: "# GCP Project-Level Metadata\n# Generated by CloudFox\n# SSH keys here apply to ALL instances (unless blocked)\n\n",
	}
	m.LootMap["instances-custom-metadata"] = &internal.LootFile{
		Name:     "instances-custom-metadata",
		Contents: "# GCP Custom Metadata Keys\n# Generated by CloudFox\n# These may contain secrets, API keys, or sensitive config\n\n",
	}
}

func (m *InstancesModule) addProjectMetadataToLoot(meta *ComputeEngineService.ProjectMetadataInfo) {
	if meta == nil {
		return
	}

	// Project-level SSH keys
	if meta.HasProjectSSHKeys && len(meta.ProjectSSHKeys) > 0 {
		m.LootMap["instances-project-metadata"].Contents += fmt.Sprintf(
			"## Project: %s\n"+
				"## Project-level SSH Keys (apply to all instances unless blocked):\n"+
				"## OS Login: %v, OS Login 2FA: %v\n",
			meta.ProjectID, meta.OSLoginEnabled, meta.OSLogin2FAEnabled,
		)
		for _, key := range meta.ProjectSSHKeys {
			m.LootMap["instances-project-metadata"].Contents += key + "\n"
		}
		m.LootMap["instances-project-metadata"].Contents += "\n"

		// Also add to SSH keys loot
		m.LootMap["instances-ssh-keys"].Contents += fmt.Sprintf(
			"## PROJECT-LEVEL SSH KEYS (Project: %s)\n"+
				"## These apply to ALL instances that don't block project SSH keys\n",
			meta.ProjectID,
		)
		for _, key := range meta.ProjectSSHKeys {
			m.LootMap["instances-ssh-keys"].Contents += key + "\n"
		}
		m.LootMap["instances-ssh-keys"].Contents += "\n"
	}

	// Project-level startup script
	if meta.HasProjectStartupScript && meta.ProjectStartupScript != "" {
		m.LootMap["instances-startup-scripts"].Contents += fmt.Sprintf(
			"## PROJECT-LEVEL STARTUP SCRIPT (Project: %s)\n"+
				"## This runs on ALL instances in the project\n"+
				"## ------- PROJECT STARTUP SCRIPT BEGIN -------\n"+
				"%s\n"+
				"## ------- PROJECT STARTUP SCRIPT END -------\n\n",
			meta.ProjectID, meta.ProjectStartupScript,
		)
	}

	// Custom metadata keys at project level
	if len(meta.CustomMetadataKeys) > 0 {
		m.LootMap["instances-custom-metadata"].Contents += fmt.Sprintf(
			"## PROJECT-LEVEL CUSTOM METADATA (Project: %s)\n"+
				"## These may contain secrets, API keys, or sensitive config\n"+
				"## Custom keys found:\n",
			meta.ProjectID,
		)
		for _, key := range meta.CustomMetadataKeys {
			m.LootMap["instances-custom-metadata"].Contents += fmt.Sprintf("##   - %s\n", key)
		}
		m.LootMap["instances-custom-metadata"].Contents += fmt.Sprintf(
			"# Retrieve all project metadata with:\n"+
				"gcloud compute project-info describe --project=%s --format='yaml(commonInstanceMetadata)'\n\n",
			meta.ProjectID,
		)
	}

	// Project-level security settings
	m.LootMap["instances-project-metadata"].Contents += fmt.Sprintf(
		"## Project: %s Security Settings\n"+
			"## OS Login Enabled: %v\n"+
			"## OS Login 2FA Enabled: %v\n"+
			"## Serial Port Enabled: %v\n\n",
		meta.ProjectID, meta.OSLoginEnabled, meta.OSLogin2FAEnabled, meta.SerialPortEnabled,
	)
}

func (m *InstancesModule) addInstanceToLoot(instance ComputeEngineService.ComputeEngineInfo) {
	// Build service account string
	var saEmails []string
	for _, sa := range instance.ServiceAccounts {
		saEmails = append(saEmails, sa.Email)
	}
	saString := strings.Join(saEmails, ", ")

	// Build security flags string
	var securityFlags []string
	if instance.HasDefaultSA {
		securityFlags = append(securityFlags, "DEFAULT_SA")
	}
	if instance.HasCloudScopes {
		securityFlags = append(securityFlags, "BROAD_SCOPES")
	}
	if instance.ExternalIP != "" {
		securityFlags = append(securityFlags, "EXTERNAL_IP")
	}
	if instance.SerialPortEnabled {
		securityFlags = append(securityFlags, "SERIAL_PORT")
	}
	if !instance.OSLoginEnabled {
		securityFlags = append(securityFlags, "NO_OSLOGIN")
	}
	securityString := strings.Join(securityFlags, ", ")
	if securityString == "" {
		securityString = "None"
	}

	// gcloud commands for enumeration
	m.LootMap["instances-gcloud-commands"].Contents += fmt.Sprintf(
		"# Instance: %s (Project: %s, Zone: %s)\n"+
			"# Service Accounts: %s\n"+
			"# Security Flags: %s\n"+
			"gcloud compute instances describe %s --zone=%s --project=%s\n"+
			"gcloud compute instances get-serial-port-output %s --zone=%s --project=%s\n"+
			"gcloud compute instances get-iam-policy %s --zone=%s --project=%s\n\n",
		instance.Name, instance.ProjectID, instance.Zone, saString, securityString,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// SSH commands (if external IP exists)
	if instance.ExternalIP != "" {
		m.LootMap["instances-ssh-commands"].Contents += fmt.Sprintf(
			"# Instance: %s (External IP: %s)\n"+
				"# OS Login: %v, Serial Port: %v\n"+
				"gcloud compute ssh %s --zone=%s --project=%s\n"+
				"# Direct SSH (if OS Login disabled):\n"+
				"ssh -i <key> <user>@%s\n\n",
			instance.Name, instance.ExternalIP, instance.OSLoginEnabled, instance.SerialPortEnabled,
			instance.Name, instance.Zone, instance.ProjectID,
			instance.ExternalIP,
		)
	} else {
		m.LootMap["instances-ssh-commands"].Contents += fmt.Sprintf(
			"# Instance: %s (Internal IP: %s, No external IP)\n"+
				"# OS Login: %v\n"+
				"# Use IAP tunnel:\n"+
				"gcloud compute ssh %s --zone=%s --project=%s --tunnel-through-iap\n\n",
			instance.Name, instance.InternalIP, instance.OSLoginEnabled,
			instance.Name, instance.Zone, instance.ProjectID,
		)
	}

	// Exploitation commands
	m.LootMap["instances-exploitation"].Contents += fmt.Sprintf(
		"# Instance: %s (State: %s)\n"+
			"# Service Account: %s\n"+
			"# Default SA: %v, Broad Scopes: %v\n"+
			"# Get instance metadata (from inside the instance):\n"+
			"curl -H \"Metadata-Flavor: Google\" http://169.254.169.254/computeMetadata/v1/?recursive=true\n"+
			"# Get service account token:\n"+
			"curl -H \"Metadata-Flavor: Google\" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token\n"+
			"# Run command via startup script:\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata=startup-script='#!/bin/bash\\nwhoami > /tmp/pwned'\n"+
			"# Reset SSH keys:\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata-from-file=ssh-keys=<ssh-keys-file>\n\n",
		instance.Name, instance.State, saString, instance.HasDefaultSA, instance.HasCloudScopes,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// Metadata access commands
	m.LootMap["instances-metadata"].Contents += fmt.Sprintf(
		"# Instance: %s\n"+
			"# Has Startup Script: %v, Has SSH Keys: %v\n"+
			"# Block Project SSH Keys: %v\n"+
			"# Get instance metadata:\n"+
			"gcloud compute instances describe %s --zone=%s --project=%s --format='yaml(metadata)'\n"+
			"# Get custom metadata (startup scripts, SSH keys, etc):\n"+
			"gcloud compute project-info describe --project=%s --format='yaml(commonInstanceMetadata)'\n\n",
		instance.Name, instance.HasStartupScript, instance.HasSSHKeys, instance.BlockProjectSSHKeys,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.ProjectID,
	)

	// Pentest: Extract startup scripts
	if instance.StartupScriptContent != "" {
		m.LootMap["instances-startup-scripts"].Contents += fmt.Sprintf(
			"## Instance: %s (Project: %s, Zone: %s)\n"+
				"## Service Account: %s\n"+
				"## ------- STARTUP SCRIPT BEGIN -------\n"+
				"%s\n"+
				"## ------- STARTUP SCRIPT END -------\n\n",
			instance.Name, instance.ProjectID, instance.Zone, saString,
			instance.StartupScriptContent,
		)
	}
	if instance.StartupScriptURL != "" {
		m.LootMap["instances-startup-scripts"].Contents += fmt.Sprintf(
			"## Instance: %s (Project: %s, Zone: %s)\n"+
				"## Startup Script URL (fetch separately):\n"+
				"## %s\n"+
				"# Fetch with: gsutil cat %s\n\n",
			instance.Name, instance.ProjectID, instance.Zone,
			instance.StartupScriptURL,
			instance.StartupScriptURL,
		)
	}

	// Pentest: Extract SSH keys
	if len(instance.SSHKeys) > 0 {
		m.LootMap["instances-ssh-keys"].Contents += fmt.Sprintf(
			"## Instance: %s (Project: %s, Zone: %s)\n"+
				"## Block Project SSH Keys: %v\n",
			instance.Name, instance.ProjectID, instance.Zone, instance.BlockProjectSSHKeys,
		)
		for _, key := range instance.SSHKeys {
			m.LootMap["instances-ssh-keys"].Contents += key + "\n"
		}
		m.LootMap["instances-ssh-keys"].Contents += "\n"
	}

	// Pentest: Custom metadata keys (may contain secrets)
	if len(instance.CustomMetadata) > 0 {
		m.LootMap["instances-custom-metadata"].Contents += fmt.Sprintf(
			"## Instance: %s (Project: %s, Zone: %s)\n"+
				"## Custom metadata keys found:\n",
			instance.Name, instance.ProjectID, instance.Zone,
		)
		for _, key := range instance.CustomMetadata {
			m.LootMap["instances-custom-metadata"].Contents += fmt.Sprintf("##   - %s\n", key)
		}
		m.LootMap["instances-custom-metadata"].Contents += fmt.Sprintf(
			"# Retrieve values with:\n"+
				"gcloud compute instances describe %s --zone=%s --project=%s --format='yaml(metadata.items)'\n\n",
			instance.Name, instance.Zone, instance.ProjectID,
		)
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func instanceBoolToCheck(b bool) string {
	if b {
		return "✓"
	}
	return "-"
}

// SSHKeyParts contains parsed SSH key components
type SSHKeyParts struct {
	Username     string
	KeyType      string
	KeyTruncated string
	Comment      string
}

// parseSSHKeyLine parses a GCP SSH key line (format: user:ssh-rsa KEY comment)
func parseSSHKeyLine(line string) SSHKeyParts {
	parts := SSHKeyParts{
		Username:     "-",
		KeyType:      "-",
		KeyTruncated: "-",
		Comment:      "",
	}

	// Split on first colon to get username
	colonIdx := strings.Index(line, ":")
	if colonIdx > 0 {
		parts.Username = line[:colonIdx]
		line = line[colonIdx+1:]
	}

	// Split remaining by spaces: key-type KEY comment
	fields := strings.Fields(line)
	if len(fields) >= 1 {
		parts.KeyType = fields[0]
	}
	if len(fields) >= 2 {
		key := fields[1]
		if len(key) > 20 {
			parts.KeyTruncated = key[:10] + "..." + key[len(key)-10:]
		} else {
			parts.KeyTruncated = key
		}
	}
	if len(fields) >= 3 {
		parts.Comment = strings.Join(fields[2:], " ")
	}

	return parts
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *InstancesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main table with security-relevant columns
	header := []string{
		"Project ID",
		"Name",
		"Zone",
		"State",
		"External IP",
		"Internal IP",
		"Service Account",
		"DefaultSA",
		"BroadScopes",
		"OSLogin",
		"SerialPort",
		"ShieldedVM",
		"SecureBoot",
		"Encryption",
	}

	var body [][]string
	for _, instance := range m.Instances {
		// Get first service account email (most instances have just one)
		saEmail := "-"
		if len(instance.ServiceAccounts) > 0 {
			saEmail = instance.ServiceAccounts[0].Email
			// Shorten default SA for display
			if strings.Contains(saEmail, "-compute@developer.gserviceaccount.com") {
				saEmail = "default-compute-sa"
			}
		}

		// External IP display
		externalIP := instance.ExternalIP
		if externalIP == "" {
			externalIP = "-"
		}

		body = append(body, []string{
			instance.ProjectID,
			instance.Name,
			instance.Zone,
			instance.State,
			externalIP,
			instance.InternalIP,
			saEmail,
			instanceBoolToCheck(instance.HasDefaultSA),
			instanceBoolToCheck(instance.HasCloudScopes),
			instanceBoolToCheck(instance.OSLoginEnabled),
			instanceBoolToCheck(instance.SerialPortEnabled),
			instanceBoolToCheck(instance.ShieldedVM),
			instanceBoolToCheck(instance.SecureBoot),
			instance.BootDiskEncryption,
		})
	}

	// Detailed service account table - shows full SA info with scopes
	saHeader := []string{
		"Instance",
		"Project ID",
		"Zone",
		"Service Account",
		"Default SA",
		"Scopes",
	}

	var saBody [][]string
	for _, instance := range m.Instances {
		for _, sa := range instance.ServiceAccounts {
			isDefault := "-"
			if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") {
				isDefault = "✓"
			}

			// Format scopes (shorten URLs)
			scopes := ComputeEngineService.FormatScopes(sa.Scopes)

			saBody = append(saBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				sa.Email,
				isDefault,
				scopes,
			})
		}
	}

	// Security findings table - highlight risky configurations
	findingsHeader := []string{
		"Instance",
		"Project ID",
		"Zone",
		"Finding",
		"Severity",
		"Details",
	}

	var findingsBody [][]string
	for _, instance := range m.Instances {
		// Check for security issues
		if instance.HasDefaultSA {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Default Service Account",
				"MEDIUM",
				"Using default compute service account - consider using a custom SA",
			})
		}
		if instance.HasCloudScopes {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Broad OAuth Scopes",
				"HIGH",
				"Has cloud-platform or other broad scopes - potential for privilege escalation",
			})
		}
		if instance.ExternalIP != "" && !instance.OSLoginEnabled {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"External IP without OS Login",
				"MEDIUM",
				fmt.Sprintf("External IP %s exposed without OS Login enabled", instance.ExternalIP),
			})
		}
		if instance.SerialPortEnabled {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Serial Port Enabled",
				"LOW",
				"Serial port access enabled - potential for console access",
			})
		}
		if instance.CanIPForward {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"IP Forwarding Enabled",
				"INFO",
				"Can forward packets - may be intentional for NAT/routing",
			})
		}
		if !instance.ShieldedVM {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Shielded VM Disabled",
				"LOW",
				"Shielded VM not enabled - consider enabling for security",
			})
		}
		if instance.HasStartupScript && instance.HasDefaultSA && instance.HasCloudScopes {
			findingsBody = append(findingsBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Startup Script with Broad Access",
				"HIGH",
				"Has startup script with default SA and broad scopes - potential for code execution",
			})
		}
	}

	// Startup scripts table (pentest-focused)
	startupHeader := []string{
		"Instance",
		"Project ID",
		"Zone",
		"Script Type",
		"Service Account",
		"Content Preview",
	}

	var startupBody [][]string
	for _, instance := range m.Instances {
		if instance.StartupScriptContent != "" {
			// Preview first 100 chars
			preview := instance.StartupScriptContent
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}
			// Replace newlines for table display
			preview = strings.ReplaceAll(preview, "\n", "\\n")

			saEmail := "-"
			if len(instance.ServiceAccounts) > 0 {
				saEmail = instance.ServiceAccounts[0].Email
			}

			startupBody = append(startupBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"Inline",
				saEmail,
				preview,
			})
		}
		if instance.StartupScriptURL != "" {
			saEmail := "-"
			if len(instance.ServiceAccounts) > 0 {
				saEmail = instance.ServiceAccounts[0].Email
			}

			startupBody = append(startupBody, []string{
				instance.Name,
				instance.ProjectID,
				instance.Zone,
				"URL",
				saEmail,
				instance.StartupScriptURL,
			})
		}
	}

	// SSH keys table (pentest-focused)
	sshKeysHeader := []string{
		"Source",
		"Project ID",
		"Zone",
		"Username",
		"Key Type",
		"Key (truncated)",
	}

	var sshKeysBody [][]string

	// Add project-level SSH keys
	for projectID, meta := range m.ProjectMetadata {
		if meta != nil && len(meta.ProjectSSHKeys) > 0 {
			for _, key := range meta.ProjectSSHKeys {
				parts := parseSSHKeyLine(key)
				sshKeysBody = append(sshKeysBody, []string{
					"PROJECT",
					projectID,
					"-",
					parts.Username,
					parts.KeyType,
					parts.KeyTruncated,
				})
			}
		}
	}

	// Add instance-level SSH keys
	for _, instance := range m.Instances {
		if len(instance.SSHKeys) > 0 {
			for _, key := range instance.SSHKeys {
				parts := parseSSHKeyLine(key)
				sshKeysBody = append(sshKeysBody, []string{
					instance.Name,
					instance.ProjectID,
					instance.Zone,
					parts.Username,
					parts.KeyType,
					parts.KeyTruncated,
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

	// Build table files
	tableFiles := []internal.TableFile{
		{
			Name:   globals.GCP_INSTANCES_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	// Add service accounts table if there are any
	if len(saBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-service-accounts",
			Header: saHeader,
			Body:   saBody,
		})
	}

	// Add findings table if there are any
	if len(findingsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-findings",
			Header: findingsHeader,
			Body:   findingsBody,
		})
	}

	// Add startup scripts table if there are any
	if len(startupBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-startup-scripts",
			Header: startupHeader,
			Body:   startupBody,
		})
	}

	// Add SSH keys table if there are any
	if len(sshKeysBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "instances-ssh-keys",
			Header: sshKeysHeader,
			Body:   sshKeysBody,
		})
	}

	output := InstancesOutput{
		Table: tableFiles,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_INSTANCES_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
