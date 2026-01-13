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
	Aliases: []string{"vms", "compute", "ssh", "oslogin"},
	Short:   "Enumerate GCP Compute Engine instances with security configuration",
	Long: `Enumerate GCP Compute Engine instances across projects with security-relevant details.

Features:
- Lists all instances with network and security configuration
- Shows attached service accounts and their scopes
- Identifies instances with default service accounts or broad scopes
- Shows Shielded VM, Secure Boot, and Confidential VM status
- Shows OS Login configuration (enabled, 2FA, block project keys)
- Shows serial port and disk encryption configuration
- Extracts SSH keys from project and instance metadata
- Extracts startup scripts (may contain secrets)
- Generates gcloud commands for instance access and exploitation

Security Columns:
- ExternalIP: Instances with external IPs are internet-accessible
- DefaultSA: Uses default compute service account (security risk)
- BroadScopes: Has cloud-platform or other broad OAuth scopes
- OSLogin: OS Login enabled (recommended for access control)
- OSLogin2FA: OS Login with 2FA required
- BlockProjKeys: Instance blocks project-wide SSH keys
- SerialPort: Serial port access enabled (security risk if exposed)
- CanIPForward: Can forward packets (potential for lateral movement)
- ShieldedVM/SecureBoot/vTPM/Integrity: Hardware security features
- Confidential: Confidential computing enabled
- Encryption: Boot disk encryption type (Google-managed, CMEK, CSEK)`,
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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_INSTANCES_MODULE_NAME,
			fmt.Sprintf("Could not enumerate instances in project %s", projectID))
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
	m.LootMap["instances-commands"] = &internal.LootFile{
		Name:     "instances-commands",
		Contents: "# GCP Compute Engine Instance Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *InstancesModule) addProjectMetadataToLoot(meta *ComputeEngineService.ProjectMetadataInfo) {
	if meta == nil {
		return
	}

	m.LootMap["instances-commands"].Contents += fmt.Sprintf(
		"# ==========================================\n"+
			"# PROJECT-LEVEL METADATA (Project: %s)\n"+
			"# ==========================================\n"+
			"# OS Login: %v, OS Login 2FA: %v, Serial Port: %v\n",
		meta.ProjectID, meta.OSLoginEnabled, meta.OSLogin2FAEnabled, meta.SerialPortEnabled,
	)

	// Project-level SSH keys
	if meta.HasProjectSSHKeys && len(meta.ProjectSSHKeys) > 0 {
		m.LootMap["instances-commands"].Contents += fmt.Sprintf(
			"# Project SSH Keys: %d (apply to ALL instances not blocking project keys)\n",
			len(meta.ProjectSSHKeys),
		)
		for _, key := range meta.ProjectSSHKeys {
			m.LootMap["instances-commands"].Contents += fmt.Sprintf("#   %s\n", key)
		}
	}

	// Project-level startup script
	if meta.HasProjectStartupScript && meta.ProjectStartupScript != "" {
		m.LootMap["instances-commands"].Contents += fmt.Sprintf(
			"#\n# PROJECT STARTUP SCRIPT (runs on ALL instances):\n"+
				"# ------- BEGIN -------\n"+
				"%s\n"+
				"# ------- END -------\n",
			meta.ProjectStartupScript,
		)
	}

	// Custom metadata keys at project level
	if len(meta.CustomMetadataKeys) > 0 {
		m.LootMap["instances-commands"].Contents += "# Custom metadata keys (may contain secrets):\n"
		for _, key := range meta.CustomMetadataKeys {
			m.LootMap["instances-commands"].Contents += fmt.Sprintf("#   - %s\n", key)
		}
	}

	m.LootMap["instances-commands"].Contents += fmt.Sprintf(
		"\n# Get project metadata:\n"+
			"gcloud compute project-info describe --project=%s --format='yaml(commonInstanceMetadata)'\n\n",
		meta.ProjectID,
	)
}

func (m *InstancesModule) addInstanceToLoot(instance ComputeEngineService.ComputeEngineInfo) {
	// Build service account string
	var saEmails []string
	for _, sa := range instance.ServiceAccounts {
		saEmails = append(saEmails, sa.Email)
	}
	saString := strings.Join(saEmails, ", ")
	if saString == "" {
		saString = "-"
	}

	// External IP for display
	externalIP := instance.ExternalIP
	if externalIP == "" {
		externalIP = "None"
	}

	m.LootMap["instances-commands"].Contents += fmt.Sprintf(
		"# ==========================================\n"+
			"# INSTANCE: %s (Project: %s, Zone: %s)\n"+
			"# ==========================================\n"+
			"# State: %s, Machine Type: %s\n"+
			"# External IP: %s, Internal IP: %s\n"+
			"# Service Account: %s\n"+
			"# Default SA: %v, Broad Scopes: %v\n"+
			"# OS Login: %v, OS Login 2FA: %v, Block Project Keys: %v\n"+
			"# Serial Port: %v, Shielded VM: %v, Secure Boot: %v\n",
		instance.Name, instance.ProjectID, instance.Zone,
		instance.State, instance.MachineType,
		externalIP, instance.InternalIP,
		saString,
		instance.HasDefaultSA, instance.HasCloudScopes,
		instance.OSLoginEnabled, instance.OSLogin2FAEnabled, instance.BlockProjectSSHKeys,
		instance.SerialPortEnabled, instance.ShieldedVM, instance.SecureBoot,
	)

	// SSH keys on this instance
	if len(instance.SSHKeys) > 0 {
		m.LootMap["instances-commands"].Contents += fmt.Sprintf("# Instance SSH Keys: %d\n", len(instance.SSHKeys))
		for _, key := range instance.SSHKeys {
			m.LootMap["instances-commands"].Contents += fmt.Sprintf("#   %s\n", key)
		}
	}

	// Startup script content
	if instance.StartupScriptContent != "" {
		m.LootMap["instances-commands"].Contents += fmt.Sprintf(
			"#\n# STARTUP SCRIPT (may contain secrets):\n"+
				"# ------- BEGIN -------\n"+
				"%s\n"+
				"# ------- END -------\n",
			instance.StartupScriptContent,
		)
	}
	if instance.StartupScriptURL != "" {
		m.LootMap["instances-commands"].Contents += fmt.Sprintf(
			"# Startup Script URL: %s\n"+
				"# Fetch with: gsutil cat %s\n",
			instance.StartupScriptURL, instance.StartupScriptURL,
		)
	}

	// Custom metadata keys
	if len(instance.CustomMetadata) > 0 {
		m.LootMap["instances-commands"].Contents += "# Custom metadata keys (may contain secrets):\n"
		for _, key := range instance.CustomMetadata {
			m.LootMap["instances-commands"].Contents += fmt.Sprintf("#   - %s\n", key)
		}
	}

	// Commands section
	m.LootMap["instances-commands"].Contents += fmt.Sprintf(
		"\n# Describe instance:\n"+
			"gcloud compute instances describe %s --zone=%s --project=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud compute instances get-iam-policy %s --zone=%s --project=%s\n"+
			"# Get serial port output:\n"+
			"gcloud compute instances get-serial-port-output %s --zone=%s --project=%s\n"+
			"# Get metadata:\n"+
			"gcloud compute instances describe %s --zone=%s --project=%s --format='yaml(metadata)'\n",
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)

	// SSH commands
	if instance.ExternalIP != "" {
		m.LootMap["instances-commands"].Contents += fmt.Sprintf(
			"# SSH (external IP):\n"+
				"gcloud compute ssh %s --zone=%s --project=%s\n"+
				"# Direct SSH (if OS Login disabled):\n"+
				"ssh -i ~/.ssh/google_compute_engine <user>@%s\n",
			instance.Name, instance.Zone, instance.ProjectID,
			instance.ExternalIP,
		)
	} else {
		m.LootMap["instances-commands"].Contents += fmt.Sprintf(
			"# SSH via IAP tunnel (no external IP):\n"+
				"gcloud compute ssh %s --zone=%s --project=%s --tunnel-through-iap\n",
			instance.Name, instance.Zone, instance.ProjectID,
		)
	}

	// Exploitation commands
	m.LootMap["instances-commands"].Contents += fmt.Sprintf(
		"# Metadata from inside instance:\n"+
			"curl -H \"Metadata-Flavor: Google\" http://169.254.169.254/computeMetadata/v1/?recursive=true\n"+
			"# Get service account token:\n"+
			"curl -H \"Metadata-Flavor: Google\" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token\n"+
			"# Add startup script (persistence):\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata=startup-script='#!/bin/bash\\nwhoami > /tmp/pwned'\n"+
			"# Add SSH keys:\n"+
			"gcloud compute instances add-metadata %s --zone=%s --project=%s --metadata-from-file=ssh-keys=<ssh-keys-file>\n\n",
		instance.Name, instance.Zone, instance.ProjectID,
		instance.Name, instance.Zone, instance.ProjectID,
	)
}

// ------------------------------
// Helper Functions
// ------------------------------

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
	// Single combined table with all security-relevant columns and IAM bindings
	header := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Zone",
		"State",
		"Machine Type",
		"External IP",
		"Internal IP",
		"Service Account",
		"Scopes",
		"Default SA",
		"Broad Scopes",
		"OS Login",
		"OS Login 2FA",
		"Block Proj Keys",
		"Serial Port",
		"IP Forward",
		"Shielded VM",
		"Secure Boot",
		"vTPM",
		"Integrity",
		"Confidential",
		"Encryption",
		"KMS Key",
		"IAM Role",
		"IAM Member",
	}

	var body [][]string
	for _, instance := range m.Instances {
		// Get first service account email (most instances have just one)
		saEmail := "-"
		scopes := "-"
		if len(instance.ServiceAccounts) > 0 {
			saEmail = instance.ServiceAccounts[0].Email
			scopes = ComputeEngineService.FormatScopes(instance.ServiceAccounts[0].Scopes)
		}

		// External IP display
		externalIP := instance.ExternalIP
		if externalIP == "" {
			externalIP = "-"
		}

		// Encryption display
		encryption := instance.BootDiskEncryption
		if encryption == "" {
			encryption = "Google"
		}

		// KMS Key display
		kmsKey := instance.BootDiskKMSKey
		if kmsKey == "" {
			kmsKey = "-"
		}

		// Base row data (reused for each IAM binding)
		baseRow := []string{
			m.GetProjectName(instance.ProjectID),
			instance.ProjectID,
			instance.Name,
			instance.Zone,
			instance.State,
			instance.MachineType,
			externalIP,
			instance.InternalIP,
			saEmail,
			scopes,
			boolToYesNo(instance.HasDefaultSA),
			boolToYesNo(instance.HasCloudScopes),
			boolToYesNo(instance.OSLoginEnabled),
			boolToYesNo(instance.OSLogin2FAEnabled),
			boolToYesNo(instance.BlockProjectSSHKeys),
			boolToYesNo(instance.SerialPortEnabled),
			boolToYesNo(instance.CanIPForward),
			boolToYesNo(instance.ShieldedVM),
			boolToYesNo(instance.SecureBoot),
			boolToYesNo(instance.VTPMEnabled),
			boolToYesNo(instance.IntegrityMonitoring),
			boolToYesNo(instance.ConfidentialVM),
			encryption,
			kmsKey,
		}

		// If instance has IAM bindings, create one row per binding
		if len(instance.IAMBindings) > 0 {
			for _, binding := range instance.IAMBindings {
				row := make([]string, len(baseRow)+2)
				copy(row, baseRow)
				row[len(baseRow)] = binding.Role
				row[len(baseRow)+1] = binding.Member
				body = append(body, row)
			}
		} else {
			// No IAM bindings - single row
			row := make([]string, len(baseRow)+2)
			copy(row, baseRow)
			row[len(baseRow)] = "-"
			row[len(baseRow)+1] = "-"
			body = append(body, row)
		}
	}

	// SSH keys table (pentest-focused - keep separate)
	sshKeysHeader := []string{
		"Project Name",
		"Project ID",
		"Source",
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
					m.GetProjectName(projectID),
					projectID,
					"PROJECT",
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
					m.GetProjectName(instance.ProjectID),
					instance.ProjectID,
					instance.Name,
					instance.Zone,
					parts.Username,
					parts.KeyType,
					parts.KeyTruncated,
				})
			}
		}
	}

	// Collect loot files (only if content was added beyond header)
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_INSTANCES_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
