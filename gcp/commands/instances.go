package commands

import (
	"github.com/BishopFox/cloudfox/gcp/shared"
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

	// Module-specific fields - per-project for hierarchical output
	ProjectInstances map[string][]ComputeEngineService.ComputeEngineInfo    // projectID -> instances
	ProjectMetadata  map[string]*ComputeEngineService.ProjectMetadataInfo   // projectID -> metadata
	LootMap          map[string]map[string]*internal.LootFile               // projectID -> loot files
	AttackPathCache  *gcpinternal.AttackPathCache                           // Cached attack path analysis results
	mu               sync.Mutex
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
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectInstances: make(map[string][]ComputeEngineService.ComputeEngineInfo),
		ProjectMetadata:  make(map[string]*ComputeEngineService.ProjectMetadataInfo),
		LootMap:          make(map[string]map[string]*internal.LootFile),
	}

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *InstancesModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get attack path cache from context (populated by all-checks or attack path analysis)
	m.AttackPathCache = gcpinternal.GetAttackPathCacheFromContext(ctx)

	// If no context cache, try loading from disk cache
	if m.AttackPathCache == nil || !m.AttackPathCache.IsPopulated() {
		diskCache, metadata, err := gcpinternal.LoadAttackPathCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			logger.InfoM(fmt.Sprintf("Using attack path cache from disk (created: %s)",
				metadata.CreatedAt.Format("2006-01-02 15:04:05")), globals.GCP_INSTANCES_MODULE_NAME)
			m.AttackPathCache = diskCache
		}
	}

	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_INSTANCES_MODULE_NAME, m.processProject)

	// Get all instances for stats
	allInstances := m.getAllInstances()
	if len(allInstances) == 0 {
		logger.InfoM("No instances found", globals.GCP_INSTANCES_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d instance(s)", len(allInstances)), globals.GCP_INSTANCES_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// getAllInstances returns all instances from all projects (for statistics)
func (m *InstancesModule) getAllInstances() []ComputeEngineService.ComputeEngineInfo {
	var all []ComputeEngineService.ComputeEngineInfo
	for _, instances := range m.ProjectInstances {
		all = append(all, instances...)
	}
	return all
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

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectInstances[projectID] = instances
	m.ProjectMetadata[projectID] = projectMeta

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["instances-commands"] = &internal.LootFile{
			Name:     "instances-commands",
			Contents: "# GCP Compute Engine Instance Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
		}
	}

	// Generate loot for each instance
	for _, instance := range instances {
		m.addInstanceToLoot(projectID, instance)
	}

	// Add project metadata to loot
	m.addProjectMetadataToLoot(projectID, projectMeta)
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d instance(s) in project %s", len(instances), projectID), globals.GCP_INSTANCES_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *InstancesModule) addProjectMetadataToLoot(projectID string, meta *ComputeEngineService.ProjectMetadataInfo) {
	if meta == nil {
		return
	}

	lootFile := m.LootMap[projectID]["instances-commands"]
	if lootFile == nil {
		return
	}

	lootFile.Contents += fmt.Sprintf(
		"# ==========================================\n"+
			"# PROJECT-LEVEL METADATA (Project: %s)\n"+
			"# ==========================================\n"+
			"# OS Login: %v, OS Login 2FA: %v, Serial Port: %v\n",
		meta.ProjectID, meta.OSLoginEnabled, meta.OSLogin2FAEnabled, meta.SerialPortEnabled,
	)

	// Project-level SSH keys
	if meta.HasProjectSSHKeys && len(meta.ProjectSSHKeys) > 0 {
		lootFile.Contents += fmt.Sprintf(
			"# Project SSH Keys: %d (apply to ALL instances not blocking project keys)\n",
			len(meta.ProjectSSHKeys),
		)
		for _, key := range meta.ProjectSSHKeys {
			lootFile.Contents += fmt.Sprintf("#   %s\n", key)
		}
	}

	// Project-level startup script
	if meta.HasProjectStartupScript && meta.ProjectStartupScript != "" {
		lootFile.Contents += fmt.Sprintf(
			"#\n# PROJECT STARTUP SCRIPT (runs on ALL instances):\n"+
				"# ------- BEGIN -------\n"+
				"%s\n"+
				"# ------- END -------\n",
			meta.ProjectStartupScript,
		)
	}

	// Custom metadata keys at project level
	if len(meta.CustomMetadataKeys) > 0 {
		lootFile.Contents += "# Custom metadata keys (may contain secrets):\n"
		for _, key := range meta.CustomMetadataKeys {
			lootFile.Contents += fmt.Sprintf("#   - %s\n", key)
		}
	}

	lootFile.Contents += fmt.Sprintf(
		"\n# Get project metadata:\n"+
			"gcloud compute project-info describe --project=%s --format='yaml(commonInstanceMetadata)'\n\n",
		meta.ProjectID,
	)
}

func (m *InstancesModule) addInstanceToLoot(projectID string, instance ComputeEngineService.ComputeEngineInfo) {
	lootFile := m.LootMap[projectID]["instances-commands"]
	if lootFile == nil {
		return
	}
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

	lootFile.Contents += fmt.Sprintf(
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
		lootFile.Contents += fmt.Sprintf("# Instance SSH Keys: %d\n", len(instance.SSHKeys))
		for _, key := range instance.SSHKeys {
			lootFile.Contents += fmt.Sprintf("#   %s\n", key)
		}
	}

	// Startup script content
	if instance.StartupScriptContent != "" {
		lootFile.Contents += fmt.Sprintf(
			"#\n# STARTUP SCRIPT (may contain secrets):\n"+
				"# ------- BEGIN -------\n"+
				"%s\n"+
				"# ------- END -------\n",
			instance.StartupScriptContent,
		)
	}
	if instance.StartupScriptURL != "" {
		lootFile.Contents += fmt.Sprintf(
			"# Startup Script URL: %s\n"+
				"# Fetch with: gsutil cat %s\n",
			instance.StartupScriptURL, instance.StartupScriptURL,
		)
	}

	// Custom metadata keys
	if len(instance.CustomMetadata) > 0 {
		lootFile.Contents += "# Custom metadata keys (may contain secrets):\n"
		for _, key := range instance.CustomMetadata {
			lootFile.Contents += fmt.Sprintf("#   - %s\n", key)
		}
	}

	// Commands section
	lootFile.Contents += fmt.Sprintf(
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
		lootFile.Contents += fmt.Sprintf(
			"# SSH (external IP):\n"+
				"gcloud compute ssh %s --zone=%s --project=%s\n"+
				"# Direct SSH (if OS Login disabled):\n"+
				"ssh -i ~/.ssh/google_compute_engine <user>@%s\n",
			instance.Name, instance.Zone, instance.ProjectID,
			instance.ExternalIP,
		)
	} else {
		lootFile.Contents += fmt.Sprintf(
			"# SSH via IAP tunnel (no external IP):\n"+
				"gcloud compute ssh %s --zone=%s --project=%s --tunnel-through-iap\n",
			instance.Name, instance.Zone, instance.ProjectID,
		)
	}

	// Exploitation commands
	lootFile.Contents += fmt.Sprintf(
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
	// Decide between hierarchical and flat output
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// writeHierarchicalOutput writes output to per-project directories
func (m *InstancesModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	header := m.getInstancesTableHeader()
	sshKeysHeader := m.getSSHKeysTableHeader()

	// Build hierarchical output data
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Build project-level outputs
	for projectID, instances := range m.ProjectInstances {
		body := m.instancesToTableBody(instances)
		tables := []internal.TableFile{{
			Name:   globals.GCP_INSTANCES_MODULE_NAME,
			Header: header,
			Body:   body,
		}}

		// Build SSH keys table for this project
		sshKeysBody := m.buildSSHKeysTableForProject(projectID, instances)
		if len(sshKeysBody) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "instances-ssh-keys",
				Header: sshKeysHeader,
				Body:   sshKeysBody,
			})
		}

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = InstancesOutput{Table: tables, Loot: lootFiles}
	}

	// Create path builder using the module's hierarchy
	pathBuilder := m.BuildPathBuilder()

	// Write using hierarchical output
	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_INSTANCES_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *InstancesModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getInstancesTableHeader()
	sshKeysHeader := m.getSSHKeysTableHeader()

	allInstances := m.getAllInstances()
	body := m.instancesToTableBody(allInstances)

	// Build SSH keys table for all projects
	var sshKeysBody [][]string
	for projectID, instances := range m.ProjectInstances {
		sshKeysBody = append(sshKeysBody, m.buildSSHKeysTableForProject(projectID, instances)...)
	}

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{{
		Name:   globals.GCP_INSTANCES_MODULE_NAME,
		Header: header,
		Body:   body,
	}}

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

// getInstancesTableHeader returns the instances table header
func (m *InstancesModule) getInstancesTableHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Name",
		"Zone",
		"State",
		"Machine Type",
		"External IP",
		"Internal IP",
		"Service Account",
		"SA Attack Paths",
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
		"IAM Binding Role",
		"IAM Binding Principal",
	}
}

// getSSHKeysTableHeader returns the SSH keys table header
func (m *InstancesModule) getSSHKeysTableHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Source",
		"Zone",
		"Username",
		"Key Type",
		"Key (truncated)",
	}
}

// instancesToTableBody converts instances to table body rows
func (m *InstancesModule) instancesToTableBody(instances []ComputeEngineService.ComputeEngineInfo) [][]string {
	var body [][]string
	for _, instance := range instances {
		// Get first service account email (most instances have just one)
		saEmail := "-"
		scopes := "-"
		if len(instance.ServiceAccounts) > 0 {
			saEmail = instance.ServiceAccounts[0].Email
			scopes = ComputeEngineService.FormatScopes(instance.ServiceAccounts[0].Scopes)
		}

		// Check attack paths (privesc/exfil/lateral) for the service account
		attackPaths := "run --attack-paths"
		if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
			if saEmail != "-" {
				attackPaths = m.AttackPathCache.GetAttackSummary(saEmail)
			} else {
				attackPaths = "No"
			}
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
			attackPaths,
			scopes,
			shared.BoolToYesNo(instance.HasDefaultSA),
			shared.BoolToYesNo(instance.HasCloudScopes),
			shared.BoolToYesNo(instance.OSLoginEnabled),
			shared.BoolToYesNo(instance.OSLogin2FAEnabled),
			shared.BoolToYesNo(instance.BlockProjectSSHKeys),
			shared.BoolToYesNo(instance.SerialPortEnabled),
			shared.BoolToYesNo(instance.CanIPForward),
			shared.BoolToYesNo(instance.ShieldedVM),
			shared.BoolToYesNo(instance.SecureBoot),
			shared.BoolToYesNo(instance.VTPMEnabled),
			shared.BoolToYesNo(instance.IntegrityMonitoring),
			shared.BoolToYesNo(instance.ConfidentialVM),
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
	return body
}

// buildSSHKeysTableForProject builds the SSH keys table body for a specific project
func (m *InstancesModule) buildSSHKeysTableForProject(projectID string, instances []ComputeEngineService.ComputeEngineInfo) [][]string {
	var sshKeysBody [][]string

	// Add project-level SSH keys
	if meta, ok := m.ProjectMetadata[projectID]; ok && meta != nil && len(meta.ProjectSSHKeys) > 0 {
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

	// Add instance-level SSH keys
	for _, instance := range instances {
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

	return sshKeysBody
}
