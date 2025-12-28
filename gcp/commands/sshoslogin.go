package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	sshosloginservice "github.com/BishopFox/cloudfox/gcp/services/sshOsLoginService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPSSHOsLoginCommand = &cobra.Command{
	Use:     globals.GCP_SSHOSLOGIN_MODULE_NAME,
	Aliases: []string{"ssh", "oslogin", "ssh-keys"},
	Short:   "Enumerate SSH access and OS Login configuration",
	Long: `Enumerate SSH access configuration across projects and instances.

This module identifies:
- OS Login configuration (project and instance level)
- SSH keys in project metadata (accessible to all instances)
- SSH keys in instance metadata
- Instances accessible via SSH
- 2FA requirements for OS Login

Security Analysis:
- Legacy SSH keys vs OS Login
- Project-wide SSH key exposure
- External IP + SSH access combinations
- Missing 2FA for OS Login

Output:
- OS Login configuration per project
- SSH keys from metadata
- Instance SSH access details
- SSH commands for accessible instances`,
	Run: runGCPSSHOsLoginCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type SSHOsLoginModule struct {
	gcpinternal.BaseGCPModule

	OSLoginConfigs []sshosloginservice.OSLoginConfig
	SSHKeys        []sshosloginservice.SSHKeyInfo
	InstanceAccess []sshosloginservice.InstanceSSHAccess
	LootMap        map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type SSHOsLoginOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SSHOsLoginOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SSHOsLoginOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPSSHOsLoginCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_SSHOSLOGIN_MODULE_NAME)
	if err != nil {
		return
	}

	module := &SSHOsLoginModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		OSLoginConfigs: []sshosloginservice.OSLoginConfig{},
		SSHKeys:        []sshosloginservice.SSHKeyInfo{},
		InstanceAccess: []sshosloginservice.InstanceSSHAccess{},
		LootMap:        make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *SSHOsLoginModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_SSHOSLOGIN_MODULE_NAME, m.processProject)

	if len(m.InstanceAccess) == 0 && len(m.SSHKeys) == 0 {
		logger.InfoM("No SSH access information found", globals.GCP_SSHOSLOGIN_MODULE_NAME)
		return
	}

	// Count instances with external IPs
	externalCount := 0
	for _, access := range m.InstanceAccess {
		if access.ExternalIP != "" {
			externalCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d instance(s), %d SSH key(s), %d with external IPs",
		len(m.InstanceAccess), len(m.SSHKeys), externalCount), globals.GCP_SSHOSLOGIN_MODULE_NAME)

	if len(m.SSHKeys) > 0 {
		logger.InfoM("[PENTEST] SSH keys found in metadata - check for access!", globals.GCP_SSHOSLOGIN_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *SSHOsLoginModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating SSH/OS Login in project: %s", projectID), globals.GCP_SSHOSLOGIN_MODULE_NAME)
	}

	svc := sshosloginservice.New()

	// Get OS Login config
	config, err := svc.GetProjectOSLoginConfig(projectID)
	if err == nil && config != nil {
		m.mu.Lock()
		m.OSLoginConfigs = append(m.OSLoginConfigs, *config)
		m.mu.Unlock()
	}

	// Get project SSH keys
	projectKeys, err := svc.GetProjectSSHKeys(projectID)
	if err == nil {
		m.mu.Lock()
		m.SSHKeys = append(m.SSHKeys, projectKeys...)
		for _, key := range projectKeys {
			m.addSSHKeyToLoot(key)
		}
		m.mu.Unlock()
	}

	// Get instance SSH access
	instances, instanceKeys, err := svc.GetInstanceSSHAccess(projectID)
	if err == nil {
		m.mu.Lock()
		m.InstanceAccess = append(m.InstanceAccess, instances...)
		m.SSHKeys = append(m.SSHKeys, instanceKeys...)

		for _, access := range instances {
			m.addInstanceAccessToLoot(access)
		}
		for _, key := range instanceKeys {
			m.addSSHKeyToLoot(key)
		}
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d instance(s), %d SSH key(s) in project %s",
			len(instances), len(projectKeys)+len(instanceKeys), projectID), globals.GCP_SSHOSLOGIN_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *SSHOsLoginModule) initializeLootFiles() {
	m.LootMap["ssh-commands"] = &internal.LootFile{
		Name:     "ssh-commands",
		Contents: "# SSH Commands for Instances\n# Generated by CloudFox\n\n",
	}
	m.LootMap["ssh-keys-found"] = &internal.LootFile{
		Name:     "ssh-keys-found",
		Contents: "# SSH Keys Found in Metadata\n# Generated by CloudFox\n# These keys grant access to instances\n\n",
	}
	m.LootMap["ssh-external-access"] = &internal.LootFile{
		Name:     "ssh-external-access",
		Contents: "# Instances with External SSH Access\n# Generated by CloudFox\n# Direct SSH targets from internet\n\n",
	}
}

func (m *SSHOsLoginModule) addSSHKeyToLoot(key sshosloginservice.SSHKeyInfo) {
	source := "Project-wide"
	if key.Source == "instance" {
		source = fmt.Sprintf("Instance: %s", key.InstanceName)
	}

	m.LootMap["ssh-keys-found"].Contents += fmt.Sprintf(
		"## User: %s\n"+
			"## Key Type: %s\n"+
			"## Source: %s\n"+
			"## Project: %s\n",
		key.Username, key.KeyType, source, key.ProjectID,
	)

	for _, cmd := range key.ExploitCommands {
		m.LootMap["ssh-keys-found"].Contents += cmd + "\n"
	}
	m.LootMap["ssh-keys-found"].Contents += "\n"
}

func (m *SSHOsLoginModule) addInstanceAccessToLoot(access sshosloginservice.InstanceSSHAccess) {
	// SSH commands for all instances
	m.LootMap["ssh-commands"].Contents += fmt.Sprintf(
		"## Instance: %s (Project: %s)\n",
		access.InstanceName, access.ProjectID,
	)
	for _, cmd := range access.SSHCommands {
		m.LootMap["ssh-commands"].Contents += cmd + "\n"
	}
	m.LootMap["ssh-commands"].Contents += "\n"

	// External access specifically
	if access.ExternalIP != "" {
		m.LootMap["ssh-external-access"].Contents += fmt.Sprintf(
			"## [%s] %s\n"+
				"## External IP: %s\n"+
				"## Project: %s, Zone: %s\n"+
				"## OS Login: %v, Block Project Keys: %v\n",
			access.RiskLevel, access.InstanceName,
			access.ExternalIP,
			access.ProjectID, access.Zone,
			access.OSLoginEnabled, access.BlockProjectKeys,
		)

		if len(access.RiskReasons) > 0 {
			for _, reason := range access.RiskReasons {
				m.LootMap["ssh-external-access"].Contents += fmt.Sprintf("##   - %s\n", reason)
			}
		}

		m.LootMap["ssh-external-access"].Contents += fmt.Sprintf(
			"gcloud compute ssh %s --zone=%s --project=%s\n\n",
			access.InstanceName, access.Zone, access.ProjectID,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *SSHOsLoginModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// OS Login Config table
	if len(m.OSLoginConfigs) > 0 {
		configHeader := []string{
			"Project",
			"OS Login",
			"2FA Required",
			"Block Project Keys",
			"Risk",
		}

		var configBody [][]string
		for _, config := range m.OSLoginConfigs {
			configBody = append(configBody, []string{
				config.ProjectID,
				boolToYesNo(config.OSLoginEnabled),
				boolToYesNo(config.OSLogin2FAEnabled),
				boolToYesNo(config.BlockProjectSSHKeys),
				config.RiskLevel,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "oslogin-config",
			Header: configHeader,
			Body:   configBody,
		})
	}

	// Instance SSH Access table
	if len(m.InstanceAccess) > 0 {
		accessHeader := []string{
			"Instance",
			"External IP",
			"Internal IP",
			"OS Login",
			"SSH Keys",
			"Risk",
			"Zone",
			"Project",
		}

		var accessBody [][]string
		for _, access := range m.InstanceAccess {
			externalIP := access.ExternalIP
			if externalIP == "" {
				externalIP = "-"
			}

			accessBody = append(accessBody, []string{
				access.InstanceName,
				externalIP,
				access.InternalIP,
				boolToYesNo(access.OSLoginEnabled),
				fmt.Sprintf("%d", access.SSHKeysCount),
				access.RiskLevel,
				access.Zone,
				access.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "ssh-instance-access",
			Header: accessHeader,
			Body:   accessBody,
		})
	}

	// SSH Keys table
	if len(m.SSHKeys) > 0 {
		keysHeader := []string{
			"Username",
			"Key Type",
			"Source",
			"Instance",
			"Project",
		}

		var keysBody [][]string
		for _, key := range m.SSHKeys {
			instance := "-"
			if key.InstanceName != "" {
				instance = key.InstanceName
			}

			keysBody = append(keysBody, []string{
				key.Username,
				key.KeyType,
				key.Source,
				instance,
				key.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "ssh-keys",
			Header: keysHeader,
			Body:   keysBody,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	output := SSHOsLoginOutput{
		Table: tables,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SSHOSLOGIN_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
