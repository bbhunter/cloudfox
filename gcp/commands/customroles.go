package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	customrolesservice "github.com/BishopFox/cloudfox/gcp/services/customRolesService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCustomRolesCommand = &cobra.Command{
	Use:     globals.GCP_CUSTOMROLES_MODULE_NAME,
	Aliases: []string{"roles", "custom-role"},
	Short:   "Analyze custom IAM roles for dangerous permissions",
	Long: `Analyze custom IAM roles for overly permissive or dangerous permissions.

This module focuses on identifying custom roles that may be exploited for:
- Privilege escalation (SA key creation, token generation, IAM modification)
- Data exfiltration (secret access, storage access, BigQuery access)
- Persistence (instance creation, function deployment, metadata modification)
- Lateral movement (SA impersonation, GKE access, Cloud SQL access)

Features:
- Lists all custom roles in specified projects
- Identifies dangerous permissions in each role
- Highlights privilege escalation permissions
- Generates exploitation commands for risky roles
- Provides risk scoring (CRITICAL, HIGH, MEDIUM, LOW)

Use with privesc module for complete privilege escalation analysis.`,
	Run: runGCPCustomRolesCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CustomRolesModule struct {
	gcpinternal.BaseGCPModule

	Roles           []customrolesservice.CustomRoleInfo
	RoleAnalyses    []customrolesservice.RolePermissionAnalysis
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CustomRolesOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CustomRolesOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CustomRolesOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCustomRolesCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CUSTOMROLES_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CustomRolesModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Roles:         []customrolesservice.CustomRoleInfo{},
		RoleAnalyses:  []customrolesservice.RolePermissionAnalysis{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CustomRolesModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CUSTOMROLES_MODULE_NAME, m.processProject)

	if len(m.Roles) == 0 {
		logger.InfoM("No custom IAM roles found", globals.GCP_CUSTOMROLES_MODULE_NAME)
		return
	}

	// Count risky roles
	criticalCount := 0
	highCount := 0
	for _, role := range m.Roles {
		switch role.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d custom role(s)", len(m.Roles)), globals.GCP_CUSTOMROLES_MODULE_NAME)

	if criticalCount > 0 || highCount > 0 {
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d CRITICAL, %d HIGH risk custom role(s)!", criticalCount, highCount), globals.GCP_CUSTOMROLES_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CustomRolesModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing custom roles in project: %s", projectID), globals.GCP_CUSTOMROLES_MODULE_NAME)
	}

	svc := customrolesservice.New()

	roles, err := svc.ListCustomRoles(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.InfoM(fmt.Sprintf("Could not list custom roles in project %s: %v", projectID, err), globals.GCP_CUSTOMROLES_MODULE_NAME)
		}
		return
	}

	var analyses []customrolesservice.RolePermissionAnalysis
	for _, role := range roles {
		analysis := svc.AnalyzeRoleInDepth(role)
		analyses = append(analyses, analysis)
	}

	m.mu.Lock()
	m.Roles = append(m.Roles, roles...)
	m.RoleAnalyses = append(m.RoleAnalyses, analyses...)

	for _, role := range roles {
		m.addRoleToLoot(role)
	}
	for _, analysis := range analyses {
		m.addAnalysisToLoot(analysis)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d custom role(s) in project %s", len(roles), projectID), globals.GCP_CUSTOMROLES_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CustomRolesModule) initializeLootFiles() {
	m.LootMap["custom-roles-all"] = &internal.LootFile{
		Name:     "custom-roles-all",
		Contents: "# Custom IAM Roles\n# Generated by CloudFox\n\n",
	}
	m.LootMap["custom-roles-dangerous"] = &internal.LootFile{
		Name:     "custom-roles-dangerous",
		Contents: "# Dangerous Custom IAM Roles\n# Generated by CloudFox\n# Roles with privilege escalation or high-risk permissions\n\n",
	}
	m.LootMap["custom-roles-privesc"] = &internal.LootFile{
		Name:     "custom-roles-privesc",
		Contents: "# Custom Roles with Privilege Escalation Permissions\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["custom-roles-exploit"] = &internal.LootFile{
		Name:     "custom-roles-exploit",
		Contents: "# Custom Role Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *CustomRolesModule) addRoleToLoot(role customrolesservice.CustomRoleInfo) {
	m.LootMap["custom-roles-all"].Contents += fmt.Sprintf(
		"## Role: %s\n"+
			"## Project: %s\n"+
			"## Title: %s\n"+
			"## Permissions: %d\n"+
			"## Risk Level: %s\n\n",
		role.Name,
		role.ProjectID,
		role.Title,
		role.PermissionCount,
		role.RiskLevel,
	)

	// Dangerous roles
	if role.RiskLevel == "CRITICAL" || role.RiskLevel == "HIGH" {
		m.LootMap["custom-roles-dangerous"].Contents += fmt.Sprintf(
			"## [%s] Role: %s (Project: %s)\n"+
				"## Title: %s\n"+
				"## Permissions: %d\n",
			role.RiskLevel, role.Name, role.ProjectID,
			role.Title,
			role.PermissionCount,
		)

		if len(role.RiskReasons) > 0 {
			m.LootMap["custom-roles-dangerous"].Contents += "## Risk Reasons:\n"
			for _, reason := range role.RiskReasons {
				m.LootMap["custom-roles-dangerous"].Contents += fmt.Sprintf("##   - %s\n", reason)
			}
		}

		if len(role.DangerousPerms) > 0 {
			m.LootMap["custom-roles-dangerous"].Contents += "## Dangerous Permissions:\n"
			for _, perm := range role.DangerousPerms {
				m.LootMap["custom-roles-dangerous"].Contents += fmt.Sprintf("##   - %s\n", perm)
			}
		}
		m.LootMap["custom-roles-dangerous"].Contents += "\n"
	}

	// Privesc-specific roles
	if len(role.PrivescPerms) > 0 {
		m.LootMap["custom-roles-privesc"].Contents += fmt.Sprintf(
			"## [%s] Role: %s (Project: %s)\n"+
				"## Privilege Escalation Permissions:\n",
			role.RiskLevel, role.Name, role.ProjectID,
		)
		for _, perm := range role.PrivescPerms {
			m.LootMap["custom-roles-privesc"].Contents += fmt.Sprintf("##   - %s\n", perm)
		}
		m.LootMap["custom-roles-privesc"].Contents += "\n"
	}
}

func (m *CustomRolesModule) addAnalysisToLoot(analysis customrolesservice.RolePermissionAnalysis) {
	if len(analysis.ExploitCommands) > 0 {
		m.LootMap["custom-roles-exploit"].Contents += fmt.Sprintf(
			"## [%s] Role: %s (Project: %s)\n"+
				"## Dangerous: %d, Privesc: %d\n",
			analysis.RiskLevel, analysis.RoleName, analysis.ProjectID,
			analysis.DangerousCount, analysis.PrivescCount,
		)
		for _, cmd := range analysis.ExploitCommands {
			m.LootMap["custom-roles-exploit"].Contents += cmd + "\n"
		}
		m.LootMap["custom-roles-exploit"].Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CustomRolesModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main roles table
	rolesHeader := []string{
		"Risk",
		"Role Name",
		"Title",
		"Permissions",
		"Dangerous",
		"Privesc",
		"Stage",
		"Project Name",
		"Project",
	}

	var rolesBody [][]string
	for i, role := range m.Roles {
		dangerousCount := 0
		privescCount := 0
		if i < len(m.RoleAnalyses) {
			dangerousCount = m.RoleAnalyses[i].DangerousCount
			privescCount = m.RoleAnalyses[i].PrivescCount
		}

		rolesBody = append(rolesBody, []string{
			role.RiskLevel,
			role.Name,
			role.Title,
			fmt.Sprintf("%d", role.PermissionCount),
			fmt.Sprintf("%d", dangerousCount),
			fmt.Sprintf("%d", privescCount),
			role.Stage,
			m.GetProjectName(role.ProjectID),
			role.ProjectID,
		})
	}

	// Dangerous permissions table
	dangerousHeader := []string{
		"Risk",
		"Role",
		"Permission",
		"Description",
		"Project Name",
		"Project",
	}

	var dangerousBody [][]string
	svc := customrolesservice.New()
	dangerousPerms := svc.GetDangerousPermissions()
	dangerousMap := make(map[string]customrolesservice.DangerousPermission)
	for _, dp := range dangerousPerms {
		dangerousMap[dp.Permission] = dp
	}

	for _, role := range m.Roles {
		for _, perm := range role.DangerousPerms {
			if dp, found := dangerousMap[perm]; found {
				dangerousBody = append(dangerousBody, []string{
					dp.RiskLevel,
					role.Name,
					perm,
					dp.Description,
					m.GetProjectName(role.ProjectID),
					role.ProjectID,
				})
			}
		}
	}

	// Privesc roles table
	privescHeader := []string{
		"Role",
		"Privesc Permissions",
		"Project Name",
		"Project",
	}

	var privescBody [][]string
	for _, role := range m.Roles {
		if len(role.PrivescPerms) > 0 {
			perms := strings.Join(role.PrivescPerms, ", ")
			if len(perms) > 60 {
				perms = perms[:60] + "..."
			}
			privescBody = append(privescBody, []string{
				role.Name,
				perms,
				m.GetProjectName(role.ProjectID),
				role.ProjectID,
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
			Name:   "custom-roles",
			Header: rolesHeader,
			Body:   rolesBody,
		},
	}

	if len(dangerousBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "custom-roles-dangerous-perms",
			Header: dangerousHeader,
			Body:   dangerousBody,
		})
	}

	if len(privescBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "custom-roles-privesc",
			Header: privescHeader,
			Body:   privescBody,
		})
	}

	output := CustomRolesOutput{
		Table: tables,
		Loot:  lootFiles,
	}

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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CUSTOMROLES_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
