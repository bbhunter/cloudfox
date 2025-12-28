package commands

import (
	"context"
	"fmt"
	"strings"

	crossprojectservice "github.com/BishopFox/cloudfox/gcp/services/crossProjectService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCrossProjectCommand = &cobra.Command{
	Use:     globals.GCP_CROSSPROJECT_MODULE_NAME,
	Aliases: []string{"cross-project", "xproject", "lateral"},
	Short:   "Analyze cross-project access patterns for lateral movement",
	Long: `Analyze cross-project IAM bindings to identify lateral movement paths.

This module is designed for penetration testing and identifies:
- Service accounts with access to multiple projects
- Cross-project IAM role bindings
- Potential lateral movement paths between projects

Features:
- Maps cross-project service account access
- Identifies high-risk cross-project roles (owner, editor, admin)
- Generates exploitation commands for lateral movement
- Highlights service accounts spanning trust boundaries

Risk Analysis:
- CRITICAL: Owner/Editor/Admin roles across projects
- HIGH: Sensitive admin roles (IAM, Secrets, Compute)
- MEDIUM: Standard roles with cross-project access
- LOW: Read-only cross-project access

WARNING: Requires multiple projects to be specified for effective analysis.
Use -p for single project or -l for project list file.`,
	Run: runGCPCrossProjectCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CrossProjectModule struct {
	gcpinternal.BaseGCPModule

	CrossBindings       []crossprojectservice.CrossProjectBinding
	CrossProjectSAs     []crossprojectservice.CrossProjectServiceAccount
	LateralMovementPaths []crossprojectservice.LateralMovementPath
	LootMap             map[string]*internal.LootFile
}

// ------------------------------
// Output Struct
// ------------------------------
type CrossProjectOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CrossProjectOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CrossProjectOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCrossProjectCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CROSSPROJECT_MODULE_NAME)
	if err != nil {
		return
	}

	if len(cmdCtx.ProjectIDs) < 2 {
		cmdCtx.Logger.InfoM("Cross-project analysis works best with multiple projects. Consider using -l to specify a project list.", globals.GCP_CROSSPROJECT_MODULE_NAME)
	}

	module := &CrossProjectModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		CrossBindings:        []crossprojectservice.CrossProjectBinding{},
		CrossProjectSAs:      []crossprojectservice.CrossProjectServiceAccount{},
		LateralMovementPaths: []crossprojectservice.LateralMovementPath{},
		LootMap:              make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CrossProjectModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM(fmt.Sprintf("Analyzing cross-project access patterns across %d project(s)...", len(m.ProjectIDs)), globals.GCP_CROSSPROJECT_MODULE_NAME)

	svc := crossprojectservice.New()

	// Analyze cross-project bindings
	bindings, err := svc.AnalyzeCrossProjectAccess(m.ProjectIDs)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error analyzing cross-project access: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		}
	} else {
		m.CrossBindings = bindings
	}

	// Get cross-project service accounts
	sas, err := svc.GetCrossProjectServiceAccounts(m.ProjectIDs)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting cross-project service accounts: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		}
	} else {
		m.CrossProjectSAs = sas
	}

	// Find lateral movement paths
	paths, err := svc.FindLateralMovementPaths(m.ProjectIDs)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error finding lateral movement paths: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		}
	} else {
		m.LateralMovementPaths = paths
	}

	if len(m.CrossBindings) == 0 && len(m.CrossProjectSAs) == 0 && len(m.LateralMovementPaths) == 0 {
		logger.InfoM("No cross-project access patterns found", globals.GCP_CROSSPROJECT_MODULE_NAME)
		return
	}

	// Count high-risk findings
	criticalCount := 0
	highCount := 0
	for _, binding := range m.CrossBindings {
		switch binding.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
		m.addBindingToLoot(binding)
	}

	for _, sa := range m.CrossProjectSAs {
		m.addServiceAccountToLoot(sa)
	}

	for _, path := range m.LateralMovementPaths {
		m.addLateralMovementToLoot(path)
	}

	logger.SuccessM(fmt.Sprintf("Found %d cross-project binding(s), %d cross-project SA(s), %d lateral movement path(s)",
		len(m.CrossBindings), len(m.CrossProjectSAs), len(m.LateralMovementPaths)), globals.GCP_CROSSPROJECT_MODULE_NAME)

	if criticalCount > 0 || highCount > 0 {
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d CRITICAL, %d HIGH risk cross-project bindings!", criticalCount, highCount), globals.GCP_CROSSPROJECT_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CrossProjectModule) initializeLootFiles() {
	m.LootMap["cross-project-bindings"] = &internal.LootFile{
		Name:     "cross-project-bindings",
		Contents: "# Cross-Project IAM Bindings\n# Generated by CloudFox\n# Service accounts and users with access across project boundaries\n\n",
	}
	m.LootMap["cross-project-sas"] = &internal.LootFile{
		Name:     "cross-project-sas",
		Contents: "# Cross-Project Service Accounts\n# Generated by CloudFox\n# Service accounts with access to multiple projects\n\n",
	}
	m.LootMap["lateral-movement-paths"] = &internal.LootFile{
		Name:     "lateral-movement-paths",
		Contents: "# Lateral Movement Paths\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["cross-project-exploitation"] = &internal.LootFile{
		Name:     "cross-project-exploitation",
		Contents: "# Cross-Project Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *CrossProjectModule) addBindingToLoot(binding crossprojectservice.CrossProjectBinding) {
	m.LootMap["cross-project-bindings"].Contents += fmt.Sprintf(
		"## [%s] %s -> %s\n"+
			"## Principal: %s\n"+
			"## Role: %s\n",
		binding.RiskLevel, binding.SourceProject, binding.TargetProject,
		binding.Principal,
		binding.Role,
	)

	if len(binding.RiskReasons) > 0 {
		m.LootMap["cross-project-bindings"].Contents += "## Risk Reasons:\n"
		for _, reason := range binding.RiskReasons {
			m.LootMap["cross-project-bindings"].Contents += fmt.Sprintf("##   - %s\n", reason)
		}
	}
	m.LootMap["cross-project-bindings"].Contents += "\n"

	// Exploitation commands
	if len(binding.ExploitCommands) > 0 && (binding.RiskLevel == "CRITICAL" || binding.RiskLevel == "HIGH") {
		m.LootMap["cross-project-exploitation"].Contents += fmt.Sprintf(
			"## [%s] %s -> %s via %s\n",
			binding.RiskLevel, binding.SourceProject, binding.TargetProject, binding.Role,
		)
		for _, cmd := range binding.ExploitCommands {
			m.LootMap["cross-project-exploitation"].Contents += cmd + "\n"
		}
		m.LootMap["cross-project-exploitation"].Contents += "\n"
	}
}

func (m *CrossProjectModule) addServiceAccountToLoot(sa crossprojectservice.CrossProjectServiceAccount) {
	m.LootMap["cross-project-sas"].Contents += fmt.Sprintf(
		"## Service Account: %s\n"+
			"## Home Project: %s\n"+
			"## Cross-Project Access:\n",
		sa.Email, sa.ProjectID,
	)
	for _, access := range sa.TargetAccess {
		m.LootMap["cross-project-sas"].Contents += fmt.Sprintf("##   - %s\n", access)
	}
	m.LootMap["cross-project-sas"].Contents += "\n"

	// Add impersonation commands
	m.LootMap["cross-project-exploitation"].Contents += fmt.Sprintf(
		"## Impersonate cross-project SA: %s\n"+
			"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
		sa.Email, sa.Email,
	)
}

func (m *CrossProjectModule) addLateralMovementToLoot(path crossprojectservice.LateralMovementPath) {
	m.LootMap["lateral-movement-paths"].Contents += fmt.Sprintf(
		"## [%s] %s -> %s\n"+
			"## Principal: %s\n"+
			"## Method: %s\n"+
			"## Roles: %s\n",
		path.PrivilegeLevel, path.SourceProject, path.TargetProject,
		path.SourcePrincipal,
		path.AccessMethod,
		strings.Join(path.TargetRoles, ", "),
	)

	if len(path.ExploitCommands) > 0 {
		m.LootMap["lateral-movement-paths"].Contents += "## Exploitation:\n"
		for _, cmd := range path.ExploitCommands {
			m.LootMap["lateral-movement-paths"].Contents += cmd + "\n"
		}
	}
	m.LootMap["lateral-movement-paths"].Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CrossProjectModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Cross-project bindings table
	bindingsHeader := []string{
		"Risk",
		"Source Project",
		"Target Project",
		"Principal",
		"Type",
		"Role",
		"Reasons",
	}

	var bindingsBody [][]string
	for _, binding := range m.CrossBindings {
		reasons := strings.Join(binding.RiskReasons, "; ")
		if len(reasons) > 50 {
			reasons = reasons[:50] + "..."
		}

		// Shorten principal for display
		principal := binding.Principal
		if len(principal) > 40 {
			principal = principal[:37] + "..."
		}

		bindingsBody = append(bindingsBody, []string{
			binding.RiskLevel,
			binding.SourceProject,
			binding.TargetProject,
			principal,
			binding.PrincipalType,
			binding.Role,
			reasons,
		})
	}

	// Cross-project service accounts table
	sasHeader := []string{
		"Service Account",
		"Home Project",
		"# Target Projects",
		"Target Access",
	}

	var sasBody [][]string
	for _, sa := range m.CrossProjectSAs {
		// Count unique target projects
		projectSet := make(map[string]bool)
		for _, access := range sa.TargetAccess {
			parts := strings.Split(access, ":")
			if len(parts) > 0 {
				projectSet[parts[0]] = true
			}
		}

		accessSummary := strings.Join(sa.TargetAccess, "; ")
		if len(accessSummary) > 60 {
			accessSummary = accessSummary[:60] + "..."
		}

		sasBody = append(sasBody, []string{
			sa.Email,
			sa.ProjectID,
			fmt.Sprintf("%d", len(projectSet)),
			accessSummary,
		})
	}

	// Lateral movement paths table
	pathsHeader := []string{
		"Privilege",
		"Source Project",
		"Target Project",
		"Principal",
		"Method",
		"Roles",
	}

	var pathsBody [][]string
	for _, path := range m.LateralMovementPaths {
		// Shorten principal for display
		principal := path.SourcePrincipal
		if len(principal) > 40 {
			principal = principal[:37] + "..."
		}

		roles := strings.Join(path.TargetRoles, ", ")
		if len(roles) > 40 {
			roles = roles[:40] + "..."
		}

		pathsBody = append(pathsBody, []string{
			path.PrivilegeLevel,
			path.SourceProject,
			path.TargetProject,
			principal,
			path.AccessMethod,
			roles,
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
	var tables []internal.TableFile

	if len(bindingsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cross-project-bindings",
			Header: bindingsHeader,
			Body:   bindingsBody,
		})
	}

	if len(sasBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "cross-project-sas",
			Header: sasHeader,
			Body:   sasBody,
		})
	}

	if len(pathsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-movement-paths",
			Header: pathsHeader,
			Body:   pathsBody,
		})
	}

	output := CrossProjectOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
