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
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not analyze cross-project access")
	} else {
		m.CrossBindings = bindings
	}

	// Get cross-project service accounts
	sas, err := svc.GetCrossProjectServiceAccounts(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not get cross-project service accounts")
	} else {
		m.CrossProjectSAs = sas
	}

	// Find lateral movement paths
	paths, err := svc.FindLateralMovementPaths(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find lateral movement paths")
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
	m.LootMap["crossproject-exploit-commands"] = &internal.LootFile{
		Name:     "crossproject-exploit-commands",
		Contents: "# Cross-Project Exploit Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["crossproject-enum-commands"] = &internal.LootFile{
		Name:     "crossproject-enum-commands",
		Contents: "# Cross-Project Enumeration Commands\n# External/Cross-Tenant principals with access to your projects\n# Generated by CloudFox\n\n",
	}
}

func (m *CrossProjectModule) addBindingToLoot(binding crossprojectservice.CrossProjectBinding) {
	// Add exploitation commands
	if len(binding.ExploitCommands) > 0 {
		m.LootMap["crossproject-exploit-commands"].Contents += fmt.Sprintf(
			"# %s -> %s (Principal: %s, Role: %s)\n",
			binding.SourceProject, binding.TargetProject, binding.Principal, binding.Role,
		)
		for _, cmd := range binding.ExploitCommands {
			m.LootMap["crossproject-exploit-commands"].Contents += cmd + "\n"
		}
		m.LootMap["crossproject-exploit-commands"].Contents += "\n"
	}

	// Check for cross-tenant/external access
	if isCrossTenantPrincipal(binding.Principal, m.ProjectIDs) {
		m.LootMap["crossproject-enum-commands"].Contents += fmt.Sprintf(
			"# External Principal: %s\n"+
				"# Target Project: %s\n"+
				"# Role: %s\n",
			binding.Principal,
			binding.TargetProject,
			binding.Role,
		)

		// External service accounts - add check command
		if strings.Contains(binding.Principal, "serviceAccount:") {
			m.LootMap["crossproject-enum-commands"].Contents += fmt.Sprintf(
				"gcloud projects get-iam-policy %s --flatten='bindings[].members' --filter='bindings.members:%s'\n",
				binding.TargetProject,
				strings.TrimPrefix(binding.Principal, "serviceAccount:"),
			)
		}
		m.LootMap["crossproject-enum-commands"].Contents += "\n"
	}
}

// isCrossTenantPrincipal checks if a principal is from outside the organization
func isCrossTenantPrincipal(principal string, projectIDs []string) bool {
	// Extract service account email
	email := strings.TrimPrefix(principal, "serviceAccount:")
	email = strings.TrimPrefix(email, "user:")
	email = strings.TrimPrefix(email, "group:")

	// Check if the email domain is gserviceaccount.com (service account)
	if strings.Contains(email, "@") && strings.Contains(email, ".iam.gserviceaccount.com") {
		// Extract project from SA email
		// Format: NAME@PROJECT.iam.gserviceaccount.com
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			domain := parts[1]
			saProject := strings.TrimSuffix(domain, ".iam.gserviceaccount.com")

			// Check if SA's project is in our project list
			for _, p := range projectIDs {
				if p == saProject {
					return false // It's from within our organization
				}
			}
			return true // External SA
		}
	}

	// Check for compute/appspot service accounts
	if strings.Contains(email, "-compute@developer.gserviceaccount.com") ||
		strings.Contains(email, "@appspot.gserviceaccount.com") {
		// Extract project number/ID
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			projectPart := strings.Split(parts[0], "-")[0]
			for _, p := range projectIDs {
				if strings.Contains(p, projectPart) {
					return false
				}
			}
			return true
		}
	}

	// For regular users, check domain
	if strings.Contains(email, "@") && !strings.Contains(email, "gserviceaccount.com") {
		// Can't determine organization from email alone
		return false
	}

	return false
}

func (m *CrossProjectModule) addServiceAccountToLoot(sa crossprojectservice.CrossProjectServiceAccount) {
	// Add impersonation commands for cross-project SAs
	m.LootMap["crossproject-exploit-commands"].Contents += fmt.Sprintf(
		"# Cross-project SA: %s (Home: %s)\n"+
			"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
		sa.Email, sa.ProjectID, sa.Email,
	)
}

func (m *CrossProjectModule) addLateralMovementToLoot(path crossprojectservice.LateralMovementPath) {
	// Add lateral movement exploitation commands
	m.LootMap["crossproject-exploit-commands"].Contents += fmt.Sprintf(
		"# Lateral Movement: %s -> %s\n"+
			"# Principal: %s\n"+
			"# Method: %s\n"+
			"# Target Roles: %s\n",
		path.SourceProject, path.TargetProject,
		path.SourcePrincipal,
		path.AccessMethod,
		strings.Join(path.TargetRoles, ", "),
	)

	if len(path.ExploitCommands) > 0 {
		for _, cmd := range path.ExploitCommands {
			m.LootMap["crossproject-exploit-commands"].Contents += cmd + "\n"
		}
	}
	m.LootMap["crossproject-exploit-commands"].Contents += "\n"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CrossProjectModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Cross-project bindings table
	// Reads: Source principal from source project has role on target project
	bindingsHeader := []string{
		"Source Project Name",
		"Source Project ID",
		"Source Principal",
		"Source Principal Type",
		"Action",
		"Target Project Name",
		"Target Project ID",
		"Target Role",
		"External",
	}

	var bindingsBody [][]string
	for _, binding := range m.CrossBindings {
		// Check if external/cross-tenant
		external := "No"
		if isCrossTenantPrincipal(binding.Principal, m.ProjectIDs) {
			external = "Yes"
		}

		// Action is always "direct IAM binding" for cross-project bindings
		action := "direct IAM binding"

		bindingsBody = append(bindingsBody, []string{
			m.GetProjectName(binding.SourceProject),
			binding.SourceProject,
			binding.Principal,
			binding.PrincipalType,
			action,
			m.GetProjectName(binding.TargetProject),
			binding.TargetProject,
			binding.Role,
			external,
		})
	}

	// Cross-project service accounts table
	// Reads: Source SA from source project has access to target projects
	sasHeader := []string{
		"Source Project Name",
		"Source Project ID",
		"Source Service Account",
		"Action",
		"Target Project Count",
		"Target Access (project:role)",
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

		// Action describes how the SA has cross-project access
		action := "cross-project access"

		// Join target access with newlines for readability
		accessList := strings.Join(sa.TargetAccess, "\n")

		sasBody = append(sasBody, []string{
			m.GetProjectName(sa.ProjectID),
			sa.ProjectID,
			sa.Email,
			action,
			fmt.Sprintf("%d", len(projectSet)),
			accessList,
		})
	}

	// Lateral movement paths table
	// Reads: Source principal from source project can move to target project via method
	pathsHeader := []string{
		"Source Project Name",
		"Source Project ID",
		"Source Principal",
		"Action",
		"Target Project Name",
		"Target Project ID",
		"Target Roles",
	}

	var pathsBody [][]string
	for _, path := range m.LateralMovementPaths {
		// Use access method as action (human-readable)
		action := path.AccessMethod

		// Join roles with newlines for readability
		roles := strings.Join(path.TargetRoles, "\n")

		pathsBody = append(pathsBody, []string{
			m.GetProjectName(path.SourceProject),
			path.SourceProject,
			path.SourcePrincipal,
			action,
			m.GetProjectName(path.TargetProject),
			path.TargetProject,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
