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
	// Cross-tenant/external access loot files
	m.LootMap["cross-tenant-access"] = &internal.LootFile{
		Name:     "cross-tenant-access",
		Contents: "# Cross-Tenant/External Access\n# Principals from outside the organization with access to your projects\n# Generated by CloudFox\n\n",
	}
	m.LootMap["cross-tenant-external-sas"] = &internal.LootFile{
		Name:     "cross-tenant-external-sas",
		Contents: "# External Service Accounts with Access\n# Service accounts from other organizations/projects\n# Generated by CloudFox\n\n",
	}
	m.LootMap["cross-project-security-recommendations"] = &internal.LootFile{
		Name:     "cross-project-security-recommendations",
		Contents: "# Cross-Project/Cross-Tenant Security Recommendations\n# Generated by CloudFox\n\n",
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

	// Check for cross-tenant/external access
	if isCrossTenantPrincipal(binding.Principal, m.ProjectIDs) {
		m.LootMap["cross-tenant-access"].Contents += fmt.Sprintf(
			"# EXTERNAL ACCESS: %s\n"+
				"# Target Project: %s\n"+
				"# Source (external): %s\n"+
				"# Role: %s\n"+
				"# Risk Level: %s\n"+
				"# This principal is from outside your organization!\n\n",
			binding.Principal,
			binding.TargetProject,
			binding.SourceProject,
			binding.Role,
			binding.RiskLevel,
		)

		// External service accounts
		if strings.Contains(binding.Principal, "serviceAccount:") {
			m.LootMap["cross-tenant-external-sas"].Contents += fmt.Sprintf(
				"# External Service Account: %s\n"+
					"# Has access to project: %s\n"+
					"# Role: %s\n"+
					"# Check this SA's permissions:\n"+
					"gcloud projects get-iam-policy %s --flatten='bindings[].members' --filter='bindings.members:%s'\n\n",
				strings.TrimPrefix(binding.Principal, "serviceAccount:"),
				binding.TargetProject,
				binding.Role,
				binding.TargetProject,
				strings.TrimPrefix(binding.Principal, "serviceAccount:"),
			)
		}
	}

	// Add security recommendations
	m.addBindingSecurityRecommendations(binding)

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

// addBindingSecurityRecommendations generates security recommendations for a cross-project binding
func (m *CrossProjectModule) addBindingSecurityRecommendations(binding crossprojectservice.CrossProjectBinding) {
	var recommendations []string

	// CRITICAL: Owner/Editor roles across projects
	if strings.Contains(binding.Role, "owner") || strings.Contains(binding.Role, "editor") {
		recommendations = append(recommendations,
			fmt.Sprintf("[CRITICAL] %s has %s role across projects (%s -> %s)\n"+
				"  Risk: Full administrative access to another project\n"+
				"  Fix: Use least-privilege roles instead of owner/editor\n"+
				"  gcloud projects remove-iam-policy-binding %s --member='%s' --role='%s'\n",
				binding.Principal, binding.Role, binding.SourceProject, binding.TargetProject,
				binding.TargetProject, binding.Principal, binding.Role))
	}

	// HIGH: Admin roles across projects
	if strings.Contains(binding.Role, "admin") && !strings.Contains(binding.Role, "owner") {
		recommendations = append(recommendations,
			fmt.Sprintf("[HIGH] %s has admin role %s in project %s\n"+
				"  Risk: Administrative access from external project\n"+
				"  Review: Verify this cross-project access is necessary\n"+
				"  gcloud projects get-iam-policy %s --flatten='bindings[].members' --filter='bindings.members:%s'\n",
				binding.Principal, binding.Role, binding.TargetProject,
				binding.TargetProject, binding.Principal))
	}

	// External service account access
	if isCrossTenantPrincipal(binding.Principal, m.ProjectIDs) {
		recommendations = append(recommendations,
			fmt.Sprintf("[HIGH] External principal %s has access to project %s\n"+
				"  Risk: Principal from outside your organization has access\n"+
				"  Review: Verify this external access is authorized\n"+
				"  Fix: Remove external access if not needed:\n"+
				"  gcloud projects remove-iam-policy-binding %s --member='%s' --role='%s'\n",
				binding.Principal, binding.TargetProject,
				binding.TargetProject, binding.Principal, binding.Role))
	}

	if len(recommendations) > 0 {
		m.LootMap["cross-project-security-recommendations"].Contents += fmt.Sprintf(
			"# Binding: %s -> %s\n%s\n",
			binding.SourceProject, binding.TargetProject,
			strings.Join(recommendations, "\n"))
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
		"Source Project Name",
		"Source Project",
		"Target Project Name",
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
			m.GetProjectName(binding.SourceProject),
			binding.SourceProject,
			m.GetProjectName(binding.TargetProject),
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
		"Home Project Name",
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
			m.GetProjectName(sa.ProjectID),
			sa.ProjectID,
			fmt.Sprintf("%d", len(projectSet)),
			accessSummary,
		})
	}

	// Lateral movement paths table
	pathsHeader := []string{
		"Privilege",
		"Source Project Name",
		"Source Project",
		"Target Project Name",
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
			m.GetProjectName(path.SourceProject),
			path.SourceProject,
			m.GetProjectName(path.TargetProject),
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
