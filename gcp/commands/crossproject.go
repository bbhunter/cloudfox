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
	Long: `Analyze cross-project access patterns to identify lateral movement paths and data flows.

This module is designed for penetration testing and identifies:
- Service accounts with access to multiple projects
- Cross-project IAM role bindings
- Potential lateral movement paths between projects
- Cross-project logging sinks (data exfiltration via logs)
- Cross-project Pub/Sub exports (data exfiltration via messages)
- Impersonation targets (which SAs can be impersonated in target projects)

Features:
- Maps cross-project service account access
- Identifies cross-project roles (owner, editor, admin)
- Discovers logging sinks sending logs to other projects
- Discovers Pub/Sub subscriptions exporting to other projects (BQ, GCS, push)
- Generates exploitation commands for lateral movement
- Highlights service accounts spanning trust boundaries
- Shows impersonation targets when --attack-paths flag is used

TIP: For a complete picture including impersonation targets and attack paths,
use the global --attack-paths flag:

  cloudfox gcp crossproject -l projects.txt --attack-paths

This will populate the Target Type, Target Principal, and Attack Path columns
with detailed information about what service accounts can be impersonated and
what privesc/exfil/lateral movement capabilities exist.

WARNING: Requires multiple projects to be specified for effective analysis.
Use -p for single project or -l for project list file.`,
	Run: runGCPCrossProjectCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CrossProjectModule struct {
	gcpinternal.BaseGCPModule

	CrossBindings         []crossprojectservice.CrossProjectBinding
	CrossProjectSAs       []crossprojectservice.CrossProjectServiceAccount
	LateralMovementPaths  []crossprojectservice.LateralMovementPath
	CrossProjectSinks     []crossprojectservice.CrossProjectLoggingSink
	CrossProjectPubSub    []crossprojectservice.CrossProjectPubSubExport
	LootMap               map[string]*internal.LootFile
	AttackPathCache       *gcpinternal.AttackPathCache
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
		CrossProjectSinks:    []crossprojectservice.CrossProjectLoggingSink{},
		CrossProjectPubSub:   []crossprojectservice.CrossProjectPubSubExport{},
		LootMap:              make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CrossProjectModule) Execute(ctx context.Context, logger internal.Logger) {
	// Get attack path cache from context (populated by all-checks or attack path analysis)
	m.AttackPathCache = gcpinternal.GetAttackPathCacheFromContext(ctx)

	// If no context cache, try loading from disk cache
	if m.AttackPathCache == nil || !m.AttackPathCache.IsPopulated() {
		diskCache, metadata, err := gcpinternal.LoadAttackPathCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.IsPopulated() {
			logger.InfoM(fmt.Sprintf("Using attack path cache from disk (created: %s)",
				metadata.CreatedAt.Format("2006-01-02 15:04:05")), globals.GCP_CROSSPROJECT_MODULE_NAME)
			m.AttackPathCache = diskCache
		}
	}

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

	// Find cross-project logging sinks
	sinks, err := svc.FindCrossProjectLoggingSinks(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find cross-project logging sinks")
	} else {
		m.CrossProjectSinks = sinks
	}

	// Find cross-project Pub/Sub exports
	pubsubExports, err := svc.FindCrossProjectPubSubExports(m.ProjectIDs)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CROSSPROJECT_MODULE_NAME,
			"Could not find cross-project Pub/Sub exports")
	} else {
		m.CrossProjectPubSub = pubsubExports
	}

	if len(m.CrossBindings) == 0 && len(m.CrossProjectSAs) == 0 && len(m.LateralMovementPaths) == 0 &&
		len(m.CrossProjectSinks) == 0 && len(m.CrossProjectPubSub) == 0 {
		logger.InfoM("No cross-project access patterns found", globals.GCP_CROSSPROJECT_MODULE_NAME)
		return
	}

	// Add findings to loot
	for _, binding := range m.CrossBindings {
		m.addBindingToLoot(binding)
	}

	for _, sa := range m.CrossProjectSAs {
		m.addServiceAccountToLoot(sa)
	}

	for _, path := range m.LateralMovementPaths {
		m.addLateralMovementToLoot(path)
	}

	for _, sink := range m.CrossProjectSinks {
		m.addLoggingSinkToLoot(sink)
	}

	for _, export := range m.CrossProjectPubSub {
		m.addPubSubExportToLoot(export)
	}

	logger.SuccessM(fmt.Sprintf("Found %d binding(s), %d SA(s), %d lateral path(s), %d logging sink(s), %d pubsub export(s)",
		len(m.CrossBindings), len(m.CrossProjectSAs), len(m.LateralMovementPaths),
		len(m.CrossProjectSinks), len(m.CrossProjectPubSub)), globals.GCP_CROSSPROJECT_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CrossProjectModule) initializeLootFiles() {
	m.LootMap["crossproject-commands"] = &internal.LootFile{
		Name:     "crossproject-commands",
		Contents: "# Cross-Project Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *CrossProjectModule) addBindingToLoot(binding crossprojectservice.CrossProjectBinding) {
	// Add exploitation commands
	if len(binding.ExploitCommands) > 0 {
		m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
			"# IAM Binding: %s -> %s\n# Principal: %s\n# Role: %s\n",
			binding.SourceProject, binding.TargetProject, binding.Principal, binding.Role,
		)
		for _, cmd := range binding.ExploitCommands {
			m.LootMap["crossproject-commands"].Contents += cmd + "\n"
		}
		m.LootMap["crossproject-commands"].Contents += "\n"
	}
}

func (m *CrossProjectModule) addServiceAccountToLoot(sa crossprojectservice.CrossProjectServiceAccount) {
	// Add impersonation commands for cross-project SAs
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"# Cross-project SA: %s (Home: %s)\n"+
			"gcloud auth print-access-token --impersonate-service-account=%s\n\n",
		sa.Email, sa.ProjectID, sa.Email,
	)
}

func (m *CrossProjectModule) addLateralMovementToLoot(path crossprojectservice.LateralMovementPath) {
	// Add lateral movement exploitation commands
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
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
			m.LootMap["crossproject-commands"].Contents += cmd + "\n"
		}
	}
	m.LootMap["crossproject-commands"].Contents += "\n"
}

func (m *CrossProjectModule) addLoggingSinkToLoot(sink crossprojectservice.CrossProjectLoggingSink) {
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"# Cross-Project Logging Sink: %s\n"+
			"# Source Project: %s -> Target Project: %s\n"+
			"# Destination: %s (%s)\n",
		sink.SinkName,
		sink.SourceProject, sink.TargetProject,
		sink.Destination, sink.DestinationType,
	)
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"gcloud logging sinks describe %s --project=%s\n\n",
		sink.SinkName, sink.SourceProject,
	)
}

func (m *CrossProjectModule) addPubSubExportToLoot(export crossprojectservice.CrossProjectPubSubExport) {
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"# Cross-Project Pub/Sub Export: %s\n"+
			"# Subscription: %s (Source: %s)\n"+
			"# Topic: %s (Project: %s)\n"+
			"# Export Type: %s -> Destination: %s\n",
		export.SubscriptionName,
		export.SubscriptionName, export.SourceProject,
		export.TopicName, export.TopicProject,
		export.ExportType,
		export.ExportDest,
	)
	m.LootMap["crossproject-commands"].Contents += fmt.Sprintf(
		"gcloud pubsub subscriptions describe %s --project=%s\n\n",
		export.SubscriptionName, export.SourceProject,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CrossProjectModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *CrossProjectModule) getHeader() []string {
	return []string{
		"Source Project",
		"Source Type",
		"Source Principal",
		"Binding Type",
		"Target Project",
		"Target Type",
		"Target Principal",
		"Target Role",
		"Attack Path",
	}
}

// getImpersonationTarget checks if a role grants impersonation capabilities and returns the target
// Returns (targetType, targetPrincipal) - both "-" if no impersonation target found
func (m *CrossProjectModule) getImpersonationTarget(principal, role, targetProject string) (string, string) {
	// Roles that grant impersonation capabilities
	impersonationRoles := map[string]bool{
		"roles/iam.serviceAccountTokenCreator": true,
		"roles/iam.serviceAccountKeyAdmin":     true,
		"iam.serviceAccountTokenCreator":       true,
		"iam.serviceAccountKeyAdmin":           true,
	}

	cleanedRole := cleanRole(role)

	// Check if this is an impersonation role
	if !impersonationRoles[role] && !impersonationRoles[cleanedRole] &&
		!strings.Contains(cleanedRole, "serviceAccountTokenCreator") &&
		!strings.Contains(cleanedRole, "serviceAccountKeyAdmin") {
		return "-", "-"
	}

	// Try to get impersonation targets from cache
	if m.AttackPathCache != nil && m.AttackPathCache.IsPopulated() {
		cleanedPrincipal := cleanPrincipal(principal)
		targets := m.AttackPathCache.GetImpersonationTargets(cleanedPrincipal)
		if len(targets) > 0 {
			// Filter targets to those in the target project
			var projectTargets []string
			for _, t := range targets {
				if strings.Contains(t, targetProject) {
					projectTargets = append(projectTargets, t)
				}
			}
			if len(projectTargets) > 0 {
				if len(projectTargets) == 1 {
					return "Service Account", projectTargets[0]
				}
				return "Service Account", fmt.Sprintf("%d SAs", len(projectTargets))
			}
			// If no project-specific targets, show all targets
			if len(targets) == 1 {
				return "Service Account", targets[0]
			}
			return "Service Account", fmt.Sprintf("%d SAs", len(targets))
		}
	}

	// No specific targets found in cache - this likely means the role was granted at the
	// project level (not on specific SAs), which means ALL SAs in the target project can be impersonated
	return "Service Account", fmt.Sprintf("All SAs in %s", m.GetProjectName(targetProject))
}

// getPrincipalTypeDisplay returns a human-readable type for the principal
func getPrincipalTypeDisplay(principal string) string {
	if strings.HasPrefix(principal, "serviceAccount:") {
		return "Service Account"
	} else if strings.HasPrefix(principal, "user:") {
		return "User"
	} else if strings.HasPrefix(principal, "group:") {
		return "Group"
	} else if strings.HasPrefix(principal, "domain:") {
		return "Domain"
	}
	return "Unknown"
}

// cleanPrincipal removes common prefixes from principal strings for cleaner display
func cleanPrincipal(principal string) string {
	// Remove serviceAccount:, user:, group: prefixes
	principal = strings.TrimPrefix(principal, "serviceAccount:")
	principal = strings.TrimPrefix(principal, "user:")
	principal = strings.TrimPrefix(principal, "group:")
	principal = strings.TrimPrefix(principal, "domain:")
	return principal
}

// cleanRole extracts just the role name from a full role path
func cleanRole(role string) string {
	// Handle full project paths like "projects/project-id/roles/customRole"
	if strings.Contains(role, "/roles/") {
		parts := strings.Split(role, "/roles/")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	// Handle standard roles like "roles/compute.admin"
	if strings.HasPrefix(role, "roles/") {
		return strings.TrimPrefix(role, "roles/")
	}
	return role
}

// extractCrossProjectResourceName extracts just the resource name from a full resource path
func extractCrossProjectResourceName(path string) string {
	// Handle various path formats
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}

// getAttackPathForTarget returns attack path summary for a principal accessing a target project
func (m *CrossProjectModule) getAttackPathForTarget(targetProject, principal string) string {
	if m.AttackPathCache == nil || !m.AttackPathCache.IsPopulated() {
		return "-"
	}

	// Clean principal for lookup
	cleanedPrincipal := cleanPrincipal(principal)

	// Check if this is a service account
	if strings.Contains(cleanedPrincipal, "@") && strings.Contains(cleanedPrincipal, ".iam.gserviceaccount.com") {
		return m.AttackPathCache.GetAttackSummary(cleanedPrincipal)
	}

	return "-"
}

func (m *CrossProjectModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

// buildTableBodyByTargetProject builds table bodies grouped by target project
// Returns a map of targetProjectID -> [][]string (rows for that target project)
func (m *CrossProjectModule) buildTableBodyByTargetProject() map[string][][]string {
	bodyByProject := make(map[string][][]string)

	// Add cross-project bindings
	for _, binding := range m.CrossBindings {
		principalType := getPrincipalTypeDisplay(binding.Principal)
		principal := cleanPrincipal(binding.Principal)
		role := cleanRole(binding.Role)
		attackPath := m.getAttackPathForTarget(binding.TargetProject, binding.Principal)
		targetType, targetPrincipal := m.getImpersonationTarget(binding.Principal, binding.Role, binding.TargetProject)

		row := []string{
			m.GetProjectName(binding.SourceProject),
			principalType,
			principal,
			"IAM Binding",
			m.GetProjectName(binding.TargetProject),
			targetType,
			targetPrincipal,
			role,
			attackPath,
		}
		bodyByProject[binding.TargetProject] = append(bodyByProject[binding.TargetProject], row)
	}

	// Add cross-project service accounts
	for _, sa := range m.CrossProjectSAs {
		for _, access := range sa.TargetAccess {
			parts := strings.SplitN(access, ": ", 2)
			targetProject := ""
			role := access
			if len(parts) == 2 {
				targetProject = parts[0]
				role = parts[1]
			}

			role = cleanRole(role)
			attackPath := m.getAttackPathForTarget(targetProject, "serviceAccount:"+sa.Email)
			targetType, targetPrincipal := m.getImpersonationTarget(sa.Email, role, targetProject)

			row := []string{
				m.GetProjectName(sa.ProjectID),
				"Service Account",
				sa.Email,
				"IAM Binding",
				m.GetProjectName(targetProject),
				targetType,
				targetPrincipal,
				role,
				attackPath,
			}
			bodyByProject[targetProject] = append(bodyByProject[targetProject], row)
		}
	}

	// Add lateral movement paths
	for _, path := range m.LateralMovementPaths {
		for _, role := range path.TargetRoles {
			principalType := getPrincipalTypeDisplay(path.SourcePrincipal)
			principal := cleanPrincipal(path.SourcePrincipal)
			cleanedRole := cleanRole(role)
			attackPath := m.getAttackPathForTarget(path.TargetProject, path.SourcePrincipal)
			targetType, targetPrincipal := m.getImpersonationTarget(path.SourcePrincipal, role, path.TargetProject)

			row := []string{
				m.GetProjectName(path.SourceProject),
				principalType,
				principal,
				path.AccessMethod,
				m.GetProjectName(path.TargetProject),
				targetType,
				targetPrincipal,
				cleanedRole,
				attackPath,
			}
			bodyByProject[path.TargetProject] = append(bodyByProject[path.TargetProject], row)
		}
	}

	// Add logging sinks - these are resources, not principals
	for _, sink := range m.CrossProjectSinks {
		dest := sink.DestinationType
		if sink.Filter != "" {
			filter := sink.Filter
			if len(filter) > 30 {
				filter = filter[:27] + "..."
			}
			dest = fmt.Sprintf("%s (%s)", sink.DestinationType, filter)
		}

		row := []string{
			m.GetProjectName(sink.SourceProject),
			"Logging Sink",
			sink.SinkName,
			"Data Export",
			m.GetProjectName(sink.TargetProject),
			"-",
			"-",
			dest,
			"-",
		}
		bodyByProject[sink.TargetProject] = append(bodyByProject[sink.TargetProject], row)
	}

	// Add Pub/Sub exports - these are resources, not principals
	for _, export := range m.CrossProjectPubSub {
		dest := export.ExportType
		if export.ExportDest != "" {
			destName := extractCrossProjectResourceName(export.ExportDest)
			dest = fmt.Sprintf("%s: %s", export.ExportType, destName)
		}

		row := []string{
			m.GetProjectName(export.SourceProject),
			"Pub/Sub",
			export.SubscriptionName,
			"Data Export",
			m.GetProjectName(export.TargetProject),
			"-",
			"-",
			dest,
			"-",
		}
		bodyByProject[export.TargetProject] = append(bodyByProject[export.TargetProject], row)
	}

	return bodyByProject
}

func (m *CrossProjectModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	// For crossproject, output at project level grouped by TARGET project
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	header := m.getHeader()
	bodyByProject := m.buildTableBodyByTargetProject()
	lootFiles := m.collectLootFiles()

	// Create output for each target project
	for targetProject, body := range bodyByProject {
		if len(body) == 0 {
			continue
		}

		tables := []internal.TableFile{
			{
				Name:   "crossproject",
				Header: header,
				Body:   body,
			},
		}

		output := CrossProjectOutput{
			Table: tables,
			Loot:  lootFiles, // Loot files are shared across all projects
		}

		outputData.ProjectLevelData[targetProject] = output
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_CROSSPROJECT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

func (m *CrossProjectModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	header := m.getHeader()
	bodyByProject := m.buildTableBodyByTargetProject()
	lootFiles := m.collectLootFiles()

	// Write output for each target project separately
	for targetProject, body := range bodyByProject {
		if len(body) == 0 {
			continue
		}

		tables := []internal.TableFile{
			{
				Name:   "crossproject",
				Header: header,
				Body:   body,
			},
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
			[]string{targetProject},
			[]string{m.GetProjectName(targetProject)},
			m.Account,
			output,
		)
		if err != nil {
			logger.ErrorM(fmt.Sprintf("Error writing output for project %s: %v", targetProject, err), globals.GCP_CROSSPROJECT_MODULE_NAME)
			m.CommandCounter.Error++
		}
	}
}
