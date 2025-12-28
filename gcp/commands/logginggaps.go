package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	logginggapsservice "github.com/BishopFox/cloudfox/gcp/services/loggingGapsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPLoggingGapsCommand = &cobra.Command{
	Use:     globals.GCP_LOGGINGGAPS_MODULE_NAME,
	Aliases: []string{"log-gaps", "stealth", "blind-spots"},
	Short:   "Find resources with missing or incomplete logging",
	Long: `Identify logging gaps across GCP resources for stealth assessment.

This module helps identify resources where actions may not be properly logged,
which is valuable for understanding detection blind spots.

Resources Checked:
- Cloud Storage buckets (access logging)
- VPC subnets (flow logs)
- GKE clusters (workload and system logging)
- Cloud SQL instances (query and connection logging)
- Log sinks and exclusions (export gaps)
- Project-level audit logging configuration

Output:
- Resources with disabled or partial logging
- Stealth value rating (CRITICAL, HIGH, MEDIUM, LOW)
- Specific missing log types
- Recommendations for defenders
- Commands for testing detection gaps

Stealth Value Ratings:
- CRITICAL: No logging, actions completely invisible
- HIGH: Significant gaps enabling undetected activity
- MEDIUM: Some logging present but incomplete
- LOW: Minor gaps with limited stealth value`,
	Run: runGCPLoggingGapsCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type LoggingGapsModule struct {
	gcpinternal.BaseGCPModule

	Gaps         []logginggapsservice.LoggingGap
	AuditConfigs []*logginggapsservice.AuditLogConfig
	LootMap      map[string]*internal.LootFile
	mu           sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type LoggingGapsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LoggingGapsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LoggingGapsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPLoggingGapsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_LOGGINGGAPS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &LoggingGapsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Gaps:          []logginggapsservice.LoggingGap{},
		AuditConfigs:  []*logginggapsservice.AuditLogConfig{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LoggingGapsModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_LOGGINGGAPS_MODULE_NAME, m.processProject)

	if len(m.Gaps) == 0 {
		logger.InfoM("No logging gaps found - environment has good logging coverage", globals.GCP_LOGGINGGAPS_MODULE_NAME)
		return
	}

	// Count by stealth value
	criticalCount := 0
	highCount := 0
	for _, gap := range m.Gaps {
		switch gap.StealthValue {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d logging gap(s)", len(m.Gaps)), globals.GCP_LOGGINGGAPS_MODULE_NAME)
	if criticalCount > 0 || highCount > 0 {
		logger.InfoM(fmt.Sprintf("[STEALTH] %d CRITICAL, %d HIGH stealth value gaps!", criticalCount, highCount), globals.GCP_LOGGINGGAPS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LoggingGapsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Scanning logging gaps in project: %s", projectID), globals.GCP_LOGGINGGAPS_MODULE_NAME)
	}

	svc := logginggapsservice.New()
	gaps, auditConfig, err := svc.EnumerateLoggingGaps(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error scanning project %s: %v", projectID, err), globals.GCP_LOGGINGGAPS_MODULE_NAME)
		}
		return
	}

	m.mu.Lock()
	m.Gaps = append(m.Gaps, gaps...)
	if auditConfig != nil {
		m.AuditConfigs = append(m.AuditConfigs, auditConfig)
	}

	for _, gap := range gaps {
		m.addGapToLoot(gap)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d logging gap(s) in project %s", len(gaps), projectID), globals.GCP_LOGGINGGAPS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LoggingGapsModule) initializeLootFiles() {
	m.LootMap["logging-gaps-all"] = &internal.LootFile{
		Name:     "logging-gaps-all",
		Contents: "# All Logging Gaps\n# Generated by CloudFox\n\n",
	}
	m.LootMap["logging-gaps-critical"] = &internal.LootFile{
		Name:     "logging-gaps-critical",
		Contents: "# CRITICAL Stealth Value Gaps\n# Generated by CloudFox\n# Actions on these resources are essentially invisible\n\n",
	}
	m.LootMap["logging-gaps-stealth-commands"] = &internal.LootFile{
		Name:     "logging-gaps-stealth-commands",
		Contents: "# Commands for Stealthy Activity\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["logging-gaps-remediation"] = &internal.LootFile{
		Name:     "logging-gaps-remediation",
		Contents: "# Logging Gap Remediation\n# Generated by CloudFox\n# Recommendations for defenders\n\n",
	}
}

func (m *LoggingGapsModule) addGapToLoot(gap logginggapsservice.LoggingGap) {
	// Add to all gaps
	m.LootMap["logging-gaps-all"].Contents += fmt.Sprintf(
		"## [%s] %s: %s\n"+
			"## Project: %s, Location: %s\n"+
			"## Status: %s\n"+
			"## Missing:\n",
		gap.StealthValue, gap.ResourceType, gap.ResourceName,
		gap.ProjectID, gap.Location,
		gap.LoggingStatus,
	)
	for _, missing := range gap.MissingLogs {
		m.LootMap["logging-gaps-all"].Contents += fmt.Sprintf("##   - %s\n", missing)
	}
	m.LootMap["logging-gaps-all"].Contents += "\n"

	// Add critical gaps separately
	if gap.StealthValue == "CRITICAL" {
		m.LootMap["logging-gaps-critical"].Contents += fmt.Sprintf(
			"## [CRITICAL] %s: %s\n"+
				"## Project: %s\n"+
				"## Missing Logs:\n",
			gap.ResourceType, gap.ResourceName,
			gap.ProjectID,
		)
		for _, missing := range gap.MissingLogs {
			m.LootMap["logging-gaps-critical"].Contents += fmt.Sprintf("##   - %s\n", missing)
		}
		m.LootMap["logging-gaps-critical"].Contents += "\n"
	}

	// Add stealth commands
	if len(gap.ExploitCommands) > 0 {
		m.LootMap["logging-gaps-stealth-commands"].Contents += fmt.Sprintf(
			"## [%s] %s: %s (%s)\n",
			gap.StealthValue, gap.ResourceType, gap.ResourceName, gap.ProjectID,
		)
		for _, cmd := range gap.ExploitCommands {
			m.LootMap["logging-gaps-stealth-commands"].Contents += cmd + "\n"
		}
		m.LootMap["logging-gaps-stealth-commands"].Contents += "\n"
	}

	// Add remediation
	if len(gap.Recommendations) > 0 {
		m.LootMap["logging-gaps-remediation"].Contents += fmt.Sprintf(
			"## %s: %s (%s)\n",
			gap.ResourceType, gap.ResourceName, gap.ProjectID,
		)
		for _, rec := range gap.Recommendations {
			m.LootMap["logging-gaps-remediation"].Contents += fmt.Sprintf("# %s\n", rec)
		}
		m.LootMap["logging-gaps-remediation"].Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LoggingGapsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main gaps table
	header := []string{
		"Stealth",
		"Type",
		"Resource",
		"Status",
		"Missing Logs",
		"Project",
	}

	var body [][]string
	for _, gap := range m.Gaps {
		missingLogs := strings.Join(gap.MissingLogs, "; ")
		if len(missingLogs) > 50 {
			missingLogs = missingLogs[:50] + "..."
		}

		body = append(body, []string{
			gap.StealthValue,
			gap.ResourceType,
			gap.ResourceName,
			gap.LoggingStatus,
			missingLogs,
			gap.ProjectID,
		})
	}

	// Summary by type table
	typeHeader := []string{
		"Resource Type",
		"Count",
		"Critical",
		"High",
	}

	typeCounts := make(map[string]struct {
		total    int
		critical int
		high     int
	})

	for _, gap := range m.Gaps {
		counts := typeCounts[gap.ResourceType]
		counts.total++
		if gap.StealthValue == "CRITICAL" {
			counts.critical++
		} else if gap.StealthValue == "HIGH" {
			counts.high++
		}
		typeCounts[gap.ResourceType] = counts
	}

	var typeBody [][]string
	for resourceType, counts := range typeCounts {
		typeBody = append(typeBody, []string{
			resourceType,
			fmt.Sprintf("%d", counts.total),
			fmt.Sprintf("%d", counts.critical),
			fmt.Sprintf("%d", counts.high),
		})
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
			Name:   "logging-gaps",
			Header: header,
			Body:   body,
		},
	}

	if len(typeBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "logging-gaps-summary",
			Header: typeHeader,
			Body:   typeBody,
		})
	}

	output := LoggingGapsOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_LOGGINGGAPS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
