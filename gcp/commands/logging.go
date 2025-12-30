package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	LoggingService "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPLoggingCommand = &cobra.Command{
	Use:     globals.GCP_LOGGING_MODULE_NAME,
	Aliases: []string{"logs", "sinks", "log-sinks"},
	Short:   "Enumerate Cloud Logging sinks and metrics with security analysis",
	Long: `Enumerate Cloud Logging sinks and log-based metrics across projects.

Features:
- Lists all logging sinks (log exports)
- Shows sink destinations (Storage, BigQuery, Pub/Sub, Logging buckets)
- Identifies cross-project log exports
- Shows sink filters and exclusions
- Lists log-based metrics for alerting
- Generates gcloud commands for further analysis

Security Columns:
- Destination: Where logs are exported (bucket, dataset, topic)
- CrossProject: Whether logs are exported to another project
- WriterIdentity: Service account used for export
- Filter: What logs are included/excluded

Attack Surface:
- Cross-project exports may leak logs to external projects
- Sink writer identity may have excessive permissions
- Disabled sinks may indicate log evasion
- Missing sinks may indicate lack of log retention`,
	Run: runGCPLoggingCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type LoggingModule struct {
	gcpinternal.BaseGCPModule

	Sinks   []LoggingService.SinkInfo
	Metrics []LoggingService.MetricInfo
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type LoggingOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LoggingOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LoggingOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPLoggingCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_LOGGING_MODULE_NAME)
	if err != nil {
		return
	}

	module := &LoggingModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Sinks:         []LoggingService.SinkInfo{},
		Metrics:       []LoggingService.MetricInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LoggingModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_LOGGING_MODULE_NAME, m.processProject)

	if len(m.Sinks) == 0 && len(m.Metrics) == 0 {
		logger.InfoM("No logging sinks or metrics found", globals.GCP_LOGGING_MODULE_NAME)
		return
	}

	// Count interesting sinks
	crossProjectCount := 0
	disabledCount := 0
	for _, sink := range m.Sinks {
		if sink.IsCrossProject {
			crossProjectCount++
		}
		if sink.Disabled {
			disabledCount++
		}
	}

	msg := fmt.Sprintf("Found %d sink(s), %d metric(s)", len(m.Sinks), len(m.Metrics))
	if crossProjectCount > 0 {
		msg += fmt.Sprintf(" [%d cross-project]", crossProjectCount)
	}
	if disabledCount > 0 {
		msg += fmt.Sprintf(" [%d disabled]", disabledCount)
	}
	logger.SuccessM(msg, globals.GCP_LOGGING_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LoggingModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Logging in project: %s", projectID), globals.GCP_LOGGING_MODULE_NAME)
	}

	ls := LoggingService.New()

	// Get sinks
	sinks, err := ls.Sinks(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating logging sinks in project %s: %v", projectID, err), globals.GCP_LOGGING_MODULE_NAME)
		}
	} else {
		m.mu.Lock()
		m.Sinks = append(m.Sinks, sinks...)
		for _, sink := range sinks {
			m.addSinkToLoot(sink)
		}
		m.mu.Unlock()
	}

	// Get metrics
	metrics, err := ls.Metrics(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating log metrics in project %s: %v", projectID, err), globals.GCP_LOGGING_MODULE_NAME)
		}
	} else {
		m.mu.Lock()
		m.Metrics = append(m.Metrics, metrics...)
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d sink(s), %d metric(s) in project %s", len(sinks), len(metrics), projectID), globals.GCP_LOGGING_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LoggingModule) initializeLootFiles() {
	m.LootMap["logging-gcloud-commands"] = &internal.LootFile{
		Name:     "logging-gcloud-commands",
		Contents: "# Cloud Logging gcloud Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["logging-cross-project"] = &internal.LootFile{
		Name:     "logging-cross-project",
		Contents: "# Cross-Project Log Exports\n# Generated by CloudFox\n# These sinks export logs to external projects\n\n",
	}
	m.LootMap["logging-writer-identities"] = &internal.LootFile{
		Name:     "logging-writer-identities",
		Contents: "# Logging Sink Writer Identities\n# Generated by CloudFox\n# Service accounts that have write access to destinations\n\n",
	}
	m.LootMap["logging-exploitation"] = &internal.LootFile{
		Name:     "logging-exploitation",
		Contents: "# Logging Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	// New enhancement loot files
	m.LootMap["logging-disabled-sinks"] = &internal.LootFile{
		Name:     "logging-disabled-sinks",
		Contents: "# Disabled Logging Sinks\n# These sinks are not exporting logs - potential log evasion\n# Generated by CloudFox\n\n",
	}
	m.LootMap["logging-exclusion-filters"] = &internal.LootFile{
		Name:     "logging-exclusion-filters",
		Contents: "# Logging Sink Exclusion Filters\n# These filters exclude specific logs from export\n# Generated by CloudFox\n\n",
	}
	m.LootMap["logging-storage-destinations"] = &internal.LootFile{
		Name:     "logging-storage-destinations",
		Contents: "# Cloud Storage Log Destinations\n# Log export buckets to investigate\n# Generated by CloudFox\n\n",
	}
	m.LootMap["logging-bigquery-destinations"] = &internal.LootFile{
		Name:     "logging-bigquery-destinations",
		Contents: "# BigQuery Log Destinations\n# Log export datasets for querying\n# Generated by CloudFox\n\n",
	}
	m.LootMap["logging-security-recommendations"] = &internal.LootFile{
		Name:     "logging-security-recommendations",
		Contents: "# Cloud Logging Security Recommendations\n# Generated by CloudFox\n\n",
	}
}

func (m *LoggingModule) addSinkToLoot(sink LoggingService.SinkInfo) {
	// gcloud commands
	m.LootMap["logging-gcloud-commands"].Contents += fmt.Sprintf(
		"# Sink: %s (Project: %s)\n"+
			"gcloud logging sinks describe %s --project=%s\n\n",
		sink.Name, sink.ProjectID,
		sink.Name, sink.ProjectID,
	)

	// Cross-project exports
	if sink.IsCrossProject {
		m.LootMap["logging-cross-project"].Contents += fmt.Sprintf(
			"# SINK: %s\n"+
				"# Source Project: %s\n"+
				"# Destination Project: %s\n"+
				"# Destination Type: %s\n"+
				"# Destination: %s\n"+
				"# Filter: %s\n"+
				"# Writer Identity: %s\n\n",
			sink.Name,
			sink.ProjectID,
			sink.DestinationProject,
			sink.DestinationType,
			sink.Destination,
			truncateFilter(sink.Filter),
			sink.WriterIdentity,
		)
	}

	// Writer identities
	if sink.WriterIdentity != "" {
		m.LootMap["logging-writer-identities"].Contents += fmt.Sprintf(
			"# Sink: %s -> %s\n"+
				"%s\n\n",
			sink.Name, sink.DestinationType,
			sink.WriterIdentity,
		)
	}

	// Disabled sinks - potential log evasion
	if sink.Disabled {
		m.LootMap["logging-disabled-sinks"].Contents += fmt.Sprintf(
			"# DISABLED SINK: %s\n"+
				"# Project: %s\n"+
				"# Destination: %s (%s)\n"+
				"# This sink is not exporting logs!\n"+
				"# Re-enable: gcloud logging sinks update %s --no-disabled --project=%s\n\n",
			sink.Name,
			sink.ProjectID,
			sink.DestinationType, getDestinationName(sink),
			sink.Name, sink.ProjectID,
		)
	}

	// Exclusion filters - may hide malicious activity
	if len(sink.ExclusionFilters) > 0 {
		m.LootMap["logging-exclusion-filters"].Contents += fmt.Sprintf(
			"# Sink: %s (Project: %s)\n"+
				"# Destination: %s\n"+
				"# Exclusion Filters (%d):\n",
			sink.Name, sink.ProjectID,
			getDestinationName(sink),
			len(sink.ExclusionFilters),
		)
		for i, filter := range sink.ExclusionFilters {
			m.LootMap["logging-exclusion-filters"].Contents += fmt.Sprintf(
				"#   [%d] %s\n",
				i+1, filter,
			)
		}
		m.LootMap["logging-exclusion-filters"].Contents += "\n"
	}

	// Storage destinations
	if sink.DestinationType == "storage" && sink.DestinationBucket != "" {
		m.LootMap["logging-storage-destinations"].Contents += fmt.Sprintf(
			"# Sink: %s (Project: %s)\n"+
				"# Bucket: %s\n"+
				"# Cross-Project: %v\n"+
				"gsutil ls gs://%s/\n"+
				"gsutil ls -r gs://%s/ | head -50\n"+
				"# Sample logs:\n"+
				"gsutil cat gs://%s/$(gsutil ls gs://%s/ | head -1)/*.json 2>/dev/null | head -20\n\n",
			sink.Name, sink.ProjectID,
			sink.DestinationBucket,
			sink.IsCrossProject,
			sink.DestinationBucket,
			sink.DestinationBucket,
			sink.DestinationBucket, sink.DestinationBucket,
		)
	}

	// BigQuery destinations
	if sink.DestinationType == "bigquery" && sink.DestinationDataset != "" {
		destProject := sink.DestinationProject
		if destProject == "" {
			destProject = sink.ProjectID
		}
		m.LootMap["logging-bigquery-destinations"].Contents += fmt.Sprintf(
			"# Sink: %s (Project: %s)\n"+
				"# Dataset: %s.%s\n"+
				"# Cross-Project: %v\n"+
				"bq ls %s:%s\n"+
				"# Query recent logs:\n"+
				"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s.*` WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY) LIMIT 100'\n\n",
			sink.Name, sink.ProjectID,
			destProject, sink.DestinationDataset,
			sink.IsCrossProject,
			destProject, sink.DestinationDataset,
			destProject, sink.DestinationDataset,
		)
	}

	// Add security recommendations
	m.addSinkSecurityRecommendations(sink)

	// Exploitation commands
	m.LootMap["logging-exploitation"].Contents += fmt.Sprintf(
		"# Sink: %s (Project: %s)\n"+
			"# Destination: %s (%s)\n"+
			"# Disabled: %v\n\n"+
			"# Read logs from destination:\n",
		sink.Name, sink.ProjectID,
		sink.DestinationType, getDestinationName(sink),
		sink.Disabled,
	)

	switch sink.DestinationType {
	case "storage":
		m.LootMap["logging-exploitation"].Contents += fmt.Sprintf(
			"gsutil ls gs://%s/\n"+
				"gsutil cat gs://%s/**.json | head -100\n\n",
			sink.DestinationBucket, sink.DestinationBucket,
		)
	case "bigquery":
		m.LootMap["logging-exploitation"].Contents += fmt.Sprintf(
			"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s.*` LIMIT 100'\n\n",
			sink.DestinationProject, sink.DestinationDataset,
		)
	case "pubsub":
		m.LootMap["logging-exploitation"].Contents += fmt.Sprintf(
			"# Create subscription to capture logs:\n"+
				"gcloud pubsub subscriptions create log-capture --topic=%s --project=%s\n"+
				"gcloud pubsub subscriptions pull log-capture --limit=10 --auto-ack --project=%s\n\n",
			sink.DestinationTopic, sink.DestinationProject, sink.DestinationProject,
		)
	}

	m.LootMap["logging-exploitation"].Contents += fmt.Sprintf(
		"# Disable sink (if you have logging.sinks.update):\n"+
			"gcloud logging sinks update %s --disabled --project=%s\n\n"+
			"# Delete sink (if you have logging.sinks.delete):\n"+
			"gcloud logging sinks delete %s --project=%s\n\n",
		sink.Name, sink.ProjectID,
		sink.Name, sink.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LoggingModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sinks table
	sinksHeader := []string{
		"Project Name",
		"Project ID",
		"Sink Name",
		"Destination Type",
		"Destination",
		"Cross-Project",
		"Disabled",
		"Filter",
	}

	var sinksBody [][]string
	for _, sink := range m.Sinks {
		// Format destination
		destination := getDestinationName(sink)

		// Format cross-project
		crossProject := "No"
		if sink.IsCrossProject {
			crossProject = fmt.Sprintf("Yes -> %s", sink.DestinationProject)
		}

		// Format disabled
		disabled := "No"
		if sink.Disabled {
			disabled = "YES"
		}

		// Format filter
		filter := "-"
		if sink.Filter != "" {
			filter = truncateFilter(sink.Filter)
		}

		sinksBody = append(sinksBody, []string{
			m.GetProjectName(sink.ProjectID),
			sink.ProjectID,
			sink.Name,
			sink.DestinationType,
			destination,
			crossProject,
			disabled,
			filter,
		})
	}

	// Metrics table
	metricsHeader := []string{
		"Project Name",
		"Project ID",
		"Metric Name",
		"Description",
		"Filter",
		"Type",
	}

	var metricsBody [][]string
	for _, metric := range m.Metrics {
		// Format description
		description := metric.Description
		if len(description) > 40 {
			description = description[:37] + "..."
		}

		// Format filter
		filter := truncateFilter(metric.Filter)

		// Format type
		metricType := metric.MetricKind
		if metric.ValueType != "" {
			metricType += "/" + metric.ValueType
		}

		metricsBody = append(metricsBody, []string{
			m.GetProjectName(metric.ProjectID),
			metric.ProjectID,
			metric.Name,
			description,
			filter,
			metricType,
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
	tableFiles := []internal.TableFile{}

	if len(sinksBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-sinks",
			Header: sinksHeader,
			Body:   sinksBody,
		})
	}

	if len(metricsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-metrics",
			Header: metricsHeader,
			Body:   metricsBody,
		})
	}

	output := LoggingOutput{
		Table: tableFiles,
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_LOGGING_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// getDestinationName returns a human-readable destination name
func getDestinationName(sink LoggingService.SinkInfo) string {
	switch sink.DestinationType {
	case "storage":
		return sink.DestinationBucket
	case "bigquery":
		return sink.DestinationDataset
	case "pubsub":
		return sink.DestinationTopic
	case "logging":
		// Extract bucket name from full path
		parts := strings.Split(sink.Destination, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
		return sink.Destination
	default:
		return sink.Destination
	}
}

// truncateFilter truncates a log filter for display
func truncateFilter(filter string) string {
	// Remove newlines
	filter = strings.ReplaceAll(filter, "\n", " ")
	filter = strings.ReplaceAll(filter, "\t", " ")

	// Collapse multiple spaces
	for strings.Contains(filter, "  ") {
		filter = strings.ReplaceAll(filter, "  ", " ")
	}

	// Truncate
	if len(filter) > 50 {
		return filter[:47] + "..."
	}
	return filter
}

// ------------------------------
// Security Recommendations
// ------------------------------

// addSinkSecurityRecommendations generates security recommendations for a logging sink
func (m *LoggingModule) addSinkSecurityRecommendations(sink LoggingService.SinkInfo) {
	var recommendations []string

	// Disabled sink - CRITICAL (log evasion)
	if sink.Disabled {
		recommendations = append(recommendations,
			fmt.Sprintf("[CRITICAL] Sink %s is DISABLED - logs are not being exported\n"+
				"  Risk: Potential log evasion or security monitoring gap\n"+
				"  Fix: Re-enable the sink:\n"+
				"  gcloud logging sinks update %s --no-disabled --project=%s\n",
				sink.Name,
				sink.Name, sink.ProjectID))
	}

	// Cross-project export - HIGH (data exfiltration risk)
	if sink.IsCrossProject {
		recommendations = append(recommendations,
			fmt.Sprintf("[HIGH] Sink %s exports logs to different project: %s\n"+
				"  Risk: Logs may be exfiltrated to external project\n"+
				"  Review: Verify this cross-project export is authorized\n"+
				"  gcloud logging sinks describe %s --project=%s\n",
				sink.Name, sink.DestinationProject,
				sink.Name, sink.ProjectID))
	}

	// Exclusion filters - HIGH (may hide malicious activity)
	if len(sink.ExclusionFilters) > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("[HIGH] Sink %s has %d exclusion filter(s)\n"+
				"  Risk: Exclusion filters may hide malicious activity from logs\n"+
				"  Review: Verify exclusion filters are appropriate\n"+
				"  gcloud logging sinks describe %s --project=%s\n",
				sink.Name, len(sink.ExclusionFilters),
				sink.Name, sink.ProjectID))
	}

	// No filter (exports all logs) - MEDIUM
	if sink.Filter == "" {
		recommendations = append(recommendations,
			fmt.Sprintf("[MEDIUM] Sink %s has no filter - exports ALL logs\n"+
				"  Risk: Sensitive logs may be exported, increased storage costs\n"+
				"  Consider: Adding a filter to export only necessary logs\n"+
				"  gcloud logging sinks update %s --log-filter='severity>=WARNING' --project=%s\n",
				sink.Name,
				sink.Name, sink.ProjectID))
	}

	// Storage destination without CMEK - LOW
	if sink.DestinationType == "storage" {
		recommendations = append(recommendations,
			fmt.Sprintf("[LOW] Sink %s exports to Cloud Storage bucket: %s\n"+
				"  Review: Verify bucket has appropriate encryption and access controls\n"+
				"  gsutil iam get gs://%s\n",
				sink.Name, sink.DestinationBucket,
				sink.DestinationBucket))
	}

	// Pub/Sub destination - INFO (real-time access)
	if sink.DestinationType == "pubsub" {
		recommendations = append(recommendations,
			fmt.Sprintf("[INFO] Sink %s exports to Pub/Sub topic: %s\n"+
				"  Note: Logs are available in real-time via Pub/Sub\n"+
				"  Review: Check who can subscribe to this topic\n"+
				"  gcloud pubsub topics get-iam-policy %s --project=%s\n",
				sink.Name, sink.DestinationTopic,
				sink.DestinationTopic, sink.DestinationProject))
	}

	if len(recommendations) > 0 {
		m.LootMap["logging-security-recommendations"].Contents += fmt.Sprintf(
			"# Sink: %s (Project: %s)\n%s\n",
			sink.Name, sink.ProjectID,
			strings.Join(recommendations, "\n"))
	}
}
