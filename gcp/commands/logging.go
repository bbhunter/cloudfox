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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_LOGGING_MODULE_NAME,
			fmt.Sprintf("Could not enumerate logging sinks in project %s", projectID))
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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_LOGGING_MODULE_NAME,
			fmt.Sprintf("Could not enumerate log metrics in project %s", projectID))
	} else {
		m.mu.Lock()
		m.Metrics = append(m.Metrics, metrics...)
		for _, metric := range metrics {
			m.addMetricToLoot(metric)
		}
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
	// Sinks loot files
	m.LootMap["sinks-commands"] = &internal.LootFile{
		Name:     "sinks-commands",
		Contents: "# Cloud Logging Sinks Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["sinks-cross-project"] = &internal.LootFile{
		Name:     "sinks-cross-project",
		Contents: "# Cross-Project Log Exports\n# Generated by CloudFox\n# These sinks export logs to external projects\n\n",
	}
	m.LootMap["sinks-writer-identities"] = &internal.LootFile{
		Name:     "sinks-writer-identities",
		Contents: "# Logging Sink Writer Identities\n# Generated by CloudFox\n# Service accounts that have write access to destinations\n\n",
	}
	// Metrics loot files
	m.LootMap["metrics-commands"] = &internal.LootFile{
		Name:     "metrics-commands",
		Contents: "# Cloud Logging Metrics Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *LoggingModule) addSinkToLoot(sink LoggingService.SinkInfo) {
	// Sinks commands file
	m.LootMap["sinks-commands"].Contents += fmt.Sprintf(
		"# Sink: %s (Project: %s)\n"+
			"# Destination: %s (%s)\n"+
			"gcloud logging sinks describe %s --project=%s\n",
		sink.Name, sink.ProjectID,
		sink.DestinationType, getDestinationName(sink),
		sink.Name, sink.ProjectID,
	)

	// Add destination-specific commands
	switch sink.DestinationType {
	case "storage":
		if sink.DestinationBucket != "" {
			m.LootMap["sinks-commands"].Contents += fmt.Sprintf(
				"gsutil ls gs://%s/\n"+
					"gsutil cat gs://%s/**/*.json 2>/dev/null | head -100\n",
				sink.DestinationBucket, sink.DestinationBucket,
			)
		}
	case "bigquery":
		if sink.DestinationDataset != "" {
			destProject := sink.DestinationProject
			if destProject == "" {
				destProject = sink.ProjectID
			}
			m.LootMap["sinks-commands"].Contents += fmt.Sprintf(
				"bq ls %s:%s\n"+
					"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s.*` LIMIT 100'\n",
				destProject, sink.DestinationDataset,
				destProject, sink.DestinationDataset,
			)
		}
	case "pubsub":
		if sink.DestinationTopic != "" {
			destProject := sink.DestinationProject
			if destProject == "" {
				destProject = sink.ProjectID
			}
			m.LootMap["sinks-commands"].Contents += fmt.Sprintf(
				"gcloud pubsub subscriptions create log-capture --topic=%s --project=%s\n"+
					"gcloud pubsub subscriptions pull log-capture --limit=10 --auto-ack --project=%s\n",
				sink.DestinationTopic, destProject, destProject,
			)
		}
	}
	m.LootMap["sinks-commands"].Contents += "\n"

	// Cross-project exports
	if sink.IsCrossProject {
		filter := sink.Filter
		if filter == "" {
			filter = "(no filter - all logs)"
		}
		m.LootMap["sinks-cross-project"].Contents += fmt.Sprintf(
			"# Sink: %s\n"+
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
			filter,
			sink.WriterIdentity,
		)
	}

	// Writer identities
	if sink.WriterIdentity != "" {
		m.LootMap["sinks-writer-identities"].Contents += fmt.Sprintf(
			"# Sink: %s -> %s (%s)\n"+
				"%s\n\n",
			sink.Name, sink.DestinationType, getDestinationName(sink),
			sink.WriterIdentity,
		)
	}
}

func (m *LoggingModule) addMetricToLoot(metric LoggingService.MetricInfo) {
	m.LootMap["metrics-commands"].Contents += fmt.Sprintf(
		"# Metric: %s (Project: %s)\n"+
			"gcloud logging metrics describe %s --project=%s\n\n",
		metric.Name, metric.ProjectID,
		metric.Name, metric.ProjectID,
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
		"Writer Identity",
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
			disabled = "Yes"
		}

		// Format filter (no truncation)
		filter := "-"
		if sink.Filter != "" {
			filter = normalizeFilter(sink.Filter)
		}

		// Format writer identity
		writerIdentity := "-"
		if sink.WriterIdentity != "" {
			writerIdentity = sink.WriterIdentity
		}

		sinksBody = append(sinksBody, []string{
			m.GetProjectName(sink.ProjectID),
			sink.ProjectID,
			sink.Name,
			sink.DestinationType,
			destination,
			crossProject,
			disabled,
			writerIdentity,
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
		// Format filter (no truncation)
		filter := "-"
		if metric.Filter != "" {
			filter = normalizeFilter(metric.Filter)
		}

		// Format type
		metricType := metric.MetricKind
		if metric.ValueType != "" {
			metricType += "/" + metric.ValueType
		}

		// Format description (no truncation)
		description := metric.Description
		if description == "" {
			description = "-"
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

// normalizeFilter normalizes a log filter for display (removes newlines but no truncation)
func normalizeFilter(filter string) string {
	// Remove newlines
	filter = strings.ReplaceAll(filter, "\n", " ")
	filter = strings.ReplaceAll(filter, "\t", " ")

	// Collapse multiple spaces
	for strings.Contains(filter, "  ") {
		filter = strings.ReplaceAll(filter, "  ", " ")
	}

	return strings.TrimSpace(filter)
}
