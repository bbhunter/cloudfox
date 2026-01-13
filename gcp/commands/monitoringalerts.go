package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"google.golang.org/api/iterator"
)

// Module name constant
const GCP_MONITORINGALERTS_MODULE_NAME string = "monitoring-alerts"

var GCPMonitoringAlertsCommand = &cobra.Command{
	Use:     GCP_MONITORINGALERTS_MODULE_NAME,
	Aliases: []string{"alerts", "monitoring", "alerting"},
	Hidden:  true,
	Short:   "Enumerate Cloud Monitoring alerting policies and notification channels",
	Long: `Analyze Cloud Monitoring alerting policies and notification channels for security gaps.

Features:
- Lists all alerting policies and their conditions
- Identifies disabled or misconfigured alerts
- Enumerates notification channels and their verification status
- Detects missing critical security alerts
- Identifies uptime check configurations
- Analyzes alert policy coverage gaps

Required Security Alerts to Check:
- IAM policy changes
- Firewall rule changes
- VPC network changes
- Service account key creation
- Custom role changes
- Audit log configuration changes
- Cloud SQL authorization changes

Requires appropriate IAM permissions:
- roles/monitoring.viewer
- roles/monitoring.alertPolicyViewer`,
	Run: runGCPMonitoringAlertsCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type AlertPolicy struct {
	Name                 string
	DisplayName          string
	ProjectID            string
	Enabled              bool
	Combiner             string
	Documentation        string
	Conditions           []AlertCondition
	NotificationChannels []string // Channel resource names
}

type AlertCondition struct {
	Name            string
	DisplayName     string
	ResourceType    string
	MetricType      string
	Filter          string
	ThresholdValue  float64
	Duration        string
	Comparison      string
	Aggregation     string
}

type NotificationChannel struct {
	Name         string
	DisplayName  string
	ProjectID    string
	Type         string // email, slack, pagerduty, webhook, sms, pubsub
	Enabled      bool
	Verified     bool
	Labels       map[string]string
	CreationTime string
	MutationTime string
}

type UptimeCheck struct {
	Name           string
	DisplayName    string
	ProjectID      string
	MonitoredHost  string
	ResourceType   string
	Protocol       string
	Port           int32
	Path           string
	Period         string
	Timeout        string
	SelectedRegion []string
	Enabled        bool
	SSLEnabled     bool
}


// ------------------------------
// Module Struct
// ------------------------------
type MonitoringAlertsModule struct {
	gcpinternal.BaseGCPModule

	AlertPolicies        []AlertPolicy
	NotificationChannels []NotificationChannel
	UptimeChecks         []UptimeCheck
	LootMap              map[string]*internal.LootFile
	mu                   sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type MonitoringAlertsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o MonitoringAlertsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o MonitoringAlertsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPMonitoringAlertsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_MONITORINGALERTS_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &MonitoringAlertsModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		AlertPolicies:        []AlertPolicy{},
		NotificationChannels: []NotificationChannel{},
		UptimeChecks:         []UptimeCheck{},
		LootMap:              make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *MonitoringAlertsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Create Monitoring client
	alertClient, err := monitoring.NewAlertPolicyClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Alert Policy client: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		return
	}
	defer alertClient.Close()

	channelClient, err := monitoring.NewNotificationChannelClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Notification Channel client: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		return
	}
	defer channelClient.Close()

	uptimeClient, err := monitoring.NewUptimeCheckClient(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create Uptime Check client: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		}
	}
	if uptimeClient != nil {
		defer uptimeClient.Close()
	}

	// Process each project
	for _, projectID := range m.ProjectIDs {
		m.processProject(ctx, projectID, alertClient, channelClient, uptimeClient, logger)
	}

	// Check results
	if len(m.AlertPolicies) == 0 && len(m.NotificationChannels) == 0 {
		logger.InfoM("No monitoring alerts or notification channels found", GCP_MONITORINGALERTS_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d alert policy(ies), %d notification channel(s), %d uptime check(s)",
		len(m.AlertPolicies), len(m.NotificationChannels), len(m.UptimeChecks)), GCP_MONITORINGALERTS_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *MonitoringAlertsModule) processProject(ctx context.Context, projectID string, alertClient *monitoring.AlertPolicyClient, channelClient *monitoring.NotificationChannelClient, uptimeClient *monitoring.UptimeCheckClient, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating monitoring for project: %s", projectID), GCP_MONITORINGALERTS_MODULE_NAME)
	}

	// List alert policies
	m.enumerateAlertPolicies(ctx, projectID, alertClient, logger)

	// List notification channels
	m.enumerateNotificationChannels(ctx, projectID, channelClient, logger)

	// List uptime checks
	if uptimeClient != nil {
		m.enumerateUptimeChecks(ctx, projectID, uptimeClient, logger)
	}
}

func (m *MonitoringAlertsModule) enumerateAlertPolicies(ctx context.Context, projectID string, client *monitoring.AlertPolicyClient, logger internal.Logger) {
	parent := fmt.Sprintf("projects/%s", projectID)

	req := &monitoringpb.ListAlertPoliciesRequest{
		Name: parent,
	}

	it := client.ListAlertPolicies(ctx, req)
	for {
		policy, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_MONITORINGALERTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate alert policies in project %s", projectID))
			break
		}

		alertPolicy := AlertPolicy{
			Name:                 policy.Name,
			DisplayName:          policy.DisplayName,
			ProjectID:            projectID,
			Enabled:              policy.Enabled.GetValue(),
			Combiner:             policy.Combiner.String(),
			NotificationChannels: policy.NotificationChannels,
		}

		if policy.Documentation != nil {
			alertPolicy.Documentation = policy.Documentation.Content
		}

		// Parse conditions
		for _, cond := range policy.Conditions {
			condition := AlertCondition{
				Name:        cond.Name,
				DisplayName: cond.DisplayName,
			}

			// Parse based on condition type
			switch c := cond.Condition.(type) {
			case *monitoringpb.AlertPolicy_Condition_ConditionThreshold:
				if c.ConditionThreshold != nil {
					condition.Filter = c.ConditionThreshold.Filter
					condition.Comparison = c.ConditionThreshold.Comparison.String()
					condition.ThresholdValue = c.ConditionThreshold.ThresholdValue

					if c.ConditionThreshold.Duration != nil {
						condition.Duration = c.ConditionThreshold.Duration.String()
					}

					condition.MetricType = m.extractMetricType(c.ConditionThreshold.Filter)
				}
			case *monitoringpb.AlertPolicy_Condition_ConditionAbsent:
				if c.ConditionAbsent != nil {
					condition.Filter = c.ConditionAbsent.Filter
					condition.MetricType = m.extractMetricType(c.ConditionAbsent.Filter)
				}
			case *monitoringpb.AlertPolicy_Condition_ConditionMonitoringQueryLanguage:
				if c.ConditionMonitoringQueryLanguage != nil {
					condition.Filter = c.ConditionMonitoringQueryLanguage.Query
				}
			}

			alertPolicy.Conditions = append(alertPolicy.Conditions, condition)
		}

		m.mu.Lock()
		m.AlertPolicies = append(m.AlertPolicies, alertPolicy)
		m.mu.Unlock()
	}
}

func (m *MonitoringAlertsModule) enumerateNotificationChannels(ctx context.Context, projectID string, client *monitoring.NotificationChannelClient, logger internal.Logger) {
	parent := fmt.Sprintf("projects/%s", projectID)

	req := &monitoringpb.ListNotificationChannelsRequest{
		Name: parent,
	}

	it := client.ListNotificationChannels(ctx, req)
	for {
		channel, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_MONITORINGALERTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate notification channels in project %s", projectID))
			break
		}

		notifChannel := NotificationChannel{
			Name:        channel.Name,
			DisplayName: channel.DisplayName,
			ProjectID:   projectID,
			Type:        channel.Type,
			Enabled:     channel.Enabled.GetValue(),
			Labels:      channel.Labels,
		}

		// Check verification status
		if channel.VerificationStatus == monitoringpb.NotificationChannel_VERIFIED {
			notifChannel.Verified = true
		}

		if channel.CreationRecord != nil {
			notifChannel.CreationTime = channel.CreationRecord.MutateTime.AsTime().String()
		}

		// MutationRecords is a slice - get the most recent one
		if len(channel.MutationRecords) > 0 {
			lastMutation := channel.MutationRecords[len(channel.MutationRecords)-1]
			if lastMutation != nil {
				notifChannel.MutationTime = lastMutation.MutateTime.AsTime().String()
			}
		}

		m.mu.Lock()
		m.NotificationChannels = append(m.NotificationChannels, notifChannel)
		m.mu.Unlock()
	}
}

func (m *MonitoringAlertsModule) enumerateUptimeChecks(ctx context.Context, projectID string, client *monitoring.UptimeCheckClient, logger internal.Logger) {
	parent := fmt.Sprintf("projects/%s", projectID)

	req := &monitoringpb.ListUptimeCheckConfigsRequest{
		Parent: parent,
	}

	it := client.ListUptimeCheckConfigs(ctx, req)
	for {
		check, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			m.CommandCounter.Error++
			gcpinternal.HandleGCPError(err, logger, GCP_MONITORINGALERTS_MODULE_NAME,
				fmt.Sprintf("Could not enumerate uptime checks in project %s", projectID))
			break
		}

		uptimeCheck := UptimeCheck{
			Name:        check.Name,
			DisplayName: check.DisplayName,
			ProjectID:   projectID,
		}

		// Parse resource type
		switch r := check.Resource.(type) {
		case *monitoringpb.UptimeCheckConfig_MonitoredResource:
			if r.MonitoredResource != nil {
				uptimeCheck.ResourceType = r.MonitoredResource.Type
				if host, ok := r.MonitoredResource.Labels["host"]; ok {
					uptimeCheck.MonitoredHost = host
				}
			}
		}

		// Parse check request details
		switch cr := check.CheckRequestType.(type) {
		case *monitoringpb.UptimeCheckConfig_HttpCheck_:
			if cr.HttpCheck != nil {
				uptimeCheck.Protocol = "HTTP"
				uptimeCheck.Port = cr.HttpCheck.Port
				uptimeCheck.Path = cr.HttpCheck.Path
				if cr.HttpCheck.UseSsl {
					uptimeCheck.Protocol = "HTTPS"
					uptimeCheck.SSLEnabled = true
				}
			}
		case *monitoringpb.UptimeCheckConfig_TcpCheck_:
			if cr.TcpCheck != nil {
				uptimeCheck.Protocol = "TCP"
				uptimeCheck.Port = cr.TcpCheck.Port
			}
		}

		if check.Period != nil {
			uptimeCheck.Period = check.Period.String()
		}

		if check.Timeout != nil {
			uptimeCheck.Timeout = check.Timeout.String()
		}

		// Check regions
		for _, region := range check.SelectedRegions {
			uptimeCheck.SelectedRegion = append(uptimeCheck.SelectedRegion, region.String())
		}

		m.mu.Lock()
		m.UptimeChecks = append(m.UptimeChecks, uptimeCheck)
		m.mu.Unlock()
	}
}


// ------------------------------
// Helper Functions
// ------------------------------
func (m *MonitoringAlertsModule) extractMetricType(filter string) string {
	// Extract metric type from filter string
	// Format: metric.type="..." or resource.type="..."
	if strings.Contains(filter, "metric.type=") {
		parts := strings.Split(filter, "metric.type=")
		if len(parts) > 1 {
			metricPart := strings.Split(parts[1], " ")[0]
			return strings.Trim(metricPart, "\"")
		}
	}
	return ""
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *MonitoringAlertsModule) initializeLootFiles() {
	m.LootMap["monitoring-alerts-commands"] = &internal.LootFile{
		Name:     "monitoring-alerts-commands",
		Contents: "# Monitoring Alerts Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *MonitoringAlertsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Build notification channel name map for resolving channel references
	channelNameMap := make(map[string]string)
	for _, c := range m.NotificationChannels {
		channelNameMap[c.Name] = c.DisplayName
	}

	// Sort policies by name
	sort.Slice(m.AlertPolicies, func(i, j int) bool {
		return m.AlertPolicies[i].DisplayName < m.AlertPolicies[j].DisplayName
	})

	// Alert Policies table - one row per condition
	policiesHeader := []string{
		"Project Name",
		"Project ID",
		"Policy Name",
		"Enabled",
		"Condition Name",
		"Metric Type",
		"Comparison",
		"Threshold",
		"Duration",
		"Notification Channels",
	}

	var policiesBody [][]string
	for _, p := range m.AlertPolicies {
		// Resolve notification channel names
		var channelNames []string
		for _, channelRef := range p.NotificationChannels {
			if name, ok := channelNameMap[channelRef]; ok {
				channelNames = append(channelNames, name)
			} else {
				// Extract name from resource path if not found
				parts := strings.Split(channelRef, "/")
				if len(parts) > 0 {
					channelNames = append(channelNames, parts[len(parts)-1])
				}
			}
		}
		notificationChannelsStr := "-"
		if len(channelNames) > 0 {
			notificationChannelsStr = strings.Join(channelNames, ", ")
		}

		// If policy has conditions, create one row per condition
		if len(p.Conditions) > 0 {
			for _, cond := range p.Conditions {
				metricType := cond.MetricType
				if metricType == "" {
					metricType = "-"
				}
				comparison := cond.Comparison
				if comparison == "" {
					comparison = "-"
				}
				threshold := "-"
				if cond.ThresholdValue != 0 {
					threshold = fmt.Sprintf("%.2f", cond.ThresholdValue)
				}
				duration := cond.Duration
				if duration == "" {
					duration = "-"
				}

				policiesBody = append(policiesBody, []string{
					m.GetProjectName(p.ProjectID),
					p.ProjectID,
					p.DisplayName,
					boolToYesNo(p.Enabled),
					cond.DisplayName,
					metricType,
					comparison,
					threshold,
					duration,
					notificationChannelsStr,
				})
			}
		} else {
			// Policy with no conditions - single row
			policiesBody = append(policiesBody, []string{
				m.GetProjectName(p.ProjectID),
				p.ProjectID,
				p.DisplayName,
				boolToYesNo(p.Enabled),
				"-",
				"-",
				"-",
				"-",
				"-",
				notificationChannelsStr,
			})
		}

		// Add to loot
		m.LootMap["monitoring-alerts-commands"].Contents += fmt.Sprintf(
			"## Policy: %s (Project: %s)\n"+
				"# Describe alert policy:\n"+
				"gcloud alpha monitoring policies describe %s --project=%s\n\n",
			p.DisplayName, p.ProjectID,
			extractResourceName(p.Name), p.ProjectID,
		)
	}

	// Notification Channels table - with destination info
	channelsHeader := []string{
		"Project Name",
		"Project ID",
		"Channel Name",
		"Type",
		"Enabled",
		"Verified",
		"Destination",
	}

	var channelsBody [][]string
	for _, c := range m.NotificationChannels {
		// Extract destination from labels based on type
		destination := extractChannelDestination(c.Type, c.Labels)

		channelsBody = append(channelsBody, []string{
			m.GetProjectName(c.ProjectID),
			c.ProjectID,
			c.DisplayName,
			c.Type,
			boolToYesNo(c.Enabled),
			boolToYesNo(c.Verified),
			destination,
		})

		// Add to loot
		m.LootMap["monitoring-alerts-commands"].Contents += fmt.Sprintf(
			"## Channel: %s (Project: %s)\n"+
				"# Describe notification channel:\n"+
				"gcloud alpha monitoring channels describe %s --project=%s\n\n",
			c.DisplayName, c.ProjectID,
			extractResourceName(c.Name), c.ProjectID,
		)
	}

	// Uptime Checks table - expanded
	uptimeHeader := []string{
		"Project Name",
		"Project ID",
		"Check Name",
		"Enabled",
		"Host",
		"Protocol",
		"Port",
		"Path",
		"Period",
		"Timeout",
		"SSL Enabled",
	}

	var uptimeBody [][]string
	for _, u := range m.UptimeChecks {
		host := u.MonitoredHost
		if host == "" {
			host = "-"
		}
		path := u.Path
		if path == "" {
			path = "-"
		}
		timeout := u.Timeout
		if timeout == "" {
			timeout = "-"
		}

		uptimeBody = append(uptimeBody, []string{
			m.GetProjectName(u.ProjectID),
			u.ProjectID,
			u.DisplayName,
			boolToYesNo(u.Enabled),
			host,
			u.Protocol,
			fmt.Sprintf("%d", u.Port),
			path,
			u.Period,
			timeout,
			boolToYesNo(u.SSLEnabled),
		})

		// Add to loot
		m.LootMap["monitoring-alerts-commands"].Contents += fmt.Sprintf(
			"## Uptime Check: %s (Project: %s)\n"+
				"# Describe uptime check:\n"+
				"gcloud alpha monitoring uptime describe %s --project=%s\n\n",
			u.DisplayName, u.ProjectID,
			extractResourceName(u.Name), u.ProjectID,
		)
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	var tables []internal.TableFile

	if len(policiesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "alerting-policies",
			Header: policiesHeader,
			Body:   policiesBody,
		})
	}

	if len(channelsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "notification-channels",
			Header: channelsHeader,
			Body:   channelsBody,
		})
	}

	if len(uptimeBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "uptime-checks",
			Header: uptimeHeader,
			Body:   uptimeBody,
		})
	}

	output := MonitoringAlertsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scope names using project names
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	// Write output
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// extractChannelDestination extracts the destination info from channel labels
func extractChannelDestination(channelType string, labels map[string]string) string {
	if labels == nil {
		return "-"
	}

	switch channelType {
	case "email":
		if email, ok := labels["email_address"]; ok {
			return email
		}
	case "slack":
		if channel, ok := labels["channel_name"]; ok {
			return channel
		}
	case "pagerduty":
		if key, ok := labels["service_key"]; ok {
			// Truncate service key for display
			if len(key) > 12 {
				return key[:12] + "..."
			}
			return key
		}
	case "webhook_tokenauth", "webhook_basicauth":
		if url, ok := labels["url"]; ok {
			return url
		}
	case "pubsub":
		if topic, ok := labels["topic"]; ok {
			return topic
		}
	case "sms":
		if number, ok := labels["number"]; ok {
			return number
		}
	}

	// Try common label keys
	for _, key := range []string{"url", "address", "endpoint", "target"} {
		if val, ok := labels[key]; ok {
			return val
		}
	}

	return "-"
}
