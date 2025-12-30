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
	Name              string
	DisplayName       string
	ProjectID         string
	Enabled           bool
	ConditionCount    int
	NotificationCount int
	Combiner          string
	CreationRecord    string
	MutationRecord    string
	Severity          string
	Documentation     string
	Conditions        []AlertCondition
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

type AlertGap struct {
	GapType        string // missing-alert, disabled-alert, no-notification
	Severity       string
	Description    string
	Recommendation string
	AffectedArea   string
}

// ------------------------------
// Module Struct
// ------------------------------
type MonitoringAlertsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	AlertPolicies        []AlertPolicy
	NotificationChannels []NotificationChannel
	UptimeChecks         []UptimeCheck
	AlertGaps            []AlertGap
	LootMap              map[string]*internal.LootFile
	mu                   sync.Mutex

	// Tracking for gap analysis
	hasIAMChangeAlert      bool
	hasFirewallChangeAlert bool
	hasNetworkChangeAlert  bool
	hasSAKeyAlert          bool
	hasAuditLogAlert       bool
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
		AlertGaps:            []AlertGap{},
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
	logger.InfoM("Analyzing Cloud Monitoring alerting configuration...", GCP_MONITORINGALERTS_MODULE_NAME)

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

	// Analyze for gaps
	m.analyzeAlertGaps(logger)

	// Check results
	totalPolicies := len(m.AlertPolicies)
	totalChannels := len(m.NotificationChannels)
	totalGaps := len(m.AlertGaps)

	if totalPolicies == 0 && totalChannels == 0 {
		logger.InfoM("No monitoring alerts or notification channels found", GCP_MONITORINGALERTS_MODULE_NAME)
		logger.InfoM("[CRITICAL] Projects have no alerting configured!", GCP_MONITORINGALERTS_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d alert policy(ies), %d notification channel(s)",
		totalPolicies, totalChannels), GCP_MONITORINGALERTS_MODULE_NAME)

	if totalGaps > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Identified %d alerting gap(s)", totalGaps), GCP_MONITORINGALERTS_MODULE_NAME)
	}

	// Write output
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
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing alert policies for project %s: %v", projectID, err), GCP_MONITORINGALERTS_MODULE_NAME)
			}
			break
		}

		alertPolicy := AlertPolicy{
			Name:              policy.Name,
			DisplayName:       policy.DisplayName,
			ProjectID:         projectID,
			Enabled:           policy.Enabled.GetValue(),
			ConditionCount:    len(policy.Conditions),
			NotificationCount: len(policy.NotificationChannels),
			Combiner:          policy.Combiner.String(),
		}

		if policy.Documentation != nil {
			alertPolicy.Documentation = policy.Documentation.Content
		}

		if policy.CreationRecord != nil {
			alertPolicy.CreationRecord = policy.CreationRecord.MutateTime.AsTime().String()
		}

		if policy.MutationRecord != nil {
			alertPolicy.MutationRecord = policy.MutationRecord.MutateTime.AsTime().String()
		}

		// Severity from user labels or documentation
		if policy.UserLabels != nil {
			if sev, ok := policy.UserLabels["severity"]; ok {
				alertPolicy.Severity = sev
			}
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

					// Extract metric type from filter
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

			// Check for security-related alerts
			m.checkSecurityAlert(condition.Filter, condition.DisplayName)
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
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing notification channels for project %s: %v", projectID, err), GCP_MONITORINGALERTS_MODULE_NAME)
			}
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
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing uptime checks for project %s: %v", projectID, err), GCP_MONITORINGALERTS_MODULE_NAME)
			}
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
// Security Alert Detection
// ------------------------------
func (m *MonitoringAlertsModule) checkSecurityAlert(filter, displayName string) {
	filterLower := strings.ToLower(filter)
	nameLower := strings.ToLower(displayName)

	// IAM policy changes
	if strings.Contains(filterLower, "setiampolicy") ||
		strings.Contains(filterLower, "iam_policy") ||
		strings.Contains(nameLower, "iam") {
		m.mu.Lock()
		m.hasIAMChangeAlert = true
		m.mu.Unlock()
	}

	// Firewall changes
	if strings.Contains(filterLower, "compute.firewalls") ||
		strings.Contains(filterLower, "firewall") ||
		strings.Contains(nameLower, "firewall") {
		m.mu.Lock()
		m.hasFirewallChangeAlert = true
		m.mu.Unlock()
	}

	// Network changes
	if strings.Contains(filterLower, "compute.networks") ||
		strings.Contains(filterLower, "vpc") ||
		strings.Contains(nameLower, "network") {
		m.mu.Lock()
		m.hasNetworkChangeAlert = true
		m.mu.Unlock()
	}

	// Service account key creation
	if strings.Contains(filterLower, "serviceaccountkeys") ||
		strings.Contains(filterLower, "service_account_key") ||
		strings.Contains(nameLower, "service account key") {
		m.mu.Lock()
		m.hasSAKeyAlert = true
		m.mu.Unlock()
	}

	// Audit log configuration
	if strings.Contains(filterLower, "auditconfig") ||
		strings.Contains(filterLower, "audit_config") ||
		strings.Contains(nameLower, "audit") {
		m.mu.Lock()
		m.hasAuditLogAlert = true
		m.mu.Unlock()
	}
}

// ------------------------------
// Gap Analysis
// ------------------------------
func (m *MonitoringAlertsModule) analyzeAlertGaps(logger internal.Logger) {
	// Check for disabled alerts
	for _, policy := range m.AlertPolicies {
		if !policy.Enabled {
			gap := AlertGap{
				GapType:        "disabled-alert",
				Severity:       "MEDIUM",
				Description:    fmt.Sprintf("Alert policy '%s' is disabled", policy.DisplayName),
				Recommendation: fmt.Sprintf("Enable the alert policy if it's still needed: gcloud alpha monitoring policies update %s --enabled", policy.Name),
				AffectedArea:   policy.DisplayName,
			}
			m.AlertGaps = append(m.AlertGaps, gap)
		}

		// Check for alerts without notifications
		if policy.NotificationCount == 0 && policy.Enabled {
			gap := AlertGap{
				GapType:        "no-notification",
				Severity:       "HIGH",
				Description:    fmt.Sprintf("Alert policy '%s' has no notification channels", policy.DisplayName),
				Recommendation: "Add notification channels to ensure alerts are received",
				AffectedArea:   policy.DisplayName,
			}
			m.AlertGaps = append(m.AlertGaps, gap)
		}
	}

	// Check for unverified notification channels
	for _, channel := range m.NotificationChannels {
		if !channel.Verified && channel.Enabled {
			gap := AlertGap{
				GapType:        "unverified-channel",
				Severity:       "MEDIUM",
				Description:    fmt.Sprintf("Notification channel '%s' (%s) is not verified", channel.DisplayName, channel.Type),
				Recommendation: "Verify the notification channel to ensure alerts are delivered",
				AffectedArea:   channel.DisplayName,
			}
			m.AlertGaps = append(m.AlertGaps, gap)
		}

		if !channel.Enabled {
			gap := AlertGap{
				GapType:        "disabled-channel",
				Severity:       "LOW",
				Description:    fmt.Sprintf("Notification channel '%s' is disabled", channel.DisplayName),
				Recommendation: "Enable or remove unused notification channels",
				AffectedArea:   channel.DisplayName,
			}
			m.AlertGaps = append(m.AlertGaps, gap)
		}
	}

	// Check for missing security alerts
	if !m.hasIAMChangeAlert {
		gap := AlertGap{
			GapType:        "missing-alert",
			Severity:       "HIGH",
			Description:    "No alert policy for IAM policy changes",
			Recommendation: "Create an alert for protoPayload.methodName=\"SetIamPolicy\"",
			AffectedArea:   "IAM Security",
		}
		m.AlertGaps = append(m.AlertGaps, gap)
		m.addMissingAlertToLoot("IAM Policy Changes", `resource.type="project" AND protoPayload.methodName="SetIamPolicy"`)
	}

	if !m.hasFirewallChangeAlert {
		gap := AlertGap{
			GapType:        "missing-alert",
			Severity:       "HIGH",
			Description:    "No alert policy for firewall rule changes",
			Recommendation: "Create an alert for compute.firewalls.* methods",
			AffectedArea:   "Network Security",
		}
		m.AlertGaps = append(m.AlertGaps, gap)
		m.addMissingAlertToLoot("Firewall Changes", `resource.type="gce_firewall_rule" AND protoPayload.methodName=~"compute.firewalls.*"`)
	}

	if !m.hasNetworkChangeAlert {
		gap := AlertGap{
			GapType:        "missing-alert",
			Severity:       "MEDIUM",
			Description:    "No alert policy for VPC network changes",
			Recommendation: "Create an alert for compute.networks.* methods",
			AffectedArea:   "Network Security",
		}
		m.AlertGaps = append(m.AlertGaps, gap)
		m.addMissingAlertToLoot("VPC Network Changes", `resource.type="gce_network" AND protoPayload.methodName=~"compute.networks.*"`)
	}

	if !m.hasSAKeyAlert {
		gap := AlertGap{
			GapType:        "missing-alert",
			Severity:       "HIGH",
			Description:    "No alert policy for service account key creation",
			Recommendation: "Create an alert for CreateServiceAccountKey method",
			AffectedArea:   "IAM Security",
		}
		m.AlertGaps = append(m.AlertGaps, gap)
		m.addMissingAlertToLoot("Service Account Key Creation", `protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"`)
	}

	if !m.hasAuditLogAlert {
		gap := AlertGap{
			GapType:        "missing-alert",
			Severity:       "MEDIUM",
			Description:    "No alert policy for audit configuration changes",
			Recommendation: "Create an alert for SetIamPolicy on audit configs",
			AffectedArea:   "Logging Security",
		}
		m.AlertGaps = append(m.AlertGaps, gap)
		m.addMissingAlertToLoot("Audit Configuration Changes", `protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*`)
	}

	// Check if no notification channels exist at all
	if len(m.NotificationChannels) == 0 && len(m.AlertPolicies) > 0 {
		gap := AlertGap{
			GapType:        "missing-alert",
			Severity:       "CRITICAL",
			Description:    "No notification channels configured",
			Recommendation: "Create notification channels (email, Slack, PagerDuty) to receive alerts",
			AffectedArea:   "Alert Delivery",
		}
		m.AlertGaps = append(m.AlertGaps, gap)
	}
}

func (m *MonitoringAlertsModule) addMissingAlertToLoot(alertName, filter string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.LootMap["missing-alerts"].Contents += fmt.Sprintf(
		"## Missing Alert: %s\n"+
			"Recommended Filter:\n"+
			"%s\n\n"+
			"# Create with gcloud:\n"+
			"# gcloud alpha monitoring policies create --display-name=\"%s\" \\\n"+
			"#   --condition-filter=\"%s\"\n\n",
		alertName, filter, alertName, filter,
	)
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
	m.LootMap["disabled-alerts"] = &internal.LootFile{
		Name:     "disabled-alerts",
		Contents: "# Disabled Alert Policies\n# Generated by CloudFox\n\n",
	}
	m.LootMap["missing-alerts"] = &internal.LootFile{
		Name:     "missing-alerts",
		Contents: "# Missing Security Alerts\n# Generated by CloudFox\n# Recommended alerts for security monitoring\n\n",
	}
	m.LootMap["alert-setup-commands"] = &internal.LootFile{
		Name:     "alert-setup-commands",
		Contents: "# Alert Setup Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["notification-channels"] = &internal.LootFile{
		Name:     "notification-channels",
		Contents: "# Notification Channels\n# Generated by CloudFox\n\n",
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *MonitoringAlertsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort policies by enabled status and name
	sort.Slice(m.AlertPolicies, func(i, j int) bool {
		if m.AlertPolicies[i].Enabled != m.AlertPolicies[j].Enabled {
			return m.AlertPolicies[i].Enabled
		}
		return m.AlertPolicies[i].DisplayName < m.AlertPolicies[j].DisplayName
	})

	// Alert Policies table
	policiesHeader := []string{
		"Policy",
		"Project Name",
		"Project ID",
		"Enabled",
		"Conditions",
		"Notifications",
		"Combiner",
	}

	var policiesBody [][]string
	for _, p := range m.AlertPolicies {
		enabled := "No"
		if p.Enabled {
			enabled = "Yes"
		}

		policiesBody = append(policiesBody, []string{
			truncateString(p.DisplayName, 40),
			m.GetProjectName(p.ProjectID),
			p.ProjectID,
			enabled,
			fmt.Sprintf("%d", p.ConditionCount),
			fmt.Sprintf("%d", p.NotificationCount),
			p.Combiner,
		})

		// Add disabled alerts to loot
		if !p.Enabled {
			m.LootMap["disabled-alerts"].Contents += fmt.Sprintf(
				"## %s\n"+
					"Project: %s\n"+
					"Name: %s\n"+
					"# Enable: gcloud alpha monitoring policies update %s --enabled\n\n",
				p.DisplayName, p.ProjectID, p.Name, p.Name,
			)
		}
	}

	// Notification Channels table
	channelsHeader := []string{
		"Channel",
		"Project Name",
		"Project ID",
		"Type",
		"Enabled",
		"Verified",
	}

	var channelsBody [][]string
	for _, c := range m.NotificationChannels {
		enabled := "No"
		if c.Enabled {
			enabled = "Yes"
		}
		verified := "No"
		if c.Verified {
			verified = "Yes"
		}

		channelsBody = append(channelsBody, []string{
			truncateString(c.DisplayName, 40),
			m.GetProjectName(c.ProjectID),
			c.ProjectID,
			c.Type,
			enabled,
			verified,
		})

		// Add to notification channels loot
		m.LootMap["notification-channels"].Contents += fmt.Sprintf(
			"%s (%s) - Enabled: %t, Verified: %t\n",
			c.DisplayName, c.Type, c.Enabled, c.Verified,
		)
	}

	// Alert Gaps table
	gapsHeader := []string{
		"Gap Type",
		"Severity",
		"Affected Area",
		"Description",
	}

	var gapsBody [][]string
	for _, g := range m.AlertGaps {
		gapsBody = append(gapsBody, []string{
			g.GapType,
			g.Severity,
			g.AffectedArea,
			truncateString(g.Description, 50),
		})

		// Add setup commands to loot
		if g.Recommendation != "" {
			m.LootMap["alert-setup-commands"].Contents += fmt.Sprintf(
				"# %s (%s)\n# %s\n%s\n\n",
				g.AffectedArea, g.GapType, g.Description, g.Recommendation,
			)
		}
	}

	// Uptime Checks table
	uptimeHeader := []string{
		"Check",
		"Project Name",
		"Project ID",
		"Host",
		"Protocol",
		"Port",
		"Period",
	}

	var uptimeBody [][]string
	for _, u := range m.UptimeChecks {
		uptimeBody = append(uptimeBody, []string{
			truncateString(u.DisplayName, 30),
			m.GetProjectName(u.ProjectID),
			u.ProjectID,
			truncateString(u.MonitoredHost, 30),
			u.Protocol,
			fmt.Sprintf("%d", u.Port),
			u.Period,
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
			Name:   "alerting-policies",
			Header: policiesHeader,
			Body:   policiesBody,
		},
	}

	if len(channelsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "notification-channels",
			Header: channelsHeader,
			Body:   channelsBody,
		})
	}

	if len(gapsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "alert-gaps",
			Header: gapsHeader,
			Body:   gapsBody,
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
		scopeNames,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_MONITORINGALERTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
