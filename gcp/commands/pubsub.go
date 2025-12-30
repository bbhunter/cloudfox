package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	PubSubService "github.com/BishopFox/cloudfox/gcp/services/pubsubService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPubSubCommand = &cobra.Command{
	Use:     globals.GCP_PUBSUB_MODULE_NAME,
	Aliases: []string{"ps", "topics", "subscriptions"},
	Short:   "Enumerate Pub/Sub topics and subscriptions with security analysis",
	Long: `Enumerate Pub/Sub topics and subscriptions across projects with security-relevant details.

Features:
- Lists all Pub/Sub topics and subscriptions
- Shows IAM configuration and public access
- Identifies push endpoints and their configurations
- Shows dead letter topics and retry policies
- Detects BigQuery and Cloud Storage exports
- Generates gcloud commands for further analysis

Security Columns:
- PublicPublish: Whether allUsers/allAuthenticatedUsers can publish
- PublicSubscribe: Whether allUsers/allAuthenticatedUsers can subscribe
- KMS: Customer-managed encryption key status
- PushEndpoint: External URL receiving messages (data exfiltration risk)
- Exports: BigQuery/Cloud Storage export destinations

Attack Surface:
- Public topics allow message injection
- Public subscriptions allow message reading
- Push endpoints may leak sensitive data
- Cross-project subscriptions indicate trust relationships`,
	Run: runGCPPubSubCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type PubSubModule struct {
	gcpinternal.BaseGCPModule

	Topics        []PubSubService.TopicInfo
	Subscriptions []PubSubService.SubscriptionInfo
	LootMap       map[string]*internal.LootFile
	mu            sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type PubSubOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PubSubOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PubSubOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPPubSubCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PUBSUB_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PubSubModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Topics:        []PubSubService.TopicInfo{},
		Subscriptions: []PubSubService.SubscriptionInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *PubSubModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_PUBSUB_MODULE_NAME, m.processProject)

	totalResources := len(m.Topics) + len(m.Subscriptions)
	if totalResources == 0 {
		logger.InfoM("No Pub/Sub topics or subscriptions found", globals.GCP_PUBSUB_MODULE_NAME)
		return
	}

	// Count public resources
	publicTopics := 0
	publicSubs := 0
	pushSubs := 0
	for _, topic := range m.Topics {
		if topic.IsPublicPublish || topic.IsPublicSubscribe {
			publicTopics++
		}
	}
	for _, sub := range m.Subscriptions {
		if sub.IsPublicConsume {
			publicSubs++
		}
		if sub.PushEndpoint != "" {
			pushSubs++
		}
	}

	msg := fmt.Sprintf("Found %d topic(s), %d subscription(s)", len(m.Topics), len(m.Subscriptions))
	if publicTopics > 0 || publicSubs > 0 {
		msg += fmt.Sprintf(" (%d public topics, %d public subs)", publicTopics, publicSubs)
	}
	if pushSubs > 0 {
		msg += fmt.Sprintf(" [%d push endpoints]", pushSubs)
	}
	logger.SuccessM(msg, globals.GCP_PUBSUB_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *PubSubModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Pub/Sub in project: %s", projectID), globals.GCP_PUBSUB_MODULE_NAME)
	}

	ps := PubSubService.New()

	// Get topics
	topics, err := ps.Topics(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating Pub/Sub topics in project %s: %v", projectID, err), globals.GCP_PUBSUB_MODULE_NAME)
		}
	} else {
		m.mu.Lock()
		m.Topics = append(m.Topics, topics...)
		for _, topic := range topics {
			m.addTopicToLoot(topic)
		}
		m.mu.Unlock()
	}

	// Get subscriptions
	subs, err := ps.Subscriptions(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating Pub/Sub subscriptions in project %s: %v", projectID, err), globals.GCP_PUBSUB_MODULE_NAME)
		}
	} else {
		m.mu.Lock()
		m.Subscriptions = append(m.Subscriptions, subs...)
		for _, sub := range subs {
			m.addSubscriptionToLoot(sub)
		}
		m.mu.Unlock()
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d topic(s), %d subscription(s) in project %s", len(topics), len(subs), projectID), globals.GCP_PUBSUB_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *PubSubModule) initializeLootFiles() {
	m.LootMap["pubsub-gcloud-commands"] = &internal.LootFile{
		Name:     "pubsub-gcloud-commands",
		Contents: "# Pub/Sub gcloud Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["pubsub-public"] = &internal.LootFile{
		Name:     "pubsub-public",
		Contents: "# PUBLIC Pub/Sub Resources\n# Generated by CloudFox\n# These resources allow public access!\n\n",
	}
	m.LootMap["pubsub-push-endpoints"] = &internal.LootFile{
		Name:     "pubsub-push-endpoints",
		Contents: "# Pub/Sub Push Endpoints\n# Generated by CloudFox\n# Messages are pushed to these URLs\n\n",
	}
	m.LootMap["pubsub-exploitation"] = &internal.LootFile{
		Name:     "pubsub-exploitation",
		Contents: "# Pub/Sub Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	// New enhancement loot files
	m.LootMap["pubsub-dead-letter"] = &internal.LootFile{
		Name:     "pubsub-dead-letter",
		Contents: "# Pub/Sub Dead Letter Topic Configuration\n# Failed messages are sent to these topics\n# Generated by CloudFox\n\n",
	}
	m.LootMap["pubsub-cross-project"] = &internal.LootFile{
		Name:     "pubsub-cross-project",
		Contents: "# Pub/Sub Cross-Project Subscriptions\n# These subscriptions consume from topics in other projects\n# Generated by CloudFox\n\n",
	}
	m.LootMap["pubsub-exports"] = &internal.LootFile{
		Name:     "pubsub-exports",
		Contents: "# Pub/Sub Export Destinations\n# BigQuery and Cloud Storage export targets\n# Generated by CloudFox\n\n",
	}
	m.LootMap["pubsub-no-retention"] = &internal.LootFile{
		Name:     "pubsub-no-retention",
		Contents: "# Pub/Sub Subscriptions WITHOUT Message Retention\n# Messages may be lost if not acknowledged\n# Generated by CloudFox\n\n",
	}
	m.LootMap["pubsub-security-recommendations"] = &internal.LootFile{
		Name:     "pubsub-security-recommendations",
		Contents: "# Pub/Sub Security Recommendations\n# Generated by CloudFox\n\n",
	}
}

func (m *PubSubModule) addTopicToLoot(topic PubSubService.TopicInfo) {
	// gcloud commands
	m.LootMap["pubsub-gcloud-commands"].Contents += fmt.Sprintf(
		"# Topic: %s (Project: %s)\n"+
			"gcloud pubsub topics describe %s --project=%s\n"+
			"gcloud pubsub topics get-iam-policy %s --project=%s\n"+
			"gcloud pubsub topics list-subscriptions %s --project=%s\n\n",
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
	)

	// Public topics
	if topic.IsPublicPublish || topic.IsPublicSubscribe {
		m.LootMap["pubsub-public"].Contents += fmt.Sprintf(
			"# TOPIC: %s\n"+
				"# Project: %s\n"+
				"# Public Publish: %v\n"+
				"# Public Subscribe: %v\n"+
				"# Subscriptions: %d\n\n",
			topic.Name,
			topic.ProjectID,
			topic.IsPublicPublish,
			topic.IsPublicSubscribe,
			topic.SubscriptionCount,
		)
	}

	// Exploitation commands
	m.LootMap["pubsub-exploitation"].Contents += fmt.Sprintf(
		"# Topic: %s (Project: %s)\n"+
			"# Public Publish: %v, Public Subscribe: %v\n\n"+
			"# Publish a message (if you have pubsub.topics.publish):\n"+
			"gcloud pubsub topics publish %s --message='test' --project=%s\n\n"+
			"# Create a subscription (if you have pubsub.subscriptions.create):\n"+
			"gcloud pubsub subscriptions create my-sub --topic=%s --project=%s\n\n",
		topic.Name, topic.ProjectID,
		topic.IsPublicPublish, topic.IsPublicSubscribe,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
	)

	// Add security recommendations
	m.addTopicSecurityRecommendations(topic)
}

func (m *PubSubModule) addSubscriptionToLoot(sub PubSubService.SubscriptionInfo) {
	// gcloud commands
	m.LootMap["pubsub-gcloud-commands"].Contents += fmt.Sprintf(
		"# Subscription: %s (Project: %s, Topic: %s)\n"+
			"gcloud pubsub subscriptions describe %s --project=%s\n"+
			"gcloud pubsub subscriptions get-iam-policy %s --project=%s\n\n",
		sub.Name, sub.ProjectID, sub.Topic,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
	)

	// Push endpoints
	if sub.PushEndpoint != "" {
		m.LootMap["pubsub-push-endpoints"].Contents += fmt.Sprintf(
			"# Subscription: %s\n"+
				"# Project: %s\n"+
				"# Topic: %s\n"+
				"# Push Endpoint: %s\n"+
				"# Service Account: %s\n\n",
			sub.Name,
			sub.ProjectID,
			sub.Topic,
			sub.PushEndpoint,
			sub.PushServiceAccount,
		)
	}

	// Public subscriptions
	if sub.IsPublicConsume {
		m.LootMap["pubsub-public"].Contents += fmt.Sprintf(
			"# SUBSCRIPTION: %s\n"+
				"# Project: %s\n"+
				"# Topic: %s\n"+
				"# Public Consume: true\n\n",
			sub.Name,
			sub.ProjectID,
			sub.Topic,
		)
	}

	// Dead letter topic configuration
	if sub.DeadLetterTopic != "" {
		m.LootMap["pubsub-dead-letter"].Contents += fmt.Sprintf(
			"# Subscription: %s\n"+
				"# Project: %s\n"+
				"# Topic: %s\n"+
				"# Dead Letter Topic: %s\n"+
				"# Max Delivery Attempts: %d\n"+
				"gcloud pubsub subscriptions describe %s --project=%s\n\n",
			sub.Name,
			sub.ProjectID,
			sub.Topic,
			sub.DeadLetterTopic,
			sub.MaxDeliveryAttempts,
			sub.Name, sub.ProjectID,
		)
	}

	// Cross-project subscriptions
	if sub.TopicProject != "" && sub.TopicProject != sub.ProjectID {
		m.LootMap["pubsub-cross-project"].Contents += fmt.Sprintf(
			"# CROSS-PROJECT SUBSCRIPTION\n"+
				"# Subscription: %s (Project: %s)\n"+
				"# Subscribes to topic in: %s\n"+
				"# Topic: %s\n"+
				"# This indicates a trust relationship between projects\n"+
				"gcloud pubsub subscriptions describe %s --project=%s\n\n",
			sub.Name, sub.ProjectID,
			sub.TopicProject,
			sub.Topic,
			sub.Name, sub.ProjectID,
		)
	}

	// Export destinations (BigQuery/GCS)
	if sub.BigQueryTable != "" {
		m.LootMap["pubsub-exports"].Contents += fmt.Sprintf(
			"# BIGQUERY EXPORT\n"+
				"# Subscription: %s (Project: %s)\n"+
				"# Topic: %s\n"+
				"# BigQuery Table: %s\n"+
				"gcloud pubsub subscriptions describe %s --project=%s\n"+
				"bq show %s\n\n",
			sub.Name, sub.ProjectID,
			sub.Topic,
			sub.BigQueryTable,
			sub.Name, sub.ProjectID,
			sub.BigQueryTable,
		)
	}
	if sub.CloudStorageBucket != "" {
		m.LootMap["pubsub-exports"].Contents += fmt.Sprintf(
			"# CLOUD STORAGE EXPORT\n"+
				"# Subscription: %s (Project: %s)\n"+
				"# Topic: %s\n"+
				"# GCS Bucket: %s\n"+
				"gcloud pubsub subscriptions describe %s --project=%s\n"+
				"gsutil ls gs://%s/\n\n",
			sub.Name, sub.ProjectID,
			sub.Topic,
			sub.CloudStorageBucket,
			sub.Name, sub.ProjectID,
			sub.CloudStorageBucket,
		)
	}

	// No message retention (potential data loss)
	if sub.MessageRetention == "" && !sub.RetainAckedMessages {
		m.LootMap["pubsub-no-retention"].Contents += fmt.Sprintf(
			"# Subscription: %s\n"+
				"# Project: %s\n"+
				"# Topic: %s\n"+
				"# No message retention configured - unacked messages may be lost\n"+
				"# Ack Deadline: %ds\n"+
				"gcloud pubsub subscriptions update %s --project=%s --message-retention-duration=7d\n\n",
			sub.Name,
			sub.ProjectID,
			sub.Topic,
			sub.AckDeadlineSeconds,
			sub.Name, sub.ProjectID,
		)
	}

	// Add security recommendations
	m.addSubscriptionSecurityRecommendations(sub)

	// Exploitation commands
	m.LootMap["pubsub-exploitation"].Contents += fmt.Sprintf(
		"# Subscription: %s (Project: %s)\n"+
			"# Topic: %s\n"+
			"# Public Consume: %v\n\n"+
			"# Pull messages (if you have pubsub.subscriptions.consume):\n"+
			"gcloud pubsub subscriptions pull %s --project=%s --limit=10 --auto-ack\n\n"+
			"# Seek to beginning (replay all messages):\n"+
			"gcloud pubsub subscriptions seek %s --time=2020-01-01T00:00:00Z --project=%s\n\n",
		sub.Name, sub.ProjectID,
		sub.Topic,
		sub.IsPublicConsume,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PubSubModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Topics table
	topicsHeader := []string{
		"Project Name",
		"Project ID",
		"Topic Name",
		"Subscriptions",
		"Public Publish",
		"Public Subscribe",
		"KMS Key",
		"Retention",
	}

	var topicsBody [][]string
	for _, topic := range m.Topics {
		// Format public status
		publicPublish := "No"
		if topic.IsPublicPublish {
			publicPublish = "YES"
		}
		publicSubscribe := "No"
		if topic.IsPublicSubscribe {
			publicSubscribe = "YES"
		}

		// Format KMS key
		kmsKey := "-"
		if topic.KmsKeyName != "" {
			kmsKey = extractKmsKeyName(topic.KmsKeyName)
		}

		// Format retention
		retention := "-"
		if topic.MessageRetentionDuration != "" {
			retention = topic.MessageRetentionDuration
		}

		topicsBody = append(topicsBody, []string{
			m.GetProjectName(topic.ProjectID),
			topic.ProjectID,
			topic.Name,
			fmt.Sprintf("%d", topic.SubscriptionCount),
			publicPublish,
			publicSubscribe,
			kmsKey,
			retention,
		})
	}

	// Subscriptions table
	subsHeader := []string{
		"Project Name",
		"Project ID",
		"Subscription",
		"Topic",
		"Type",
		"Push Endpoint / Export",
		"Public",
		"Dead Letter",
		"Ack Deadline",
	}

	var subsBody [][]string
	for _, sub := range m.Subscriptions {
		// Determine type
		subType := "Pull"
		destination := "-"
		if sub.PushEndpoint != "" {
			subType = "Push"
			destination = truncateURL(sub.PushEndpoint)
		} else if sub.BigQueryTable != "" {
			subType = "BigQuery"
			destination = truncateBQ(sub.BigQueryTable)
		} else if sub.CloudStorageBucket != "" {
			subType = "GCS"
			destination = sub.CloudStorageBucket
		}

		// Format public status
		publicConsume := "No"
		if sub.IsPublicConsume {
			publicConsume = "YES"
		}

		// Format dead letter
		deadLetter := "-"
		if sub.DeadLetterTopic != "" {
			deadLetter = sub.DeadLetterTopic
		}

		subsBody = append(subsBody, []string{
			m.GetProjectName(sub.ProjectID),
			sub.ProjectID,
			sub.Name,
			sub.Topic,
			subType,
			destination,
			publicConsume,
			deadLetter,
			fmt.Sprintf("%ds", sub.AckDeadlineSeconds),
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

	if len(topicsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_PUBSUB_MODULE_NAME + "-topics",
			Header: topicsHeader,
			Body:   topicsBody,
		})
	}

	if len(subsBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_PUBSUB_MODULE_NAME + "-subscriptions",
			Header: subsHeader,
			Body:   subsBody,
		})
	}

	output := PubSubOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PUBSUB_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// extractKmsKeyName extracts just the key name from the full KMS key path
func extractKmsKeyName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}

// truncateURL truncates a URL for display
func truncateURL(url string) string {
	if len(url) > 45 {
		return url[:42] + "..."
	}
	return url
}

// truncateBQ truncates a BigQuery table reference for display
func truncateBQ(table string) string {
	// Format: project:dataset.table
	if len(table) > 40 {
		parts := strings.Split(table, ".")
		if len(parts) == 2 {
			return "..." + parts[1]
		}
		return "..." + table[len(table)-30:]
	}
	return table
}

// ------------------------------
// Security Recommendations
// ------------------------------

// addTopicSecurityRecommendations generates security recommendations for a topic
func (m *PubSubModule) addTopicSecurityRecommendations(topic PubSubService.TopicInfo) {
	var recommendations []string

	// Public publish access - CRITICAL
	if topic.IsPublicPublish {
		recommendations = append(recommendations,
			fmt.Sprintf("[CRITICAL] Topic %s allows public publishing (allUsers/allAuthenticatedUsers)\n"+
				"  Risk: Anyone can inject messages into this topic\n"+
				"  Fix: Remove public access:\n"+
				"  gcloud pubsub topics remove-iam-policy-binding %s --project=%s --member=allUsers --role=roles/pubsub.publisher\n"+
				"  gcloud pubsub topics remove-iam-policy-binding %s --project=%s --member=allAuthenticatedUsers --role=roles/pubsub.publisher\n",
				topic.Name,
				topic.Name, topic.ProjectID,
				topic.Name, topic.ProjectID))
	}

	// Public subscribe access - HIGH
	if topic.IsPublicSubscribe {
		recommendations = append(recommendations,
			fmt.Sprintf("[HIGH] Topic %s allows public subscription (allUsers/allAuthenticatedUsers)\n"+
				"  Risk: Anyone can create subscriptions to read messages\n"+
				"  Fix: Remove public access:\n"+
				"  gcloud pubsub topics remove-iam-policy-binding %s --project=%s --member=allUsers --role=roles/pubsub.subscriber\n"+
				"  gcloud pubsub topics remove-iam-policy-binding %s --project=%s --member=allAuthenticatedUsers --role=roles/pubsub.subscriber\n",
				topic.Name,
				topic.Name, topic.ProjectID,
				topic.Name, topic.ProjectID))
	}

	// No KMS encryption - MEDIUM
	if topic.KmsKeyName == "" {
		recommendations = append(recommendations,
			fmt.Sprintf("[MEDIUM] Topic %s uses Google-managed encryption instead of CMEK\n"+
				"  Risk: Less control over encryption keys\n"+
				"  Fix: Configure customer-managed encryption:\n"+
				"  gcloud pubsub topics update %s --project=%s --message-encryption-key-name=projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY\n",
				topic.Name,
				topic.Name, topic.ProjectID))
	}

	// No message retention - LOW
	if topic.MessageRetentionDuration == "" {
		recommendations = append(recommendations,
			fmt.Sprintf("[LOW] Topic %s has no message retention configured\n"+
				"  Risk: Messages may be lost if subscribers are temporarily unavailable\n"+
				"  Fix: Configure message retention:\n"+
				"  gcloud pubsub topics update %s --project=%s --message-retention-duration=7d\n",
				topic.Name,
				topic.Name, topic.ProjectID))
	}

	// No subscriptions - INFO
	if topic.SubscriptionCount == 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("[INFO] Topic %s has no subscriptions\n"+
				"  Risk: Messages published to this topic are not being consumed\n"+
				"  Consider: Creating a subscription or removing unused topic\n",
				topic.Name))
	}

	if len(recommendations) > 0 {
		m.LootMap["pubsub-security-recommendations"].Contents += fmt.Sprintf(
			"# Topic: %s (Project: %s)\n%s\n",
			topic.Name, topic.ProjectID,
			strings.Join(recommendations, "\n"))
	}
}

// addSubscriptionSecurityRecommendations generates security recommendations for a subscription
func (m *PubSubModule) addSubscriptionSecurityRecommendations(sub PubSubService.SubscriptionInfo) {
	var recommendations []string

	// Public consume access - CRITICAL
	if sub.IsPublicConsume {
		recommendations = append(recommendations,
			fmt.Sprintf("[CRITICAL] Subscription %s allows public message consumption\n"+
				"  Risk: Anyone can read messages from this subscription\n"+
				"  Fix: Remove public access:\n"+
				"  gcloud pubsub subscriptions remove-iam-policy-binding %s --project=%s --member=allUsers --role=roles/pubsub.subscriber\n"+
				"  gcloud pubsub subscriptions remove-iam-policy-binding %s --project=%s --member=allAuthenticatedUsers --role=roles/pubsub.subscriber\n",
				sub.Name,
				sub.Name, sub.ProjectID,
				sub.Name, sub.ProjectID))
	}

	// Push endpoint without OIDC auth - HIGH
	if sub.PushEndpoint != "" && sub.PushServiceAccount == "" {
		recommendations = append(recommendations,
			fmt.Sprintf("[HIGH] Push subscription %s has no OIDC authentication configured\n"+
				"  Risk: Push endpoint may not verify message authenticity\n"+
				"  Fix: Configure OIDC authentication:\n"+
				"  gcloud pubsub subscriptions update %s --project=%s --push-auth-service-account=SA_EMAIL --push-auth-token-audience=AUDIENCE\n",
				sub.Name,
				sub.Name, sub.ProjectID))
	}

	// Push endpoint to external URL - MEDIUM
	if sub.PushEndpoint != "" && !strings.Contains(sub.PushEndpoint, ".run.app") && !strings.Contains(sub.PushEndpoint, "cloudfunctions.net") {
		recommendations = append(recommendations,
			fmt.Sprintf("[MEDIUM] Push subscription %s sends to external endpoint: %s\n"+
				"  Risk: Data exfiltration to external systems\n"+
				"  Review: Verify this is an authorized endpoint\n"+
				"  gcloud pubsub subscriptions describe %s --project=%s\n",
				sub.Name, sub.PushEndpoint,
				sub.Name, sub.ProjectID))
	}

	// No dead letter topic - LOW
	if sub.DeadLetterTopic == "" {
		recommendations = append(recommendations,
			fmt.Sprintf("[LOW] Subscription %s has no dead letter topic configured\n"+
				"  Risk: Failed messages may be lost without visibility\n"+
				"  Fix: Configure dead letter topic:\n"+
				"  gcloud pubsub subscriptions update %s --project=%s --dead-letter-topic=TOPIC_NAME --max-delivery-attempts=5\n",
				sub.Name,
				sub.Name, sub.ProjectID))
	}

	// Short ack deadline - INFO
	if sub.AckDeadlineSeconds < 30 {
		recommendations = append(recommendations,
			fmt.Sprintf("[INFO] Subscription %s has short ack deadline (%ds)\n"+
				"  Risk: Messages may be redelivered unnecessarily\n"+
				"  Consider: Increasing ack deadline if processing takes longer:\n"+
				"  gcloud pubsub subscriptions update %s --project=%s --ack-deadline=60\n",
				sub.Name, sub.AckDeadlineSeconds,
				sub.Name, sub.ProjectID))
	}

	// Cross-project subscription - INFO
	if sub.TopicProject != "" && sub.TopicProject != sub.ProjectID {
		recommendations = append(recommendations,
			fmt.Sprintf("[INFO] Subscription %s consumes from topic in different project (%s)\n"+
				"  Note: This indicates a cross-project trust relationship\n"+
				"  Review: Verify this cross-project access is intended\n",
				sub.Name, sub.TopicProject))
	}

	if len(recommendations) > 0 {
		m.LootMap["pubsub-security-recommendations"].Contents += fmt.Sprintf(
			"# Subscription: %s (Project: %s)\n%s\n",
			sub.Name, sub.ProjectID,
			strings.Join(recommendations, "\n"))
	}
}
