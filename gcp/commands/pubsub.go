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
