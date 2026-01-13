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

	// Count public resources and push subscriptions
	publicTopics := 0
	publicSubs := 0
	pushSubs := 0
	for _, topic := range m.Topics {
		for _, binding := range topic.IAMBindings {
			if binding.Member == "allUsers" || binding.Member == "allAuthenticatedUsers" {
				publicTopics++
				break
			}
		}
	}
	for _, sub := range m.Subscriptions {
		for _, binding := range sub.IAMBindings {
			if binding.Member == "allUsers" || binding.Member == "allAuthenticatedUsers" {
				publicSubs++
				break
			}
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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBSUB_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Pub/Sub topics in project %s", projectID))
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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PUBSUB_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Pub/Sub subscriptions in project %s", projectID))
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
	m.LootMap["pubsub-commands"] = &internal.LootFile{
		Name:     "pubsub-commands",
		Contents: "# Pub/Sub Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *PubSubModule) addTopicToLoot(topic PubSubService.TopicInfo) {
	m.LootMap["pubsub-commands"].Contents += fmt.Sprintf(
		"## Topic: %s (Project: %s)\n"+
			"# Subscriptions: %d\n",
		topic.Name, topic.ProjectID,
		topic.SubscriptionCount,
	)

	if topic.KmsKeyName != "" {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("# KMS Key: %s\n", topic.KmsKeyName)
	}

	if len(topic.IAMBindings) > 0 {
		m.LootMap["pubsub-commands"].Contents += "# IAM Bindings:\n"
		for _, binding := range topic.IAMBindings {
			m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("#   %s -> %s\n", binding.Role, binding.Member)
		}
	}

	m.LootMap["pubsub-commands"].Contents += fmt.Sprintf(
		"\n# Describe topic:\n"+
			"gcloud pubsub topics describe %s --project=%s\n\n"+
			"# Get IAM policy:\n"+
			"gcloud pubsub topics get-iam-policy %s --project=%s\n\n"+
			"# List subscriptions:\n"+
			"gcloud pubsub topics list-subscriptions %s --project=%s\n\n"+
			"# Publish a message:\n"+
			"gcloud pubsub topics publish %s --message='test' --project=%s\n\n",
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
		topic.Name, topic.ProjectID,
	)
}

func (m *PubSubModule) addSubscriptionToLoot(sub PubSubService.SubscriptionInfo) {
	m.LootMap["pubsub-commands"].Contents += fmt.Sprintf(
		"## Subscription: %s (Project: %s)\n"+
			"# Topic: %s\n",
		sub.Name, sub.ProjectID,
		sub.Topic,
	)

	// Cross-project info
	if sub.TopicProject != "" && sub.TopicProject != sub.ProjectID {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("# Cross-Project: Yes (topic in %s)\n", sub.TopicProject)
	}

	// Push endpoint info
	if sub.PushEndpoint != "" {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf(
			"# Push Endpoint: %s\n"+
				"# Push Service Account: %s\n",
			sub.PushEndpoint,
			sub.PushServiceAccount,
		)
	}

	// Export destinations
	if sub.BigQueryTable != "" {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("# BigQuery Export: %s\n", sub.BigQueryTable)
	}
	if sub.CloudStorageBucket != "" {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("# GCS Export: %s\n", sub.CloudStorageBucket)
	}

	// Dead letter config
	if sub.DeadLetterTopic != "" {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf(
			"# Dead Letter Topic: %s (Max Attempts: %d)\n",
			sub.DeadLetterTopic,
			sub.MaxDeliveryAttempts,
		)
	}

	// IAM bindings
	if len(sub.IAMBindings) > 0 {
		m.LootMap["pubsub-commands"].Contents += "# IAM Bindings:\n"
		for _, binding := range sub.IAMBindings {
			m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("#   %s -> %s\n", binding.Role, binding.Member)
		}
	}

	m.LootMap["pubsub-commands"].Contents += fmt.Sprintf(
		"\n# Describe subscription:\n"+
			"gcloud pubsub subscriptions describe %s --project=%s\n\n"+
			"# Get IAM policy:\n"+
			"gcloud pubsub subscriptions get-iam-policy %s --project=%s\n\n"+
			"# Pull messages:\n"+
			"gcloud pubsub subscriptions pull %s --project=%s --limit=10 --auto-ack\n\n",
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
		sub.Name, sub.ProjectID,
	)

	// BigQuery command
	if sub.BigQueryTable != "" {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("# Query BigQuery export:\nbq show %s\n\n", sub.BigQueryTable)
	}

	// GCS command
	if sub.CloudStorageBucket != "" {
		m.LootMap["pubsub-commands"].Contents += fmt.Sprintf("# List GCS export:\ngsutil ls gs://%s/\n\n", sub.CloudStorageBucket)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *PubSubModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Topics table - one row per IAM binding
	topicsHeader := []string{
		"Project Name",
		"Project ID",
		"Topic Name",
		"Subscriptions",
		"KMS Key",
		"Retention",
		"IAM Role",
		"IAM Member",
	}

	var topicsBody [][]string
	for _, topic := range m.Topics {
		// Format KMS key
		kmsKey := "-"
		if topic.KmsKeyName != "" {
			kmsKey = topic.KmsKeyName
		}

		// Format retention
		retention := "-"
		if topic.MessageRetentionDuration != "" {
			retention = topic.MessageRetentionDuration
		}

		if len(topic.IAMBindings) > 0 {
			// One row per IAM binding
			for _, binding := range topic.IAMBindings {
				topicsBody = append(topicsBody, []string{
					m.GetProjectName(topic.ProjectID),
					topic.ProjectID,
					topic.Name,
					fmt.Sprintf("%d", topic.SubscriptionCount),
					kmsKey,
					retention,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// No IAM bindings - single row with empty IAM columns
			topicsBody = append(topicsBody, []string{
				m.GetProjectName(topic.ProjectID),
				topic.ProjectID,
				topic.Name,
				fmt.Sprintf("%d", topic.SubscriptionCount),
				kmsKey,
				retention,
				"-",
				"-",
			})
		}
	}

	// Subscriptions table - one row per IAM binding
	subsHeader := []string{
		"Project Name",
		"Project ID",
		"Subscription",
		"Topic",
		"Type",
		"Push Endpoint / Export",
		"Cross-Project",
		"Dead Letter",
		"IAM Role",
		"IAM Member",
	}

	var subsBody [][]string
	for _, sub := range m.Subscriptions {
		// Determine type
		subType := "Pull"
		destination := "-"
		if sub.PushEndpoint != "" {
			subType = "Push"
			destination = sub.PushEndpoint
		} else if sub.BigQueryTable != "" {
			subType = "BigQuery"
			destination = sub.BigQueryTable
		} else if sub.CloudStorageBucket != "" {
			subType = "GCS"
			destination = sub.CloudStorageBucket
		}

		// Format cross-project
		crossProject := "-"
		if sub.TopicProject != "" && sub.TopicProject != sub.ProjectID {
			crossProject = sub.TopicProject
		}

		// Format dead letter
		deadLetter := "-"
		if sub.DeadLetterTopic != "" {
			deadLetter = sub.DeadLetterTopic
		}

		if len(sub.IAMBindings) > 0 {
			// One row per IAM binding
			for _, binding := range sub.IAMBindings {
				subsBody = append(subsBody, []string{
					m.GetProjectName(sub.ProjectID),
					sub.ProjectID,
					sub.Name,
					sub.Topic,
					subType,
					destination,
					crossProject,
					deadLetter,
					binding.Role,
					binding.Member,
				})
			}
		} else {
			// No IAM bindings - single row with empty IAM columns
			subsBody = append(subsBody, []string{
				m.GetProjectName(sub.ProjectID),
				sub.ProjectID,
				sub.Name,
				sub.Topic,
				subType,
				destination,
				crossProject,
				deadLetter,
				"-",
				"-",
			})
		}
	}

	// Collect loot files - only include if they have content beyond the header
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
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


