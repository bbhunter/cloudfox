package pubsubservice

import (
	"context"
	"fmt"
	"strings"

	pubsub "google.golang.org/api/pubsub/v1"
)

type PubSubService struct{}

func New() *PubSubService {
	return &PubSubService{}
}

// TopicInfo holds Pub/Sub topic details with security-relevant information
type TopicInfo struct {
	Name                    string
	ProjectID               string
	KmsKeyName              string  // Encryption key if set
	MessageRetentionDuration string
	SchemaSettings          string
	Labels                  map[string]string

	// IAM
	PublisherMembers        []string
	SubscriberMembers       []string
	IsPublicPublish         bool  // allUsers/allAuthenticatedUsers can publish
	IsPublicSubscribe       bool  // allUsers/allAuthenticatedUsers can subscribe

	// Subscriptions count
	SubscriptionCount       int
}

// SubscriptionInfo holds Pub/Sub subscription details
type SubscriptionInfo struct {
	Name                    string
	ProjectID               string
	Topic                   string
	TopicProject            string  // Topic may be in different project

	// Configuration
	AckDeadlineSeconds      int64
	MessageRetention        string
	RetainAckedMessages     bool
	ExpirationPolicy        string  // TTL
	Filter                  string

	// Push configuration
	PushEndpoint            string  // Empty if pull subscription
	PushOIDCAudience        string
	PushServiceAccount      string

	// Dead letter
	DeadLetterTopic         string
	MaxDeliveryAttempts     int64

	// BigQuery export
	BigQueryTable           string

	// Cloud Storage export
	CloudStorageBucket      string

	// IAM
	ConsumerMembers         []string
	IsPublicConsume         bool
}

// Topics retrieves all Pub/Sub topics in a project
func (ps *PubSubService) Topics(projectID string) ([]TopicInfo, error) {
	ctx := context.Background()

	service, err := pubsub.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Pub/Sub service: %v", err)
	}

	var topics []TopicInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Topics.List(parent)
	err = call.Pages(ctx, func(page *pubsub.ListTopicsResponse) error {
		for _, topic := range page.Topics {
			info := parseTopicInfo(topic, projectID)

			// Get subscription count
			subCount, _ := ps.getTopicSubscriptionCount(service, topic.Name)
			info.SubscriptionCount = subCount

			// Try to get IAM policy
			iamPolicy, iamErr := ps.getTopicIAMPolicy(service, topic.Name)
			if iamErr == nil && iamPolicy != nil {
				info.PublisherMembers, info.SubscriberMembers,
					info.IsPublicPublish, info.IsPublicSubscribe = parseTopicBindings(iamPolicy)
			}

			topics = append(topics, info)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list topics: %v", err)
	}

	return topics, nil
}

// Subscriptions retrieves all Pub/Sub subscriptions in a project
func (ps *PubSubService) Subscriptions(projectID string) ([]SubscriptionInfo, error) {
	ctx := context.Background()

	service, err := pubsub.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Pub/Sub service: %v", err)
	}

	var subscriptions []SubscriptionInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Subscriptions.List(parent)
	err = call.Pages(ctx, func(page *pubsub.ListSubscriptionsResponse) error {
		for _, sub := range page.Subscriptions {
			info := parseSubscriptionInfo(sub, projectID)

			// Try to get IAM policy
			iamPolicy, iamErr := ps.getSubscriptionIAMPolicy(service, sub.Name)
			if iamErr == nil && iamPolicy != nil {
				info.ConsumerMembers, info.IsPublicConsume = parseSubscriptionBindings(iamPolicy)
			}

			subscriptions = append(subscriptions, info)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %v", err)
	}

	return subscriptions, nil
}

// parseTopicInfo extracts relevant information from a Pub/Sub topic
func parseTopicInfo(topic *pubsub.Topic, projectID string) TopicInfo {
	info := TopicInfo{
		Name:      extractName(topic.Name),
		ProjectID: projectID,
		Labels:    topic.Labels,
	}

	if topic.KmsKeyName != "" {
		info.KmsKeyName = topic.KmsKeyName
	}

	if topic.MessageRetentionDuration != "" {
		info.MessageRetentionDuration = topic.MessageRetentionDuration
	}

	if topic.SchemaSettings != nil {
		info.SchemaSettings = fmt.Sprintf("%s (%s)",
			extractName(topic.SchemaSettings.Schema),
			topic.SchemaSettings.Encoding)
	}

	return info
}

// parseSubscriptionInfo extracts relevant information from a Pub/Sub subscription
func parseSubscriptionInfo(sub *pubsub.Subscription, projectID string) SubscriptionInfo {
	info := SubscriptionInfo{
		Name:                sub.Name,
		ProjectID:           projectID,
		Topic:               extractName(sub.Topic),
		AckDeadlineSeconds:  sub.AckDeadlineSeconds,
		RetainAckedMessages: sub.RetainAckedMessages,
		Filter:              sub.Filter,
	}

	// Extract name from full path
	info.Name = extractName(sub.Name)

	// Extract topic project (may be different from subscription project)
	if strings.Contains(sub.Topic, "/") {
		parts := strings.Split(sub.Topic, "/")
		if len(parts) >= 2 {
			info.TopicProject = parts[1]
		}
	}

	// Message retention
	if sub.MessageRetentionDuration != "" {
		info.MessageRetention = sub.MessageRetentionDuration
	}

	// Expiration policy
	if sub.ExpirationPolicy != nil && sub.ExpirationPolicy.Ttl != "" {
		info.ExpirationPolicy = sub.ExpirationPolicy.Ttl
	}

	// Push configuration
	if sub.PushConfig != nil {
		info.PushEndpoint = sub.PushConfig.PushEndpoint

		if sub.PushConfig.OidcToken != nil {
			info.PushServiceAccount = sub.PushConfig.OidcToken.ServiceAccountEmail
			info.PushOIDCAudience = sub.PushConfig.OidcToken.Audience
		}
	}

	// Dead letter policy
	if sub.DeadLetterPolicy != nil {
		info.DeadLetterTopic = extractName(sub.DeadLetterPolicy.DeadLetterTopic)
		info.MaxDeliveryAttempts = sub.DeadLetterPolicy.MaxDeliveryAttempts
	}

	// BigQuery config
	if sub.BigqueryConfig != nil {
		info.BigQueryTable = sub.BigqueryConfig.Table
	}

	// Cloud Storage config
	if sub.CloudStorageConfig != nil {
		info.CloudStorageBucket = sub.CloudStorageConfig.Bucket
	}

	return info
}

// getTopicSubscriptionCount counts subscriptions for a topic
func (ps *PubSubService) getTopicSubscriptionCount(service *pubsub.Service, topicName string) (int, error) {
	ctx := context.Background()

	resp, err := service.Projects.Topics.Subscriptions.List(topicName).Context(ctx).Do()
	if err != nil {
		return 0, err
	}

	return len(resp.Subscriptions), nil
}

// getTopicIAMPolicy retrieves the IAM policy for a topic
func (ps *PubSubService) getTopicIAMPolicy(service *pubsub.Service, topicName string) (*pubsub.Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Topics.GetIamPolicy(topicName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// getSubscriptionIAMPolicy retrieves the IAM policy for a subscription
func (ps *PubSubService) getSubscriptionIAMPolicy(service *pubsub.Service, subscriptionName string) (*pubsub.Policy, error) {
	ctx := context.Background()

	policy, err := service.Projects.Subscriptions.GetIamPolicy(subscriptionName).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// parseTopicBindings extracts who can publish/subscribe and checks for public access
func parseTopicBindings(policy *pubsub.Policy) (publishers []string, subscribers []string, publicPublish bool, publicSubscribe bool) {
	for _, binding := range policy.Bindings {
		switch binding.Role {
		case "roles/pubsub.publisher":
			publishers = append(publishers, binding.Members...)
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					publicPublish = true
				}
			}
		case "roles/pubsub.subscriber":
			subscribers = append(subscribers, binding.Members...)
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					publicSubscribe = true
				}
			}
		}
	}
	return
}

// parseSubscriptionBindings extracts who can consume messages
func parseSubscriptionBindings(policy *pubsub.Policy) (consumers []string, isPublic bool) {
	for _, binding := range policy.Bindings {
		if binding.Role == "roles/pubsub.subscriber" ||
			binding.Role == "roles/pubsub.viewer" {
			consumers = append(consumers, binding.Members...)
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					isPublic = true
				}
			}
		}
	}
	return
}

// extractName extracts just the resource name from the full resource name
func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
