package loggingservice

import (
	"context"
	"fmt"
	"strings"

	logging "google.golang.org/api/logging/v2"
)

type LoggingService struct{}

func New() *LoggingService {
	return &LoggingService{}
}

// SinkInfo holds Cloud Logging sink details with security-relevant information
type SinkInfo struct {
	Name              string
	ProjectID         string
	Description       string
	CreateTime        string
	UpdateTime        string

	// Destination configuration
	Destination       string  // Full destination resource name
	DestinationType   string  // bigquery, storage, pubsub, logging
	DestinationBucket string  // For storage destinations
	DestinationDataset string // For BigQuery destinations
	DestinationTopic  string  // For Pub/Sub destinations
	DestinationProject string // Project containing the destination

	// Filter
	Filter            string
	Disabled          bool

	// Export identity
	WriterIdentity    string  // Service account that writes to destination

	// Inclusion/exclusion
	ExclusionFilters  []string

	// Cross-project indicator
	IsCrossProject    bool
}

// MetricInfo holds log-based metric details
type MetricInfo struct {
	Name        string
	ProjectID   string
	Description string
	Filter      string
	CreateTime  string
	UpdateTime  string

	// Metric configuration
	MetricKind  string  // DELTA, GAUGE, CUMULATIVE
	ValueType   string  // INT64, DOUBLE, DISTRIBUTION

	// Labels extracted from logs
	LabelCount  int
}

// Sinks retrieves all logging sinks in a project
func (ls *LoggingService) Sinks(projectID string) ([]SinkInfo, error) {
	ctx := context.Background()

	service, err := logging.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Logging service: %v", err)
	}

	var sinks []SinkInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Sinks.List(parent)
	err = call.Pages(ctx, func(page *logging.ListSinksResponse) error {
		for _, sink := range page.Sinks {
			info := parseSinkInfo(sink, projectID)
			sinks = append(sinks, info)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list sinks: %v", err)
	}

	return sinks, nil
}

// Metrics retrieves all log-based metrics in a project
func (ls *LoggingService) Metrics(projectID string) ([]MetricInfo, error) {
	ctx := context.Background()

	service, err := logging.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Logging service: %v", err)
	}

	var metrics []MetricInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	call := service.Projects.Metrics.List(parent)
	err = call.Pages(ctx, func(page *logging.ListLogMetricsResponse) error {
		for _, metric := range page.Metrics {
			info := parseMetricInfo(metric, projectID)
			metrics = append(metrics, info)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list metrics: %v", err)
	}

	return metrics, nil
}

// parseSinkInfo extracts relevant information from a logging sink
func parseSinkInfo(sink *logging.LogSink, projectID string) SinkInfo {
	info := SinkInfo{
		Name:           sink.Name,
		ProjectID:      projectID,
		Description:    sink.Description,
		CreateTime:     sink.CreateTime,
		UpdateTime:     sink.UpdateTime,
		Destination:    sink.Destination,
		Filter:         sink.Filter,
		Disabled:       sink.Disabled,
		WriterIdentity: sink.WriterIdentity,
	}

	// Parse destination type and details
	info.DestinationType, info.DestinationProject = parseDestination(sink.Destination)

	switch info.DestinationType {
	case "storage":
		info.DestinationBucket = extractBucketName(sink.Destination)
	case "bigquery":
		info.DestinationDataset = extractDatasetName(sink.Destination)
	case "pubsub":
		info.DestinationTopic = extractTopicName(sink.Destination)
	}

	// Check if cross-project
	if info.DestinationProject != "" && info.DestinationProject != projectID {
		info.IsCrossProject = true
	}

	// Parse exclusion filters
	for _, exclusion := range sink.Exclusions {
		if !exclusion.Disabled {
			info.ExclusionFilters = append(info.ExclusionFilters, exclusion.Filter)
		}
	}

	return info
}

// parseMetricInfo extracts relevant information from a log-based metric
func parseMetricInfo(metric *logging.LogMetric, projectID string) MetricInfo {
	info := MetricInfo{
		Name:        metric.Name,
		ProjectID:   projectID,
		Description: metric.Description,
		Filter:      metric.Filter,
		CreateTime:  metric.CreateTime,
		UpdateTime:  metric.UpdateTime,
	}

	if metric.MetricDescriptor != nil {
		info.MetricKind = metric.MetricDescriptor.MetricKind
		info.ValueType = metric.MetricDescriptor.ValueType
		info.LabelCount = len(metric.MetricDescriptor.Labels)
	}

	return info
}

// parseDestination parses the destination resource name
func parseDestination(destination string) (destType string, project string) {
	switch {
	case strings.HasPrefix(destination, "storage.googleapis.com/"):
		destType = "storage"
		// Format: storage.googleapis.com/bucket-name
		parts := strings.Split(destination, "/")
		if len(parts) >= 2 {
			// Bucket name might encode project, but typically doesn't
			project = ""
		}
	case strings.HasPrefix(destination, "bigquery.googleapis.com/"):
		destType = "bigquery"
		// Format: bigquery.googleapis.com/projects/PROJECT_ID/datasets/DATASET_ID
		if idx := strings.Index(destination, "/projects/"); idx >= 0 {
			remainder := destination[idx+len("/projects/"):]
			if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
				project = remainder[:slashIdx]
			}
		}
	case strings.HasPrefix(destination, "pubsub.googleapis.com/"):
		destType = "pubsub"
		// Format: pubsub.googleapis.com/projects/PROJECT_ID/topics/TOPIC_ID
		if idx := strings.Index(destination, "/projects/"); idx >= 0 {
			remainder := destination[idx+len("/projects/"):]
			if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
				project = remainder[:slashIdx]
			}
		}
	case strings.HasPrefix(destination, "logging.googleapis.com/"):
		destType = "logging"
		// Format: logging.googleapis.com/projects/PROJECT_ID/locations/LOCATION/buckets/BUCKET_ID
		if idx := strings.Index(destination, "/projects/"); idx >= 0 {
			remainder := destination[idx+len("/projects/"):]
			if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
				project = remainder[:slashIdx]
			}
		}
	default:
		destType = "unknown"
	}
	return
}

// extractBucketName extracts bucket name from storage destination
func extractBucketName(destination string) string {
	// Format: storage.googleapis.com/bucket-name
	parts := strings.SplitN(destination, "/", 2)
	if len(parts) >= 2 {
		return parts[1]
	}
	return destination
}

// extractDatasetName extracts dataset name from BigQuery destination
func extractDatasetName(destination string) string {
	// Format: bigquery.googleapis.com/projects/PROJECT_ID/datasets/DATASET_ID
	if idx := strings.Index(destination, "/datasets/"); idx >= 0 {
		remainder := destination[idx+len("/datasets/"):]
		if slashIdx := strings.Index(remainder, "/"); slashIdx >= 0 {
			return remainder[:slashIdx]
		}
		return remainder
	}
	return ""
}

// extractTopicName extracts topic name from Pub/Sub destination
func extractTopicName(destination string) string {
	// Format: pubsub.googleapis.com/projects/PROJECT_ID/topics/TOPIC_ID
	if idx := strings.Index(destination, "/topics/"); idx >= 0 {
		return destination[idx+len("/topics/"):]
	}
	return ""
}
