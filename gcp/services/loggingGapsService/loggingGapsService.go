package logginggapsservice

import (
	"context"
	"fmt"
	"strings"

	logging "cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	compute "google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	storage "google.golang.org/api/storage/v1"
	"google.golang.org/api/iterator"
)

type LoggingGapsService struct{}

func New() *LoggingGapsService {
	return &LoggingGapsService{}
}

// LoggingGap represents a resource with missing or incomplete logging
type LoggingGap struct {
	ResourceType    string   // compute, cloudsql, gke, bucket, project
	ResourceName    string
	ProjectID       string
	Location        string
	LoggingStatus   string   // disabled, partial, misconfigured
	MissingLogs     []string // Which logs are missing
	StealthValue    string   // HIGH, MEDIUM, LOW - value for attacker stealth
	Recommendations []string
	ExploitCommands []string // Commands to exploit the gap
}

// AuditLogConfig represents the audit logging configuration for a project
type AuditLogConfig struct {
	ProjectID          string
	DataAccessEnabled  bool
	AdminActivityEnabled bool // Always on, but good to verify
	SystemEventEnabled bool
	PolicyDeniedEnabled bool
	ExemptedMembers    []string
	ExemptedServices   []string
}

// EnumerateLoggingGaps finds resources with logging gaps
func (s *LoggingGapsService) EnumerateLoggingGaps(projectID string) ([]LoggingGap, *AuditLogConfig, error) {
	var gaps []LoggingGap

	// Get project-level audit log config
	auditConfig, err := s.getProjectAuditConfig(projectID)
	if err != nil {
		auditConfig = &AuditLogConfig{ProjectID: projectID}
	}

	// Check various resource types for logging gaps
	if bucketGaps, err := s.checkBucketLogging(projectID); err == nil {
		gaps = append(gaps, bucketGaps...)
	}

	if computeGaps, err := s.checkComputeLogging(projectID); err == nil {
		gaps = append(gaps, computeGaps...)
	}

	if gkeGaps, err := s.checkGKELogging(projectID); err == nil {
		gaps = append(gaps, gkeGaps...)
	}

	if sqlGaps, err := s.checkCloudSQLLogging(projectID); err == nil {
		gaps = append(gaps, sqlGaps...)
	}

	// Check for log sinks that might be misconfigured
	if sinkGaps, err := s.checkLogSinks(projectID); err == nil {
		gaps = append(gaps, sinkGaps...)
	}

	return gaps, auditConfig, nil
}

func (s *LoggingGapsService) getProjectAuditConfig(projectID string) (*AuditLogConfig, error) {
	ctx := context.Background()
	client, err := logging.NewConfigClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	config := &AuditLogConfig{
		ProjectID:            projectID,
		AdminActivityEnabled: true, // Always enabled
	}

	// List log sinks to understand logging configuration
	parent := fmt.Sprintf("projects/%s", projectID)
	it := client.ListSinks(ctx, &loggingpb.ListSinksRequest{Parent: parent})

	for {
		sink, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		// Check if there's a sink for audit logs
		if strings.Contains(sink.Filter, "protoPayload.@type") {
			config.DataAccessEnabled = true
		}
	}

	return config, nil
}

func (s *LoggingGapsService) checkBucketLogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := storage.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	resp, err := service.Buckets.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, bucket := range resp.Items {
		missingLogs := []string{}
		loggingStatus := "enabled"

		// Check if bucket logging is enabled
		if bucket.Logging == nil || bucket.Logging.LogBucket == "" {
			missingLogs = append(missingLogs, "Access logs disabled")
			loggingStatus = "disabled"
		}

		if len(missingLogs) > 0 {
			gap := LoggingGap{
				ResourceType:  "bucket",
				ResourceName:  bucket.Name,
				ProjectID:     projectID,
				Location:      bucket.Location,
				LoggingStatus: loggingStatus,
				MissingLogs:   missingLogs,
				StealthValue:  "MEDIUM",
				Recommendations: []string{
					"Enable access logging for the bucket",
					fmt.Sprintf("gsutil logging set on -b gs://%s gs://%s", bucket.Name, bucket.Name),
				},
				ExploitCommands: []string{
					fmt.Sprintf("# Access without logs - stealth data exfil:\ngsutil cp gs://%s/* ./loot/ 2>/dev/null", bucket.Name),
					fmt.Sprintf("# List contents without being logged:\ngsutil ls -r gs://%s/", bucket.Name),
				},
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps, nil
}

func (s *LoggingGapsService) checkComputeLogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	// Check VPC flow logs on subnets
	req := service.Subnetworks.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for region, subnets := range page.Items {
			regionName := region
			if strings.HasPrefix(region, "regions/") {
				regionName = strings.TrimPrefix(region, "regions/")
			}

			for _, subnet := range subnets.Subnetworks {
				missingLogs := []string{}
				loggingStatus := "enabled"

				// Check if VPC flow logs are enabled
				if subnet.LogConfig == nil || !subnet.LogConfig.Enable {
					missingLogs = append(missingLogs, "VPC Flow Logs disabled")
					loggingStatus = "disabled"
				} else if subnet.LogConfig.AggregationInterval != "INTERVAL_5_SEC" {
					missingLogs = append(missingLogs, "VPC Flow Logs not at max granularity")
					loggingStatus = "partial"
				}

				if len(missingLogs) > 0 {
					gap := LoggingGap{
						ResourceType:  "subnet",
						ResourceName:  subnet.Name,
						ProjectID:     projectID,
						Location:      regionName,
						LoggingStatus: loggingStatus,
						MissingLogs:   missingLogs,
						StealthValue:  "HIGH",
						Recommendations: []string{
							"Enable VPC Flow Logs on subnet",
							"Set aggregation interval to 5 seconds for maximum visibility",
						},
						ExploitCommands: []string{
							fmt.Sprintf("# Network activity on this subnet won't be logged"),
							fmt.Sprintf("# Lateral movement within VPC: %s", subnet.IpCidrRange),
						},
					}
					gaps = append(gaps, gap)
				}
			}
		}
		return nil
	})

	return gaps, err
}

func (s *LoggingGapsService) checkGKELogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := container.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := service.Projects.Locations.Clusters.List(parent).Do()
	if err != nil {
		return nil, err
	}

	for _, cluster := range resp.Clusters {
		missingLogs := []string{}
		loggingStatus := "enabled"

		// Check logging service
		if cluster.LoggingService == "" || cluster.LoggingService == "none" {
			missingLogs = append(missingLogs, "Cluster logging disabled")
			loggingStatus = "disabled"
		} else if cluster.LoggingService != "logging.googleapis.com/kubernetes" {
			missingLogs = append(missingLogs, "Not using Cloud Logging")
			loggingStatus = "partial"
		}

		// Check monitoring service
		if cluster.MonitoringService == "" || cluster.MonitoringService == "none" {
			missingLogs = append(missingLogs, "Cluster monitoring disabled")
		}

		// Check for specific logging components
		if cluster.LoggingConfig != nil && cluster.LoggingConfig.ComponentConfig != nil {
			components := cluster.LoggingConfig.ComponentConfig.EnableComponents
			hasSystemComponents := false
			hasWorkloads := false
			for _, comp := range components {
				if comp == "SYSTEM_COMPONENTS" {
					hasSystemComponents = true
				}
				if comp == "WORKLOADS" {
					hasWorkloads = true
				}
			}
			if !hasSystemComponents {
				missingLogs = append(missingLogs, "System component logs disabled")
			}
			if !hasWorkloads {
				missingLogs = append(missingLogs, "Workload logs disabled")
			}
		}

		if len(missingLogs) > 0 {
			gap := LoggingGap{
				ResourceType:  "gke",
				ResourceName:  cluster.Name,
				ProjectID:     projectID,
				Location:      cluster.Location,
				LoggingStatus: loggingStatus,
				MissingLogs:   missingLogs,
				StealthValue:  "CRITICAL",
				Recommendations: []string{
					"Enable Cloud Logging for GKE cluster",
					"Enable SYSTEM_COMPONENTS and WORKLOADS logging",
				},
				ExploitCommands: []string{
					fmt.Sprintf("# Get credentials for cluster with limited logging:\ngcloud container clusters get-credentials %s --location=%s --project=%s", cluster.Name, cluster.Location, projectID),
					"# Run commands without workload logging:\nkubectl exec -it <pod> -- /bin/sh",
					"# Deploy backdoor pods without detection:\nkubectl run backdoor --image=alpine -- sleep infinity",
				},
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps, nil
}

func (s *LoggingGapsService) checkCloudSQLLogging(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	service, err := sqladmin.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var gaps []LoggingGap

	resp, err := service.Instances.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, instance := range resp.Items {
		missingLogs := []string{}
		loggingStatus := "enabled"

		// Check database flags for logging
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			hasQueryLogging := false
			hasConnectionLogging := false

			for _, flag := range instance.Settings.DatabaseFlags {
				// MySQL flags
				if flag.Name == "general_log" && flag.Value == "on" {
					hasQueryLogging = true
				}
				// PostgreSQL flags
				if flag.Name == "log_statement" && flag.Value == "all" {
					hasQueryLogging = true
				}
				if flag.Name == "log_connections" && flag.Value == "on" {
					hasConnectionLogging = true
				}
			}

			if !hasQueryLogging {
				missingLogs = append(missingLogs, "Query logging not enabled")
				loggingStatus = "partial"
			}
			if !hasConnectionLogging {
				missingLogs = append(missingLogs, "Connection logging not enabled")
			}
		} else {
			missingLogs = append(missingLogs, "No logging flags configured")
			loggingStatus = "disabled"
		}

		if len(missingLogs) > 0 {
			gap := LoggingGap{
				ResourceType:  "cloudsql",
				ResourceName:  instance.Name,
				ProjectID:     projectID,
				Location:      instance.Region,
				LoggingStatus: loggingStatus,
				MissingLogs:   missingLogs,
				StealthValue:  "HIGH",
				Recommendations: []string{
					"Enable query and connection logging",
					"For MySQL: SET GLOBAL general_log = 'ON'",
					"For PostgreSQL: ALTER SYSTEM SET log_statement = 'all'",
				},
				ExploitCommands: []string{
					fmt.Sprintf("# Connect without query logging:\ngcloud sql connect %s --user=root --project=%s", instance.Name, projectID),
					"# Execute queries without being logged",
					"# Exfiltrate data stealthily",
				},
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps, nil
}

func (s *LoggingGapsService) checkLogSinks(projectID string) ([]LoggingGap, error) {
	ctx := context.Background()
	client, err := logging.NewConfigClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var gaps []LoggingGap

	parent := fmt.Sprintf("projects/%s", projectID)
	it := client.ListSinks(ctx, &loggingpb.ListSinksRequest{Parent: parent})

	sinkCount := 0
	for {
		sink, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		sinkCount++

		// Check for disabled sinks
		if sink.Disabled {
			gap := LoggingGap{
				ResourceType:  "log-sink",
				ResourceName:  sink.Name,
				ProjectID:     projectID,
				Location:      "global",
				LoggingStatus: "disabled",
				MissingLogs:   []string{"Sink is disabled"},
				StealthValue:  "HIGH",
				Recommendations: []string{
					"Enable the log sink or remove if not needed",
				},
				ExploitCommands: []string{
					"# Logs matching this sink filter are not being exported",
					fmt.Sprintf("# Sink filter: %s", sink.Filter),
				},
			}
			gaps = append(gaps, gap)
		}

		// Check for overly permissive exclusion filters
		for _, exclusion := range sink.Exclusions {
			if !exclusion.Disabled {
				gap := LoggingGap{
					ResourceType:  "log-exclusion",
					ResourceName:  fmt.Sprintf("%s/%s", sink.Name, exclusion.Name),
					ProjectID:     projectID,
					Location:      "global",
					LoggingStatus: "exclusion-active",
					MissingLogs:   []string{fmt.Sprintf("Exclusion filter: %s", exclusion.Filter)},
					StealthValue:  "MEDIUM",
					Recommendations: []string{
						"Review exclusion filter for security implications",
					},
					ExploitCommands: []string{
						fmt.Sprintf("# Logs matching this filter are excluded: %s", exclusion.Filter),
					},
				}
				gaps = append(gaps, gap)
			}
		}
	}

	// Check if there are no sinks at all
	if sinkCount == 0 {
		gap := LoggingGap{
			ResourceType:  "project",
			ResourceName:  projectID,
			ProjectID:     projectID,
			Location:      "global",
			LoggingStatus: "no-export",
			MissingLogs:   []string{"No log sinks configured - logs only in Cloud Logging"},
			StealthValue:  "LOW",
			Recommendations: []string{
				"Configure log sinks to export logs to external storage",
				"Ensures logs are preserved even if project is compromised",
			},
			ExploitCommands: []string{
				"# Logs can be deleted if project is compromised",
				"# Consider exporting to separate project or external SIEM",
			},
		}
		gaps = append(gaps, gap)
	}

	return gaps, nil
}
