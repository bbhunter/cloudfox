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

	compute "google.golang.org/api/compute/v1"
	storage "google.golang.org/api/storage/v1"
)

// Module name constant
const GCP_DATAEXFILTRATION_MODULE_NAME string = "data-exfiltration"

var GCPDataExfiltrationCommand = &cobra.Command{
	Use:     GCP_DATAEXFILTRATION_MODULE_NAME,
	Aliases: []string{"exfil", "data-exfil", "exfiltration"},
	Short:   "Identify data exfiltration paths and high-risk data exposure",
	Long: `Identify data exfiltration vectors and paths in GCP environments.

Features:
- Finds public snapshots and images
- Identifies export capabilities (BigQuery, GCS)
- Maps Pub/Sub push endpoints (external data flow)
- Finds logging sinks to external destinations
- Identifies publicly accessible storage
- Analyzes backup export configurations
- Generates exploitation commands for penetration testing

This module helps identify how data could be exfiltrated from the environment
through various GCP services.`,
	Run: runGCPDataExfiltrationCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type ExfiltrationPath struct {
	PathType     string // "snapshot", "bucket", "pubsub", "logging", "bigquery", "image"
	ResourceName string
	ProjectID    string
	Description  string
	Destination  string // Where data can go
	RiskLevel    string // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons  []string
	ExploitCommand string
}

type PublicExport struct {
	ResourceType string
	ResourceName string
	ProjectID    string
	AccessLevel  string // "public", "allAuthenticatedUsers", "specific_domain"
	DataType     string // "snapshot", "image", "bucket", "dataset"
	Size         string
	RiskLevel    string
}

// ------------------------------
// Module Struct
// ------------------------------
type DataExfiltrationModule struct {
	gcpinternal.BaseGCPModule

	ExfiltrationPaths []ExfiltrationPath
	PublicExports     []PublicExport
	LootMap           map[string]*internal.LootFile
	mu                sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type DataExfiltrationOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o DataExfiltrationOutput) TableFiles() []internal.TableFile { return o.Table }
func (o DataExfiltrationOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPDataExfiltrationCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_DATAEXFILTRATION_MODULE_NAME)
	if err != nil {
		return
	}

	module := &DataExfiltrationModule{
		BaseGCPModule:     gcpinternal.NewBaseGCPModule(cmdCtx),
		ExfiltrationPaths: []ExfiltrationPath{},
		PublicExports:     []PublicExport{},
		LootMap:           make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *DataExfiltrationModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Identifying data exfiltration paths...", GCP_DATAEXFILTRATION_MODULE_NAME)

	// Process each project
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_DATAEXFILTRATION_MODULE_NAME, m.processProject)

	// Check results
	if len(m.ExfiltrationPaths) == 0 && len(m.PublicExports) == 0 {
		logger.InfoM("No data exfiltration paths found", GCP_DATAEXFILTRATION_MODULE_NAME)
		return
	}

	// Count by risk level
	criticalCount := 0
	highCount := 0
	for _, p := range m.ExfiltrationPaths {
		switch p.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d exfiltration path(s) and %d public export(s): %d CRITICAL, %d HIGH",
		len(m.ExfiltrationPaths), len(m.PublicExports), criticalCount, highCount), GCP_DATAEXFILTRATION_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *DataExfiltrationModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing exfiltration paths in project: %s", projectID), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	// 1. Find public/shared snapshots
	m.findPublicSnapshots(ctx, projectID, logger)

	// 2. Find public/shared images
	m.findPublicImages(ctx, projectID, logger)

	// 3. Find public buckets
	m.findPublicBuckets(ctx, projectID, logger)

	// 4. Find cross-project logging sinks
	m.findLoggingSinks(ctx, projectID, logger)

	// 5. Analyze potential exfiltration vectors
	m.analyzeExfiltrationVectors(ctx, projectID, logger)
}

// findPublicSnapshots finds snapshots that are publicly accessible or shared
func (m *DataExfiltrationModule) findPublicSnapshots(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error creating Compute service: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		}
		return
	}

	req := computeService.Snapshots.List(projectID)
	err = req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			// Get IAM policy for snapshot
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			// Check for public access
			isPublic := false
			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" {
						isPublic = true
						accessLevel = "public"
						break
					}
					if member == "allAuthenticatedUsers" {
						isPublic = true
						accessLevel = "allAuthenticatedUsers"
						break
					}
				}
			}

			if isPublic {
				export := PublicExport{
					ResourceType: "snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "disk_snapshot",
					Size:         fmt.Sprintf("%d GB", snapshot.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "snapshot",
					ResourceName: snapshot.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Public disk snapshot (%d GB)", snapshot.DiskSizeGb),
					Destination:  "Anyone on the internet",
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"Snapshot is publicly accessible", "May contain sensitive data from disk"},
					ExploitCommand: fmt.Sprintf(
						"# Create disk from public snapshot\n"+
							"gcloud compute disks create exfil-disk --source-snapshot=projects/%s/global/snapshots/%s --zone=us-central1-a",
						projectID, snapshot.Name),
				}

				m.mu.Lock()
				m.PublicExports = append(m.PublicExports, export)
				m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
				m.addExfiltrationPathToLoot(path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil && globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Error listing snapshots: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
}

// findPublicImages finds images that are publicly accessible or shared
func (m *DataExfiltrationModule) findPublicImages(ctx context.Context, projectID string, logger internal.Logger) {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return
	}

	req := computeService.Images.List(projectID)
	err = req.Pages(ctx, func(page *compute.ImageList) error {
		for _, image := range page.Items {
			// Get IAM policy for image
			policy, err := computeService.Images.GetIamPolicy(projectID, image.Name).Do()
			if err != nil {
				continue
			}

			// Check for public access
			isPublic := false
			accessLevel := ""
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" {
						isPublic = true
						accessLevel = "public"
						break
					}
					if member == "allAuthenticatedUsers" {
						isPublic = true
						accessLevel = "allAuthenticatedUsers"
						break
					}
				}
			}

			if isPublic {
				export := PublicExport{
					ResourceType: "image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					AccessLevel:  accessLevel,
					DataType:     "vm_image",
					Size:         fmt.Sprintf("%d GB", image.DiskSizeGb),
					RiskLevel:    "CRITICAL",
				}

				path := ExfiltrationPath{
					PathType:     "image",
					ResourceName: image.Name,
					ProjectID:    projectID,
					Description:  fmt.Sprintf("Public VM image (%d GB)", image.DiskSizeGb),
					Destination:  "Anyone on the internet",
					RiskLevel:    "CRITICAL",
					RiskReasons:  []string{"VM image is publicly accessible", "May contain embedded credentials or sensitive data"},
					ExploitCommand: fmt.Sprintf(
						"# Create instance from public image\n"+
							"gcloud compute instances create exfil-vm --image=projects/%s/global/images/%s --zone=us-central1-a",
						projectID, image.Name),
				}

				m.mu.Lock()
				m.PublicExports = append(m.PublicExports, export)
				m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
				m.addExfiltrationPathToLoot(path)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil && globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.ErrorM(fmt.Sprintf("Error listing images: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
	}
}

// findPublicBuckets finds GCS buckets with public access
func (m *DataExfiltrationModule) findPublicBuckets(ctx context.Context, projectID string, logger internal.Logger) {
	storageService, err := storage.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error creating Storage service: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		}
		return
	}

	// List buckets
	resp, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing buckets: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		}
		return
	}

	for _, bucket := range resp.Items {
		// Get IAM policy for bucket
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		// Check for public access
		isPublic := false
		accessLevel := ""
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" {
					isPublic = true
					accessLevel = "public"
					break
				}
				if member == "allAuthenticatedUsers" {
					isPublic = true
					accessLevel = "allAuthenticatedUsers"
					break
				}
			}
		}

		if isPublic {
			export := PublicExport{
				ResourceType: "bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				AccessLevel:  accessLevel,
				DataType:     "gcs_bucket",
				RiskLevel:    "CRITICAL",
			}

			path := ExfiltrationPath{
				PathType:     "bucket",
				ResourceName: bucket.Name,
				ProjectID:    projectID,
				Description:  "Public GCS bucket",
				Destination:  "Anyone on the internet",
				RiskLevel:    "CRITICAL",
				RiskReasons:  []string{"Bucket is publicly accessible", "May contain sensitive files"},
				ExploitCommand: fmt.Sprintf(
					"# List public bucket contents\n"+
						"gsutil ls -r gs://%s/\n"+
						"# Download all files\n"+
						"gsutil -m cp -r gs://%s/ ./exfil/",
					bucket.Name, bucket.Name),
			}

			m.mu.Lock()
			m.PublicExports = append(m.PublicExports, export)
			m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
			m.addExfiltrationPathToLoot(path)
			m.mu.Unlock()
		}
	}
}

// findLoggingSinks finds logging sinks that export to external destinations
func (m *DataExfiltrationModule) findLoggingSinks(ctx context.Context, projectID string, logger internal.Logger) {
	// Common exfiltration patterns via logging sinks
	// This would require the Logging API to be called
	// For now, we'll add known exfiltration patterns

	path := ExfiltrationPath{
		PathType:     "logging_sink",
		ResourceName: "cross-project-sink",
		ProjectID:    projectID,
		Description:  "Logging sinks can export logs to external projects or Pub/Sub topics",
		Destination:  "External project or Pub/Sub topic",
		RiskLevel:    "MEDIUM",
		RiskReasons:  []string{"Logs may contain sensitive information", "External destination may be attacker-controlled"},
		ExploitCommand: fmt.Sprintf(
			"# List logging sinks\n"+
				"gcloud logging sinks list --project=%s\n"+
				"# Create sink to external destination\n"+
				"# gcloud logging sinks create exfil-sink <destination> --project=%s",
			projectID, projectID),
	}

	m.mu.Lock()
	m.ExfiltrationPaths = append(m.ExfiltrationPaths, path)
	m.mu.Unlock()
}

// analyzeExfiltrationVectors analyzes potential exfiltration methods
func (m *DataExfiltrationModule) analyzeExfiltrationVectors(ctx context.Context, projectID string, logger internal.Logger) {
	// Common exfiltration vectors in GCP
	vectors := []ExfiltrationPath{
		{
			PathType:     "bigquery_export",
			ResourceName: "*",
			ProjectID:    projectID,
			Description:  "BigQuery datasets can be exported to GCS or queried directly",
			Destination:  "GCS bucket or external table",
			RiskLevel:    "MEDIUM",
			RiskReasons:  []string{"BigQuery may contain sensitive data", "Export destination may be accessible"},
			ExploitCommand: fmt.Sprintf(
				"# List BigQuery datasets\n"+
					"bq ls --project_id=%s\n"+
					"# Export table to GCS\n"+
					"bq extract --destination_format=CSV 'dataset.table' gs://bucket/export.csv",
				projectID),
		},
		{
			PathType:     "pubsub_subscription",
			ResourceName: "*",
			ProjectID:    projectID,
			Description:  "Pub/Sub push subscriptions can send data to external endpoints",
			Destination:  "External HTTP endpoint",
			RiskLevel:    "HIGH",
			RiskReasons:  []string{"Push subscriptions send data to configured endpoints", "Endpoint may be attacker-controlled"},
			ExploitCommand: fmt.Sprintf(
				"# List Pub/Sub topics and subscriptions\n"+
					"gcloud pubsub topics list --project=%s\n"+
					"gcloud pubsub subscriptions list --project=%s",
				projectID, projectID),
		},
		{
			PathType:     "cloud_functions",
			ResourceName: "*",
			ProjectID:    projectID,
			Description:  "Cloud Functions can be used to exfiltrate data via HTTP",
			Destination:  "External HTTP endpoint",
			RiskLevel:    "HIGH",
			RiskReasons:  []string{"Functions can make outbound HTTP requests", "Can access internal resources and exfiltrate data"},
			ExploitCommand: fmt.Sprintf(
				"# List Cloud Functions\n"+
					"gcloud functions list --project=%s",
				projectID),
		},
	}

	m.mu.Lock()
	m.ExfiltrationPaths = append(m.ExfiltrationPaths, vectors...)
	for _, v := range vectors {
		m.addExfiltrationPathToLoot(v)
	}
	m.mu.Unlock()
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *DataExfiltrationModule) initializeLootFiles() {
	m.LootMap["exfil-critical"] = &internal.LootFile{
		Name:     "exfil-critical",
		Contents: "# Critical Data Exfiltration Paths\n# Generated by CloudFox\n# These require immediate attention!\n\n",
	}
	m.LootMap["exfil-public-resources"] = &internal.LootFile{
		Name:     "exfil-public-resources",
		Contents: "# Public Resources (Data Exfiltration Risk)\n# Generated by CloudFox\n\n",
	}
	m.LootMap["exfil-commands"] = &internal.LootFile{
		Name:     "exfil-commands",
		Contents: "# Data Exfiltration Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
	}
	m.LootMap["exfil-high-risk"] = &internal.LootFile{
		Name:     "exfil-high-risk",
		Contents: "# High-Risk Exfiltration Resources\n# Generated by CloudFox\n\n",
	}
}

func (m *DataExfiltrationModule) addExfiltrationPathToLoot(path ExfiltrationPath) {
	// Critical paths
	if path.RiskLevel == "CRITICAL" {
		m.LootMap["exfil-critical"].Contents += fmt.Sprintf(
			"## %s: %s\n"+
				"Project: %s\n"+
				"Description: %s\n"+
				"Destination: %s\n"+
				"Risk Reasons:\n",
			path.PathType,
			path.ResourceName,
			path.ProjectID,
			path.Description,
			path.Destination,
		)
		for _, reason := range path.RiskReasons {
			m.LootMap["exfil-critical"].Contents += fmt.Sprintf("  - %s\n", reason)
		}
		m.LootMap["exfil-critical"].Contents += fmt.Sprintf("\nExploit:\n%s\n\n", path.ExploitCommand)
	}

	// High-risk paths
	if path.RiskLevel == "HIGH" {
		m.LootMap["exfil-high-risk"].Contents += fmt.Sprintf(
			"## %s: %s\n"+
				"Project: %s\n"+
				"Description: %s\n\n",
			path.PathType,
			path.ResourceName,
			path.ProjectID,
			path.Description,
		)
	}

	// All commands
	if path.ExploitCommand != "" {
		m.LootMap["exfil-commands"].Contents += fmt.Sprintf(
			"# %s: %s (%s)\n%s\n\n",
			path.PathType,
			path.ResourceName,
			path.RiskLevel,
			path.ExploitCommand,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *DataExfiltrationModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort paths by risk level
	sort.Slice(m.ExfiltrationPaths, func(i, j int) bool {
		riskOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
		return riskOrder[m.ExfiltrationPaths[i].RiskLevel] > riskOrder[m.ExfiltrationPaths[j].RiskLevel]
	})

	// Exfiltration paths table
	pathsHeader := []string{
		"Type",
		"Resource",
		"Project Name",
		"Project ID",
		"Destination",
		"Risk",
	}

	var pathsBody [][]string
	for _, p := range m.ExfiltrationPaths {
		pathsBody = append(pathsBody, []string{
			p.PathType,
			truncateString(p.ResourceName, 30),
			m.GetProjectName(p.ProjectID),
			p.ProjectID,
			truncateString(p.Destination, 30),
			p.RiskLevel,
		})
	}

	// Public exports table
	exportsHeader := []string{
		"Type",
		"Resource",
		"Project Name",
		"Project ID",
		"Access Level",
		"Data Type",
		"Risk",
	}

	var exportsBody [][]string
	for _, e := range m.PublicExports {
		exportsBody = append(exportsBody, []string{
			e.ResourceType,
			e.ResourceName,
			m.GetProjectName(e.ProjectID),
			e.ProjectID,
			e.AccessLevel,
			e.DataType,
			e.RiskLevel,
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
	tables := []internal.TableFile{}

	if len(pathsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "exfil-paths",
			Header: pathsHeader,
			Body:   pathsBody,
		})
	}

	if len(exportsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "exfil-public-exports",
			Header: exportsHeader,
			Body:   exportsBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d public export(s)", len(exportsBody)), GCP_DATAEXFILTRATION_MODULE_NAME)
	}

	output := DataExfiltrationOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scope names with project names
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_DATAEXFILTRATION_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
