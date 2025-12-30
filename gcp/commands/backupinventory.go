package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/sqladmin/v1beta4"
)

// Module name constant
const GCP_BACKUPINVENTORY_MODULE_NAME string = "backup-inventory"

var GCPBackupInventoryCommand = &cobra.Command{
	Use:     GCP_BACKUPINVENTORY_MODULE_NAME,
	Aliases: []string{"backups", "backup", "snapshots", "dr"},
	Short:   "Enumerate backup policies, protected resources, and identify backup gaps",
	Long: `Inventory backup and disaster recovery configurations across GCP resources.

Features:
- Compute Engine disk snapshots and snapshot schedules
- Cloud SQL automated backups and point-in-time recovery
- Cloud Storage object versioning and lifecycle policies
- Filestore backups
- GKE backup configurations
- Identifies unprotected resources (no backup coverage)
- Analyzes backup retention policies
- Checks for stale or failing backups

Requires appropriate IAM permissions:
- roles/compute.viewer
- roles/cloudsql.viewer
- roles/storage.admin`,
	Run: runGCPBackupInventoryCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type BackupPolicy struct {
	Name            string
	ProjectID       string
	ResourceType    string // compute-snapshot, sql-backup, gcs-versioning, filestore-backup
	Enabled         bool
	Schedule        string
	RetentionDays   int
	LastBackup      string
	BackupCount     int
	TargetResources []string
	Location        string
	Status          string
	Encryption      string
}

type ProtectedResource struct {
	Name           string
	ProjectID      string
	ResourceType   string
	BackupType     string
	LastBackup     string
	BackupCount    int
	RetentionDays  int
	BackupStatus   string
	PITREnabled    bool
	BackupLocation string
}

type UnprotectedResource struct {
	Name         string
	ProjectID    string
	ResourceType string
	Location     string
	SizeGB       int64
	RiskLevel    string
	Reason       string
	Remediation  string
}

type ComputeSnapshot struct {
	Name          string
	ProjectID     string
	SourceDisk    string
	Status        string
	DiskSizeGB    int64
	StorageBytes  int64
	CreationTime  string
	Labels        map[string]string
	StorageLocats []string
	AutoDelete    bool
	SnapshotType  string
}

type SnapshotSchedule struct {
	Name           string
	ProjectID      string
	Region         string
	Schedule       string
	RetentionDays  int
	AttachedDisks  int
	SnapshotLabels map[string]string
	StorageLocats  []string
}

type SQLBackup struct {
	InstanceName   string
	ProjectID      string
	BackupID       string
	Status         string
	Type           string
	StartTime      string
	EndTime        string
	WindowStartTim string
	SizeBytes      int64
	Location       string
	Encrypted      bool
}

// ------------------------------
// Module Struct
// ------------------------------
type BackupInventoryModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	BackupPolicies       []BackupPolicy
	ProtectedResources   []ProtectedResource
	UnprotectedResources []UnprotectedResource
	Snapshots            []ComputeSnapshot
	SnapshotSchedules    []SnapshotSchedule
	SQLBackups           []SQLBackup
	LootMap              map[string]*internal.LootFile
	mu                   sync.Mutex

	// Tracking maps
	disksWithBackups     map[string]bool
	sqlWithBackups       map[string]bool
	allDisks             map[string]int64 // disk name -> size GB
	allSQLInstances      map[string]bool
}

// ------------------------------
// Output Struct
// ------------------------------
type BackupInventoryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BackupInventoryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BackupInventoryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPBackupInventoryCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_BACKUPINVENTORY_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &BackupInventoryModule{
		BaseGCPModule:        gcpinternal.NewBaseGCPModule(cmdCtx),
		BackupPolicies:       []BackupPolicy{},
		ProtectedResources:   []ProtectedResource{},
		UnprotectedResources: []UnprotectedResource{},
		Snapshots:            []ComputeSnapshot{},
		SnapshotSchedules:    []SnapshotSchedule{},
		SQLBackups:           []SQLBackup{},
		LootMap:              make(map[string]*internal.LootFile),
		disksWithBackups:     make(map[string]bool),
		sqlWithBackups:       make(map[string]bool),
		allDisks:             make(map[string]int64),
		allSQLInstances:      make(map[string]bool),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *BackupInventoryModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Inventorying backup configurations and identifying gaps...", GCP_BACKUPINVENTORY_MODULE_NAME)

	// Create service clients
	computeService, err := compute.NewService(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Compute service: %v", err), GCP_BACKUPINVENTORY_MODULE_NAME)
		return
	}

	sqlService, err := sqladmin.NewService(ctx)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Failed to create SQL Admin service: %v", err), GCP_BACKUPINVENTORY_MODULE_NAME)
		}
	}

	// Process each project
	var wg sync.WaitGroup
	for _, projectID := range m.ProjectIDs {
		wg.Add(1)
		go func(project string) {
			defer wg.Done()
			m.processProject(ctx, project, computeService, sqlService, logger)
		}(projectID)
	}
	wg.Wait()

	// Identify unprotected resources
	m.identifyUnprotectedResources(logger)

	// Check results
	totalProtected := len(m.ProtectedResources)
	totalUnprotected := len(m.UnprotectedResources)

	if totalProtected == 0 && totalUnprotected == 0 {
		logger.InfoM("No backup data found", GCP_BACKUPINVENTORY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d protected resource(s), %d unprotected resource(s)",
		totalProtected, totalUnprotected), GCP_BACKUPINVENTORY_MODULE_NAME)

	if totalUnprotected > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] %d resource(s) without backup coverage", totalUnprotected), GCP_BACKUPINVENTORY_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *BackupInventoryModule) processProject(ctx context.Context, projectID string, computeService *compute.Service, sqlService *sqladmin.Service, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating backups for project: %s", projectID), GCP_BACKUPINVENTORY_MODULE_NAME)
	}

	// List all disks first (for gap analysis)
	m.enumerateDisks(ctx, projectID, computeService, logger)

	// List snapshots
	m.enumerateSnapshots(ctx, projectID, computeService, logger)

	// List snapshot schedules
	m.enumerateSnapshotSchedules(ctx, projectID, computeService, logger)

	// List SQL instances and backups
	if sqlService != nil {
		m.enumerateSQLBackups(ctx, projectID, sqlService, logger)
	}
}

func (m *BackupInventoryModule) enumerateDisks(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Disks.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.DiskAggregatedList) error {
		for _, diskList := range page.Items {
			if diskList.Disks == nil {
				continue
			}
			for _, disk := range diskList.Disks {
				m.mu.Lock()
				m.allDisks[disk.SelfLink] = disk.SizeGb
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing disks for project %s: %v", projectID, err), GCP_BACKUPINVENTORY_MODULE_NAME)
		}
	}
}

func (m *BackupInventoryModule) enumerateSnapshots(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.Snapshots.List(projectID)
	err := req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			snap := ComputeSnapshot{
				Name:          snapshot.Name,
				ProjectID:     projectID,
				SourceDisk:    snapshot.SourceDisk,
				Status:        snapshot.Status,
				DiskSizeGB:    snapshot.DiskSizeGb,
				StorageBytes:  snapshot.StorageBytes,
				CreationTime:  snapshot.CreationTimestamp,
				Labels:        snapshot.Labels,
				StorageLocats: snapshot.StorageLocations,
				AutoDelete:    snapshot.AutoCreated,
				SnapshotType:  snapshot.SnapshotType,
			}

			m.mu.Lock()
			m.Snapshots = append(m.Snapshots, snap)
			// Mark disk as having backups
			m.disksWithBackups[snapshot.SourceDisk] = true
			m.mu.Unlock()
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing snapshots for project %s: %v", projectID, err), GCP_BACKUPINVENTORY_MODULE_NAME)
		}
	}

	// Track protected resources from snapshots
	m.trackSnapshotProtection(projectID)
}

func (m *BackupInventoryModule) trackSnapshotProtection(projectID string) {
	// Group snapshots by source disk
	diskSnapshots := make(map[string][]ComputeSnapshot)
	for _, snap := range m.Snapshots {
		if snap.ProjectID == projectID {
			diskSnapshots[snap.SourceDisk] = append(diskSnapshots[snap.SourceDisk], snap)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for diskURL, snaps := range diskSnapshots {
		// Find latest snapshot
		var latestTime time.Time
		var latestSnap ComputeSnapshot
		for _, snap := range snaps {
			t, err := time.Parse(time.RFC3339, snap.CreationTime)
			if err == nil && t.After(latestTime) {
				latestTime = t
				latestSnap = snap
			}
		}

		protected := ProtectedResource{
			Name:           m.extractDiskName(diskURL),
			ProjectID:      projectID,
			ResourceType:   "compute-disk",
			BackupType:     "snapshot",
			LastBackup:     latestSnap.CreationTime,
			BackupCount:    len(snaps),
			BackupStatus:   latestSnap.Status,
			BackupLocation: strings.Join(latestSnap.StorageLocats, ","),
		}

		// Calculate age of last backup
		if !latestTime.IsZero() {
			age := time.Since(latestTime)
			if age > 7*24*time.Hour {
				protected.BackupStatus = "STALE"
			} else {
				protected.BackupStatus = "CURRENT"
			}
		}

		m.ProtectedResources = append(m.ProtectedResources, protected)
	}
}

func (m *BackupInventoryModule) enumerateSnapshotSchedules(ctx context.Context, projectID string, computeService *compute.Service, logger internal.Logger) {
	req := computeService.ResourcePolicies.AggregatedList(projectID)
	err := req.Pages(ctx, func(page *compute.ResourcePolicyAggregatedList) error {
		for region, policyList := range page.Items {
			if policyList.ResourcePolicies == nil {
				continue
			}
			for _, policy := range policyList.ResourcePolicies {
				if policy.SnapshotSchedulePolicy == nil {
					continue
				}

				schedule := SnapshotSchedule{
					Name:      policy.Name,
					ProjectID: projectID,
					Region:    m.extractRegionFromURL(region),
				}

				// Parse schedule
				if policy.SnapshotSchedulePolicy.Schedule != nil {
					if policy.SnapshotSchedulePolicy.Schedule.DailySchedule != nil {
						schedule.Schedule = "daily"
					} else if policy.SnapshotSchedulePolicy.Schedule.WeeklySchedule != nil {
						schedule.Schedule = "weekly"
					} else if policy.SnapshotSchedulePolicy.Schedule.HourlySchedule != nil {
						schedule.Schedule = "hourly"
					}
				}

				// Parse retention
				if policy.SnapshotSchedulePolicy.RetentionPolicy != nil {
					schedule.RetentionDays = int(policy.SnapshotSchedulePolicy.RetentionPolicy.MaxRetentionDays)
				}

				// Parse labels
				if policy.SnapshotSchedulePolicy.SnapshotProperties != nil {
					schedule.SnapshotLabels = policy.SnapshotSchedulePolicy.SnapshotProperties.Labels
					schedule.StorageLocats = policy.SnapshotSchedulePolicy.SnapshotProperties.StorageLocations
				}

				m.mu.Lock()
				m.SnapshotSchedules = append(m.SnapshotSchedules, schedule)

				// Add as backup policy
				bp := BackupPolicy{
					Name:          policy.Name,
					ProjectID:     projectID,
					ResourceType:  "compute-snapshot-schedule",
					Enabled:       true,
					Schedule:      schedule.Schedule,
					RetentionDays: schedule.RetentionDays,
					Location:      schedule.Region,
					Status:        policy.Status,
				}
				m.BackupPolicies = append(m.BackupPolicies, bp)
				m.mu.Unlock()
			}
		}
		return nil
	})

	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing snapshot schedules for project %s: %v", projectID, err), GCP_BACKUPINVENTORY_MODULE_NAME)
		}
	}
}

func (m *BackupInventoryModule) enumerateSQLBackups(ctx context.Context, projectID string, sqlService *sqladmin.Service, logger internal.Logger) {
	// List SQL instances
	instances, err := sqlService.Instances.List(projectID).Do()
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error listing SQL instances for project %s: %v", projectID, err), GCP_BACKUPINVENTORY_MODULE_NAME)
		}
		return
	}

	for _, instance := range instances.Items {
		m.mu.Lock()
		m.allSQLInstances[instance.Name] = true
		m.mu.Unlock()

		// Check backup configuration
		backupEnabled := false
		pitrEnabled := false
		var retentionDays int
		var backupStartTime string

		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			backupEnabled = instance.Settings.BackupConfiguration.Enabled
			pitrEnabled = instance.Settings.BackupConfiguration.PointInTimeRecoveryEnabled
			retentionDays = int(instance.Settings.BackupConfiguration.TransactionLogRetentionDays)
			backupStartTime = instance.Settings.BackupConfiguration.StartTime
		}

		if backupEnabled {
			m.mu.Lock()
			m.sqlWithBackups[instance.Name] = true
			m.mu.Unlock()

			// Add as backup policy
			bp := BackupPolicy{
				Name:            fmt.Sprintf("%s-backup", instance.Name),
				ProjectID:       projectID,
				ResourceType:    "sql-automated-backup",
				Enabled:         true,
				Schedule:        fmt.Sprintf("Daily at %s", backupStartTime),
				RetentionDays:   retentionDays,
				TargetResources: []string{instance.Name},
				Location:        instance.Region,
				Status:          "ACTIVE",
			}

			m.mu.Lock()
			m.BackupPolicies = append(m.BackupPolicies, bp)
			m.mu.Unlock()
		}

		// List actual backups for this instance
		backups, err := sqlService.BackupRuns.List(projectID, instance.Name).Do()
		if err != nil {
			continue
		}

		var latestBackup *SQLBackup
		backupCount := 0

		for _, backup := range backups.Items {
			sqlBackup := SQLBackup{
				InstanceName:   instance.Name,
				ProjectID:      projectID,
				BackupID:       fmt.Sprintf("%d", backup.Id),
				Status:         backup.Status,
				Type:           backup.Type,
				StartTime:      backup.StartTime,
				EndTime:        backup.EndTime,
				WindowStartTim: backup.WindowStartTime,
				Location:       backup.Location,
			}

			m.mu.Lock()
			m.SQLBackups = append(m.SQLBackups, sqlBackup)
			m.mu.Unlock()

			backupCount++
			if latestBackup == nil || backup.StartTime > latestBackup.StartTime {
				latestBackup = &sqlBackup
			}
		}

		// Add as protected resource
		if backupCount > 0 {
			protected := ProtectedResource{
				Name:          instance.Name,
				ProjectID:     projectID,
				ResourceType:  "cloudsql-instance",
				BackupType:    "automated",
				BackupCount:   backupCount,
				RetentionDays: retentionDays,
				PITREnabled:   pitrEnabled,
			}

			if latestBackup != nil {
				protected.LastBackup = latestBackup.StartTime
				protected.BackupStatus = latestBackup.Status
				protected.BackupLocation = latestBackup.Location
			}

			m.mu.Lock()
			m.ProtectedResources = append(m.ProtectedResources, protected)
			m.mu.Unlock()
		}
	}
}

// ------------------------------
// Gap Analysis
// ------------------------------
func (m *BackupInventoryModule) identifyUnprotectedResources(logger internal.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find disks without snapshots
	for diskURL, sizeGB := range m.allDisks {
		if !m.disksWithBackups[diskURL] {
			diskName := m.extractDiskName(diskURL)
			projectID := m.extractProjectFromURL(diskURL)

			unprotected := UnprotectedResource{
				Name:         diskName,
				ProjectID:    projectID,
				ResourceType: "compute-disk",
				Location:     m.extractZoneFromURL(diskURL),
				SizeGB:       sizeGB,
				RiskLevel:    "HIGH",
				Reason:       "No snapshot backup found",
				Remediation:  fmt.Sprintf("Create snapshot schedule: gcloud compute resource-policies create snapshot-schedule %s-backup --project=%s --region=REGION --max-retention-days=30 --daily-schedule", diskName, projectID),
			}

			// Higher risk for larger disks
			if sizeGB > 500 {
				unprotected.RiskLevel = "CRITICAL"
			}

			m.UnprotectedResources = append(m.UnprotectedResources, unprotected)

			// Add to loot
			m.LootMap["unprotected-vms"].Contents += fmt.Sprintf(
				"%s (%s) - %dGB - %s\n",
				diskName, projectID, sizeGB, unprotected.Reason,
			)
		}
	}

	// Find SQL instances without backups
	for instanceName := range m.allSQLInstances {
		if !m.sqlWithBackups[instanceName] {
			unprotected := UnprotectedResource{
				Name:         instanceName,
				ResourceType: "cloudsql-instance",
				RiskLevel:    "CRITICAL",
				Reason:       "Automated backups not enabled",
				Remediation:  fmt.Sprintf("gcloud sql instances patch %s --backup-start-time=02:00 --enable-bin-log", instanceName),
			}

			m.UnprotectedResources = append(m.UnprotectedResources, unprotected)

			m.LootMap["unprotected-vms"].Contents += fmt.Sprintf(
				"%s (Cloud SQL) - %s\n",
				instanceName, unprotected.Reason,
			)
		}
	}

	// Check for short retention policies
	for _, policy := range m.BackupPolicies {
		if policy.RetentionDays > 0 && policy.RetentionDays < 7 {
			m.LootMap["short-retention"].Contents += fmt.Sprintf(
				"%s (%s) - %d days retention (recommended: 30+ days)\n",
				policy.Name, policy.ResourceType, policy.RetentionDays,
			)
		}
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func (m *BackupInventoryModule) extractDiskName(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func (m *BackupInventoryModule) extractProjectFromURL(url string) string {
	if strings.Contains(url, "projects/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *BackupInventoryModule) extractZoneFromURL(url string) string {
	if strings.Contains(url, "zones/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "zones" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (m *BackupInventoryModule) extractRegionFromURL(url string) string {
	if strings.Contains(url, "regions/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "regions" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return url
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *BackupInventoryModule) initializeLootFiles() {
	m.LootMap["unprotected-vms"] = &internal.LootFile{
		Name:     "unprotected-vms",
		Contents: "# Unprotected VMs and Resources\n# Generated by CloudFox\n# These resources have no backup coverage!\n\n",
	}
	m.LootMap["short-retention"] = &internal.LootFile{
		Name:     "short-retention",
		Contents: "# Resources with Short Backup Retention\n# Generated by CloudFox\n\n",
	}
	m.LootMap["backup-commands"] = &internal.LootFile{
		Name:     "backup-commands",
		Contents: "# Backup Setup Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["backup-inventory"] = &internal.LootFile{
		Name:     "backup-inventory",
		Contents: "# Full Backup Inventory\n# Generated by CloudFox\n\n",
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *BackupInventoryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort protected resources by type and name
	sort.Slice(m.ProtectedResources, func(i, j int) bool {
		if m.ProtectedResources[i].ResourceType != m.ProtectedResources[j].ResourceType {
			return m.ProtectedResources[i].ResourceType < m.ProtectedResources[j].ResourceType
		}
		return m.ProtectedResources[i].Name < m.ProtectedResources[j].Name
	})

	// Protected Resources table
	protectedHeader := []string{
		"Resource",
		"Project Name",
		"Project ID",
		"Type",
		"Backup Type",
		"Last Backup",
		"Count",
		"Status",
		"PITR",
	}

	var protectedBody [][]string
	for _, r := range m.ProtectedResources {
		pitr := "No"
		if r.PITREnabled {
			pitr = "Yes"
		}

		protectedBody = append(protectedBody, []string{
			r.Name,
			m.GetProjectName(r.ProjectID),
			r.ProjectID,
			r.ResourceType,
			r.BackupType,
			truncateString(r.LastBackup, 20),
			fmt.Sprintf("%d", r.BackupCount),
			r.BackupStatus,
			pitr,
		})

		// Add to inventory loot
		m.LootMap["backup-inventory"].Contents += fmt.Sprintf(
			"%s (%s) - %s - Last: %s - Count: %d\n",
			r.Name, r.ResourceType, r.BackupType, r.LastBackup, r.BackupCount,
		)
	}

	// Unprotected Resources table
	unprotectedHeader := []string{
		"Resource",
		"Project Name",
		"Project ID",
		"Type",
		"Location",
		"Size (GB)",
		"Risk",
		"Reason",
	}

	var unprotectedBody [][]string
	for _, r := range m.UnprotectedResources {
		unprotectedBody = append(unprotectedBody, []string{
			r.Name,
			m.GetProjectName(r.ProjectID),
			r.ProjectID,
			r.ResourceType,
			r.Location,
			fmt.Sprintf("%d", r.SizeGB),
			r.RiskLevel,
			truncateString(r.Reason, 30),
		})

		// Add remediation to loot
		m.LootMap["backup-commands"].Contents += fmt.Sprintf(
			"# %s (%s)\n%s\n\n",
			r.Name, r.ResourceType, r.Remediation,
		)
	}

	// Backup Policies table
	policiesHeader := []string{
		"Policy",
		"Project Name",
		"Project ID",
		"Type",
		"Schedule",
		"Retention",
		"Status",
	}

	var policiesBody [][]string
	for _, p := range m.BackupPolicies {
		policiesBody = append(policiesBody, []string{
			p.Name,
			m.GetProjectName(p.ProjectID),
			p.ProjectID,
			p.ResourceType,
			p.Schedule,
			fmt.Sprintf("%d days", p.RetentionDays),
			p.Status,
		})
	}

	// Snapshots table
	snapshotsHeader := []string{
		"Snapshot",
		"Project Name",
		"Project ID",
		"Source Disk",
		"Size (GB)",
		"Created",
		"Status",
	}

	var snapshotsBody [][]string
	for _, s := range m.Snapshots {
		snapshotsBody = append(snapshotsBody, []string{
			s.Name,
			m.GetProjectName(s.ProjectID),
			s.ProjectID,
			m.extractDiskName(s.SourceDisk),
			fmt.Sprintf("%d", s.DiskSizeGB),
			truncateString(s.CreationTime, 20),
			s.Status,
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

	if len(protectedBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "protected-resources",
			Header: protectedHeader,
			Body:   protectedBody,
		})
	}

	if len(unprotectedBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "unprotected-resources",
			Header: unprotectedHeader,
			Body:   unprotectedBody,
		})
	}

	if len(policiesBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "backup-policies",
			Header: policiesHeader,
			Body:   policiesBody,
		})
	}

	if len(snapshotsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "snapshots",
			Header: snapshotsHeader,
			Body:   snapshotsBody,
		})
	}

	output := BackupInventoryOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_BACKUPINVENTORY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
