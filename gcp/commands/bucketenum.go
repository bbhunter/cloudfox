package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	bucketenumservice "github.com/BishopFox/cloudfox/gcp/services/bucketEnumService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var (
	bucketEnumMaxObjects  int
	bucketEnumAllObjects  bool
	bucketEnumNoLimit     bool
	maxObjectsWasSet      bool // tracks if --max-objects was explicitly set
)

var GCPBucketEnumCommand = &cobra.Command{
	Use:     globals.GCP_BUCKETENUM_MODULE_NAME,
	Aliases: []string{"bucket-scan", "gcs-enum", "sensitive-files"},
	Short:   "Enumerate GCS buckets for sensitive files (credentials, secrets, configs)",
	Long: `Enumerate GCS buckets to find potentially sensitive files.

This module scans bucket contents for files that may contain:
- Credentials (service account keys, SSH keys, certificates)
- Secrets (environment files, API keys, tokens)
- Configuration files (may contain hardcoded secrets)
- Database backups
- Terraform state files
- Source code/git repositories

File categories detected:
- Credential: .json keys, .pem, .key, .p12, SSH keys
- Secret: .env, passwords, API keys, tokens
- Config: YAML, properties, settings files
- Backup: SQL dumps, archives
- Source: Git repositories
- Cloud: Cloud Functions source, build artifacts

Use --all-objects to enumerate ALL bucket contents (not just sensitive files).
WARNING: Full enumeration may take a long time for buckets with many objects.
Use --max-objects to limit the scan, or --no-limit for unlimited.`,
	Run: runGCPBucketEnumCommand,
}

func init() {
	GCPBucketEnumCommand.Flags().IntVar(&bucketEnumMaxObjects, "max-objects", 1000, "Maximum objects to scan per bucket (default 1000)")
	GCPBucketEnumCommand.Flags().BoolVar(&bucketEnumAllObjects, "all-objects", false, "Enumerate ALL bucket contents, not just sensitive files (implies --no-limit unless --max-objects is set)")
	GCPBucketEnumCommand.Flags().BoolVar(&bucketEnumNoLimit, "no-limit", false, "Remove the object limit (enumerate all objects in each bucket)")
}

type BucketEnumModule struct {
	gcpinternal.BaseGCPModule
	ProjectSensitiveFiles map[string][]bucketenumservice.SensitiveFileInfo // projectID -> files
	ProjectAllObjects     map[string][]bucketenumservice.ObjectInfo        // projectID -> all objects (when --all-objects)
	LootMap               map[string]map[string]*internal.LootFile         // projectID -> loot files
	EnumerateAll          bool                                             // whether to enumerate all objects
	MaxObjects            int                                              // max objects per bucket (0 = unlimited)
	mu                    sync.Mutex
}

type BucketEnumOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BucketEnumOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BucketEnumOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPBucketEnumCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_BUCKETENUM_MODULE_NAME)
	if err != nil {
		return
	}

	// Determine effective max objects limit
	effectiveMaxObjects := bucketEnumMaxObjects
	maxObjectsExplicitlySet := cmd.Flags().Changed("max-objects")

	// --no-limit flag sets unlimited
	if bucketEnumNoLimit {
		effectiveMaxObjects = 0
	}

	// --all-objects implies no limit UNLESS --max-objects was explicitly set
	if bucketEnumAllObjects && !maxObjectsExplicitlySet {
		effectiveMaxObjects = 0
	}

	module := &BucketEnumModule{
		BaseGCPModule:         gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectSensitiveFiles: make(map[string][]bucketenumservice.SensitiveFileInfo),
		ProjectAllObjects:     make(map[string][]bucketenumservice.ObjectInfo),
		LootMap:               make(map[string]map[string]*internal.LootFile),
		EnumerateAll:          bucketEnumAllObjects,
		MaxObjects:            effectiveMaxObjects,
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *BucketEnumModule) Execute(ctx context.Context, logger internal.Logger) {
	maxMsg := fmt.Sprintf("%d", m.MaxObjects)
	if m.MaxObjects == 0 {
		maxMsg = "unlimited"
	}

	if m.EnumerateAll {
		logger.InfoM(fmt.Sprintf("Enumerating ALL bucket contents (%s objects per bucket)...", maxMsg), globals.GCP_BUCKETENUM_MODULE_NAME)
	} else {
		logger.InfoM(fmt.Sprintf("Scanning buckets for sensitive files (%s objects per bucket)...", maxMsg), globals.GCP_BUCKETENUM_MODULE_NAME)
	}

	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_BUCKETENUM_MODULE_NAME, m.processProject)

	if m.EnumerateAll {
		// Full enumeration mode
		allObjects := m.getAllObjects()
		if len(allObjects) == 0 {
			logger.InfoM("No objects found in buckets", globals.GCP_BUCKETENUM_MODULE_NAME)
			return
		}

		// Count public objects
		publicCount := 0
		for _, obj := range allObjects {
			if obj.IsPublic {
				publicCount++
			}
		}

		logger.SuccessM(fmt.Sprintf("Found %d object(s) across all buckets (%d public)",
			len(allObjects), publicCount), globals.GCP_BUCKETENUM_MODULE_NAME)
	} else {
		// Sensitive files mode
		allFiles := m.getAllSensitiveFiles()
		if len(allFiles) == 0 {
			logger.InfoM("No sensitive files found", globals.GCP_BUCKETENUM_MODULE_NAME)
			return
		}

		// Count by risk level
		criticalCount := 0
		highCount := 0
		for _, file := range allFiles {
			switch file.RiskLevel {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			}
		}

		logger.SuccessM(fmt.Sprintf("Found %d potentially sensitive file(s) (%d CRITICAL, %d HIGH)",
			len(allFiles), criticalCount, highCount), globals.GCP_BUCKETENUM_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

func (m *BucketEnumModule) getAllObjects() []bucketenumservice.ObjectInfo {
	var all []bucketenumservice.ObjectInfo
	for _, objects := range m.ProjectAllObjects {
		all = append(all, objects...)
	}
	return all
}

func (m *BucketEnumModule) getAllSensitiveFiles() []bucketenumservice.SensitiveFileInfo {
	var all []bucketenumservice.SensitiveFileInfo
	for _, files := range m.ProjectSensitiveFiles {
		all = append(all, files...)
	}
	return all
}

func (m *BucketEnumModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Scanning buckets in project: %s", projectID), globals.GCP_BUCKETENUM_MODULE_NAME)
	}

	svc := bucketenumservice.New()

	m.mu.Lock()
	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		if m.EnumerateAll {
			m.LootMap[projectID]["bucket-enum-all-commands"] = &internal.LootFile{
				Name:     "bucket-enum-all-commands",
				Contents: "# GCS Download Commands for All Objects\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
			}
		} else {
			m.LootMap[projectID]["bucket-enum-sensitive-commands"] = &internal.LootFile{
				Name:     "bucket-enum-sensitive-commands",
				Contents: "# GCS Download Commands for CRITICAL/HIGH Risk Files\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
			}
			m.LootMap[projectID]["bucket-enum-commands"] = &internal.LootFile{
				Name:     "bucket-enum-commands",
				Contents: "# GCS Download Commands for All Detected Files\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
			}
		}
	}
	m.mu.Unlock()

	// Get list of buckets
	buckets, err := svc.GetBucketsList(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_BUCKETENUM_MODULE_NAME,
			fmt.Sprintf("Could not enumerate buckets in project %s", projectID))
		return
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d bucket(s) in project %s", len(buckets), projectID), globals.GCP_BUCKETENUM_MODULE_NAME)
	}

	if m.EnumerateAll {
		// Enumerate ALL objects in each bucket
		var projectObjects []bucketenumservice.ObjectInfo
		for _, bucketName := range buckets {
			objects, err := svc.EnumerateAllBucketObjects(bucketName, projectID, m.MaxObjects)
			if err != nil {
				m.CommandCounter.Error++
				gcpinternal.HandleGCPError(err, logger, globals.GCP_BUCKETENUM_MODULE_NAME,
					fmt.Sprintf("Could not enumerate bucket %s in project %s", bucketName, projectID))
				continue
			}
			projectObjects = append(projectObjects, objects...)
		}

		m.mu.Lock()
		m.ProjectAllObjects[projectID] = projectObjects
		for _, obj := range projectObjects {
			m.addObjectToLoot(projectID, obj)
		}
		m.mu.Unlock()
	} else {
		// Scan for sensitive files only
		var projectFiles []bucketenumservice.SensitiveFileInfo
		for _, bucketName := range buckets {
			files, err := svc.EnumerateBucketSensitiveFiles(bucketName, projectID, m.MaxObjects)
			if err != nil {
				m.CommandCounter.Error++
				gcpinternal.HandleGCPError(err, logger, globals.GCP_BUCKETENUM_MODULE_NAME,
					fmt.Sprintf("Could not scan bucket %s in project %s", bucketName, projectID))
				continue
			}
			projectFiles = append(projectFiles, files...)
		}

		m.mu.Lock()
		m.ProjectSensitiveFiles[projectID] = projectFiles
		for _, file := range projectFiles {
			m.addFileToLoot(projectID, file)
		}
		m.mu.Unlock()
	}
}

func (m *BucketEnumModule) addObjectToLoot(projectID string, obj bucketenumservice.ObjectInfo) {
	if lootFile := m.LootMap[projectID]["bucket-enum-all-commands"]; lootFile != nil {
		publicMarker := ""
		if obj.IsPublic {
			publicMarker = " [PUBLIC]"
		}
		// Build local directory path: bucket/BUCKETNAME/OBJECTPATH/
		localDir := fmt.Sprintf("bucket/%s/%s", obj.BucketName, getObjectDir(obj.ObjectName))
		localCpCmd := fmt.Sprintf("gsutil cp gs://%s/%s %s", obj.BucketName, obj.ObjectName, localDir)
		lootFile.Contents += fmt.Sprintf(
			"# gs://%s/%s%s\n"+
				"# Size: %d bytes, Type: %s\n"+
				"mkdir -p %s\n"+
				"%s\n\n",
			obj.BucketName, obj.ObjectName, publicMarker,
			obj.Size, obj.ContentType,
			localDir,
			localCpCmd,
		)
	}
}

func (m *BucketEnumModule) addFileToLoot(projectID string, file bucketenumservice.SensitiveFileInfo) {
	// Build local directory path: bucket/BUCKETNAME/OBJECTPATH/
	localDir := fmt.Sprintf("bucket/%s/%s", file.BucketName, getObjectDir(file.ObjectName))
	localCpCmd := fmt.Sprintf("gsutil cp gs://%s/%s %s", file.BucketName, file.ObjectName, localDir)

	// All files go to the general commands file
	if lootFile := m.LootMap[projectID]["bucket-enum-commands"]; lootFile != nil {
		lootFile.Contents += fmt.Sprintf(
			"# [%s] %s - gs://%s/%s\n"+
				"# Category: %s, Size: %d bytes\n"+
				"mkdir -p %s\n"+
				"%s\n\n",
			file.RiskLevel, file.Category,
			file.BucketName, file.ObjectName,
			file.Description, file.Size,
			localDir,
			localCpCmd,
		)
	}

	// CRITICAL and HIGH risk files also go to the sensitive commands file
	if file.RiskLevel == "CRITICAL" || file.RiskLevel == "HIGH" {
		if lootFile := m.LootMap[projectID]["bucket-enum-sensitive-commands"]; lootFile != nil {
			lootFile.Contents += fmt.Sprintf(
				"# [%s] %s - gs://%s/%s\n"+
					"# Category: %s, Size: %d bytes\n"+
					"mkdir -p %s\n"+
					"%s\n\n",
				file.RiskLevel, file.Category,
				file.BucketName, file.ObjectName,
				file.Description, file.Size,
				localDir,
				localCpCmd,
			)
		}
	}
}

func (m *BucketEnumModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *BucketEnumModule) getFilesHeader() []string {
	return []string{"Project", "Bucket", "Object Name", "Category", "Size", "Public", "Description"}
}

func (m *BucketEnumModule) getSensitiveFilesHeader() []string {
	return []string{"Project", "Bucket", "Object Name", "Category", "Size", "Public"}
}

func (m *BucketEnumModule) getAllObjectsHeader() []string {
	return []string{"Project", "Bucket", "Object Name", "Content Type", "Size", "Public", "Updated"}
}

func (m *BucketEnumModule) filesToTableBody(files []bucketenumservice.SensitiveFileInfo) [][]string {
	var body [][]string
	for _, file := range files {
		publicStatus := "No"
		if file.IsPublic {
			publicStatus = "Yes"
		}
		body = append(body, []string{
			m.GetProjectName(file.ProjectID),
			file.BucketName,
			file.ObjectName,
			file.Category,
			formatFileSize(file.Size),
			publicStatus,
			file.Description,
		})
	}
	return body
}

func (m *BucketEnumModule) sensitiveFilesToTableBody(files []bucketenumservice.SensitiveFileInfo) [][]string {
	var body [][]string
	for _, file := range files {
		if file.RiskLevel == "CRITICAL" || file.RiskLevel == "HIGH" {
			publicStatus := "No"
			if file.IsPublic {
				publicStatus = "Yes"
			}
			body = append(body, []string{
				m.GetProjectName(file.ProjectID),
				file.BucketName,
				file.ObjectName,
				file.Category,
				formatFileSize(file.Size),
				publicStatus,
			})
		}
	}
	return body
}

func (m *BucketEnumModule) allObjectsToTableBody(objects []bucketenumservice.ObjectInfo) [][]string {
	var body [][]string
	for _, obj := range objects {
		publicStatus := "No"
		if obj.IsPublic {
			publicStatus = "Yes"
		}
		body = append(body, []string{
			m.GetProjectName(obj.ProjectID),
			obj.BucketName,
			obj.ObjectName,
			obj.ContentType,
			formatFileSize(obj.Size),
			publicStatus,
			obj.Updated,
		})
	}
	return body
}

func (m *BucketEnumModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if m.EnumerateAll {
		// Full enumeration mode
		objects := m.ProjectAllObjects[projectID]
		if len(objects) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "bucket-enum-all",
				Header: m.getAllObjectsHeader(),
				Body:   m.allObjectsToTableBody(objects),
			})
		}
	} else {
		// Sensitive files mode
		files := m.ProjectSensitiveFiles[projectID]
		if len(files) > 0 {
			tableFiles = append(tableFiles, internal.TableFile{
				Name:   "bucket-enum",
				Header: m.getFilesHeader(),
				Body:   m.filesToTableBody(files),
			})

			sensitiveBody := m.sensitiveFilesToTableBody(files)
			if len(sensitiveBody) > 0 {
				tableFiles = append(tableFiles, internal.TableFile{
					Name:   "bucket-enum-sensitive",
					Header: m.getSensitiveFilesHeader(),
					Body:   sensitiveBody,
				})
			}
		}
	}

	return tableFiles
}

func (m *BucketEnumModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Get the appropriate project map based on mode
	var projectIDs []string
	if m.EnumerateAll {
		for projectID := range m.ProjectAllObjects {
			projectIDs = append(projectIDs, projectID)
		}
	} else {
		for projectID := range m.ProjectSensitiveFiles {
			projectIDs = append(projectIDs, projectID)
		}
	}

	for _, projectID := range projectIDs {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = BucketEnumOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_BUCKETENUM_MODULE_NAME)
	}
}

func (m *BucketEnumModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	if m.EnumerateAll {
		// Full enumeration mode
		allObjects := m.getAllObjects()
		if len(allObjects) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "bucket-enum-all",
				Header: m.getAllObjectsHeader(),
				Body:   m.allObjectsToTableBody(allObjects),
			})

			// Count public objects
			publicCount := 0
			for _, obj := range allObjects {
				if obj.IsPublic {
					publicCount++
				}
			}
			if publicCount > 0 {
				logger.InfoM(fmt.Sprintf("[FINDING] Found %d publicly accessible object(s)!", publicCount), globals.GCP_BUCKETENUM_MODULE_NAME)
			}
		}
	} else {
		// Sensitive files mode
		allFiles := m.getAllSensitiveFiles()
		if len(allFiles) > 0 {
			tables = append(tables, internal.TableFile{
				Name:   "bucket-enum",
				Header: m.getFilesHeader(),
				Body:   m.filesToTableBody(allFiles),
			})

			sensitiveBody := m.sensitiveFilesToTableBody(allFiles)
			if len(sensitiveBody) > 0 {
				tables = append(tables, internal.TableFile{
					Name:   "bucket-enum-sensitive",
					Header: m.getSensitiveFilesHeader(),
					Body:   sensitiveBody,
				})
				logger.InfoM(fmt.Sprintf("[FINDING] Found %d CRITICAL/HIGH risk files!", len(sensitiveBody)), globals.GCP_BUCKETENUM_MODULE_NAME)
			}
		}
	}

	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := BucketEnumOutput{Table: tables, Loot: lootFiles}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart("gcp", m.Format, m.OutputDirectory, m.Verbosity, m.WrapTable,
		"project", m.ProjectIDs, scopeNames, m.Account, output)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_BUCKETENUM_MODULE_NAME)
	}
}

// getObjectDir returns the directory portion of an object path
// e.g., "processReports-pilot-gcp-01/function-source.zip" -> "processReports-pilot-gcp-01/"
// e.g., "file.txt" -> ""
func getObjectDir(objectName string) string {
	lastSlash := strings.LastIndex(objectName, "/")
	if lastSlash == -1 {
		return ""
	}
	return objectName[:lastSlash+1]
}

func formatFileSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
