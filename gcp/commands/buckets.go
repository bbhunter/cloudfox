package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudStorageService "github.com/BishopFox/cloudfox/gcp/services/cloudStorageService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPBucketsCommand = &cobra.Command{
	Use:     globals.GCP_BUCKETS_MODULE_NAME,
	Aliases: []string{"storage", "gcs"},
	Short:   "Enumerate GCP Cloud Storage buckets with security configuration",
	Long: `Enumerate GCP Cloud Storage buckets across projects with security-relevant details.

Features:
- Lists all buckets accessible to the authenticated user
- Shows security configuration (public access prevention, uniform access, versioning)
- Enumerates IAM policies and identifies public buckets
- Shows encryption type (Google-managed vs CMEK)
- Shows retention and soft delete policies
- Generates gcloud commands for further enumeration
- Generates exploitation commands for data access

Security Columns:
- Public: Whether the bucket has allUsers or allAuthenticatedUsers access
- PublicAccessPrevention: "enforced" prevents public access at org/project level
- UniformAccess: true means IAM-only (no ACLs), recommended for security
- Versioning: Object versioning enabled (helps with recovery/compliance)
- Logging: Access logging enabled (audit trail)
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)
- Retention: Data retention policy (compliance/immutability)`,
	Run: runGCPBucketsCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type BucketsModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Buckets []CloudStorageService.BucketInfo
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type BucketsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o BucketsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o BucketsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPBucketsCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_BUCKETS_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create module instance
	module := &BucketsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Buckets:       []CloudStorageService.BucketInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *BucketsModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_BUCKETS_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Buckets) == 0 {
		logger.InfoM("No buckets found", globals.GCP_BUCKETS_MODULE_NAME)
		return
	}

	// Count public buckets for summary
	publicCount := 0
	for _, bucket := range m.Buckets {
		if bucket.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d bucket(s), %d PUBLIC", len(m.Buckets), publicCount), globals.GCP_BUCKETS_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d bucket(s)", len(m.Buckets)), globals.GCP_BUCKETS_MODULE_NAME)
	}

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *BucketsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating buckets in project: %s", projectID), globals.GCP_BUCKETS_MODULE_NAME)
	}

	// Create service and fetch buckets
	cs := CloudStorageService.New()
	buckets, err := cs.Buckets(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating buckets in project %s: %v", projectID, err), globals.GCP_BUCKETS_MODULE_NAME)
		}
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Buckets = append(m.Buckets, buckets...)

	// Generate loot for each bucket
	for _, bucket := range buckets {
		m.addBucketToLoot(bucket)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d bucket(s) in project %s", len(buckets), projectID), globals.GCP_BUCKETS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *BucketsModule) initializeLootFiles() {
	m.LootMap["buckets-gcloud-commands"] = &internal.LootFile{
		Name:     "buckets-gcloud-commands",
		Contents: "# GCP Cloud Storage Bucket Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-gsutil-commands"] = &internal.LootFile{
		Name:     "buckets-gsutil-commands",
		Contents: "# GCP gsutil Commands for Data Access\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-exploitation"] = &internal.LootFile{
		Name:     "buckets-exploitation",
		Contents: "# GCP Bucket Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["buckets-public"] = &internal.LootFile{
		Name:     "buckets-public",
		Contents: "# PUBLIC GCP Buckets\n# Generated by CloudFox\n# These buckets have allUsers or allAuthenticatedUsers access!\n\n",
	}
	m.LootMap["buckets-iam-bindings"] = &internal.LootFile{
		Name:     "buckets-iam-bindings",
		Contents: "# GCP Bucket IAM Bindings\n# Generated by CloudFox\n\n",
	}
	// New enhancement loot files
	m.LootMap["buckets-no-versioning"] = &internal.LootFile{
		Name:     "buckets-no-versioning",
		Contents: "# GCP Buckets WITHOUT Object Versioning\n# These buckets have no protection against accidental deletion or overwrites\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-no-lifecycle"] = &internal.LootFile{
		Name:     "buckets-no-lifecycle",
		Contents: "# GCP Buckets WITHOUT Lifecycle Policies\n# These buckets may accumulate unnecessary data and costs\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-short-retention"] = &internal.LootFile{
		Name:     "buckets-short-retention",
		Contents: "# GCP Buckets with Short Delete Lifecycle (< 30 days)\n# Data may be deleted quickly - verify this is intentional\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-locked-retention"] = &internal.LootFile{
		Name:     "buckets-locked-retention",
		Contents: "# GCP Buckets with LOCKED Retention Policies\n# These buckets have immutable retention - data cannot be deleted before policy expires\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-dual-region"] = &internal.LootFile{
		Name:     "buckets-dual-region",
		Contents: "# GCP Buckets with Dual/Multi-Region Configuration\n# These buckets have built-in geo-redundancy\n# Generated by CloudFox\n\n",
	}
	m.LootMap["buckets-security-recommendations"] = &internal.LootFile{
		Name:     "buckets-security-recommendations",
		Contents: "# GCP Bucket Security Recommendations\n# Generated by CloudFox\n\n",
	}
}

func (m *BucketsModule) addBucketToLoot(bucket CloudStorageService.BucketInfo) {
	// gcloud commands for enumeration
	m.LootMap["buckets-gcloud-commands"].Contents += fmt.Sprintf(
		"# Bucket: %s (Project: %s, Location: %s)\n"+
			"gcloud storage buckets describe gs://%s --project=%s\n"+
			"gcloud storage buckets get-iam-policy gs://%s --project=%s\n\n",
		bucket.Name, bucket.ProjectID, bucket.Location,
		bucket.Name, bucket.ProjectID,
		bucket.Name, bucket.ProjectID,
	)

	// gsutil commands for data access
	m.LootMap["buckets-gsutil-commands"].Contents += fmt.Sprintf(
		"# Bucket: %s\n"+
			"gsutil ls gs://%s/\n"+
			"gsutil ls -L gs://%s/\n"+
			"gsutil du -s gs://%s/\n\n",
		bucket.Name,
		bucket.Name,
		bucket.Name,
		bucket.Name,
	)

	// Exploitation commands
	m.LootMap["buckets-exploitation"].Contents += fmt.Sprintf(
		"# Bucket: %s\n"+
			"# List all objects recursively:\n"+
			"gsutil ls -r gs://%s/**\n"+
			"# Download all contents:\n"+
			"gsutil -m cp -r gs://%s/ ./loot/%s/\n"+
			"# Check for public access:\n"+
			"curl -s https://storage.googleapis.com/%s/ | head -20\n\n",
		bucket.Name,
		bucket.Name,
		bucket.Name, bucket.Name,
		bucket.Name,
	)

	// Public buckets
	if bucket.IsPublic {
		m.LootMap["buckets-public"].Contents += fmt.Sprintf(
			"# BUCKET: %s\n"+
				"# Project: %s\n"+
				"# Public Access: %s\n"+
				"# Public Access Prevention: %s\n"+
				"# Direct URL: https://storage.googleapis.com/%s/\n"+
				"# Console URL: https://console.cloud.google.com/storage/browser/%s\n"+
				"curl -s https://storage.googleapis.com/%s/ | head -50\n"+
				"gsutil ls gs://%s/\n\n",
			bucket.Name,
			bucket.ProjectID,
			bucket.PublicAccess,
			bucket.PublicAccessPrevention,
			bucket.Name,
			bucket.Name,
			bucket.Name,
			bucket.Name,
		)
	}

	// IAM bindings
	if len(bucket.IAMBindings) > 0 {
		m.LootMap["buckets-iam-bindings"].Contents += fmt.Sprintf(
			"# Bucket: %s (Project: %s)\n",
			bucket.Name, bucket.ProjectID,
		)
		for _, binding := range bucket.IAMBindings {
			m.LootMap["buckets-iam-bindings"].Contents += fmt.Sprintf(
				"# Role: %s\n#   Members: %s\n",
				binding.Role,
				strings.Join(binding.Members, ", "),
			)
		}
		m.LootMap["buckets-iam-bindings"].Contents += "\n"
	}

	// Enhancement: No versioning
	if !bucket.VersioningEnabled {
		m.LootMap["buckets-no-versioning"].Contents += fmt.Sprintf(
			"gs://%s  # Project: %s, Location: %s\n"+
				"# Enable versioning: gcloud storage buckets update gs://%s --versioning\n\n",
			bucket.Name, bucket.ProjectID, bucket.Location,
			bucket.Name,
		)
	}

	// Enhancement: No lifecycle
	if !bucket.LifecycleEnabled {
		m.LootMap["buckets-no-lifecycle"].Contents += fmt.Sprintf(
			"gs://%s  # Project: %s, Location: %s\n"+
				"# Add lifecycle: gcloud storage buckets update gs://%s --lifecycle-file=lifecycle.json\n\n",
			bucket.Name, bucket.ProjectID, bucket.Location,
			bucket.Name,
		)
	}

	// Enhancement: Short retention (delete lifecycle < 30 days)
	if bucket.HasDeleteRule && bucket.ShortestDeleteDays > 0 && bucket.ShortestDeleteDays < 30 {
		m.LootMap["buckets-short-retention"].Contents += fmt.Sprintf(
			"gs://%s  # Project: %s, Delete after: %d days\n",
			bucket.Name, bucket.ProjectID, bucket.ShortestDeleteDays,
		)
	}

	// Enhancement: Locked retention
	if bucket.RetentionPolicyLocked {
		m.LootMap["buckets-locked-retention"].Contents += fmt.Sprintf(
			"gs://%s  # Project: %s, Retention: %d days (LOCKED - IMMUTABLE)\n",
			bucket.Name, bucket.ProjectID, bucket.RetentionPeriodDays,
		)
	}

	// Enhancement: Dual/Multi-region
	if bucket.LocationType == "dual-region" || bucket.LocationType == "multi-region" {
		turboStatus := ""
		if bucket.TurboReplication {
			turboStatus = " (Turbo Replication ENABLED)"
		}
		m.LootMap["buckets-dual-region"].Contents += fmt.Sprintf(
			"gs://%s  # Project: %s, Type: %s, Location: %s%s\n",
			bucket.Name, bucket.ProjectID, bucket.LocationType, bucket.Location, turboStatus,
		)
	}

	// Add security recommendations
	m.addBucketSecurityRecommendations(bucket)
}

// addBucketSecurityRecommendations generates security recommendations for a bucket
func (m *BucketsModule) addBucketSecurityRecommendations(bucket CloudStorageService.BucketInfo) {
	hasRecommendations := false
	recommendations := fmt.Sprintf("# BUCKET: gs://%s (Project: %s)\n", bucket.Name, bucket.ProjectID)

	// Public access
	if bucket.IsPublic {
		hasRecommendations = true
		recommendations += fmt.Sprintf("# [CRITICAL] Public access detected: %s\n", bucket.PublicAccess)
		recommendations += fmt.Sprintf("# Remediation: Review and remove public access\n")
		recommendations += fmt.Sprintf("gcloud storage buckets remove-iam-policy-binding gs://%s --member=allUsers --role=<ROLE>\n", bucket.Name)
		recommendations += fmt.Sprintf("gcloud storage buckets remove-iam-policy-binding gs://%s --member=allAuthenticatedUsers --role=<ROLE>\n", bucket.Name)
	}

	// No versioning
	if !bucket.VersioningEnabled {
		hasRecommendations = true
		recommendations += "# [MEDIUM] Object versioning is disabled - no protection against accidental deletion\n"
		recommendations += fmt.Sprintf("gcloud storage buckets update gs://%s --versioning\n", bucket.Name)
	}

	// No lifecycle policy
	if !bucket.LifecycleEnabled {
		hasRecommendations = true
		recommendations += "# [LOW] No lifecycle policy - may accumulate unnecessary data and costs\n"
		recommendations += fmt.Sprintf("# Add lifecycle: gcloud storage buckets update gs://%s --lifecycle-file=lifecycle.json\n", bucket.Name)
	}

	// Not uniform access (using ACLs)
	if !bucket.UniformBucketLevelAccess {
		hasRecommendations = true
		recommendations += "# [MEDIUM] Not using uniform bucket-level access - ACLs are harder to audit\n"
		recommendations += fmt.Sprintf("gcloud storage buckets update gs://%s --uniform-bucket-level-access\n", bucket.Name)
	}

	// No logging
	if !bucket.LoggingEnabled {
		hasRecommendations = true
		recommendations += "# [LOW] Access logging is disabled - no audit trail for bucket access\n"
		recommendations += fmt.Sprintf("gcloud storage buckets update gs://%s --log-bucket=<LOG_BUCKET> --log-object-prefix=%s\n", bucket.Name, bucket.Name)
	}

	// Google-managed encryption (not CMEK)
	if bucket.EncryptionType == "Google-managed" {
		hasRecommendations = true
		recommendations += "# [INFO] Using Google-managed encryption - consider CMEK for compliance requirements\n"
		recommendations += fmt.Sprintf("gcloud storage buckets update gs://%s --default-encryption-key=projects/<PROJECT>/locations/<LOCATION>/keyRings/<KEYRING>/cryptoKeys/<KEY>\n", bucket.Name)
	}

	// Public access prevention not enforced
	if bucket.PublicAccessPrevention != "enforced" {
		hasRecommendations = true
		recommendations += "# [MEDIUM] Public access prevention not enforced - bucket could be made public\n"
		recommendations += fmt.Sprintf("gcloud storage buckets update gs://%s --public-access-prevention\n", bucket.Name)
	}

	// No soft delete
	if !bucket.SoftDeleteEnabled {
		hasRecommendations = true
		recommendations += "# [LOW] Soft delete not enabled - deleted objects cannot be recovered\n"
		recommendations += fmt.Sprintf("gcloud storage buckets update gs://%s --soft-delete-duration=7d\n", bucket.Name)
	}

	if hasRecommendations {
		m.LootMap["buckets-security-recommendations"].Contents += recommendations + "\n"
	}
}

// ------------------------------
// Helper functions
// ------------------------------
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func boolToCheckMark(b bool) string {
	if b {
		return "✓"
	}
	return "-"
}

// getMemberType extracts the member type from a GCP IAM member string
// Member formats: user:email, serviceAccount:email, group:email, domain:domain, allUsers, allAuthenticatedUsers
func getMemberType(member string) string {
	switch {
	case member == "allUsers":
		return "PUBLIC"
	case member == "allAuthenticatedUsers":
		return "ALL_AUTHENTICATED"
	case strings.HasPrefix(member, "user:"):
		return "User"
	case strings.HasPrefix(member, "serviceAccount:"):
		return "ServiceAccount"
	case strings.HasPrefix(member, "group:"):
		return "Group"
	case strings.HasPrefix(member, "domain:"):
		return "Domain"
	case strings.HasPrefix(member, "projectOwner:"):
		return "ProjectOwner"
	case strings.HasPrefix(member, "projectEditor:"):
		return "ProjectEditor"
	case strings.HasPrefix(member, "projectViewer:"):
		return "ProjectViewer"
	case strings.HasPrefix(member, "deleted:"):
		return "Deleted"
	default:
		return "Unknown"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *BucketsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main table with security-relevant columns
	header := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Location",
		"Type",
		"Public",
		"Versioning",
		"Lifecycle",
		"Retention",
		"Encryption",
	}

	var body [][]string
	for _, bucket := range m.Buckets {
		// Format retention info
		retentionInfo := "-"
		if bucket.RetentionPolicyEnabled {
			if bucket.RetentionPolicyLocked {
				retentionInfo = fmt.Sprintf("%dd (LOCKED)", bucket.RetentionPeriodDays)
			} else {
				retentionInfo = fmt.Sprintf("%dd", bucket.RetentionPeriodDays)
			}
		}

		// Format public access - highlight if public
		publicDisplay := "-"
		if bucket.IsPublic {
			publicDisplay = "PUBLIC"
		}

		// Format lifecycle info
		lifecycleInfo := "-"
		if bucket.LifecycleEnabled {
			if bucket.HasDeleteRule {
				lifecycleInfo = fmt.Sprintf("%d rules (del:%dd)", bucket.LifecycleRuleCount, bucket.ShortestDeleteDays)
			} else {
				lifecycleInfo = fmt.Sprintf("%d rules", bucket.LifecycleRuleCount)
			}
		}

		// Format location type
		locationType := bucket.LocationType
		if locationType == "" {
			locationType = "region"
		}
		if bucket.TurboReplication {
			locationType += "+turbo"
		}

		body = append(body, []string{
			m.GetProjectName(bucket.ProjectID),
			bucket.ProjectID,
			bucket.Name,
			bucket.Location,
			locationType,
			publicDisplay,
			boolToCheckMark(bucket.VersioningEnabled),
			lifecycleInfo,
			retentionInfo,
			bucket.EncryptionType,
		})
	}

	// Security config table
	securityHeader := []string{
		"Bucket",
		"Project Name",
		"Project ID",
		"PublicAccessPrevention",
		"UniformAccess",
		"Logging",
		"SoftDelete",
		"Autoclass",
	}

	var securityBody [][]string
	for _, bucket := range m.Buckets {
		softDeleteInfo := "-"
		if bucket.SoftDeleteEnabled {
			softDeleteInfo = fmt.Sprintf("%dd", bucket.SoftDeleteRetentionDays)
		}

		autoclassInfo := "-"
		if bucket.AutoclassEnabled {
			autoclassInfo = bucket.AutoclassTerminalClass
			if autoclassInfo == "" {
				autoclassInfo = "enabled"
			}
		}

		securityBody = append(securityBody, []string{
			bucket.Name,
			m.GetProjectName(bucket.ProjectID),
			bucket.ProjectID,
			bucket.PublicAccessPrevention,
			boolToCheckMark(bucket.UniformBucketLevelAccess),
			boolToCheckMark(bucket.LoggingEnabled),
			softDeleteInfo,
			autoclassInfo,
		})
	}

	// Detailed IAM table - one row per member for granular view
	iamHeader := []string{
		"Bucket",
		"Project Name",
		"Project ID",
		"Role",
		"Member Type",
		"Member",
	}

	var iamBody [][]string
	for _, bucket := range m.Buckets {
		for _, binding := range bucket.IAMBindings {
			for _, member := range binding.Members {
				memberType := getMemberType(member)
				iamBody = append(iamBody, []string{
					bucket.Name,
					m.GetProjectName(bucket.ProjectID),
					bucket.ProjectID,
					binding.Role,
					memberType,
					member,
				})
			}
		}
	}

	// Public buckets table (if any)
	publicHeader := []string{
		"Bucket",
		"Project Name",
		"Project ID",
		"Public Access",
		"Public Access Prevention",
		"URL",
	}

	var publicBody [][]string
	for _, bucket := range m.Buckets {
		if bucket.IsPublic {
			publicBody = append(publicBody, []string{
				bucket.Name,
				m.GetProjectName(bucket.ProjectID),
				bucket.ProjectID,
				bucket.PublicAccess,
				bucket.PublicAccessPrevention,
				fmt.Sprintf("https://storage.googleapis.com/%s/", bucket.Name),
			})
		}
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{
		{
			Name:   globals.GCP_BUCKETS_MODULE_NAME,
			Header: header,
			Body:   body,
		},
		{
			Name:   "buckets-security-config",
			Header: securityHeader,
			Body:   securityBody,
		},
	}

	// Add IAM table if there are bindings
	if len(iamBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "buckets-iam",
			Header: iamHeader,
			Body:   iamBody,
		})
	}

	// Add public buckets table if any
	if len(publicBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "buckets-public",
			Header: publicHeader,
			Body:   publicBody,
		})
	}

	output := BucketsOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	// Build scope names from project names map
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	// Write output using HandleOutputSmart with scope support
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",      // scopeType
		m.ProjectIDs,   // scopeIdentifiers
		scopeNames,     // scopeNames (display names)
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_BUCKETS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
