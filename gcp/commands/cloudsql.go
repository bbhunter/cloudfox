package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudSQLService "github.com/BishopFox/cloudfox/gcp/services/cloudsqlService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudSQLCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDSQL_MODULE_NAME,
	Aliases: []string{"sql", "database", "db"},
	Short:   "Enumerate Cloud SQL instances with security analysis",
	Long: `Enumerate Cloud SQL instances across projects with security-relevant details.

Features:
- Lists all Cloud SQL instances (MySQL, PostgreSQL, SQL Server)
- Shows network configuration (public/private IP, authorized networks)
- Identifies publicly accessible databases
- Shows SSL/TLS configuration and requirements
- Checks backup and high availability configuration
- Shows encryption type (Google-managed vs CMEK)
- Shows IAM database authentication status
- Shows password policy configuration
- Shows maintenance window settings
- Shows point-in-time recovery status
- Identifies common security misconfigurations
- Generates gcloud commands for further analysis

Security Columns:
- PublicIP: Whether the instance has a public IP address
- RequireSSL: Whether SSL/TLS is required for connections
- AuthNetworks: Number of authorized network ranges
- Backups: Automated backup status
- PITR: Point-in-time recovery status
- Encryption: CMEK or Google-managed
- IAM Auth: IAM database authentication
- PwdPolicy: Password validation policy
- HA: High availability configuration
- Issues: Detected security misconfigurations

Attack Surface:
- Public IPs expose database to internet scanning
- Missing SSL allows credential sniffing
- 0.0.0.0/0 in authorized networks = world accessible
- Default service accounts may have excessive permissions
- Google-managed encryption may not meet compliance
- Missing password policy allows weak passwords`,
	Run: runGCPCloudSQLCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CloudSQLModule struct {
	gcpinternal.BaseGCPModule

	Instances []CloudSQLService.SQLInstanceInfo
	LootMap   map[string]*internal.LootFile
	mu        sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CloudSQLOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudSQLOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudSQLOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudSQLCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDSQL_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudSQLModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Instances:     []CloudSQLService.SQLInstanceInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudSQLModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDSQL_MODULE_NAME, m.processProject)

	if len(m.Instances) == 0 {
		logger.InfoM("No Cloud SQL instances found", globals.GCP_CLOUDSQL_MODULE_NAME)
		return
	}

	// Count public instances
	publicCount := 0
	for _, instance := range m.Instances {
		if instance.HasPublicIP {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d instance(s), %d with public IP", len(m.Instances), publicCount), globals.GCP_CLOUDSQL_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d instance(s)", len(m.Instances)), globals.GCP_CLOUDSQL_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudSQLModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud SQL instances in project: %s", projectID), globals.GCP_CLOUDSQL_MODULE_NAME)
	}

	cs := CloudSQLService.New()
	instances, err := cs.Instances(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating Cloud SQL in project %s: %v", projectID, err), globals.GCP_CLOUDSQL_MODULE_NAME)
		}
		return
	}

	m.mu.Lock()
	m.Instances = append(m.Instances, instances...)

	for _, instance := range instances {
		m.addInstanceToLoot(instance)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d instance(s) in project %s", len(instances), projectID), globals.GCP_CLOUDSQL_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CloudSQLModule) initializeLootFiles() {
	m.LootMap["cloudsql-gcloud-commands"] = &internal.LootFile{
		Name:     "cloudsql-gcloud-commands",
		Contents: "# Cloud SQL gcloud Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["cloudsql-connection-strings"] = &internal.LootFile{
		Name:     "cloudsql-connection-strings",
		Contents: "# Cloud SQL Connection Strings\n# Generated by CloudFox\n# NOTE: You'll need to obtain credentials separately\n\n",
	}
	m.LootMap["cloudsql-exploitation"] = &internal.LootFile{
		Name:     "cloudsql-exploitation",
		Contents: "# Cloud SQL Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["cloudsql-public"] = &internal.LootFile{
		Name:     "cloudsql-public",
		Contents: "# PUBLIC Cloud SQL Instances\n# Generated by CloudFox\n# These instances have public IP addresses!\n\n",
	}
	m.LootMap["cloudsql-security-issues"] = &internal.LootFile{
		Name:     "cloudsql-security-issues",
		Contents: "# Cloud SQL Security Issues Detected\n# Generated by CloudFox\n\n",
	}
	m.LootMap["cloudsql-backup-commands"] = &internal.LootFile{
		Name:     "cloudsql-backup-commands",
		Contents: "# Cloud SQL Backup Commands\n# Generated by CloudFox\n# Commands for backup enumeration and restoration\n\n",
	}
	m.LootMap["cloudsql-security-recommendations"] = &internal.LootFile{
		Name:     "cloudsql-security-recommendations",
		Contents: "# Cloud SQL Security Recommendations\n# Generated by CloudFox\n# Remediation commands for security issues\n\n",
	}
	m.LootMap["cloudsql-no-backups"] = &internal.LootFile{
		Name:     "cloudsql-no-backups",
		Contents: "# Cloud SQL Instances WITHOUT Backups\n# Generated by CloudFox\n# CRITICAL: These instances have no automated backups!\n\n",
	}
	m.LootMap["cloudsql-weak-encryption"] = &internal.LootFile{
		Name:     "cloudsql-weak-encryption",
		Contents: "# Cloud SQL Instances Using Google-Managed Encryption\n# Generated by CloudFox\n# Consider using CMEK for compliance requirements\n\n",
	}
}

func (m *CloudSQLModule) addInstanceToLoot(instance CloudSQLService.SQLInstanceInfo) {
	// gcloud commands
	m.LootMap["cloudsql-gcloud-commands"].Contents += fmt.Sprintf(
		"# Instance: %s (Project: %s, Region: %s)\n"+
			"gcloud sql instances describe %s --project=%s\n"+
			"gcloud sql databases list --instance=%s --project=%s\n"+
			"gcloud sql users list --instance=%s --project=%s\n"+
			"gcloud sql ssl-certs list --instance=%s --project=%s\n"+
			"gcloud sql backups list --instance=%s --project=%s\n\n",
		instance.Name, instance.ProjectID, instance.Region,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
	)

	// Connection strings based on database type
	dbType := getDatabaseType(instance.DatabaseVersion)
	connectionInstance := fmt.Sprintf("%s:%s:%s", instance.ProjectID, instance.Region, instance.Name)

	m.LootMap["cloudsql-connection-strings"].Contents += fmt.Sprintf(
		"# Instance: %s (%s)\n"+
			"# Public IP: %s\n"+
			"# Private IP: %s\n"+
			"# Connection Name: %s\n",
		instance.Name, instance.DatabaseVersion,
		instance.PublicIP,
		instance.PrivateIP,
		connectionInstance,
	)

	switch dbType {
	case "mysql":
		m.LootMap["cloudsql-connection-strings"].Contents += fmt.Sprintf(
			"# MySQL Connection:\n"+
				"mysql -h %s -u root -p\n"+
				"# Cloud SQL Proxy:\n"+
				"cloud_sql_proxy -instances=%s=tcp:3306\n"+
				"mysql -h 127.0.0.1 -u root -p\n\n",
			instance.PublicIP, connectionInstance,
		)
	case "postgres":
		m.LootMap["cloudsql-connection-strings"].Contents += fmt.Sprintf(
			"# PostgreSQL Connection:\n"+
				"psql -h %s -U postgres\n"+
				"# Cloud SQL Proxy:\n"+
				"cloud_sql_proxy -instances=%s=tcp:5432\n"+
				"psql -h 127.0.0.1 -U postgres\n\n",
			instance.PublicIP, connectionInstance,
		)
	case "sqlserver":
		m.LootMap["cloudsql-connection-strings"].Contents += fmt.Sprintf(
			"# SQL Server Connection:\n"+
				"sqlcmd -S %s -U sqlserver\n"+
				"# Cloud SQL Proxy:\n"+
				"cloud_sql_proxy -instances=%s=tcp:1433\n"+
				"sqlcmd -S 127.0.0.1 -U sqlserver\n\n",
			instance.PublicIP, connectionInstance,
		)
	}

	// Exploitation commands
	m.LootMap["cloudsql-exploitation"].Contents += fmt.Sprintf(
		"# Instance: %s (Project: %s)\n"+
			"# Database: %s\n"+
			"# Public IP: %s, Private IP: %s\n"+
			"# SSL Required: %v\n\n"+
			"# Connect via Cloud SQL Proxy (recommended):\n"+
			"cloud_sql_proxy -instances=%s=tcp:3306 &\n\n"+
			"# Create a new user (if you have sql.users.create):\n"+
			"gcloud sql users create attacker --instance=%s --password=AttackerPass123! --project=%s\n\n"+
			"# Export database (if you have sql.instances.export):\n"+
			"gcloud sql export sql %s gs://%s-backup/export.sql --database=mysql --project=%s\n\n",
		instance.Name, instance.ProjectID,
		instance.DatabaseVersion,
		instance.PublicIP, instance.PrivateIP,
		instance.RequireSSL,
		connectionInstance,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID, instance.ProjectID,
	)

	// Public instances
	if instance.HasPublicIP {
		m.LootMap["cloudsql-public"].Contents += fmt.Sprintf(
			"# INSTANCE: %s\n"+
				"# Project: %s, Region: %s\n"+
				"# Database: %s\n"+
				"# Public IP: %s\n"+
				"# SSL Required: %v\n"+
				"# Authorized Networks: %d\n",
			instance.Name,
			instance.ProjectID, instance.Region,
			instance.DatabaseVersion,
			instance.PublicIP,
			instance.RequireSSL,
			len(instance.AuthorizedNetworks),
		)
		for _, network := range instance.AuthorizedNetworks {
			marker := ""
			if network.IsPublic {
				marker = " [WORLD ACCESSIBLE!]"
			}
			m.LootMap["cloudsql-public"].Contents += fmt.Sprintf(
				"#   - %s: %s%s\n",
				network.Name, network.Value, marker,
			)
		}
		m.LootMap["cloudsql-public"].Contents += "\n"
	}

	// Security issues
	if len(instance.SecurityIssues) > 0 {
		m.LootMap["cloudsql-security-issues"].Contents += fmt.Sprintf(
			"# INSTANCE: %s (Project: %s)\n"+
				"# Database: %s\n"+
				"# Issues:\n",
			instance.Name, instance.ProjectID, instance.DatabaseVersion,
		)
		for _, issue := range instance.SecurityIssues {
			m.LootMap["cloudsql-security-issues"].Contents += fmt.Sprintf("  - %s\n", issue)
		}
		m.LootMap["cloudsql-security-issues"].Contents += "\n"
	}

	// Backup commands
	m.LootMap["cloudsql-backup-commands"].Contents += fmt.Sprintf(
		"# Instance: %s (Project: %s)\n"+
			"# Backup Enabled: %v, PITR: %v, Retention: %d days\n"+
			"gcloud sql backups list --instance=%s --project=%s\n"+
			"gcloud sql backups describe BACKUP_ID --instance=%s --project=%s\n"+
			"# Restore from backup:\n"+
			"# gcloud sql backups restore BACKUP_ID --restore-instance=%s --project=%s\n"+
			"# Point-in-time recovery (if enabled):\n"+
			"# gcloud sql instances clone %s %s-clone --point-in-time='2024-01-01T00:00:00Z' --project=%s\n\n",
		instance.Name, instance.ProjectID,
		instance.BackupEnabled, instance.PointInTimeRecovery, instance.RetentionDays,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.Name, instance.ProjectID,
	)

	// Instances without backups
	if !instance.BackupEnabled {
		m.LootMap["cloudsql-no-backups"].Contents += fmt.Sprintf(
			"# INSTANCE: %s (Project: %s)\n"+
				"# Database: %s, Tier: %s\n"+
				"# CRITICAL: No automated backups configured!\n"+
				"# Enable backups with:\n"+
				"gcloud sql instances patch %s --backup-start-time=02:00 --project=%s\n\n",
			instance.Name, instance.ProjectID,
			instance.DatabaseVersion, instance.Tier,
			instance.Name, instance.ProjectID,
		)
	}

	// Weak encryption (Google-managed instead of CMEK)
	if instance.EncryptionType == "Google-managed" {
		m.LootMap["cloudsql-weak-encryption"].Contents += fmt.Sprintf(
			"# INSTANCE: %s (Project: %s)\n"+
				"# Database: %s\n"+
				"# Encryption: Google-managed (not CMEK)\n"+
				"# NOTE: CMEK cannot be enabled on existing instances.\n"+
				"# For CMEK, create a new instance with:\n"+
				"# gcloud sql instances create %s-cmek \\\n"+
				"#   --database-version=%s \\\n"+
				"#   --disk-encryption-key=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY \\\n"+
				"#   --project=%s\n\n",
			instance.Name, instance.ProjectID,
			instance.DatabaseVersion,
			instance.Name,
			instance.DatabaseVersion,
			instance.ProjectID,
		)
	}

	// Security recommendations
	m.addSecurityRecommendations(instance)
}

// addSecurityRecommendations adds remediation commands for security issues
func (m *CloudSQLModule) addSecurityRecommendations(instance CloudSQLService.SQLInstanceInfo) {
	hasRecommendations := false
	recommendations := fmt.Sprintf(
		"# INSTANCE: %s (Project: %s)\n"+
			"# Database: %s\n",
		instance.Name, instance.ProjectID, instance.DatabaseVersion,
	)

	// SSL not required
	if !instance.RequireSSL {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: SSL not required\n"+
				"gcloud sql instances patch %s --require-ssl --project=%s\n\n",
			instance.Name, instance.ProjectID,
		)
	}

	// Password policy not enabled
	if !instance.PasswordPolicyEnabled {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Password policy not enabled\n"+
				"gcloud sql instances patch %s \\\n"+
				"  --password-policy-min-length=12 \\\n"+
				"  --password-policy-complexity=COMPLEXITY_DEFAULT \\\n"+
				"  --password-policy-reuse-interval=5 \\\n"+
				"  --password-policy-disallow-username-substring \\\n"+
				"  --project=%s\n\n",
			instance.Name, instance.ProjectID,
		)
	}

	// Backups not enabled
	if !instance.BackupEnabled {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Automated backups not enabled\n"+
				"gcloud sql instances patch %s --backup-start-time=02:00 --project=%s\n\n",
			instance.Name, instance.ProjectID,
		)
	}

	// Point-in-time recovery not enabled (but backups are)
	if instance.BackupEnabled && !instance.PointInTimeRecovery {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Point-in-time recovery not enabled\n"+
				"gcloud sql instances patch %s --enable-point-in-time-recovery --project=%s\n\n",
			instance.Name, instance.ProjectID,
		)
	}

	// Single zone deployment
	if instance.AvailabilityType == "ZONAL" {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Single zone deployment (no HA)\n"+
				"gcloud sql instances patch %s --availability-type=REGIONAL --project=%s\n\n",
			instance.Name, instance.ProjectID,
		)
	}

	// Public IP with no SSL
	if instance.HasPublicIP && !instance.RequireSSL {
		hasRecommendations = true
		recommendations += fmt.Sprintf(
			"# Issue: Public IP without SSL requirement - HIGH RISK\n"+
				"# Option 1: Require SSL\n"+
				"gcloud sql instances patch %s --require-ssl --project=%s\n"+
				"# Option 2: Disable public IP (use Private IP only)\n"+
				"gcloud sql instances patch %s --no-assign-ip --project=%s\n\n",
			instance.Name, instance.ProjectID,
			instance.Name, instance.ProjectID,
		)
	}

	if hasRecommendations {
		m.LootMap["cloudsql-security-recommendations"].Contents += recommendations + "\n"
	}
}

// getDatabaseType returns the database type from version string
func getDatabaseType(version string) string {
	switch {
	case strings.HasPrefix(version, "MYSQL"):
		return "mysql"
	case strings.HasPrefix(version, "POSTGRES"):
		return "postgres"
	case strings.HasPrefix(version, "SQLSERVER"):
		return "sqlserver"
	default:
		return "unknown"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudSQLModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main instances table with enhanced columns
	header := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"Database",
		"Tier",
		"State",
		"Public IP",
		"Private IP",
		"SSL",
		"Auth Nets",
		"Backups",
		"PITR",
		"Encrypt",
		"IAM Auth",
		"PwdPolicy",
		"HA",
		"Issues",
	}

	var body [][]string
	for _, instance := range m.Instances {
		// Format authorized networks count
		authNetworks := fmt.Sprintf("%d", len(instance.AuthorizedNetworks))
		hasPublicNetwork := false
		for _, network := range instance.AuthorizedNetworks {
			if network.IsPublic {
				hasPublicNetwork = true
				break
			}
		}
		if hasPublicNetwork {
			authNetworks += " (PUBLIC!)"
		}

		// Format issues
		issueDisplay := "-"
		if len(instance.SecurityIssues) > 0 {
			issueDisplay = fmt.Sprintf("%d issues", len(instance.SecurityIssues))
		}

		// Format encryption type
		encryptionDisplay := instance.EncryptionType
		if encryptionDisplay == "" {
			encryptionDisplay = "Google"
		} else if encryptionDisplay == "Google-managed" {
			encryptionDisplay = "Google"
		}

		body = append(body, []string{
			m.GetProjectName(instance.ProjectID),
			instance.ProjectID,
			instance.Name,
			instance.Region,
			instance.DatabaseVersion,
			instance.Tier,
			instance.State,
			instance.PublicIP,
			instance.PrivateIP,
			boolToYesNo(instance.RequireSSL),
			authNetworks,
			boolToYesNo(instance.BackupEnabled),
			boolToYesNo(instance.PointInTimeRecovery),
			encryptionDisplay,
			boolToYesNo(instance.IAMAuthentication),
			boolToYesNo(instance.PasswordPolicyEnabled),
			instance.AvailabilityType,
			issueDisplay,
		})
	}

	// Security issues table
	issuesHeader := []string{
		"Instance",
		"Project Name",
		"Project ID",
		"Database",
		"Issue",
	}

	var issuesBody [][]string
	for _, instance := range m.Instances {
		for _, issue := range instance.SecurityIssues {
			issuesBody = append(issuesBody, []string{
				instance.Name,
				m.GetProjectName(instance.ProjectID),
				instance.ProjectID,
				instance.DatabaseVersion,
				issue,
			})
		}
	}

	// Authorized networks table
	networksHeader := []string{
		"Instance",
		"Project Name",
		"Project ID",
		"Network Name",
		"CIDR",
		"Public Access",
	}

	var networksBody [][]string
	for _, instance := range m.Instances {
		for _, network := range instance.AuthorizedNetworks {
			publicAccess := "No"
			if network.IsPublic {
				publicAccess = "YES - WORLD ACCESSIBLE"
			}
			networksBody = append(networksBody, []string{
				instance.Name,
				m.GetProjectName(instance.ProjectID),
				instance.ProjectID,
				network.Name,
				network.Value,
				publicAccess,
			})
		}
	}

	// Backup configuration table
	backupHeader := []string{
		"Instance",
		"Project Name",
		"Project ID",
		"Backups",
		"PITR",
		"Binary Log",
		"Retention Days",
		"Backup Location",
		"Failover Replica",
	}

	var backupBody [][]string
	for _, instance := range m.Instances {
		backupLocation := instance.BackupLocation
		if backupLocation == "" {
			backupLocation = "Default"
		}
		failoverReplica := instance.FailoverReplica
		if failoverReplica == "" {
			failoverReplica = "-"
		}
		backupBody = append(backupBody, []string{
			instance.Name,
			m.GetProjectName(instance.ProjectID),
			instance.ProjectID,
			boolToYesNo(instance.BackupEnabled),
			boolToYesNo(instance.PointInTimeRecovery),
			boolToYesNo(instance.BinaryLogEnabled),
			fmt.Sprintf("%d", instance.RetentionDays),
			backupLocation,
			failoverReplica,
		})
	}

	// Encryption and security configuration table
	securityConfigHeader := []string{
		"Instance",
		"Project Name",
		"Project ID",
		"Encryption",
		"KMS Key",
		"IAM Auth",
		"Pwd Policy",
		"SSL Required",
		"SSL Mode",
		"Maintenance",
	}

	var securityConfigBody [][]string
	for _, instance := range m.Instances {
		kmsKey := instance.KMSKeyName
		if kmsKey == "" {
			kmsKey = "-"
		} else {
			// Truncate long key names
			parts := strings.Split(kmsKey, "/")
			if len(parts) > 0 {
				kmsKey = parts[len(parts)-1]
			}
		}
		maintenanceWindow := instance.MaintenanceWindow
		if maintenanceWindow == "" {
			maintenanceWindow = "Not set"
		}
		sslMode := instance.SSLMode
		if sslMode == "" {
			sslMode = "Default"
		}
		securityConfigBody = append(securityConfigBody, []string{
			instance.Name,
			m.GetProjectName(instance.ProjectID),
			instance.ProjectID,
			instance.EncryptionType,
			kmsKey,
			boolToYesNo(instance.IAMAuthentication),
			boolToYesNo(instance.PasswordPolicyEnabled),
			boolToYesNo(instance.RequireSSL),
			sslMode,
			maintenanceWindow,
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
	tableFiles := []internal.TableFile{
		{
			Name:   globals.GCP_CLOUDSQL_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	if len(issuesBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "cloudsql-security-issues",
			Header: issuesHeader,
			Body:   issuesBody,
		})
	}

	if len(networksBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "cloudsql-authorized-networks",
			Header: networksHeader,
			Body:   networksBody,
		})
	}

	// Always add backup table (shows backup gaps)
	tableFiles = append(tableFiles, internal.TableFile{
		Name:   "cloudsql-backups",
		Header: backupHeader,
		Body:   backupBody,
	})

	// Always add security config table
	tableFiles = append(tableFiles, internal.TableFile{
		Name:   "cloudsql-security-config",
		Header: securityConfigHeader,
		Body:   securityConfigBody,
	})

	output := CloudSQLOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDSQL_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
