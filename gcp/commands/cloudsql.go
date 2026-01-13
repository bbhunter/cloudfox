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
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDSQL_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud SQL in project %s", projectID))
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
	m.LootMap["cloudsql-commands"] = &internal.LootFile{
		Name:     "cloudsql-commands",
		Contents: "# Cloud SQL Details\n# Generated by CloudFox\n\n",
	}
}

func (m *CloudSQLModule) addInstanceToLoot(instance CloudSQLService.SQLInstanceInfo) {
	dbType := getDatabaseType(instance.DatabaseVersion)
	connectionInstance := fmt.Sprintf("%s:%s:%s", instance.ProjectID, instance.Region, instance.Name)

	publicIP := instance.PublicIP
	if publicIP == "" {
		publicIP = "-"
	}

	m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
		"# %s (%s)\n"+
			"# Project: %s | Region: %s\n"+
			"# Public IP: %s\n",
		instance.Name, instance.DatabaseVersion,
		instance.ProjectID, instance.Region,
		publicIP,
	)

	// gcloud commands
	m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
		"gcloud sql instances describe %s --project=%s\n"+
			"gcloud sql databases list --instance=%s --project=%s\n"+
			"gcloud sql users list --instance=%s --project=%s\n",
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
		instance.Name, instance.ProjectID,
	)

	// Connection commands based on database type
	switch dbType {
	case "mysql":
		if instance.PublicIP != "" {
			m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
				"mysql -h %s -u root -p\n",
				instance.PublicIP,
			)
		}
		m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
			"cloud_sql_proxy -instances=%s=tcp:3306\n",
			connectionInstance,
		)
	case "postgres":
		if instance.PublicIP != "" {
			m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
				"psql -h %s -U postgres\n",
				instance.PublicIP,
			)
		}
		m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
			"cloud_sql_proxy -instances=%s=tcp:5432\n",
			connectionInstance,
		)
	case "sqlserver":
		if instance.PublicIP != "" {
			m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
				"sqlcmd -S %s -U sqlserver\n",
				instance.PublicIP,
			)
		}
		m.LootMap["cloudsql-commands"].Contents += fmt.Sprintf(
			"cloud_sql_proxy -instances=%s=tcp:1433\n",
			connectionInstance,
		)
	}

	m.LootMap["cloudsql-commands"].Contents += "\n"
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
	// Single merged table with one row per authorized network
	header := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"Database",
		"Tier",
		"Public IP",
		"Private IP",
		"SSL",
		"Backups",
		"PITR",
		"Encrypt",
		"IAM Auth",
		"PwdPolicy",
		"HA",
		"Auth Network",
		"CIDR",
		"Public Access",
	}

	var body [][]string
	for _, instance := range m.Instances {
		// Format encryption type
		encryptionDisplay := instance.EncryptionType
		if encryptionDisplay == "" || encryptionDisplay == "Google-managed" {
			encryptionDisplay = "Google"
		}

		// Format public/private IPs
		publicIP := instance.PublicIP
		if publicIP == "" {
			publicIP = "-"
		}
		privateIP := instance.PrivateIP
		if privateIP == "" {
			privateIP = "-"
		}

		// If instance has authorized networks, create one row per network
		if len(instance.AuthorizedNetworks) > 0 {
			for _, network := range instance.AuthorizedNetworks {
				publicAccess := "No"
				if network.IsPublic {
					publicAccess = "YES - WORLD ACCESSIBLE"
				}

				networkName := network.Name
				if networkName == "" {
					networkName = "-"
				}

				body = append(body, []string{
					m.GetProjectName(instance.ProjectID),
					instance.ProjectID,
					instance.Name,
					instance.Region,
					instance.DatabaseVersion,
					instance.Tier,
					publicIP,
					privateIP,
					boolToYesNo(instance.RequireSSL),
					boolToYesNo(instance.BackupEnabled),
					boolToYesNo(instance.PointInTimeRecovery),
					encryptionDisplay,
					boolToYesNo(instance.IAMAuthentication),
					boolToYesNo(instance.PasswordPolicyEnabled),
					instance.AvailabilityType,
					networkName,
					network.Value,
					publicAccess,
				})
			}
		} else {
			// Instance has no authorized networks - single row
			body = append(body, []string{
				m.GetProjectName(instance.ProjectID),
				instance.ProjectID,
				instance.Name,
				instance.Region,
				instance.DatabaseVersion,
				instance.Tier,
				publicIP,
				privateIP,
				boolToYesNo(instance.RequireSSL),
				boolToYesNo(instance.BackupEnabled),
				boolToYesNo(instance.PointInTimeRecovery),
				encryptionDisplay,
				boolToYesNo(instance.IAMAuthentication),
				boolToYesNo(instance.PasswordPolicyEnabled),
				instance.AvailabilityType,
				"-",
				"-",
				"-",
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
			Name:   globals.GCP_CLOUDSQL_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

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
