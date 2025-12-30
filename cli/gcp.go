package cli

import (
	"context"
	"fmt"

	"github.com/BishopFox/cloudfox/gcp/commands"
	oauthservice "github.com/BishopFox/cloudfox/gcp/services/oauthService"
	orgsservice "github.com/BishopFox/cloudfox/gcp/services/organizationsService"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var (
	// GCP resources filtering options
	GCPOrganization       string
	GCPProjectID          string
	GCPProjectIDsFilePath string
	GCPProjectIDs         []string
	GCPAllProjects        bool

	// Project name mapping (ProjectID -> DisplayName)
	GCPProjectNames map[string]string

	// Output formatting options
	GCPOutputFormat    string
	GCPOutputDirectory string
	GCPVerbosity       int
	GCPWrapTable       bool

	// misc options
	// GCPIgnoreCache		bool

	// logger
	GCPLogger = internal.NewLogger()

	// GCP root command
	GCPCommands = &cobra.Command{
		Use:     "gcp",
		Aliases: []string{"gcloud"},
		Long:    `See "Available Commands" for GCP Modules below`,
		Short:   "See \"Available Commands\" for GCP Modules below",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Initialize project names map
			GCPProjectNames = make(map[string]string)

			// Handle project discovery based on flags
			if GCPAllProjects {
				// Discover all accessible projects
				GCPLogger.InfoM("Discovering all accessible projects...", "gcp")
				orgsSvc := orgsservice.New()
				projects, err := orgsSvc.SearchProjects("")
				if err != nil {
					GCPLogger.FatalM(fmt.Sprintf("Failed to discover projects: %v. Try using -p or -l flags instead.", err), "gcp")
				}
				for _, proj := range projects {
					if proj.State == "ACTIVE" {
						GCPProjectIDs = append(GCPProjectIDs, proj.ProjectID)
						GCPProjectNames[proj.ProjectID] = proj.DisplayName
					}
				}
				if len(GCPProjectIDs) == 0 {
					GCPLogger.FatalM("No accessible projects found. Check your permissions.", "gcp")
				}
				GCPLogger.InfoM(fmt.Sprintf("Discovered %d project(s)", len(GCPProjectIDs)), "gcp")
			} else if GCPProjectID != "" {
				GCPProjectIDs = append(GCPProjectIDs, GCPProjectID)
				// Resolve project name for single project
				resolveProjectNames(GCPProjectIDs)
			} else if GCPProjectIDsFilePath != "" {
				GCPProjectIDs = internal.LoadFileLinesIntoArray(GCPProjectIDsFilePath)
				// Resolve project names for all projects in list
				resolveProjectNames(GCPProjectIDs)
			} else {
				GCPLogger.InfoM("project, project-list, or all-projects flag not given, commands requiring a project ID will fail", "gcp")
			}

			// Create a context with project IDs and names
			ctx := context.WithValue(context.Background(), "projectIDs", GCPProjectIDs)
			ctx = context.WithValue(ctx, "projectNames", GCPProjectNames)

			// Authenticate and get account info
			os := oauthservice.NewOAuthService()
			principal, err := os.WhoAmI()
			if err != nil {
				GCPLogger.FatalM(fmt.Sprintf("could not determine default user credential with error %s. \n\nPlease use default application default credentials: https://cloud.google.com/docs/authentication/application-default-credentials", err.Error()), "gcp")
			}
			ctx = context.WithValue(ctx, "account", principal.Email)
			cmd.SetContext(ctx)
		},
	}
)

// resolveProjectNames fetches display names for given project IDs
func resolveProjectNames(projectIDs []string) {
	if len(projectIDs) == 0 {
		return
	}

	orgsSvc := orgsservice.New()
	// Fetch all accessible projects and build lookup map
	projects, err := orgsSvc.SearchProjects("")
	if err != nil {
		// Non-fatal: we can continue without display names
		GCPLogger.InfoM("Could not resolve project names, using project IDs only", "gcp")
		for _, id := range projectIDs {
			GCPProjectNames[id] = id // fallback to using ID as name
		}
		return
	}

	// Build lookup from fetched projects
	projectLookup := make(map[string]string)
	for _, proj := range projects {
		projectLookup[proj.ProjectID] = proj.DisplayName
	}

	// Map our project IDs to names
	for _, id := range projectIDs {
		if name, ok := projectLookup[id]; ok {
			GCPProjectNames[id] = name
		} else {
			GCPProjectNames[id] = id // fallback to using ID as name
		}
	}
}

// New RunAllGCPCommands function to execute all child commands
var GCPAllChecksCommand = &cobra.Command{
	Use:   "all-checks",
	Short: "Runs all available GCP commands",
	Long:  `Executes all available GCP commands to collect and display information from all supported GCP services.`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, childCmd := range GCPCommands.Commands() {
			if childCmd == cmd { // Skip the run-all command itself to avoid infinite recursion
				continue
			}

			GCPLogger.InfoM(fmt.Sprintf("Running command: %s", childCmd.Use), "all-checks")
			childCmd.Run(cmd, args)
		}
	},
}

func init() {
	// Globals flags for the GCP commands

	// Allow selection of non-default account to be used when accessing gcloud API
	// TODO

	// Resource filtering options
	// GCPCommands.PersistentFlags().StringVarP(&GCPOrganization, "organization", "o", "", "Organization name or number, repetable")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectID, "project", "p", "", "GCP project ID")
	GCPCommands.PersistentFlags().StringVarP(&GCPProjectIDsFilePath, "project-list", "l", "", "Path to a file containing a list of project IDs separated by newlines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPAllProjects, "all-projects", "a", false, "Automatically discover and use all accessible projects")
	// GCPCommands.PersistentFlags().BoolVarP(&GCPConfirm, "yes", "y", false, "Non-interactive mode (like apt/yum)")
	// GCPCommands.PersistentFlags().StringVarP(&GCPOutputFormat, "output", "", "brief", "[\"brief\" | \"wide\" ]")
	GCPCommands.PersistentFlags().IntVarP(&Verbosity, "verbosity", "v", 2, "1 = Print control messages only\n2 = Print control messages, module output\n3 = Print control messages, module output, and loot file output\n")
	// defaultOutputDir is defined in cli.aws
	GCPCommands.PersistentFlags().StringVar(&GCPOutputDirectory, "outdir", defaultOutputDir, "Output Directory ")
	// GCPCommands.PersistentFlags().IntVarP(&Goroutines, "max-goroutines", "g", 30, "Maximum number of concurrent goroutines")
	GCPCommands.PersistentFlags().BoolVarP(&GCPWrapTable, "wrap", "w", false, "Wrap table to fit in terminal (complicates grepping)")

	// Available commands
	GCPCommands.AddCommand(
		// Core/existing commands
		commands.GCPBucketsCommand,
		commands.GCPArtifactRegistryCommand,
		commands.GCPBigQueryCommand,
		commands.GCPSecretsCommand,
		commands.GCPIAMCommand,
		commands.GCPPermissionsCommand,
		commands.GCPInstancesCommand,
		commands.GCPWhoAmICommand,

		// New compute/serverless commands
		commands.GCPFunctionsCommand,
		commands.GCPCloudRunCommand,
		commands.GCPGKECommand,
		commands.GCPCloudSQLCommand,

		// New infrastructure commands
		commands.GCPPubSubCommand,
		commands.GCPKMSCommand,
		commands.GCPLoggingCommand,
		commands.GCPSchedulerCommand,
		commands.GCPDNSCommand,
		commands.GCPFirewallCommand,
		commands.GCPServiceAccountsCommand,
		commands.GCPAPIKeysCommand,
		commands.GCPEndpointsCommand,
		commands.GCPWorkloadIdentityCommand,
		commands.GCPOrganizationsCommand,
		commands.GCPCloudBuildCommand,
		commands.GCPMemorystoreCommand,
		commands.GCPFilestoreCommand,
		commands.GCPSpannerCommand,
		commands.GCPBigtableCommand,

		// Data processing commands
		commands.GCPDataflowCommand,
		commands.GCPComposerCommand,

		// Security/Compliance commands
		commands.GCPVPCSCCommand,
		commands.GCPAssetInventoryCommand,

		// Network/Infrastructure commands
		commands.GCPLoadBalancersCommand,
		commands.GCPVPCNetworksCommand,

		// ML/Data Science commands
		commands.GCPNotebooksCommand,
		commands.GCPDataprocCommand,

		// Zero Trust/Access commands
		commands.GCPIAPCommand,
		commands.GCPBeyondCorpCommand,
		commands.GCPAccessLevelsCommand,

		// Pentest/Exploitation commands
		commands.GCPHMACKeysCommand,
		commands.GCPPrivescCommand,
		commands.GCPOrgPoliciesCommand,
		commands.GCPBucketEnumCommand,
		commands.GCPCrossProjectCommand,
		commands.GCPCustomRolesCommand,
		commands.GCPPublicResourcesCommand,
		commands.GCPLoggingGapsCommand,
		commands.GCPSourceReposCommand,
		commands.GCPSSHOsLoginCommand,
		commands.GCPServiceAgentsCommand,
		commands.GCPDomainWideDelegationCommand,
		commands.GCPNetworkEndpointsCommand,
		commands.GCPCloudArmorCommand,
		commands.GCPCertManagerCommand,

		// All checks (last)
		GCPAllChecksCommand,
	)
}
