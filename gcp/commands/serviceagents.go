package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	serviceagentsservice "github.com/BishopFox/cloudfox/gcp/services/serviceAgentsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPServiceAgentsCommand = &cobra.Command{
	Use:     globals.GCP_SERVICEAGENTS_MODULE_NAME,
	Aliases: []string{"agents", "service-accounts-google", "gcp-agents"},
	Short:   "Enumerate Google-managed service agents",
	Long: `Enumerate Google-managed service agents and their permissions.

Service agents are Google-managed service accounts that operate on behalf
of GCP services. Understanding them helps identify:
- Hidden access paths to resources
- Cross-project service agent access
- Overprivileged service agents
- Potential lateral movement via service agent impersonation

Common Service Agents:
- Cloud Build Service Account (@cloudbuild.gserviceaccount.com)
- Compute Engine Service Agent (@compute-system.iam.gserviceaccount.com)
- GKE Service Agent (@container-engine-robot.iam.gserviceaccount.com)
- Cloud Run/Functions (@serverless-robot-prod.iam.gserviceaccount.com)
- Cloud SQL Service Agent (@gcp-sa-cloud-sql.iam.gserviceaccount.com)

Security Considerations:
- Service agents often have broad permissions
- Cross-project agents indicate shared service access
- Cloud Build SA is a common privilege escalation vector
- Default compute SA often has Editor role`,
	Run: runGCPServiceAgentsCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type ServiceAgentsModule struct {
	gcpinternal.BaseGCPModule

	Agents  []serviceagentsservice.ServiceAgentInfo
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type ServiceAgentsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ServiceAgentsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ServiceAgentsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPServiceAgentsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_SERVICEAGENTS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &ServiceAgentsModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Agents:        []serviceagentsservice.ServiceAgentInfo{},
		LootMap:       make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ServiceAgentsModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_SERVICEAGENTS_MODULE_NAME, m.processProject)

	if len(m.Agents) == 0 {
		logger.InfoM("No service agents found", globals.GCP_SERVICEAGENTS_MODULE_NAME)
		return
	}

	// Count cross-project and high-risk
	crossProjectCount := 0
	highRiskCount := 0
	for _, agent := range m.Agents {
		if agent.IsCrossProject {
			crossProjectCount++
		}
		if agent.RiskLevel == "HIGH" {
			highRiskCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d service agent(s)", len(m.Agents)), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	if crossProjectCount > 0 {
		logger.InfoM(fmt.Sprintf("[INFO] %d cross-project service agents detected", crossProjectCount), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	}
	if highRiskCount > 0 {
		logger.InfoM(fmt.Sprintf("[PENTEST] %d high-risk service agents with elevated permissions!", highRiskCount), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *ServiceAgentsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating service agents in project: %s", projectID), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	}

	svc := serviceagentsservice.New()
	agents, err := svc.GetServiceAgents(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting service agents: %v", err), globals.GCP_SERVICEAGENTS_MODULE_NAME)
		}
		return
	}

	m.mu.Lock()
	m.Agents = append(m.Agents, agents...)

	for _, agent := range agents {
		m.addAgentToLoot(agent)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d service agent(s) in project %s", len(agents), projectID), globals.GCP_SERVICEAGENTS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ServiceAgentsModule) initializeLootFiles() {
	m.LootMap["service-agents-all"] = &internal.LootFile{
		Name:     "service-agents-all",
		Contents: "# Google-Managed Service Agents\n# Generated by CloudFox\n\n",
	}
	m.LootMap["service-agents-highrisk"] = &internal.LootFile{
		Name:     "service-agents-highrisk",
		Contents: "# High-Risk Service Agents\n# Generated by CloudFox\n# These service agents have elevated permissions\n\n",
	}
	m.LootMap["service-agents-crossproject"] = &internal.LootFile{
		Name:     "service-agents-crossproject",
		Contents: "# Cross-Project Service Agents\n# Generated by CloudFox\n# Service agents from other projects with access here\n\n",
	}
}

func (m *ServiceAgentsModule) addAgentToLoot(agent serviceagentsservice.ServiceAgentInfo) {
	// All agents
	m.LootMap["service-agents-all"].Contents += fmt.Sprintf(
		"## [%s] %s\n"+
			"## Email: %s\n"+
			"## Service: %s\n"+
			"## Description: %s\n"+
			"## Roles:\n",
		agent.RiskLevel, agent.ServiceName,
		agent.Email, agent.ServiceName, agent.Description,
	)
	for _, role := range agent.Roles {
		m.LootMap["service-agents-all"].Contents += fmt.Sprintf("##   - %s\n", role)
	}
	m.LootMap["service-agents-all"].Contents += "\n"

	// High-risk agents
	if agent.RiskLevel == "HIGH" || agent.RiskLevel == "MEDIUM" {
		m.LootMap["service-agents-highrisk"].Contents += fmt.Sprintf(
			"## [%s] %s\n"+
				"## Email: %s\n"+
				"## Project: %s\n"+
				"## Roles: %s\n"+
				"## Risks:\n",
			agent.RiskLevel, agent.ServiceName,
			agent.Email, agent.ProjectID,
			strings.Join(agent.Roles, ", "),
		)
		for _, reason := range agent.RiskReasons {
			m.LootMap["service-agents-highrisk"].Contents += fmt.Sprintf("##   - %s\n", reason)
		}
		m.LootMap["service-agents-highrisk"].Contents += "\n"
	}

	// Cross-project agents
	if agent.IsCrossProject {
		m.LootMap["service-agents-crossproject"].Contents += fmt.Sprintf(
			"## [CROSS-PROJECT] %s\n"+
				"## Email: %s\n"+
				"## Has access to project: %s\n"+
				"## Roles: %s\n"+
				"## \n"+
				"## This service agent is from a DIFFERENT project but has access here.\n"+
				"## This could indicate shared services or potential lateral movement path.\n\n",
			agent.ServiceName, agent.Email, agent.ProjectID,
			strings.Join(agent.Roles, ", "),
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ServiceAgentsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main agents table
	header := []string{
		"Risk",
		"Service",
		"Email",
		"Roles",
		"Cross-Project",
		"Project",
	}

	var body [][]string
	for _, agent := range m.Agents {
		rolesDisplay := strings.Join(agent.Roles, ", ")
		if len(rolesDisplay) > 50 {
			rolesDisplay = rolesDisplay[:50] + "..."
		}

		crossProject := "No"
		if agent.IsCrossProject {
			crossProject = "YES"
		}

		// Shorten email for display
		emailDisplay := agent.Email
		if len(emailDisplay) > 40 {
			parts := strings.Split(emailDisplay, "@")
			if len(parts) == 2 {
				emailDisplay = parts[0][:10] + "...@" + parts[1]
			}
		}

		body = append(body, []string{
			agent.RiskLevel,
			agent.ServiceName,
			emailDisplay,
			rolesDisplay,
			crossProject,
			agent.ProjectID,
		})
	}

	// By service summary
	serviceCounts := make(map[string]int)
	for _, agent := range m.Agents {
		serviceCounts[agent.ServiceName]++
	}

	summaryHeader := []string{
		"Service",
		"Count",
	}

	var summaryBody [][]string
	for service, count := range serviceCounts {
		summaryBody = append(summaryBody, []string{
			service,
			fmt.Sprintf("%d", count),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	tables := []internal.TableFile{
		{
			Name:   "service-agents",
			Header: header,
			Body:   body,
		},
	}

	if len(summaryBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "service-agents-summary",
			Header: summaryHeader,
			Body:   summaryBody,
		})
	}

	output := ServiceAgentsOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		m.ProjectIDs,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_SERVICEAGENTS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
