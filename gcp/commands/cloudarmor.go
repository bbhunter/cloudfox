package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	cloudarmorservice "github.com/BishopFox/cloudfox/gcp/services/cloudArmorService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCloudArmorCommand = &cobra.Command{
	Use:     globals.GCP_CLOUDARMOR_MODULE_NAME,
	Aliases: []string{"armor", "waf", "security-policies"},
	Short:   "Enumerate Cloud Armor security policies and find weaknesses",
	Long: `Enumerate Cloud Armor security policies and identify misconfigurations.

Cloud Armor provides DDoS protection and WAF (Web Application Firewall) capabilities
for Google Cloud load balancers.

Security Relevance:
- Misconfigured policies may not actually block attacks
- Preview-only rules don't block, just log
- Missing OWASP rules leave apps vulnerable to common attacks
- Unprotected load balancers have no WAF protection

What this module finds:
- All Cloud Armor security policies
- Policy weaknesses and misconfigurations
- Rules in preview mode (not blocking)
- Load balancers without Cloud Armor protection
- Missing adaptive protection (DDoS)`,
	Run: runGCPCloudArmorCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CloudArmorModule struct {
	gcpinternal.BaseGCPModule

	Policies              []cloudarmorservice.SecurityPolicy
	UnprotectedLBs        map[string][]string // projectID -> LB names
	LootMap               map[string]*internal.LootFile
	mu                    sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CloudArmorOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CloudArmorOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CloudArmorOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCloudArmorCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CLOUDARMOR_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CloudArmorModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		Policies:       []cloudarmorservice.SecurityPolicy{},
		UnprotectedLBs: make(map[string][]string),
		LootMap:        make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CloudArmorModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CLOUDARMOR_MODULE_NAME, m.processProject)

	// Count unprotected LBs
	totalUnprotected := 0
	for _, lbs := range m.UnprotectedLBs {
		totalUnprotected += len(lbs)
	}

	if len(m.Policies) == 0 && totalUnprotected == 0 {
		logger.InfoM("No Cloud Armor policies found", globals.GCP_CLOUDARMOR_MODULE_NAME)
		return
	}

	// Count policies with weaknesses
	weakPolicies := 0
	for _, policy := range m.Policies {
		if len(policy.Weaknesses) > 0 {
			weakPolicies++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d security policy(ies), %d with weaknesses, %d unprotected LB(s)",
		len(m.Policies), weakPolicies, totalUnprotected), globals.GCP_CLOUDARMOR_MODULE_NAME)

	if totalUnprotected > 0 {
		logger.InfoM(fmt.Sprintf("[MEDIUM] %d load balancer(s) have no Cloud Armor protection", totalUnprotected), globals.GCP_CLOUDARMOR_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CloudArmorModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking Cloud Armor in project: %s", projectID), globals.GCP_CLOUDARMOR_MODULE_NAME)
	}

	svc := cloudarmorservice.New()

	// Get security policies
	policies, err := svc.GetSecurityPolicies(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDARMOR_MODULE_NAME,
			fmt.Sprintf("Could not enumerate Cloud Armor security policies in project %s", projectID))
	}

	// Get unprotected LBs
	unprotectedLBs, err := svc.GetUnprotectedLoadBalancers(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CLOUDARMOR_MODULE_NAME,
			fmt.Sprintf("Could not enumerate unprotected load balancers in project %s", projectID))
	}

	m.mu.Lock()
	m.Policies = append(m.Policies, policies...)
	if len(unprotectedLBs) > 0 {
		m.UnprotectedLBs[projectID] = unprotectedLBs
	}

	for _, policy := range policies {
		m.addPolicyToLoot(policy)
	}
	for _, lb := range unprotectedLBs {
		m.addUnprotectedLBToLoot(projectID, lb)
	}
	m.mu.Unlock()
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CloudArmorModule) initializeLootFiles() {
	m.LootMap["cloudarmor-details"] = &internal.LootFile{
		Name:     "cloudarmor-details",
		Contents: "# Cloud Armor Details\n# Generated by CloudFox\n\n",
	}
}

func (m *CloudArmorModule) addPolicyToLoot(policy cloudarmorservice.SecurityPolicy) {
	// Build flags for special attributes
	var flags []string
	if len(policy.Weaknesses) > 0 {
		flags = append(flags, "HAS WEAKNESSES")
	}

	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, "] [") + "]"
	}

	adaptive := "No"
	if policy.AdaptiveProtection {
		adaptive = "Yes"
	}

	resources := "None"
	if len(policy.AttachedResources) > 0 {
		resources = strings.Join(policy.AttachedResources, ", ")
	}

	m.LootMap["cloudarmor-details"].Contents += fmt.Sprintf(
		"# %s%s\n"+
			"Project: %s | Type: %s\n"+
			"Rules: %d | Adaptive Protection: %s\n"+
			"Attached Resources: %s\n",
		policy.Name, flagStr,
		policy.ProjectID, policy.Type,
		policy.RuleCount, adaptive,
		resources,
	)

	// Add weaknesses if any
	if len(policy.Weaknesses) > 0 {
		m.LootMap["cloudarmor-details"].Contents += "Weaknesses:\n"
		for _, weakness := range policy.Weaknesses {
			m.LootMap["cloudarmor-details"].Contents += fmt.Sprintf("  - %s\n", weakness)
		}
	}

	// Add rules
	if len(policy.Rules) > 0 {
		m.LootMap["cloudarmor-details"].Contents += "Rules:\n"
		for _, rule := range policy.Rules {
			preview := ""
			if rule.Preview {
				preview = " [PREVIEW]"
			}
			m.LootMap["cloudarmor-details"].Contents += fmt.Sprintf(
				"  - Priority %d: %s%s\n"+
					"    Match: %s\n",
				rule.Priority, rule.Action, preview,
				rule.Match,
			)
			if rule.RateLimitConfig != nil {
				m.LootMap["cloudarmor-details"].Contents += fmt.Sprintf(
					"    Rate Limit: %d requests per %d seconds\n",
					rule.RateLimitConfig.ThresholdCount,
					rule.RateLimitConfig.IntervalSec,
				)
			}
		}
	}

	m.LootMap["cloudarmor-details"].Contents += "\n"
}

func (m *CloudArmorModule) addUnprotectedLBToLoot(projectID, lbName string) {
	m.LootMap["cloudarmor-details"].Contents += fmt.Sprintf(
		"# %s [UNPROTECTED]\n"+
			"Project: %s\n"+
			"No Cloud Armor policy attached\n\n",
		lbName, projectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CloudArmorModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// Security policies table
	if len(m.Policies) > 0 {
		header := []string{"Project Name", "Project ID", "Name", "Type", "Rules", "Attached Resources", "Adaptive Protection"}
		var body [][]string

		for _, policy := range m.Policies {
			adaptive := "No"
			if policy.AdaptiveProtection {
				adaptive = "Yes"
			}

			resources := "-"
			if len(policy.AttachedResources) > 0 {
				resources = strings.Join(policy.AttachedResources, ", ")
			}

			body = append(body, []string{
				m.GetProjectName(policy.ProjectID),
				policy.ProjectID,
				policy.Name,
				policy.Type,
				fmt.Sprintf("%d", policy.RuleCount),
				resources,
				adaptive,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "security-policies",
			Header: header,
			Body:   body,
		})
	}

	// Unprotected backend services table
	var unprotectedList []struct {
		ProjectID string
		LBName    string
	}
	for projectID, lbs := range m.UnprotectedLBs {
		for _, lb := range lbs {
			unprotectedList = append(unprotectedList, struct {
				ProjectID string
				LBName    string
			}{projectID, lb})
		}
	}

	if len(unprotectedList) > 0 {
		header := []string{"Project Name", "Project ID", "Backend Service"}
		var body [][]string

		for _, item := range unprotectedList {
			body = append(body, []string{
				m.GetProjectName(item.ProjectID),
				item.ProjectID,
				item.LBName,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "unprotected-backend-services",
			Header: header,
			Body:   body,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	output := CloudArmorOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDARMOR_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
