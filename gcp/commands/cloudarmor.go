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
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting policies for %s: %v", projectID, err), globals.GCP_CLOUDARMOR_MODULE_NAME)
		}
	}

	// Get unprotected LBs
	unprotectedLBs, err := svc.GetUnprotectedLoadBalancers(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting unprotected LBs for %s: %v", projectID, err), globals.GCP_CLOUDARMOR_MODULE_NAME)
		}
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
	m.LootMap["security-policies"] = &internal.LootFile{
		Name:     "security-policies",
		Contents: "# Cloud Armor Security Policies\n# Generated by CloudFox\n\n",
	}
	m.LootMap["policy-weaknesses"] = &internal.LootFile{
		Name:     "policy-weaknesses",
		Contents: "# Cloud Armor Policy Weaknesses\n# Generated by CloudFox\n# These policies have misconfigurations that reduce their effectiveness\n\n",
	}
	m.LootMap["unprotected-lbs"] = &internal.LootFile{
		Name:     "unprotected-lbs",
		Contents: "# Load Balancers Without Cloud Armor Protection\n# Generated by CloudFox\n# These LBs have no WAF/DDoS protection\n\n",
	}
	m.LootMap["bypass-techniques"] = &internal.LootFile{
		Name:     "bypass-techniques",
		Contents: "# Cloud Armor Bypass Techniques\n# Generated by CloudFox\n# Based on policy analysis\n\n",
	}
}

func (m *CloudArmorModule) addPolicyToLoot(policy cloudarmorservice.SecurityPolicy) {
	// All policies
	m.LootMap["security-policies"].Contents += fmt.Sprintf(
		"## [%s] %s\n"+
			"## Project: %s | Type: %s\n"+
			"## Rules: %d | Adaptive Protection: %v\n"+
			"## Attached Resources: %s\n",
		policy.RiskLevel, policy.Name,
		policy.ProjectID, policy.Type,
		policy.RuleCount, policy.AdaptiveProtection,
		strings.Join(policy.AttachedResources, ", "),
	)
	for _, reason := range policy.RiskReasons {
		m.LootMap["security-policies"].Contents += fmt.Sprintf("##   + %s\n", reason)
	}
	for _, weakness := range policy.Weaknesses {
		m.LootMap["security-policies"].Contents += fmt.Sprintf("##   - WEAKNESS: %s\n", weakness)
	}
	m.LootMap["security-policies"].Contents += "\n"

	// Policies with weaknesses
	if len(policy.Weaknesses) > 0 {
		m.LootMap["policy-weaknesses"].Contents += fmt.Sprintf(
			"## [%s] %s (Project: %s)\n",
			policy.RiskLevel, policy.Name, policy.ProjectID,
		)
		for _, weakness := range policy.Weaknesses {
			m.LootMap["policy-weaknesses"].Contents += fmt.Sprintf("##   - %s\n", weakness)
		}
		m.LootMap["policy-weaknesses"].Contents += "\n"
	}

	// Generate bypass techniques based on weaknesses
	if len(policy.Weaknesses) > 0 || len(policy.AttachedResources) > 0 {
		m.LootMap["bypass-techniques"].Contents += fmt.Sprintf("## Policy: %s (Project: %s)\n", policy.Name, policy.ProjectID)

		// Check for missing OWASP rules
		hasOWASP := false
		for _, rule := range policy.Rules {
			if strings.Contains(strings.ToLower(rule.Match), "sqli") ||
			   strings.Contains(strings.ToLower(rule.Match), "xss") {
				hasOWASP = true
				break
			}
		}

		if !hasOWASP {
			m.LootMap["bypass-techniques"].Contents +=
				"## No OWASP rules detected - try common web attacks:\n" +
				"# SQLi: ' OR '1'='1\n" +
				"# XSS: <script>alert(1)</script>\n" +
				"# Path traversal: ../../../etc/passwd\n" +
				"# Command injection: ; cat /etc/passwd\n\n"
		}

		// Check for preview-only rules
		previewCount := 0
		for _, rule := range policy.Rules {
			if rule.Preview {
				previewCount++
			}
		}
		if previewCount > 0 {
			m.LootMap["bypass-techniques"].Contents += fmt.Sprintf(
				"## %d rules in preview mode - attacks will be logged but NOT blocked\n\n",
				previewCount,
			)
		}

		// Check for rate limiting
		hasRateLimit := false
		for _, rule := range policy.Rules {
			if rule.RateLimitConfig != nil {
				hasRateLimit = true
				m.LootMap["bypass-techniques"].Contents += fmt.Sprintf(
					"## Rate limit detected: %d requests per %d seconds\n",
					rule.RateLimitConfig.ThresholdCount,
					rule.RateLimitConfig.IntervalSec,
				)
			}
		}
		if !hasRateLimit {
			m.LootMap["bypass-techniques"].Contents +=
				"## No rate limiting - brute force attacks may succeed\n\n"
		}

		m.LootMap["bypass-techniques"].Contents += "\n"
	}
}

func (m *CloudArmorModule) addUnprotectedLBToLoot(projectID, lbName string) {
	m.LootMap["unprotected-lbs"].Contents += fmt.Sprintf(
		"## [MEDIUM] %s (Project: %s)\n"+
			"## This load balancer has no Cloud Armor security policy\n"+
			"## It is vulnerable to:\n"+
			"##   - DDoS attacks\n"+
			"##   - Web application attacks (SQLi, XSS, etc.)\n"+
			"##   - Bot attacks\n"+
			"##\n"+
			"## To add protection:\n"+
			"gcloud compute backend-services update %s \\\n"+
			"  --project=%s \\\n"+
			"  --security-policy=YOUR_POLICY_NAME\n\n",
		lbName, projectID,
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
		header := []string{"Risk", "Policy", "Type", "Rules", "Adaptive", "Resources", "Weaknesses", "Project"}
		var body [][]string

		for _, policy := range m.Policies {
			adaptive := "No"
			if policy.AdaptiveProtection {
				adaptive = "Yes"
			}

			resources := "-"
			if len(policy.AttachedResources) > 0 {
				resources = fmt.Sprintf("%d", len(policy.AttachedResources))
			}

			weaknessCount := "-"
			if len(policy.Weaknesses) > 0 {
				weaknessCount = fmt.Sprintf("%d", len(policy.Weaknesses))
			}

			body = append(body, []string{
				policy.RiskLevel,
				policy.Name,
				policy.Type,
				fmt.Sprintf("%d", policy.RuleCount),
				adaptive,
				resources,
				weaknessCount,
				policy.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "security-policies",
			Header: header,
			Body:   body,
		})
	}

	// Unprotected LBs table
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
		header := []string{"Risk", "Load Balancer", "Project", "Issue"}
		var body [][]string

		for _, item := range unprotectedList {
			body = append(body, []string{
				"MEDIUM",
				item.LBName,
				item.ProjectID,
				"No Cloud Armor policy attached",
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "unprotected-load-balancers",
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CLOUDARMOR_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
