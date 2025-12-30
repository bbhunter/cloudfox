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

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/api/iterator"
)

// Module name constant
const GCP_SECURITYCENTER_MODULE_NAME string = "security-center"

var GCPSecurityCenterCommand = &cobra.Command{
	Use:     GCP_SECURITYCENTER_MODULE_NAME,
	Aliases: []string{"scc", "security", "defender"},
	Short:   "Enumerate Security Command Center findings and recommendations",
	Long: `Enumerate Security Command Center (SCC) findings, assets, and security recommendations.

Features:
- Lists all active SCC findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Shows vulnerable assets and their security issues
- Identifies security posture gaps
- Provides remediation recommendations
- Generates exploitation commands for penetration testing

Requires Security Command Center API to be enabled and appropriate IAM permissions:
- roles/securitycenter.findingsViewer or roles/securitycenter.admin`,
	Run: runGCPSecurityCenterCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type SCCFinding struct {
	Name              string
	Category          string
	Severity          string
	State             string
	ResourceName      string
	ResourceType      string
	ProjectID         string
	Description       string
	Recommendation    string
	CreateTime        string
	SourceDisplayName string
	ExternalURI       string
	RiskScore         int
}

type SCCAsset struct {
	Name         string
	ResourceName string
	ResourceType string
	ProjectID    string
	FindingCount int
	Severity     string // Highest severity finding
}

type SCCSource struct {
	Name        string
	DisplayName string
	Description string
}

// ------------------------------
// Module Struct
// ------------------------------
type SecurityCenterModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Findings    []SCCFinding
	Assets      map[string]*SCCAsset // keyed by resource name
	Sources     []SCCSource
	LootMap     map[string]*internal.LootFile
	mu          sync.Mutex
	OrgID       string
	UseOrgLevel bool
}

// ------------------------------
// Output Struct
// ------------------------------
type SecurityCenterOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o SecurityCenterOutput) TableFiles() []internal.TableFile { return o.Table }
func (o SecurityCenterOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPSecurityCenterCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_SECURITYCENTER_MODULE_NAME)
	if err != nil {
		return
	}

	// Create module instance
	module := &SecurityCenterModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Findings:      []SCCFinding{},
		Assets:        make(map[string]*SCCAsset),
		Sources:       []SCCSource{},
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
func (m *SecurityCenterModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Enumerating Security Command Center findings...", GCP_SECURITYCENTER_MODULE_NAME)

	// Create Security Command Center client
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Failed to create Security Command Center client: %v", err), GCP_SECURITYCENTER_MODULE_NAME)
		logger.InfoM("Ensure the Security Command Center API is enabled and you have appropriate permissions", GCP_SECURITYCENTER_MODULE_NAME)
		return
	}
	defer client.Close()

	// Process each project
	for _, projectID := range m.ProjectIDs {
		m.processProject(ctx, projectID, client, logger)
	}

	// Check results
	if len(m.Findings) == 0 {
		logger.InfoM("No Security Command Center findings found", GCP_SECURITYCENTER_MODULE_NAME)
		logger.InfoM("This could mean: (1) SCC is not enabled, (2) No findings exist, or (3) Insufficient permissions", GCP_SECURITYCENTER_MODULE_NAME)
		return
	}

	// Count findings by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	for _, f := range m.Findings {
		switch f.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d SCC finding(s): %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW",
		len(m.Findings), criticalCount, highCount, mediumCount, lowCount), GCP_SECURITYCENTER_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *SecurityCenterModule) processProject(ctx context.Context, projectID string, client *securitycenter.Client, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating SCC findings for project: %s", projectID), GCP_SECURITYCENTER_MODULE_NAME)
	}

	// List active findings for this project
	parent := fmt.Sprintf("projects/%s/sources/-", projectID)

	// Create request to list findings
	req := &securitycenterpb.ListFindingsRequest{
		Parent: parent,
		Filter: `state="ACTIVE"`, // Only active findings
	}

	it := client.ListFindings(ctx, req)

	findingsCount := 0
	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
				logger.ErrorM(fmt.Sprintf("Error listing findings for project %s: %v", projectID, err), GCP_SECURITYCENTER_MODULE_NAME)
			}
			break
		}

		finding := result.Finding
		if finding == nil {
			continue
		}

		// Parse the finding
		sccFinding := m.parseFinding(finding, projectID)

		m.mu.Lock()
		m.Findings = append(m.Findings, sccFinding)

		// Track affected assets
		if sccFinding.ResourceName != "" {
			if asset, exists := m.Assets[sccFinding.ResourceName]; exists {
				asset.FindingCount++
				// Update to highest severity
				if severityRank(sccFinding.Severity) > severityRank(asset.Severity) {
					asset.Severity = sccFinding.Severity
				}
			} else {
				m.Assets[sccFinding.ResourceName] = &SCCAsset{
					Name:         sccFinding.ResourceName,
					ResourceName: sccFinding.ResourceName,
					ResourceType: sccFinding.ResourceType,
					ProjectID:    projectID,
					FindingCount: 1,
					Severity:     sccFinding.Severity,
				}
			}
		}

		// Add to loot files
		m.addFindingToLoot(sccFinding, projectID)
		m.mu.Unlock()

		findingsCount++
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d finding(s) in project %s", findingsCount, projectID), GCP_SECURITYCENTER_MODULE_NAME)
	}
}

// parseFinding converts an SCC finding to our internal structure
func (m *SecurityCenterModule) parseFinding(finding *securitycenterpb.Finding, projectID string) SCCFinding {
	sccFinding := SCCFinding{
		Name:         finding.Name,
		Category:     finding.Category,
		State:        finding.State.String(),
		ProjectID:    projectID,
		ResourceName: finding.ResourceName,
		Description:  finding.Description,
		ExternalURI:  finding.ExternalUri,
	}

	// Parse severity
	if finding.Severity != securitycenterpb.Finding_SEVERITY_UNSPECIFIED {
		sccFinding.Severity = finding.Severity.String()
	} else {
		sccFinding.Severity = "UNSPECIFIED"
	}

	// Parse resource type from resource name
	if finding.ResourceName != "" {
		parts := strings.Split(finding.ResourceName, "/")
		if len(parts) >= 2 {
			sccFinding.ResourceType = parts[len(parts)-2]
		}
	}

	// Get create time
	if finding.CreateTime != nil {
		sccFinding.CreateTime = finding.CreateTime.AsTime().Format("2006-01-02 15:04:05")
	}

	// Parse source display name from finding name
	if finding.Name != "" {
		// Format: organizations/{org}/sources/{source}/findings/{finding}
		// or projects/{project}/sources/{source}/findings/{finding}
		parts := strings.Split(finding.Name, "/")
		for i, part := range parts {
			if part == "sources" && i+1 < len(parts) {
				sccFinding.SourceDisplayName = parts[i+1]
				break
			}
		}
	}

	// Calculate risk score based on severity and category
	sccFinding.RiskScore = calculateRiskScore(sccFinding.Severity, sccFinding.Category)

	// Generate recommendation based on category
	sccFinding.Recommendation = generateRecommendation(sccFinding.Category, sccFinding.ResourceType)

	return sccFinding
}

// severityRank returns a numeric rank for severity comparison
func severityRank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// calculateRiskScore calculates a risk score based on severity and category
func calculateRiskScore(severity, category string) int {
	baseScore := 0
	switch severity {
	case "CRITICAL":
		baseScore = 90
	case "HIGH":
		baseScore = 70
	case "MEDIUM":
		baseScore = 50
	case "LOW":
		baseScore = 30
	default:
		baseScore = 10
	}

	// Adjust based on category
	categoryLower := strings.ToLower(category)
	if strings.Contains(categoryLower, "public") {
		baseScore += 10
	}
	if strings.Contains(categoryLower, "credential") || strings.Contains(categoryLower, "secret") {
		baseScore += 10
	}
	if strings.Contains(categoryLower, "firewall") || strings.Contains(categoryLower, "open") {
		baseScore += 5
	}

	if baseScore > 100 {
		baseScore = 100
	}
	return baseScore
}

// generateRecommendation generates a remediation recommendation based on category
func generateRecommendation(category, resourceType string) string {
	categoryLower := strings.ToLower(category)

	switch {
	case strings.Contains(categoryLower, "public"):
		return "Restrict public access and implement proper network controls"
	case strings.Contains(categoryLower, "firewall"):
		return "Review and restrict firewall rules to limit exposure"
	case strings.Contains(categoryLower, "encryption"):
		return "Enable encryption at rest and in transit"
	case strings.Contains(categoryLower, "iam"):
		return "Review IAM permissions and apply least privilege principle"
	case strings.Contains(categoryLower, "logging"):
		return "Enable audit logging and monitoring"
	case strings.Contains(categoryLower, "mfa") || strings.Contains(categoryLower, "2sv"):
		return "Enable multi-factor authentication"
	case strings.Contains(categoryLower, "ssl") || strings.Contains(categoryLower, "tls"):
		return "Upgrade to TLS 1.2+ and disable weak ciphers"
	case strings.Contains(categoryLower, "password"):
		return "Implement strong password policies"
	case strings.Contains(categoryLower, "key"):
		return "Rotate keys and implement key management best practices"
	case strings.Contains(categoryLower, "backup"):
		return "Implement backup and disaster recovery procedures"
	default:
		return "Review finding and implement appropriate security controls"
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *SecurityCenterModule) initializeLootFiles() {
	m.LootMap["scc-critical-findings"] = &internal.LootFile{
		Name:     "scc-critical-findings",
		Contents: "# Security Command Center - Critical Findings\n# Generated by CloudFox\n# These require immediate attention!\n\n",
	}
	m.LootMap["scc-high-severity"] = &internal.LootFile{
		Name:     "scc-high-severity",
		Contents: "# Security Command Center - High Severity Findings\n# Generated by CloudFox\n\n",
	}
	m.LootMap["scc-remediation-commands"] = &internal.LootFile{
		Name:     "scc-remediation-commands",
		Contents: "# Security Command Center - Remediation Commands\n# Generated by CloudFox\n# These commands can help address security findings\n\n",
	}
	m.LootMap["scc-affected-assets"] = &internal.LootFile{
		Name:     "scc-affected-assets",
		Contents: "# Security Command Center - Affected Assets\n# Generated by CloudFox\n\n",
	}
	m.LootMap["scc-exploitation-commands"] = &internal.LootFile{
		Name:     "scc-exploitation-commands",
		Contents: "# Security Command Center - Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
	}
}

func (m *SecurityCenterModule) addFindingToLoot(finding SCCFinding, projectID string) {
	// Critical findings
	if finding.Severity == "CRITICAL" {
		m.LootMap["scc-critical-findings"].Contents += fmt.Sprintf(
			"## Finding: %s\n"+
				"Category: %s\n"+
				"Resource: %s\n"+
				"Project: %s\n"+
				"Risk Score: %d\n"+
				"Description: %s\n"+
				"Recommendation: %s\n\n",
			finding.Name,
			finding.Category,
			finding.ResourceName,
			projectID,
			finding.RiskScore,
			finding.Description,
			finding.Recommendation,
		)
	}

	// High severity findings
	if finding.Severity == "HIGH" {
		m.LootMap["scc-high-severity"].Contents += fmt.Sprintf(
			"## Finding: %s\n"+
				"Category: %s\n"+
				"Resource: %s\n"+
				"Project: %s\n"+
				"Recommendation: %s\n\n",
			finding.Name,
			finding.Category,
			finding.ResourceName,
			projectID,
			finding.Recommendation,
		)
	}

	// Remediation commands based on category
	categoryLower := strings.ToLower(finding.Category)
	if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" {
		m.LootMap["scc-remediation-commands"].Contents += fmt.Sprintf(
			"# %s (%s)\n"+
				"# Resource: %s\n",
			finding.Category,
			finding.Severity,
			finding.ResourceName,
		)

		// Add specific remediation commands based on category
		switch {
		case strings.Contains(categoryLower, "public_bucket"):
			m.LootMap["scc-remediation-commands"].Contents += fmt.Sprintf(
				"gsutil iam ch -d allUsers:objectViewer %s\n"+
					"gsutil iam ch -d allAuthenticatedUsers:objectViewer %s\n\n",
				finding.ResourceName,
				finding.ResourceName,
			)
		case strings.Contains(categoryLower, "firewall"):
			m.LootMap["scc-remediation-commands"].Contents += fmt.Sprintf(
				"# Review firewall rule:\n"+
					"gcloud compute firewall-rules describe %s --project=%s\n"+
					"# Delete if unnecessary:\n"+
					"# gcloud compute firewall-rules delete %s --project=%s\n\n",
				finding.ResourceName,
				projectID,
				finding.ResourceName,
				projectID,
			)
		case strings.Contains(categoryLower, "service_account_key"):
			m.LootMap["scc-remediation-commands"].Contents += fmt.Sprintf(
				"# List and delete old keys:\n"+
					"gcloud iam service-accounts keys list --iam-account=%s\n\n",
				finding.ResourceName,
			)
		default:
			m.LootMap["scc-remediation-commands"].Contents += fmt.Sprintf(
				"# See SCC console for detailed remediation steps:\n"+
					"# %s\n\n",
				finding.ExternalURI,
			)
		}

		// Add exploitation commands for pentest
		switch {
		case strings.Contains(categoryLower, "public"):
			m.LootMap["scc-exploitation-commands"].Contents += fmt.Sprintf(
				"# Publicly accessible resource: %s\n"+
					"# Category: %s\n"+
					"# Attempt to access without authentication\n\n",
				finding.ResourceName,
				finding.Category,
			)
		case strings.Contains(categoryLower, "firewall"):
			m.LootMap["scc-exploitation-commands"].Contents += fmt.Sprintf(
				"# Open firewall rule detected: %s\n"+
					"# Category: %s\n"+
					"# Scan for accessible services:\n"+
					"# nmap -Pn -p- <target_ip>\n\n",
				finding.ResourceName,
				finding.Category,
			)
		}
	}

	// Track affected assets
	if finding.ResourceName != "" {
		m.LootMap["scc-affected-assets"].Contents += fmt.Sprintf(
			"%s (%s) - %s\n",
			finding.ResourceName,
			finding.Severity,
			finding.Category,
		)
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *SecurityCenterModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Sort findings by severity
	sort.Slice(m.Findings, func(i, j int) bool {
		return severityRank(m.Findings[i].Severity) > severityRank(m.Findings[j].Severity)
	})

	// Main findings table
	findingsHeader := []string{
		"Severity",
		"Category",
		"Resource",
		"Project Name",
		"Project ID",
		"Risk Score",
		"Created",
	}

	var findingsBody [][]string
	for _, f := range m.Findings {
		findingsBody = append(findingsBody, []string{
			f.Severity,
			f.Category,
			sccTruncateString(f.ResourceName, 60),
			m.GetProjectName(f.ProjectID),
			f.ProjectID,
			fmt.Sprintf("%d", f.RiskScore),
			f.CreateTime,
		})
	}

	// Critical/High findings table
	criticalHeader := []string{
		"Category",
		"Resource",
		"Project Name",
		"Project ID",
		"Description",
		"Recommendation",
	}

	var criticalBody [][]string
	for _, f := range m.Findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			criticalBody = append(criticalBody, []string{
				f.Category,
				sccTruncateString(f.ResourceName, 50),
				m.GetProjectName(f.ProjectID),
				f.ProjectID,
				sccTruncateString(f.Description, 60),
				sccTruncateString(f.Recommendation, 50),
			})
		}
	}

	// Assets table
	assetsHeader := []string{
		"Resource",
		"Type",
		"Project Name",
		"Project ID",
		"Finding Count",
		"Max Severity",
	}

	var assetsBody [][]string
	for _, asset := range m.Assets {
		assetsBody = append(assetsBody, []string{
			sccTruncateString(asset.ResourceName, 60),
			asset.ResourceType,
			m.GetProjectName(asset.ProjectID),
			asset.ProjectID,
			fmt.Sprintf("%d", asset.FindingCount),
			asset.Severity,
		})
	}

	// Sort assets by finding count (index 4 now, not 3, since we added Project Name column)
	sort.Slice(assetsBody, func(i, j int) bool {
		return assetsBody[i][4] > assetsBody[j][4]
	})

	// Summary by category
	categoryCount := make(map[string]int)
	for _, f := range m.Findings {
		categoryCount[f.Category]++
	}

	summaryHeader := []string{
		"Category",
		"Finding Count",
	}

	var summaryBody [][]string
	for cat, count := range categoryCount {
		summaryBody = append(summaryBody, []string{
			cat,
			fmt.Sprintf("%d", count),
		})
	}

	// Sort summary by count
	sort.Slice(summaryBody, func(i, j int) bool {
		return summaryBody[i][1] > summaryBody[j][1]
	})

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	tables := []internal.TableFile{
		{
			Name:   "scc-findings",
			Header: findingsHeader,
			Body:   findingsBody,
		},
	}

	// Add critical/high findings table if any
	if len(criticalBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "scc-critical-high",
			Header: criticalHeader,
			Body:   criticalBody,
		})
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d CRITICAL/HIGH severity finding(s)", len(criticalBody)), GCP_SECURITYCENTER_MODULE_NAME)
	}

	// Add assets table if any
	if len(assetsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "scc-assets",
			Header: assetsHeader,
			Body:   assetsBody,
		})
	}

	// Add summary table
	if len(summaryBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "scc-summary",
			Header: summaryHeader,
			Body:   summaryBody,
		})
	}

	output := SecurityCenterOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scopeNames using GetProjectName
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_SECURITYCENTER_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// sccTruncateString truncates a string to max length with ellipsis
func sccTruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
