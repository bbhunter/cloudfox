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
	Hidden:  true,
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
	CreateTime        string
	SourceDisplayName string
	ExternalURI       string
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
		parsedErr := gcpinternal.ParseGCPError(err, "securitycenter.googleapis.com")
		gcpinternal.HandleGCPError(parsedErr, logger, GCP_SECURITYCENTER_MODULE_NAME, "Failed to create client")
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
			m.CommandCounter.Error++
			parsedErr := gcpinternal.ParseGCPError(err, "securitycenter.googleapis.com")
			gcpinternal.HandleGCPError(parsedErr, logger, GCP_SECURITYCENTER_MODULE_NAME,
				fmt.Sprintf("Project %s", projectID))
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

// ------------------------------
// Loot File Management
// ------------------------------
func (m *SecurityCenterModule) initializeLootFiles() {
	m.LootMap["security-center-commands"] = &internal.LootFile{
		Name: "security-center-commands",
		Contents: "# Security Command Center Commands\n" +
			"# Generated by CloudFox\n" +
			"# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *SecurityCenterModule) addFindingToLoot(finding SCCFinding, projectID string) {
	// Only add CRITICAL and HIGH severity findings to loot
	if finding.Severity != "CRITICAL" && finding.Severity != "HIGH" {
		return
	}

	m.LootMap["security-center-commands"].Contents += fmt.Sprintf(
		"## Finding: %s (%s)\n"+
			"# Category: %s\n"+
			"# Resource: %s\n"+
			"# Project: %s\n",
		finding.Name, finding.Severity,
		finding.Category,
		finding.ResourceName,
		projectID,
	)

	if finding.Description != "" {
		m.LootMap["security-center-commands"].Contents += fmt.Sprintf("# Description: %s\n", finding.Description)
	}

	if finding.ExternalURI != "" {
		m.LootMap["security-center-commands"].Contents += fmt.Sprintf("# Console URL: %s\n", finding.ExternalURI)
	}

	// Add gcloud commands
	m.LootMap["security-center-commands"].Contents += fmt.Sprintf(
		"\n# View finding details:\n"+
			"gcloud scc findings list --source=\"-\" --project=%s --filter=\"name:\\\"%s\\\"\"\n\n",
		projectID, finding.Name,
	)

	// Add specific commands based on category
	categoryLower := strings.ToLower(finding.Category)
	switch {
	case strings.Contains(categoryLower, "public_bucket"):
		m.LootMap["security-center-commands"].Contents += fmt.Sprintf(
			"# Remove public access:\n"+
				"gsutil iam ch -d allUsers:objectViewer %s\n"+
				"gsutil iam ch -d allAuthenticatedUsers:objectViewer %s\n\n",
			finding.ResourceName,
			finding.ResourceName,
		)
	case strings.Contains(categoryLower, "firewall"):
		m.LootMap["security-center-commands"].Contents += fmt.Sprintf(
			"# Review firewall rule:\n"+
				"gcloud compute firewall-rules describe %s --project=%s\n\n",
			finding.ResourceName,
			projectID,
		)
	case strings.Contains(categoryLower, "service_account_key"):
		m.LootMap["security-center-commands"].Contents += fmt.Sprintf(
			"# List service account keys:\n"+
				"gcloud iam service-accounts keys list --iam-account=%s\n\n",
			finding.ResourceName,
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
		"Project Name",
		"Project ID",
		"Severity",
		"Category",
		"Resource",
		"Resource Type",
		"State",
		"Created",
		"External URI",
	}

	var findingsBody [][]string
	for _, f := range m.Findings {
		resourceType := f.ResourceType
		if resourceType == "" {
			resourceType = "-"
		}
		externalURI := f.ExternalURI
		if externalURI == "" {
			externalURI = "-"
		}

		findingsBody = append(findingsBody, []string{
			m.GetProjectName(f.ProjectID),
			f.ProjectID,
			f.Severity,
			f.Category,
			f.ResourceName,
			resourceType,
			f.State,
			f.CreateTime,
			externalURI,
		})
	}

	// Assets table
	assetsHeader := []string{
		"Project Name",
		"Project ID",
		"Resource",
		"Resource Type",
		"Finding Count",
		"Max Severity",
	}

	var assetsBody [][]string
	for _, asset := range m.Assets {
		resourceType := asset.ResourceType
		if resourceType == "" {
			resourceType = "-"
		}

		assetsBody = append(assetsBody, []string{
			m.GetProjectName(asset.ProjectID),
			asset.ProjectID,
			asset.ResourceName,
			resourceType,
			fmt.Sprintf("%d", asset.FindingCount),
			asset.Severity,
		})
	}

	// Sort assets by finding count
	sort.Slice(assetsBody, func(i, j int) bool {
		return assetsBody[i][4] > assetsBody[j][4]
	})

	// Collect loot files - only include if they have content beyond the header
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# WARNING: Only use with proper authorization\n\n") {
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

	// Add assets table if any
	if len(assetsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "scc-assets",
			Header: assetsHeader,
			Body:   assetsBody,
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
