package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	FunctionsService "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPFunctionsCommand = &cobra.Command{
	Use:     globals.GCP_FUNCTIONS_MODULE_NAME,
	Aliases: []string{"function", "gcf", "cloud-functions"},
	Short:   "Enumerate GCP Cloud Functions with security analysis",
	Long: `Enumerate GCP Cloud Functions across projects with security-relevant details.

Features:
- Lists all Cloud Functions (Gen 2) accessible to the authenticated user
- Shows security configuration (ingress settings, VPC connector, service account)
- Identifies publicly invokable functions (allUsers/allAuthenticatedUsers)
- Shows runtime, trigger type, and trigger configuration
- Counts environment variables and secret references
- Generates gcloud commands for further enumeration and exploitation

Security Columns:
- Ingress: ALL_TRAFFIC (public), INTERNAL_ONLY, or INTERNAL_AND_GCLB
- Public: Whether allUsers or allAuthenticatedUsers can invoke the function
- ServiceAccount: The identity the function runs as (privilege level)
- VPCConnector: Network connectivity to VPC resources
- Secrets: Count of secret environment variables and volumes

Attack Surface:
- Public HTTP functions may be directly exploitable
- Functions with default service account may have excessive permissions
- Functions with VPC connectors can access internal resources
- Event triggers reveal integration points (Pub/Sub, Storage, etc.)`,
	Run: runGCPFunctionsCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type FunctionsModule struct {
	gcpinternal.BaseGCPModule

	Functions        []FunctionsService.FunctionInfo
	SecurityAnalysis []FunctionsService.FunctionSecurityAnalysis
	LootMap          map[string]*internal.LootFile
	mu               sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type FunctionsOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o FunctionsOutput) TableFiles() []internal.TableFile { return o.Table }
func (o FunctionsOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPFunctionsCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_FUNCTIONS_MODULE_NAME)
	if err != nil {
		return
	}

	module := &FunctionsModule{
		BaseGCPModule:    gcpinternal.NewBaseGCPModule(cmdCtx),
		Functions:        []FunctionsService.FunctionInfo{},
		SecurityAnalysis: []FunctionsService.FunctionSecurityAnalysis{},
		LootMap:          make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *FunctionsModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_FUNCTIONS_MODULE_NAME, m.processProject)

	if len(m.Functions) == 0 {
		logger.InfoM("No Cloud Functions found", globals.GCP_FUNCTIONS_MODULE_NAME)
		return
	}

	// Count public functions
	publicCount := 0
	for _, fn := range m.Functions {
		if fn.IsPublic {
			publicCount++
		}
	}

	if publicCount > 0 {
		logger.SuccessM(fmt.Sprintf("Found %d function(s), %d PUBLIC", len(m.Functions), publicCount), globals.GCP_FUNCTIONS_MODULE_NAME)
	} else {
		logger.SuccessM(fmt.Sprintf("Found %d function(s)", len(m.Functions)), globals.GCP_FUNCTIONS_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *FunctionsModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Cloud Functions in project: %s", projectID), globals.GCP_FUNCTIONS_MODULE_NAME)
	}

	fs := FunctionsService.New()
	functions, err := fs.Functions(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating functions in project %s: %v", projectID, err), globals.GCP_FUNCTIONS_MODULE_NAME)
		}
		return
	}

	m.mu.Lock()
	m.Functions = append(m.Functions, functions...)

	for _, fn := range functions {
		m.addFunctionToLoot(fn)
		// Perform security analysis
		analysis := fs.AnalyzeFunctionSecurity(fn)
		m.SecurityAnalysis = append(m.SecurityAnalysis, analysis)
		m.addSecurityAnalysisToLoot(analysis, fn)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d function(s) in project %s", len(functions), projectID), globals.GCP_FUNCTIONS_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *FunctionsModule) initializeLootFiles() {
	m.LootMap["functions-gcloud-commands"] = &internal.LootFile{
		Name:     "functions-gcloud-commands",
		Contents: "# GCP Cloud Functions Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["functions-exploitation"] = &internal.LootFile{
		Name:     "functions-exploitation",
		Contents: "# GCP Cloud Functions Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["functions-public"] = &internal.LootFile{
		Name:     "functions-public",
		Contents: "# PUBLIC GCP Cloud Functions\n# Generated by CloudFox\n# These functions can be invoked by allUsers or allAuthenticatedUsers!\n\n",
	}
	m.LootMap["functions-http-endpoints"] = &internal.LootFile{
		Name:     "functions-http-endpoints",
		Contents: "# GCP Cloud Functions HTTP Endpoints\n# Generated by CloudFox\n\n",
	}
	// Pentest-focused loot files
	m.LootMap["functions-security-analysis"] = &internal.LootFile{
		Name:     "functions-security-analysis",
		Contents: "# Cloud Functions Security Analysis\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["functions-source-locations"] = &internal.LootFile{
		Name:     "functions-source-locations",
		Contents: "# Cloud Functions Source Code Locations\n# Generated by CloudFox\n# Download and review for hardcoded secrets\n\n",
	}
	m.LootMap["functions-env-vars"] = &internal.LootFile{
		Name:     "functions-env-vars",
		Contents: "# Cloud Functions Environment Variables\n# Generated by CloudFox\n# Variable names that may hint at secrets\n\n",
	}
	m.LootMap["functions-secrets"] = &internal.LootFile{
		Name:     "functions-secrets",
		Contents: "# Cloud Functions Secret References\n# Generated by CloudFox\n# Secrets used by functions (names only)\n\n",
	}
	// New enhancement loot files
	m.LootMap["functions-internal-only"] = &internal.LootFile{
		Name:     "functions-internal-only",
		Contents: "# GCP Cloud Functions with Internal-Only Ingress\n# These functions are more secure - only accessible from VPC\n# Generated by CloudFox\n\n",
	}
	m.LootMap["functions-vpc-connected"] = &internal.LootFile{
		Name:     "functions-vpc-connected",
		Contents: "# GCP Cloud Functions with VPC Connectors\n# These functions can access internal VPC resources\n# Generated by CloudFox\n\n",
	}
	m.LootMap["functions-cold-start-risk"] = &internal.LootFile{
		Name:     "functions-cold-start-risk",
		Contents: "# GCP Cloud Functions Cold Start Risk Analysis\n# Functions with minInstances=0 may have cold starts\n# Generated by CloudFox\n\n",
	}
	m.LootMap["functions-high-concurrency"] = &internal.LootFile{
		Name:     "functions-high-concurrency",
		Contents: "# GCP Cloud Functions with High Concurrency Limits\n# High concurrency may indicate high-value targets\n# Generated by CloudFox\n\n",
	}
	m.LootMap["functions-security-recommendations"] = &internal.LootFile{
		Name:     "functions-security-recommendations",
		Contents: "# GCP Cloud Functions Security Recommendations\n# Generated by CloudFox\n\n",
	}
}

func (m *FunctionsModule) addFunctionToLoot(fn FunctionsService.FunctionInfo) {
	// gcloud commands
	m.LootMap["functions-gcloud-commands"].Contents += fmt.Sprintf(
		"# Function: %s (Project: %s, Region: %s)\n"+
			"gcloud functions describe %s --region=%s --project=%s --gen2\n"+
			"gcloud functions get-iam-policy %s --region=%s --project=%s --gen2\n"+
			"gcloud functions logs read %s --region=%s --project=%s --gen2 --limit=50\n\n",
		fn.Name, fn.ProjectID, fn.Region,
		fn.Name, fn.Region, fn.ProjectID,
		fn.Name, fn.Region, fn.ProjectID,
		fn.Name, fn.Region, fn.ProjectID,
	)

	// Exploitation commands
	if fn.TriggerType == "HTTP" && fn.TriggerURL != "" {
		m.LootMap["functions-exploitation"].Contents += fmt.Sprintf(
			"# Function: %s (Project: %s)\n"+
				"# Ingress: %s, Service Account: %s\n"+
				"# Test invocation (GET):\n"+
				"curl -s '%s'\n"+
				"# Test invocation (POST with auth):\n"+
				"curl -s -X POST '%s' \\\n"+
				"  -H 'Authorization: Bearer $(gcloud auth print-identity-token)' \\\n"+
				"  -H 'Content-Type: application/json' \\\n"+
				"  -d '{\"test\": \"data\"}'\n\n",
			fn.Name, fn.ProjectID,
			fn.IngressSettings, fn.ServiceAccount,
			fn.TriggerURL,
			fn.TriggerURL,
		)
	}

	// Public functions
	if fn.IsPublic {
		m.LootMap["functions-public"].Contents += fmt.Sprintf(
			"# FUNCTION: %s\n"+
				"# Project: %s, Region: %s\n"+
				"# Invokers: %s\n"+
				"# Service Account: %s\n"+
				"# Ingress: %s\n",
			fn.Name,
			fn.ProjectID, fn.Region,
			strings.Join(fn.InvokerMembers, ", "),
			fn.ServiceAccount,
			fn.IngressSettings,
		)
		if fn.TriggerURL != "" {
			m.LootMap["functions-public"].Contents += fmt.Sprintf(
				"# URL: %s\n"+
					"curl -s '%s'\n",
				fn.TriggerURL,
				fn.TriggerURL,
			)
		}
		m.LootMap["functions-public"].Contents += "\n"
	}

	// HTTP endpoints list
	if fn.TriggerType == "HTTP" && fn.TriggerURL != "" {
		publicMarker := ""
		if fn.IsPublic {
			publicMarker = " [PUBLIC]"
		}
		m.LootMap["functions-http-endpoints"].Contents += fmt.Sprintf(
			"%s%s\n",
			fn.TriggerURL, publicMarker,
		)
	}

	// Source code locations
	if fn.SourceLocation != "" {
		m.LootMap["functions-source-locations"].Contents += fmt.Sprintf(
			"# Function: %s (Project: %s, Region: %s)\n"+
				"# Source Type: %s\n"+
				"# Location: %s\n",
			fn.Name, fn.ProjectID, fn.Region,
			fn.SourceType, fn.SourceLocation,
		)
		if fn.SourceType == "GCS" {
			m.LootMap["functions-source-locations"].Contents += fmt.Sprintf(
				"gsutil cp %s ./function-source-%s.zip\n\n",
				fn.SourceLocation, fn.Name,
			)
		} else {
			m.LootMap["functions-source-locations"].Contents += "\n"
		}
	}

	// Environment variable names
	if len(fn.EnvVarNames) > 0 {
		m.LootMap["functions-env-vars"].Contents += fmt.Sprintf(
			"## Function: %s (Project: %s)\n",
			fn.Name, fn.ProjectID,
		)
		for _, varName := range fn.EnvVarNames {
			m.LootMap["functions-env-vars"].Contents += fmt.Sprintf("##   - %s\n", varName)
		}
		m.LootMap["functions-env-vars"].Contents += "\n"
	}

	// Secret references
	if len(fn.SecretEnvVarNames) > 0 || len(fn.SecretVolumeNames) > 0 {
		m.LootMap["functions-secrets"].Contents += fmt.Sprintf(
			"## Function: %s (Project: %s)\n",
			fn.Name, fn.ProjectID,
		)
		if len(fn.SecretEnvVarNames) > 0 {
			m.LootMap["functions-secrets"].Contents += "## Secret Environment Variables:\n"
			for _, secretName := range fn.SecretEnvVarNames {
				m.LootMap["functions-secrets"].Contents += fmt.Sprintf("##   - %s\n", secretName)
			}
		}
		if len(fn.SecretVolumeNames) > 0 {
			m.LootMap["functions-secrets"].Contents += "## Secret Volumes:\n"
			for _, volName := range fn.SecretVolumeNames {
				m.LootMap["functions-secrets"].Contents += fmt.Sprintf("##   - %s\n", volName)
			}
		}
		m.LootMap["functions-secrets"].Contents += "\n"
	}

	// Enhancement: Internal-only functions
	if fn.IngressSettings == "ALLOW_INTERNAL_ONLY" || fn.IngressSettings == "INTERNAL_ONLY" {
		m.LootMap["functions-internal-only"].Contents += fmt.Sprintf(
			"# Function: %s (Project: %s, Region: %s)\n"+
				"# Ingress: %s - Only accessible from VPC\n"+
				"# VPC Connector: %s\n\n",
			fn.Name, fn.ProjectID, fn.Region,
			fn.IngressSettings,
			fn.VPCConnector,
		)
	}

	// Enhancement: VPC-connected functions
	if fn.VPCConnector != "" {
		m.LootMap["functions-vpc-connected"].Contents += fmt.Sprintf(
			"# Function: %s (Project: %s, Region: %s)\n"+
				"# VPC Connector: %s\n"+
				"# Egress: %s\n"+
				"# Lateral Movement Potential: This function can access VPC resources\n\n",
			fn.Name, fn.ProjectID, fn.Region,
			fn.VPCConnector,
			fn.VPCEgressSettings,
		)
	}

	// Enhancement: Cold start risk
	if fn.MinInstanceCount == 0 {
		m.LootMap["functions-cold-start-risk"].Contents += fmt.Sprintf(
			"# Function: %s (Project: %s, Region: %s)\n"+
				"# Min Instances: %d (cold starts expected)\n"+
				"# Max Instances: %d\n"+
				"# Memory: %d MB, Timeout: %ds\n"+
				"# Remediation: Set min instances to reduce cold starts\n"+
				"gcloud functions deploy %s --region=%s --min-instances=1 --gen2\n\n",
			fn.Name, fn.ProjectID, fn.Region,
			fn.MinInstanceCount,
			fn.MaxInstanceCount,
			fn.AvailableMemoryMB, fn.TimeoutSeconds,
			fn.Name, fn.Region,
		)
	}

	// Enhancement: High concurrency functions
	if fn.MaxInstanceCount > 100 || fn.MaxInstanceRequestConcurrency > 80 {
		m.LootMap["functions-high-concurrency"].Contents += fmt.Sprintf(
			"# Function: %s (Project: %s, Region: %s)\n"+
				"# Max Instances: %d\n"+
				"# Max Concurrent Requests/Instance: %d\n"+
				"# Effective Concurrency: ~%d requests\n"+
				"# This is a high-traffic function - potential high-value target\n\n",
			fn.Name, fn.ProjectID, fn.Region,
			fn.MaxInstanceCount,
			fn.MaxInstanceRequestConcurrency,
			fn.MaxInstanceCount*fn.MaxInstanceRequestConcurrency,
		)
	}

	// Add security recommendations
	m.addFunctionSecurityRecommendations(fn)
}

// addFunctionSecurityRecommendations generates security recommendations for a function
func (m *FunctionsModule) addFunctionSecurityRecommendations(fn FunctionsService.FunctionInfo) {
	hasRecommendations := false
	recommendations := fmt.Sprintf("# FUNCTION: %s (Project: %s, Region: %s)\n", fn.Name, fn.ProjectID, fn.Region)

	// Public access
	if fn.IsPublic {
		hasRecommendations = true
		recommendations += "# [CRITICAL] Function is publicly accessible\n"
		recommendations += fmt.Sprintf("# Remediation: Remove public access\n")
		recommendations += fmt.Sprintf("gcloud functions remove-iam-policy-binding %s --region=%s --member=allUsers --role=roles/cloudfunctions.invoker --gen2\n", fn.Name, fn.Region)
	}

	// All traffic ingress
	if fn.IngressSettings == "ALLOW_ALL" || fn.IngressSettings == "ALL_TRAFFIC" {
		hasRecommendations = true
		recommendations += "# [MEDIUM] Function allows all ingress traffic\n"
		recommendations += "# Remediation: Restrict to internal or GCLB\n"
		recommendations += fmt.Sprintf("gcloud functions deploy %s --region=%s --ingress-settings=internal-only --gen2\n", fn.Name, fn.Region)
	}

	// Default service account
	if strings.Contains(fn.ServiceAccount, "-compute@developer.gserviceaccount.com") ||
		strings.Contains(fn.ServiceAccount, "@appspot.gserviceaccount.com") {
		hasRecommendations = true
		recommendations += "# [HIGH] Uses default service account with potentially excessive permissions\n"
		recommendations += "# Remediation: Create a dedicated service account with minimal permissions\n"
	}

	// No min instances (cold start)
	if fn.MinInstanceCount == 0 {
		hasRecommendations = true
		recommendations += "# [LOW] No minimum instances configured - cold starts expected\n"
		recommendations += fmt.Sprintf("gcloud functions deploy %s --region=%s --min-instances=1 --gen2\n", fn.Name, fn.Region)
	}

	// VPC connector without egress restriction
	if fn.VPCConnector != "" && fn.VPCEgressSettings != "PRIVATE_RANGES_ONLY" {
		hasRecommendations = true
		recommendations += "# [MEDIUM] VPC connector without private-only egress\n"
		recommendations += "# The function can reach both VPC and public internet\n"
		recommendations += fmt.Sprintf("gcloud functions deploy %s --region=%s --vpc-connector=%s --egress-settings=private-ranges-only --gen2\n",
			fn.Name, fn.Region, fn.VPCConnector)
	}

	if hasRecommendations {
		m.LootMap["functions-security-recommendations"].Contents += recommendations + "\n"
	}
}

func (m *FunctionsModule) addSecurityAnalysisToLoot(analysis FunctionsService.FunctionSecurityAnalysis, fn FunctionsService.FunctionInfo) {
	if analysis.RiskLevel == "CRITICAL" || analysis.RiskLevel == "HIGH" || analysis.RiskLevel == "MEDIUM" {
		m.LootMap["functions-security-analysis"].Contents += fmt.Sprintf(
			"## [%s] Function: %s\n"+
				"## Project: %s, Region: %s\n"+
				"## Service Account: %s\n"+
				"## Public: %v\n",
			analysis.RiskLevel, analysis.FunctionName,
			analysis.ProjectID, analysis.Region,
			analysis.ServiceAccount,
			analysis.IsPublic,
		)

		if len(analysis.RiskReasons) > 0 {
			m.LootMap["functions-security-analysis"].Contents += "## Risk Reasons:\n"
			for _, reason := range analysis.RiskReasons {
				m.LootMap["functions-security-analysis"].Contents += fmt.Sprintf("##   - %s\n", reason)
			}
		}

		if len(analysis.ExploitCommands) > 0 {
			m.LootMap["functions-security-analysis"].Contents += "## Exploitation Commands:\n"
			for _, cmd := range analysis.ExploitCommands {
				m.LootMap["functions-security-analysis"].Contents += cmd + "\n"
			}
		}
		m.LootMap["functions-security-analysis"].Contents += "\n"
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *FunctionsModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main functions table
	header := []string{
		"Project Name",
		"Project ID",
		"Name",
		"Region",
		"State",
		"Runtime",
		"Trigger",
		"Ingress",
		"Public",
		"Service Account",
		"VPC Connector",
		"Secrets",
	}

	var body [][]string
	for _, fn := range m.Functions {
		// Format public status
		publicStatus := "No"
		if fn.IsPublic {
			publicStatus = "PUBLIC"
		}

		// Format secrets count
		secretsInfo := "-"
		totalSecrets := fn.SecretEnvVarCount + fn.SecretVolumeCount
		if totalSecrets > 0 {
			secretsInfo = fmt.Sprintf("%d env, %d vol", fn.SecretEnvVarCount, fn.SecretVolumeCount)
		}

		// Format trigger info
		triggerInfo := fn.TriggerType
		if fn.TriggerEventType != "" {
			triggerInfo = fmt.Sprintf("%s (%s)", fn.TriggerType, fn.TriggerEventType)
		}

		// Shorten service account for display
		saDisplay := fn.ServiceAccount
		if strings.Contains(saDisplay, "@") {
			parts := strings.Split(saDisplay, "@")
			if len(parts) > 0 {
				saDisplay = parts[0] + "@..."
			}
		}

		body = append(body, []string{
			m.GetProjectName(fn.ProjectID),
			fn.ProjectID,
			fn.Name,
			fn.Region,
			fn.State,
			fn.Runtime,
			triggerInfo,
			fn.IngressSettings,
			publicStatus,
			saDisplay,
			fn.VPCConnector,
			secretsInfo,
		})
	}

	// HTTP endpoints table
	httpHeader := []string{
		"Function",
		"Project Name",
		"Project ID",
		"URL",
		"Ingress",
		"Public",
		"Service Account",
	}

	var httpBody [][]string
	for _, fn := range m.Functions {
		if fn.TriggerType == "HTTP" && fn.TriggerURL != "" {
			publicStatus := "No"
			if fn.IsPublic {
				publicStatus = "PUBLIC"
			}
			httpBody = append(httpBody, []string{
				fn.Name,
				m.GetProjectName(fn.ProjectID),
				fn.ProjectID,
				fn.TriggerURL,
				fn.IngressSettings,
				publicStatus,
				fn.ServiceAccount,
			})
		}
	}

	// Public functions table
	publicHeader := []string{
		"Function",
		"Project Name",
		"Project ID",
		"Region",
		"URL",
		"Invokers",
		"Service Account",
	}

	var publicBody [][]string
	for _, fn := range m.Functions {
		if fn.IsPublic {
			publicBody = append(publicBody, []string{
				fn.Name,
				m.GetProjectName(fn.ProjectID),
				fn.ProjectID,
				fn.Region,
				fn.TriggerURL,
				strings.Join(fn.InvokerMembers, ", "),
				fn.ServiceAccount,
			})
		}
	}

	// Security analysis table (pentest-focused)
	securityHeader := []string{
		"Risk",
		"Function",
		"Project Name",
		"Project",
		"Region",
		"Public",
		"Service Account",
		"Reasons",
	}

	var securityBody [][]string
	criticalCount := 0
	highCount := 0
	for _, analysis := range m.SecurityAnalysis {
		if analysis.RiskLevel == "CRITICAL" {
			criticalCount++
		} else if analysis.RiskLevel == "HIGH" {
			highCount++
		}

		publicStatus := "No"
		if analysis.IsPublic {
			publicStatus = "Yes"
		}

		reasons := strings.Join(analysis.RiskReasons, "; ")
		if len(reasons) > 60 {
			reasons = reasons[:60] + "..."
		}

		securityBody = append(securityBody, []string{
			analysis.RiskLevel,
			analysis.FunctionName,
			m.GetProjectName(analysis.ProjectID),
			analysis.ProjectID,
			analysis.Region,
			publicStatus,
			analysis.ServiceAccount,
			reasons,
		})
	}

	// Source code locations table
	sourceHeader := []string{
		"Function",
		"Project Name",
		"Project",
		"Source Type",
		"Source Location",
	}

	var sourceBody [][]string
	for _, fn := range m.Functions {
		if fn.SourceLocation != "" {
			sourceBody = append(sourceBody, []string{
				fn.Name,
				m.GetProjectName(fn.ProjectID),
				fn.ProjectID,
				fn.SourceType,
				fn.SourceLocation,
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
			Name:   globals.GCP_FUNCTIONS_MODULE_NAME,
			Header: header,
			Body:   body,
		},
	}

	if len(httpBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "functions-http",
			Header: httpHeader,
			Body:   httpBody,
		})
	}

	if len(publicBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "functions-public",
			Header: publicHeader,
			Body:   publicBody,
		})
	}

	// Add security analysis table
	if len(securityBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "functions-security",
			Header: securityHeader,
			Body:   securityBody,
		})
		if criticalCount > 0 || highCount > 0 {
			logger.InfoM(fmt.Sprintf("[PENTEST] Found %d CRITICAL, %d HIGH risk function(s)!", criticalCount, highCount), globals.GCP_FUNCTIONS_MODULE_NAME)
		}
	}

	// Add source locations table
	if len(sourceBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "functions-source",
			Header: sourceHeader,
			Body:   sourceBody,
		})
	}

	output := FunctionsOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_FUNCTIONS_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
