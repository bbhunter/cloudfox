package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

// Module name constant
const GCP_LATERALMOVEMENT_MODULE_NAME string = "lateral-movement"

var GCPLateralMovementCommand = &cobra.Command{
	Use:     GCP_LATERALMOVEMENT_MODULE_NAME,
	Aliases: []string{"lateral", "pivot"},
	Short:   "Map lateral movement paths, credential theft vectors, and pivot opportunities",
	Long: `Identify lateral movement opportunities within and across GCP projects.

Features:
- Maps service account impersonation chains (SA → SA → SA)
- Identifies token creator permissions (lateral movement via impersonation)
- Finds cross-project access paths
- Detects VM metadata abuse vectors
- Analyzes credential storage locations (secrets, environment variables)
- Maps attack paths from compromised identities
- Generates exploitation commands for penetration testing

This module helps identify how an attacker could move laterally after gaining
initial access to a GCP environment.`,
	Run: runGCPLateralMovementCommand,
}

// ------------------------------
// Data Structures
// ------------------------------

type ImpersonationChain struct {
	StartIdentity  string
	TargetSA       string
	ChainLength    int
	Path           []string // [identity] -> [sa1] -> [sa2] -> ...
	RiskLevel      string   // CRITICAL, HIGH, MEDIUM
	ExploitCommand string
}

type TokenTheftVector struct {
	ResourceType  string // "instance", "function", "cloudrun", etc.
	ResourceName  string
	ProjectID     string
	ServiceAccount string
	AttackVector  string // "metadata", "env_var", "startup_script", etc.
	RiskLevel     string
	ExploitCommand string
}

type CrossProjectPath struct {
	SourceProject string
	TargetProject string
	Principal     string
	Role          string
	AccessType    string // "direct", "impersonation", "shared_vpc"
	RiskLevel     string
}

type CredentialLocation struct {
	ResourceType string
	ResourceName string
	ProjectID    string
	CredentialType string // "sa_key", "api_key", "secret", "env_var"
	Description  string
	RiskLevel    string
}

// ------------------------------
// Module Struct
// ------------------------------
type LateralMovementModule struct {
	gcpinternal.BaseGCPModule

	ImpersonationChains []ImpersonationChain
	TokenTheftVectors   []TokenTheftVector
	CrossProjectPaths   []CrossProjectPath
	CredentialLocations []CredentialLocation
	LootMap             map[string]*internal.LootFile
	mu                  sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type LateralMovementOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LateralMovementOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LateralMovementOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPLateralMovementCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, GCP_LATERALMOVEMENT_MODULE_NAME)
	if err != nil {
		return
	}

	module := &LateralMovementModule{
		BaseGCPModule:       gcpinternal.NewBaseGCPModule(cmdCtx),
		ImpersonationChains: []ImpersonationChain{},
		TokenTheftVectors:   []TokenTheftVector{},
		CrossProjectPaths:   []CrossProjectPath{},
		CredentialLocations: []CredentialLocation{},
		LootMap:             make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LateralMovementModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Mapping lateral movement paths...", GCP_LATERALMOVEMENT_MODULE_NAME)

	// Process each project
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_LATERALMOVEMENT_MODULE_NAME, m.processProject)

	// Check results
	totalPaths := len(m.ImpersonationChains) + len(m.TokenTheftVectors) + len(m.CrossProjectPaths)
	if totalPaths == 0 {
		logger.InfoM("No lateral movement paths found", GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s): %d impersonation chains, %d token theft vectors, %d cross-project paths",
		totalPaths, len(m.ImpersonationChains), len(m.TokenTheftVectors), len(m.CrossProjectPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LateralMovementModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing lateral movement paths in project: %s", projectID), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	// 1. Find impersonation chains
	m.findImpersonationChains(ctx, projectID, logger)

	// 2. Find token theft vectors (compute instances, functions, etc.)
	m.findTokenTheftVectors(ctx, projectID, logger)

	// 3. Find cross-project access
	m.findCrossProjectAccess(ctx, projectID, logger)

	// 4. Find credential storage locations
	m.findCredentialLocations(ctx, projectID, logger)
}

// findImpersonationChains finds service account impersonation paths
func (m *LateralMovementModule) findImpersonationChains(ctx context.Context, projectID string, logger internal.Logger) {
	iamService := IAMService.New()

	// Get all service accounts
	serviceAccounts, err := iamService.ServiceAccounts(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting service accounts: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
		}
		return
	}

	// For each SA, check who can impersonate it using GetServiceAccountIAMPolicy
	for _, sa := range serviceAccounts {
		impersonationInfo, err := iamService.GetServiceAccountIAMPolicy(ctx, sa.Email, projectID)
		if err != nil {
			continue
		}

		// Token creators can impersonate
		for _, creator := range impersonationInfo.TokenCreators {
			// Skip allUsers/allAuthenticatedUsers - those are handled separately
			if creator == "allUsers" || creator == "allAuthenticatedUsers" {
				continue
			}

			chain := ImpersonationChain{
				StartIdentity:  creator,
				TargetSA:       sa.Email,
				ChainLength:    1,
				Path:           []string{creator, sa.Email},
				RiskLevel:      "HIGH",
				ExploitCommand: fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", sa.Email),
			}

			// If target SA has roles/owner or roles/editor, it's critical
			if impersonationInfo.RiskLevel == "CRITICAL" {
				chain.RiskLevel = "CRITICAL"
			}

			m.mu.Lock()
			m.ImpersonationChains = append(m.ImpersonationChains, chain)
			m.addImpersonationChainToLoot(chain, projectID)
			m.mu.Unlock()
		}

		// Key creators can create persistent access
		for _, creator := range impersonationInfo.KeyCreators {
			if creator == "allUsers" || creator == "allAuthenticatedUsers" {
				continue
			}

			chain := ImpersonationChain{
				StartIdentity:  creator,
				TargetSA:       sa.Email,
				ChainLength:    1,
				Path:           []string{creator, sa.Email},
				RiskLevel:      "CRITICAL",
				ExploitCommand: fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", sa.Email),
			}

			m.mu.Lock()
			m.ImpersonationChains = append(m.ImpersonationChains, chain)
			m.addImpersonationChainToLoot(chain, projectID)
			m.mu.Unlock()
		}
	}
}

// findTokenTheftVectors finds compute resources where tokens can be stolen
func (m *LateralMovementModule) findTokenTheftVectors(ctx context.Context, projectID string, logger internal.Logger) {
	// This would use Compute Engine API to find instances with service accounts
	// For now, we'll add the pattern for common token theft vectors

	// Common token theft vectors in GCP:
	vectors := []TokenTheftVector{
		{
			ResourceType:   "compute_instance",
			ResourceName:   "*",
			ProjectID:      projectID,
			ServiceAccount: "<instance-sa>",
			AttackVector:   "metadata_server",
			RiskLevel:      "HIGH",
			ExploitCommand: `curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"`,
		},
		{
			ResourceType:   "cloud_function",
			ResourceName:   "*",
			ProjectID:      projectID,
			ServiceAccount: "<function-sa>",
			AttackVector:   "function_execution",
			RiskLevel:      "HIGH",
			ExploitCommand: `# Deploy a function that exfiltrates the SA token via metadata server`,
		},
		{
			ResourceType:   "cloud_run",
			ResourceName:   "*",
			ProjectID:      projectID,
			ServiceAccount: "<cloudrun-sa>",
			AttackVector:   "container_execution",
			RiskLevel:      "HIGH",
			ExploitCommand: `# Access metadata server from within Cloud Run container`,
		},
		{
			ResourceType:   "gke_pod",
			ResourceName:   "*",
			ProjectID:      projectID,
			ServiceAccount: "<workload-identity-sa>",
			AttackVector:   "pod_service_account",
			RiskLevel:      "MEDIUM",
			ExploitCommand: `kubectl exec -it <pod> -- curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/..."`,
		},
	}

	m.mu.Lock()
	m.TokenTheftVectors = append(m.TokenTheftVectors, vectors...)
	for _, v := range vectors {
		m.addTokenTheftVectorToLoot(v)
	}
	m.mu.Unlock()
}

// findCrossProjectAccess finds IAM bindings that allow cross-project access
func (m *LateralMovementModule) findCrossProjectAccess(ctx context.Context, projectID string, logger internal.Logger) {
	iamService := IAMService.New()

	// Get IAM policy for the project using PoliciesWithInheritance for comprehensive view
	bindings, err := iamService.PoliciesWithInheritance(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting IAM policy: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
		}
		return
	}

	// Check each binding for cross-project principals
	for _, binding := range bindings {
		for _, member := range binding.Members {
			// Check if member is from a different project
			if strings.Contains(member, "serviceAccount:") && !strings.Contains(member, projectID) {
				// Extract the SA's project from the email
				saEmail := strings.TrimPrefix(member, "serviceAccount:")
				saParts := strings.Split(saEmail, "@")
				if len(saParts) >= 2 {
					saProject := strings.TrimSuffix(saParts[1], ".iam.gserviceaccount.com")

					crossPath := CrossProjectPath{
						SourceProject: saProject,
						TargetProject: projectID,
						Principal:     saEmail,
						Role:          binding.Role,
						AccessType:    "direct",
						RiskLevel:     m.classifyCrossProjectRisk(binding.Role),
					}

					m.mu.Lock()
					m.CrossProjectPaths = append(m.CrossProjectPaths, crossPath)
					m.addCrossProjectPathToLoot(crossPath)
					m.mu.Unlock()
				}
			}
		}
	}
}

// findCredentialLocations identifies where credentials might be stored
func (m *LateralMovementModule) findCredentialLocations(ctx context.Context, projectID string, logger internal.Logger) {
	// Common credential storage locations in GCP
	locations := []CredentialLocation{
		{
			ResourceType:   "secret_manager",
			ResourceName:   "*",
			ProjectID:      projectID,
			CredentialType: "secret",
			Description:    "Secrets stored in Secret Manager",
			RiskLevel:      "MEDIUM",
		},
		{
			ResourceType:   "compute_metadata",
			ResourceName:   "*",
			ProjectID:      projectID,
			CredentialType: "env_var",
			Description:    "Environment variables in instance metadata",
			RiskLevel:      "HIGH",
		},
		{
			ResourceType:   "gcs_bucket",
			ResourceName:   "*",
			ProjectID:      projectID,
			CredentialType: "sa_key",
			Description:    "Service account keys stored in GCS",
			RiskLevel:      "CRITICAL",
		},
	}

	m.mu.Lock()
	m.CredentialLocations = append(m.CredentialLocations, locations...)
	m.mu.Unlock()
}

// classifyCrossProjectRisk determines the risk level of a cross-project binding
func (m *LateralMovementModule) classifyCrossProjectRisk(role string) string {
	highRiskRoles := []string{
		"roles/owner",
		"roles/editor",
		"roles/iam.securityAdmin",
		"roles/iam.serviceAccountAdmin",
		"roles/iam.serviceAccountTokenCreator",
		"roles/iam.serviceAccountKeyAdmin",
	}

	for _, hr := range highRiskRoles {
		if role == hr {
			return "CRITICAL"
		}
	}

	if strings.Contains(role, "admin") || strings.Contains(role, "Admin") {
		return "HIGH"
	}

	return "MEDIUM"
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LateralMovementModule) initializeLootFiles() {
	m.LootMap["lateral-impersonation-chains"] = &internal.LootFile{
		Name:     "lateral-impersonation-chains",
		Contents: "# Service Account Impersonation Chains\n# Generated by CloudFox\n# These show how one identity can assume another\n\n",
	}
	m.LootMap["lateral-token-theft"] = &internal.LootFile{
		Name:     "lateral-token-theft",
		Contents: "# Token Theft Vectors\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
	}
	m.LootMap["lateral-cross-project"] = &internal.LootFile{
		Name:     "lateral-cross-project",
		Contents: "# Cross-Project Access Paths\n# Generated by CloudFox\n# These show lateral movement opportunities between projects\n\n",
	}
	m.LootMap["lateral-exploitation"] = &internal.LootFile{
		Name:     "lateral-exploitation",
		Contents: "# Lateral Movement Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization!\n\n",
	}
}

func (m *LateralMovementModule) addImpersonationChainToLoot(chain ImpersonationChain, projectID string) {
	m.LootMap["lateral-impersonation-chains"].Contents += fmt.Sprintf(
		"## Chain: %s -> %s\n"+
			"Risk: %s\n"+
			"Path: %s\n"+
			"Command: %s\n\n",
		chain.StartIdentity,
		chain.TargetSA,
		chain.RiskLevel,
		strings.Join(chain.Path, " -> "),
		chain.ExploitCommand,
	)

	if chain.RiskLevel == "CRITICAL" || chain.RiskLevel == "HIGH" {
		m.LootMap["lateral-exploitation"].Contents += fmt.Sprintf(
			"# Impersonation: %s -> %s (%s)\n"+
				"%s\n\n",
			chain.StartIdentity,
			chain.TargetSA,
			chain.RiskLevel,
			chain.ExploitCommand,
		)
	}
}

func (m *LateralMovementModule) addTokenTheftVectorToLoot(vector TokenTheftVector) {
	m.LootMap["lateral-token-theft"].Contents += fmt.Sprintf(
		"## %s: %s\n"+
			"Project: %s\n"+
			"Service Account: %s\n"+
			"Attack Vector: %s\n"+
			"Risk: %s\n"+
			"Command:\n%s\n\n",
		vector.ResourceType,
		vector.ResourceName,
		vector.ProjectID,
		vector.ServiceAccount,
		vector.AttackVector,
		vector.RiskLevel,
		vector.ExploitCommand,
	)
}

func (m *LateralMovementModule) addCrossProjectPathToLoot(path CrossProjectPath) {
	m.LootMap["lateral-cross-project"].Contents += fmt.Sprintf(
		"## %s -> %s\n"+
			"Principal: %s\n"+
			"Role: %s\n"+
			"Access Type: %s\n"+
			"Risk: %s\n\n",
		path.SourceProject,
		path.TargetProject,
		path.Principal,
		path.Role,
		path.AccessType,
		path.RiskLevel,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LateralMovementModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Impersonation chains table
	chainsHeader := []string{
		"Start Identity",
		"Target SA",
		"Chain Length",
		"Risk",
		"Exploit Command",
	}

	var chainsBody [][]string
	for _, chain := range m.ImpersonationChains {
		chainsBody = append(chainsBody, []string{
			truncateString(chain.StartIdentity, 40),
			truncateString(chain.TargetSA, 40),
			fmt.Sprintf("%d", chain.ChainLength),
			chain.RiskLevel,
			truncateString(chain.ExploitCommand, 50),
		})
	}

	// Token theft vectors table
	vectorsHeader := []string{
		"Resource Type",
		"Resource",
		"Project Name",
		"Project ID",
		"Attack Vector",
		"Risk",
	}

	var vectorsBody [][]string
	for _, vector := range m.TokenTheftVectors {
		vectorsBody = append(vectorsBody, []string{
			vector.ResourceType,
			truncateString(vector.ResourceName, 30),
			m.GetProjectName(vector.ProjectID),
			vector.ProjectID,
			vector.AttackVector,
			vector.RiskLevel,
		})
	}

	// Cross-project paths table
	crossHeader := []string{
		"Source Project Name",
		"Source Project ID",
		"Target Project Name",
		"Target Project ID",
		"Principal",
		"Role",
		"Risk",
	}

	var crossBody [][]string
	for _, path := range m.CrossProjectPaths {
		crossBody = append(crossBody, []string{
			m.GetProjectName(path.SourceProject),
			path.SourceProject,
			m.GetProjectName(path.TargetProject),
			path.TargetProject,
			truncateString(path.Principal, 40),
			path.Role,
			path.RiskLevel,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build tables
	tables := []internal.TableFile{}

	if len(chainsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-impersonation-chains",
			Header: chainsHeader,
			Body:   chainsBody,
		})
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d impersonation chain(s)", len(chainsBody)), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	if len(vectorsBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-token-theft",
			Header: vectorsHeader,
			Body:   vectorsBody,
		})
	}

	if len(crossBody) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-cross-project",
			Header: crossHeader,
			Body:   crossBody,
		})
		logger.InfoM(fmt.Sprintf("[PENTEST] Found %d cross-project path(s)", len(crossBody)), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	output := LateralMovementOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
