package orgpolicyservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"google.golang.org/api/orgpolicy/v2"
)

type OrgPolicyService struct {
	session *gcpinternal.SafeSession
}

func New() *OrgPolicyService {
	return &OrgPolicyService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *OrgPolicyService {
	return &OrgPolicyService{session: session}
}

// OrgPolicyInfo represents an organization policy with security analysis
type OrgPolicyInfo struct {
	Name           string   `json:"name"`
	Constraint     string   `json:"constraint"`
	ProjectID      string   `json:"projectId"`
	Enforced       bool     `json:"enforced"`
	AllowAll       bool     `json:"allowAll"`
	DenyAll        bool     `json:"denyAll"`
	AllowedValues  []string `json:"allowedValues"`
	DeniedValues   []string `json:"deniedValues"`
	InheritParent  bool     `json:"inheritFromParent"`
	RiskLevel      string   `json:"riskLevel"`
	RiskReasons    []string `json:"riskReasons"`
	SecurityImpact string   `json:"securityImpact"`
}

// SecurityRelevantConstraints maps constraint names to their security implications
var SecurityRelevantConstraints = map[string]struct {
	Description    string
	RiskWhenWeak   string
	DefaultSecure  bool
}{
	// Domain restriction
	"constraints/iam.allowedPolicyMemberDomains": {
		Description:   "Restricts IAM members to specific domains",
		RiskWhenWeak:  "Allows external users/accounts to be granted IAM permissions",
		DefaultSecure: false,
	},
	// Service account key creation
	"constraints/iam.disableServiceAccountKeyCreation": {
		Description:   "Prevents service account key creation",
		RiskWhenWeak:  "Allows persistent SA key creation for long-term access",
		DefaultSecure: false,
	},
	"constraints/iam.disableServiceAccountKeyUpload": {
		Description:   "Prevents uploading service account keys",
		RiskWhenWeak:  "Allows external keys to be uploaded for SA access",
		DefaultSecure: false,
	},
	// Workload identity
	"constraints/iam.workloadIdentityPoolProviders": {
		Description:   "Restricts workload identity pool providers",
		RiskWhenWeak:  "Allows external identity providers to assume GCP identities",
		DefaultSecure: false,
	},
	"constraints/iam.workloadIdentityPoolAwsAccounts": {
		Description:   "Restricts AWS accounts for workload identity",
		RiskWhenWeak:  "Allows any AWS account to assume GCP identity",
		DefaultSecure: false,
	},
	// Compute restrictions
	"constraints/compute.requireShieldedVm": {
		Description:   "Requires Shielded VMs",
		RiskWhenWeak:  "Allows VMs without Shielded VM protections",
		DefaultSecure: false,
	},
	"constraints/compute.requireOsLogin": {
		Description:   "Requires OS Login for SSH access",
		RiskWhenWeak:  "Allows metadata-based SSH keys instead of centralized access",
		DefaultSecure: false,
	},
	"constraints/compute.vmExternalIpAccess": {
		Description:   "Restricts which VMs can have external IPs",
		RiskWhenWeak:  "Allows any VM to have an external IP",
		DefaultSecure: false,
	},
	"constraints/compute.disableSerialPortAccess": {
		Description:   "Disables serial port access to VMs",
		RiskWhenWeak:  "Allows serial console access to VMs",
		DefaultSecure: false,
	},
	"constraints/compute.disableNestedVirtualization": {
		Description:   "Disables nested virtualization",
		RiskWhenWeak:  "Allows nested VMs for potential sandbox escape",
		DefaultSecure: false,
	},
	// Storage restrictions
	"constraints/storage.uniformBucketLevelAccess": {
		Description:   "Requires uniform bucket-level access",
		RiskWhenWeak:  "Allows ACL-based access which is harder to audit",
		DefaultSecure: false,
	},
	"constraints/storage.publicAccessPrevention": {
		Description:   "Prevents public access to storage buckets",
		RiskWhenWeak:  "Allows public bucket/object access",
		DefaultSecure: false,
	},
	// SQL restrictions
	"constraints/sql.restrictPublicIp": {
		Description:   "Restricts public IPs on Cloud SQL",
		RiskWhenWeak:  "Allows Cloud SQL instances with public IPs",
		DefaultSecure: false,
	},
	"constraints/sql.restrictAuthorizedNetworks": {
		Description:   "Restricts authorized networks for Cloud SQL",
		RiskWhenWeak:  "Allows broad network access to Cloud SQL",
		DefaultSecure: false,
	},
	// GKE restrictions
	"constraints/container.restrictPublicEndpoint": {
		Description:   "Restricts GKE public endpoints",
		RiskWhenWeak:  "Allows GKE clusters with public API endpoints",
		DefaultSecure: false,
	},
	// Resource location
	"constraints/gcp.resourceLocations": {
		Description:   "Restricts resource locations/regions",
		RiskWhenWeak:  "Allows resources in any region (compliance risk)",
		DefaultSecure: false,
	},
	// Service usage
	"constraints/serviceuser.services": {
		Description:   "Restricts which services can be enabled",
		RiskWhenWeak:  "Allows any GCP service to be enabled",
		DefaultSecure: false,
	},
	// VPC
	"constraints/compute.restrictSharedVpcSubnetworks": {
		Description:   "Restricts Shared VPC subnetworks",
		RiskWhenWeak:  "Allows access to any Shared VPC subnetwork",
		DefaultSecure: false,
	},
	"constraints/compute.restrictVpnPeerIPs": {
		Description:   "Restricts VPN peer IPs",
		RiskWhenWeak:  "Allows VPN tunnels to any peer",
		DefaultSecure: false,
	},
}

// ListProjectPolicies lists all org policies for a project
func (s *OrgPolicyService) ListProjectPolicies(projectID string) ([]OrgPolicyInfo, error) {
	ctx := context.Background()
	var service *orgpolicy.Service
	var err error

	if s.session != nil {
		service, err = orgpolicy.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = orgpolicy.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create org policy service: %v", err)
	}

	var policies []OrgPolicyInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	err = service.Projects.Policies.List(parent).Pages(ctx, func(resp *orgpolicy.GoogleCloudOrgpolicyV2ListPoliciesResponse) error {
		for _, policy := range resp.Policies {
			info := s.parsePolicyInfo(policy, projectID)
			policies = append(policies, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %v", err)
	}

	return policies, nil
}

func (s *OrgPolicyService) parsePolicyInfo(policy *orgpolicy.GoogleCloudOrgpolicyV2Policy, projectID string) OrgPolicyInfo {
	info := OrgPolicyInfo{
		Name:      policy.Name,
		ProjectID: projectID,
	}

	// Extract constraint name from policy name
	parts := strings.Split(policy.Name, "/policies/")
	if len(parts) > 1 {
		info.Constraint = "constraints/" + parts[1]
	}

	// Parse the spec
	if policy.Spec != nil {
		info.InheritParent = policy.Spec.InheritFromParent

		for _, rule := range policy.Spec.Rules {
			if rule == nil {
				continue
			}

			// In v2 API, these are booleans
			info.Enforced = rule.Enforce
			info.AllowAll = rule.AllowAll
			info.DenyAll = rule.DenyAll

			if rule.Values != nil {
				info.AllowedValues = append(info.AllowedValues, rule.Values.AllowedValues...)
				info.DeniedValues = append(info.DeniedValues, rule.Values.DeniedValues...)
			}
		}
	}

	// Analyze risk
	info.RiskLevel, info.RiskReasons, info.SecurityImpact = s.analyzePolicy(info)

	return info
}

func (s *OrgPolicyService) analyzePolicy(policy OrgPolicyInfo) (string, []string, string) {
	var reasons []string
	var impact string
	riskScore := 0

	// Get security context for this constraint
	secInfo, isSecurityRelevant := SecurityRelevantConstraints[policy.Constraint]

	if isSecurityRelevant {
		impact = secInfo.RiskWhenWeak

		// Check if policy is weakened
		if policy.AllowAll {
			reasons = append(reasons, fmt.Sprintf("Policy allows ALL values - %s", secInfo.Description))
			riskScore += 3
		}

		// Check for overly permissive allowed values
		if len(policy.AllowedValues) > 0 {
			if containsWildcard(policy.AllowedValues) {
				reasons = append(reasons, "Allowed values contains wildcard pattern")
				riskScore += 2
			}
		}

		// Check if important security constraint is not enforced
		if !policy.Enforced && secInfo.DefaultSecure {
			reasons = append(reasons, fmt.Sprintf("Security constraint not enforced: %s", secInfo.Description))
			riskScore += 2
		}

		// Check for inheritance issues
		if policy.InheritParent && policy.AllowAll {
			reasons = append(reasons, "Inherits from parent but also allows all - may override parent restrictions")
			riskScore += 1
		}
	} else {
		impact = "Custom or less common constraint"
	}

	// Determine risk level
	if riskScore >= 3 {
		return "HIGH", reasons, impact
	} else if riskScore >= 2 {
		return "MEDIUM", reasons, impact
	} else if riskScore >= 1 {
		return "LOW", reasons, impact
	}
	return "INFO", reasons, impact
}

func containsWildcard(values []string) bool {
	for _, v := range values {
		if v == "*" || strings.Contains(v, "/*") || v == "under:*" {
			return true
		}
	}
	return false
}
