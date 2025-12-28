package workloadidentityservice

import (
	"context"
	"fmt"
	"strings"

	iam "google.golang.org/api/iam/v1"
)

type WorkloadIdentityService struct{}

func New() *WorkloadIdentityService {
	return &WorkloadIdentityService{}
}

// WorkloadIdentityPool represents a Workload Identity Pool
type WorkloadIdentityPool struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	ProjectID   string `json:"projectId"`
	State       string `json:"state"`
	Disabled    bool   `json:"disabled"`
	PoolID      string `json:"poolId"`
}

// WorkloadIdentityProvider represents a Workload Identity Pool Provider
type WorkloadIdentityProvider struct {
	Name                string   `json:"name"`
	DisplayName         string   `json:"displayName"`
	Description         string   `json:"description"`
	PoolID              string   `json:"poolId"`
	ProviderID          string   `json:"providerId"`
	ProjectID           string   `json:"projectId"`
	ProviderType        string   `json:"providerType"`        // aws, oidc, saml
	Disabled            bool     `json:"disabled"`
	AttributeMapping    map[string]string `json:"attributeMapping"`
	AttributeCondition  string   `json:"attributeCondition"` // CEL expression
	// AWS specific
	AWSAccountID        string   `json:"awsAccountId"`
	// OIDC specific
	OIDCIssuerURI       string   `json:"oidcIssuerUri"`
	AllowedAudiences    []string `json:"allowedAudiences"`
	// Security analysis
	RiskLevel           string   `json:"riskLevel"`
	RiskReasons         []string `json:"riskReasons"`
	ExploitCommands     []string `json:"exploitCommands"`
}

// FederatedIdentityBinding represents a binding from federated identity to GCP SA
type FederatedIdentityBinding struct {
	ProjectID            string   `json:"projectId"`
	PoolID               string   `json:"poolId"`
	ProviderID           string   `json:"providerId"`
	GCPServiceAccount    string   `json:"gcpServiceAccount"`
	ExternalSubject      string   `json:"externalSubject"`
	AttributeCondition   string   `json:"attributeCondition"`
	RiskLevel            string   `json:"riskLevel"`
	RiskReasons          []string `json:"riskReasons"`
}

// ListWorkloadIdentityPools lists all Workload Identity Pools in a project
func (s *WorkloadIdentityService) ListWorkloadIdentityPools(projectID string) ([]WorkloadIdentityPool, error) {
	ctx := context.Background()

	iamService, err := iam.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	var pools []WorkloadIdentityPool
	parent := fmt.Sprintf("projects/%s/locations/global", projectID)

	req := iamService.Projects.Locations.WorkloadIdentityPools.List(parent)
	err = req.Pages(ctx, func(page *iam.ListWorkloadIdentityPoolsResponse) error {
		for _, pool := range page.WorkloadIdentityPools {
			// Extract pool ID from name
			// Format: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID
			poolID := extractLastPart(pool.Name)

			pools = append(pools, WorkloadIdentityPool{
				Name:        pool.Name,
				DisplayName: pool.DisplayName,
				Description: pool.Description,
				ProjectID:   projectID,
				State:       pool.State,
				Disabled:    pool.Disabled,
				PoolID:      poolID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list workload identity pools: %v", err)
	}

	return pools, nil
}

// ListWorkloadIdentityProviders lists all providers in a pool
func (s *WorkloadIdentityService) ListWorkloadIdentityProviders(projectID, poolID string) ([]WorkloadIdentityProvider, error) {
	ctx := context.Background()

	iamService, err := iam.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	var providers []WorkloadIdentityProvider
	parent := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectID, poolID)

	req := iamService.Projects.Locations.WorkloadIdentityPools.Providers.List(parent)
	err = req.Pages(ctx, func(page *iam.ListWorkloadIdentityPoolProvidersResponse) error {
		for _, provider := range page.WorkloadIdentityPoolProviders {
			// Extract provider ID from name
			providerID := extractLastPart(provider.Name)

			wip := WorkloadIdentityProvider{
				Name:               provider.Name,
				DisplayName:        provider.DisplayName,
				Description:        provider.Description,
				PoolID:             poolID,
				ProviderID:         providerID,
				ProjectID:          projectID,
				Disabled:           provider.Disabled,
				AttributeMapping:   provider.AttributeMapping,
				AttributeCondition: provider.AttributeCondition,
				RiskReasons:        []string{},
			}

			// Determine provider type and extract specific config
			if provider.Aws != nil {
				wip.ProviderType = "AWS"
				wip.AWSAccountID = provider.Aws.AccountId
			} else if provider.Oidc != nil {
				wip.ProviderType = "OIDC"
				wip.OIDCIssuerURI = provider.Oidc.IssuerUri
				wip.AllowedAudiences = provider.Oidc.AllowedAudiences
			} else if provider.Saml != nil {
				wip.ProviderType = "SAML"
			}

			// Perform security analysis
			wip.RiskLevel, wip.RiskReasons = s.analyzeProviderRisk(wip)
			wip.ExploitCommands = s.generateProviderExploitCommands(wip, projectID)

			providers = append(providers, wip)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list workload identity providers: %v", err)
	}

	return providers, nil
}

// FindFederatedIdentityBindings finds all service accounts with federated identity bindings
func (s *WorkloadIdentityService) FindFederatedIdentityBindings(projectID string, pools []WorkloadIdentityPool) ([]FederatedIdentityBinding, error) {
	ctx := context.Background()

	iamService, err := iam.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM service: %v", err)
	}

	var bindings []FederatedIdentityBinding

	// List all service accounts
	parent := fmt.Sprintf("projects/%s", projectID)
	saReq := iamService.Projects.ServiceAccounts.List(parent)
	err = saReq.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, sa := range page.Accounts {
			// Get IAM policy for this service account
			policyReq := iamService.Projects.ServiceAccounts.GetIamPolicy(sa.Name)
			policy, pErr := policyReq.Do()
			if pErr != nil {
				continue
			}

			// Look for federated identity bindings
			for _, binding := range policy.Bindings {
				if binding.Role == "roles/iam.workloadIdentityUser" {
					for _, member := range binding.Members {
						// Check if this is a federated identity
						// Format: principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/SUBJECT
						// Or: principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.ATTR/VALUE
						if strings.HasPrefix(member, "principal://") || strings.HasPrefix(member, "principalSet://") {
							fib := s.parseFederatedIdentityBinding(member, sa.Email, projectID)
							if fib != nil {
								bindings = append(bindings, *fib)
							}
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find federated identity bindings: %v", err)
	}

	return bindings, nil
}

// parseFederatedIdentityBinding parses a federated identity member string
func (s *WorkloadIdentityService) parseFederatedIdentityBinding(member, gcpSA, projectID string) *FederatedIdentityBinding {
	// principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/SUBJECT
	// principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.ATTR/VALUE

	fib := &FederatedIdentityBinding{
		ProjectID:         projectID,
		GCPServiceAccount: gcpSA,
		ExternalSubject:   member,
		RiskReasons:       []string{},
	}

	// Extract pool ID
	if idx := strings.Index(member, "workloadIdentityPools/"); idx != -1 {
		rest := member[idx+len("workloadIdentityPools/"):]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			fib.PoolID = rest[:slashIdx]
		}
	}

	// Analyze risk
	score := 0

	// principalSet is broader than principal
	if strings.HasPrefix(member, "principalSet://") {
		fib.RiskReasons = append(fib.RiskReasons,
			"Uses principalSet (grants access to multiple external identities)")
		score += 2
	}

	// Check for wildcards
	if strings.Contains(member, "*") {
		fib.RiskReasons = append(fib.RiskReasons,
			"Contains wildcard in subject/attribute matching")
		score += 3
	}

	// Check for common risky patterns
	if strings.Contains(member, "attribute.repository") {
		fib.RiskReasons = append(fib.RiskReasons,
			"Matches on repository attribute (GitHub Actions likely)")
	}

	if score >= 3 {
		fib.RiskLevel = "HIGH"
	} else if score >= 2 {
		fib.RiskLevel = "MEDIUM"
	} else if score >= 1 {
		fib.RiskLevel = "LOW"
	} else {
		fib.RiskLevel = "INFO"
	}

	return fib
}

// analyzeProviderRisk analyzes the security risk of a provider configuration
func (s *WorkloadIdentityService) analyzeProviderRisk(provider WorkloadIdentityProvider) (string, []string) {
	var reasons []string
	score := 0

	// No attribute condition means any authenticated identity from provider can federate
	if provider.AttributeCondition == "" {
		reasons = append(reasons,
			"No attribute condition set - any identity from provider can authenticate")
		score += 3
	}

	// AWS provider risks
	if provider.ProviderType == "AWS" {
		reasons = append(reasons,
			fmt.Sprintf("AWS federation enabled from account: %s", provider.AWSAccountID))
		score += 1
	}

	// OIDC provider risks
	if provider.ProviderType == "OIDC" {
		// Check for common public OIDC providers
		knownProviders := map[string]string{
			"token.actions.githubusercontent.com": "GitHub Actions",
			"gitlab.com":                          "GitLab CI",
			"accounts.google.com":                 "Google",
			"sts.windows.net":                     "Azure AD",
			"cognito-identity.amazonaws.com":      "AWS Cognito",
		}

		for pattern, name := range knownProviders {
			if strings.Contains(provider.OIDCIssuerURI, pattern) {
				reasons = append(reasons,
					fmt.Sprintf("OIDC provider: %s (%s)", name, provider.OIDCIssuerURI))
				if name == "GitHub Actions" && provider.AttributeCondition == "" {
					reasons = append(reasons,
						"CRITICAL: GitHub Actions without attribute condition - any public repo can authenticate!")
					score += 4
				}
			}
		}
	}

	// Check attribute mapping for risky patterns
	if mapping, ok := provider.AttributeMapping["google.subject"]; ok {
		if mapping == "assertion.sub" {
			reasons = append(reasons,
				"Subject mapped directly from assertion.sub")
		}
	}

	if score >= 4 {
		return "CRITICAL", reasons
	} else if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

// generateProviderExploitCommands generates exploitation commands for a provider
func (s *WorkloadIdentityService) generateProviderExploitCommands(provider WorkloadIdentityProvider, projectID string) []string {
	var commands []string

	commands = append(commands,
		fmt.Sprintf("# Workload Identity Provider: %s/%s", provider.PoolID, provider.ProviderID))

	switch provider.ProviderType {
	case "AWS":
		commands = append(commands,
			fmt.Sprintf("# From AWS account %s, use STS to federate:", provider.AWSAccountID),
			fmt.Sprintf("# 1. Get AWS credentials for a role in account %s", provider.AWSAccountID),
			"# 2. Exchange for GCP access token:",
			fmt.Sprintf("gcloud iam workload-identity-pools create-cred-config \\"),
			fmt.Sprintf("  projects/%s/locations/global/workloadIdentityPools/%s/providers/%s \\",
				projectID, provider.PoolID, provider.ProviderID),
			"  --aws --output-file=gcp-creds.json",
		)

	case "OIDC":
		if strings.Contains(provider.OIDCIssuerURI, "github") {
			commands = append(commands,
				"# From GitHub Actions workflow, add:",
				"permissions:",
				"  id-token: write",
				"  contents: read",
				"",
				"# Then use:",
				fmt.Sprintf("gcloud iam workload-identity-pools create-cred-config \\"),
				fmt.Sprintf("  projects/%s/locations/global/workloadIdentityPools/%s/providers/%s \\",
					projectID, provider.PoolID, provider.ProviderID),
				"  --service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com \\",
				"  --output-file=gcp-creds.json",
			)
		} else {
			commands = append(commands,
				fmt.Sprintf("# OIDC issuer: %s", provider.OIDCIssuerURI),
				"# Get an OIDC token from the issuer, then exchange:",
				fmt.Sprintf("gcloud iam workload-identity-pools create-cred-config \\"),
				fmt.Sprintf("  projects/%s/locations/global/workloadIdentityPools/%s/providers/%s \\",
					projectID, provider.PoolID, provider.ProviderID),
				"  --output-file=gcp-creds.json",
			)
		}
	}

	return commands
}

// extractLastPart extracts the last part of a resource name
func extractLastPart(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}
