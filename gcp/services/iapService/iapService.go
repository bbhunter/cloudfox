package iapservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	iap "google.golang.org/api/iap/v1"
)

type IAPService struct {
	session *gcpinternal.SafeSession
}

func New() *IAPService {
	return &IAPService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *IAPService {
	return &IAPService{session: session}
}

// IAPSettingsInfo represents IAP settings for a resource
type IAPSettingsInfo struct {
	Name                    string   `json:"name"`
	ProjectID               string   `json:"projectId"`
	ResourceType            string   `json:"resourceType"` // compute, app-engine, etc.
	ResourceName            string   `json:"resourceName"`
	IAPEnabled              bool     `json:"iapEnabled"`
	OAuth2ClientID          string   `json:"oauth2ClientId"`
	OAuth2ClientSecretSha   string   `json:"oauth2ClientSecretSha"`
	AccessDeniedPageURI     string   `json:"accessDeniedPageUri"`
	CORSAllowedOrigins      []string `json:"corsAllowedOrigins"`
	GCIPTenantIDs           []string `json:"gcipTenantIds"`
	ReauthPolicy            string   `json:"reauthPolicy"`
	RiskLevel               string   `json:"riskLevel"`
	RiskReasons             []string `json:"riskReasons"`
}

// TunnelDestGroup represents an IAP tunnel destination group
type TunnelDestGroup struct {
	Name        string   `json:"name"`
	ProjectID   string   `json:"projectId"`
	Region      string   `json:"region"`
	CIDRs       []string `json:"cidrs"`
	FQDNs       []string `json:"fqdns"`
	RiskLevel   string   `json:"riskLevel"`
	RiskReasons []string `json:"riskReasons"`
}

// IAPBinding represents an IAM binding for IAP
type IAPBinding struct {
	Resource    string   `json:"resource"`
	ProjectID   string   `json:"projectId"`
	Role        string   `json:"role"`
	Members     []string `json:"members"`
	RiskLevel   string   `json:"riskLevel"`
	RiskReasons []string `json:"riskReasons"`
}

// ListTunnelDestGroups retrieves tunnel destination groups
func (s *IAPService) ListTunnelDestGroups(projectID string) ([]TunnelDestGroup, error) {
	ctx := context.Background()
	var service *iap.Service
	var err error

	if s.session != nil {
		service, err = iap.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = iap.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create IAP service: %v", err)
	}

	var groups []TunnelDestGroup

	// List across common regions
	regions := []string{"us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1", "-"}

	for _, region := range regions {
		parent := fmt.Sprintf("projects/%s/iap_tunnel/locations/%s", projectID, region)
		resp, err := service.Projects.IapTunnel.Locations.DestGroups.List(parent).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, group := range resp.TunnelDestGroups {
			info := TunnelDestGroup{
				Name:        extractName(group.Name),
				ProjectID:   projectID,
				Region:      region,
				CIDRs:       group.Cidrs,
				FQDNs:       group.Fqdns,
				RiskReasons: []string{},
			}
			info.RiskLevel, info.RiskReasons = s.analyzeDestGroupRisk(info)
			groups = append(groups, info)
		}
	}

	return groups, nil
}

// GetIAPSettings retrieves IAP settings for a resource
func (s *IAPService) GetIAPSettings(projectID, resourcePath string) (*IAPSettingsInfo, error) {
	ctx := context.Background()
	var service *iap.Service
	var err error

	if s.session != nil {
		service, err = iap.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = iap.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create IAP service: %v", err)
	}

	settings, err := service.V1.GetIapSettings(resourcePath).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAP settings: %v", err)
	}

	info := &IAPSettingsInfo{
		Name:         settings.Name,
		ProjectID:    projectID,
		ResourceName: resourcePath,
		RiskReasons:  []string{},
	}

	if settings.AccessSettings != nil {
		if settings.AccessSettings.OauthSettings != nil {
			info.OAuth2ClientID = settings.AccessSettings.OauthSettings.LoginHint
		}
		// CorsSettings doesn't have AllowHttpOptions as a list - it's a bool
		// Skip CORS parsing for now
		if settings.AccessSettings.GcipSettings != nil {
			info.GCIPTenantIDs = settings.AccessSettings.GcipSettings.TenantIds
		}
		if settings.AccessSettings.ReauthSettings != nil {
			info.ReauthPolicy = settings.AccessSettings.ReauthSettings.Method
		}
	}

	info.RiskLevel, info.RiskReasons = s.analyzeSettingsRisk(*info)

	return info, nil
}

// GetIAPBindings retrieves IAM bindings for an IAP-protected resource
func (s *IAPService) GetIAPBindings(projectID, resourcePath string) ([]IAPBinding, error) {
	ctx := context.Background()
	var service *iap.Service
	var err error

	if s.session != nil {
		service, err = iap.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = iap.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create IAP service: %v", err)
	}

	policy, err := service.V1.GetIamPolicy(resourcePath, &iap.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAP IAM policy: %v", err)
	}

	var bindings []IAPBinding
	for _, binding := range policy.Bindings {
		info := IAPBinding{
			Resource:    resourcePath,
			ProjectID:   projectID,
			Role:        binding.Role,
			Members:     binding.Members,
			RiskReasons: []string{},
		}
		info.RiskLevel, info.RiskReasons = s.analyzeBindingRisk(info)
		bindings = append(bindings, info)
	}

	return bindings, nil
}

func (s *IAPService) analyzeDestGroupRisk(group TunnelDestGroup) (string, []string) {
	var reasons []string
	score := 0

	// Wide CIDR ranges
	for _, cidr := range group.CIDRs {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			reasons = append(reasons, "Allows tunneling to any IP (0.0.0.0/0)")
			score += 3
			break
		}
		// Check for /8 or larger
		if strings.HasSuffix(cidr, "/8") || strings.HasSuffix(cidr, "/0") {
			reasons = append(reasons, fmt.Sprintf("Very broad CIDR range: %s", cidr))
			score += 2
		}
	}

	// Many FQDNs
	if len(group.FQDNs) > 10 {
		reasons = append(reasons, fmt.Sprintf("Large number of FQDNs: %d", len(group.FQDNs)))
		score += 1
	}

	if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *IAPService) analyzeSettingsRisk(settings IAPSettingsInfo) (string, []string) {
	var reasons []string
	score := 0

	// No reauth policy
	if settings.ReauthPolicy == "" || settings.ReauthPolicy == "DISABLED" {
		reasons = append(reasons, "No reauthentication policy configured")
		score += 1
	}

	// Wide CORS
	for _, origin := range settings.CORSAllowedOrigins {
		if origin == "*" {
			reasons = append(reasons, "CORS allows all origins")
			score += 2
			break
		}
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *IAPService) analyzeBindingRisk(binding IAPBinding) (string, []string) {
	var reasons []string
	score := 0

	// Check for public access
	for _, member := range binding.Members {
		if member == "allUsers" {
			reasons = append(reasons, "IAP resource allows allUsers")
			score += 3
		} else if member == "allAuthenticatedUsers" {
			reasons = append(reasons, "IAP resource allows allAuthenticatedUsers")
			score += 2
		}
	}

	// Sensitive roles
	if strings.Contains(binding.Role, "admin") || strings.Contains(binding.Role, "Admin") {
		reasons = append(reasons, fmt.Sprintf("Admin role granted: %s", binding.Role))
		score += 1
	}

	if score >= 3 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func extractName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}
