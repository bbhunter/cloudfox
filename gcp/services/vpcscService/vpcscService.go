package vpcscservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
)

type VPCSCService struct {
	session *gcpinternal.SafeSession
}

func New() *VPCSCService {
	return &VPCSCService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *VPCSCService {
	return &VPCSCService{session: session}
}

// AccessPolicyInfo represents an access policy
type AccessPolicyInfo struct {
	Name       string `json:"name"`
	Title      string `json:"title"`
	Parent     string `json:"parent"`
	Etag       string `json:"etag"`
	CreateTime string `json:"createTime"`
	UpdateTime string `json:"updateTime"`
}

// ServicePerimeterInfo represents a VPC Service Control perimeter
type ServicePerimeterInfo struct {
	Name               string   `json:"name"`
	Title              string   `json:"title"`
	PolicyName         string   `json:"policyName"`
	PerimeterType      string   `json:"perimeterType"` // PERIMETER_TYPE_REGULAR or PERIMETER_TYPE_BRIDGE
	Description        string   `json:"description"`
	CreateTime         string   `json:"createTime"`
	UpdateTime         string   `json:"updateTime"`

	// Status configuration
	Resources           []string `json:"resources"`           // Projects in the perimeter
	RestrictedServices  []string `json:"restrictedServices"`  // Services protected
	AccessLevels        []string `json:"accessLevels"`        // Access levels allowed
	VPCAccessibleServices []string `json:"vpcAccessibleServices"`

	// Ingress/Egress policies
	IngressPolicyCount  int      `json:"ingressPolicyCount"`
	EgressPolicyCount   int      `json:"egressPolicyCount"`
	HasIngressRules     bool     `json:"hasIngressRules"`
	HasEgressRules      bool     `json:"hasEgressRules"`

	// Security analysis
	RiskLevel           string   `json:"riskLevel"`
	RiskReasons         []string `json:"riskReasons"`
}

// AccessLevelInfo represents an access level
type AccessLevelInfo struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	PolicyName  string   `json:"policyName"`
	Description string   `json:"description"`
	CreateTime  string   `json:"createTime"`
	UpdateTime  string   `json:"updateTime"`

	// Conditions
	IPSubnetworks []string `json:"ipSubnetworks"`
	Regions       []string `json:"regions"`
	Members       []string `json:"members"`

	// Security analysis
	RiskLevel    string   `json:"riskLevel"`
	RiskReasons  []string `json:"riskReasons"`
}

// ListAccessPolicies retrieves all access policies for an organization
func (s *VPCSCService) ListAccessPolicies(orgID string) ([]AccessPolicyInfo, error) {
	ctx := context.Background()
	var service *accesscontextmanager.Service
	var err error

	if s.session != nil {
		service, err = accesscontextmanager.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = accesscontextmanager.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Access Context Manager service: %v", err)
	}

	var policies []AccessPolicyInfo

	// List access policies for the organization
	parent := fmt.Sprintf("organizations/%s", orgID)
	req := service.AccessPolicies.List().Parent(parent)
	err = req.Pages(ctx, func(page *accesscontextmanager.ListAccessPoliciesResponse) error {
		for _, policy := range page.AccessPolicies {
			info := AccessPolicyInfo{
				Name:   extractPolicyName(policy.Name),
				Title:  policy.Title,
				Parent: policy.Parent,
				Etag:   policy.Etag,
			}
			policies = append(policies, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list access policies: %v", err)
	}

	return policies, nil
}

// ListServicePerimeters retrieves all service perimeters for an access policy
func (s *VPCSCService) ListServicePerimeters(policyName string) ([]ServicePerimeterInfo, error) {
	ctx := context.Background()
	var service *accesscontextmanager.Service
	var err error

	if s.session != nil {
		service, err = accesscontextmanager.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = accesscontextmanager.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Access Context Manager service: %v", err)
	}

	var perimeters []ServicePerimeterInfo

	parent := fmt.Sprintf("accessPolicies/%s", policyName)
	req := service.AccessPolicies.ServicePerimeters.List(parent)
	err = req.Pages(ctx, func(page *accesscontextmanager.ListServicePerimetersResponse) error {
		for _, perimeter := range page.ServicePerimeters {
			info := s.parsePerimeter(perimeter, policyName)
			perimeters = append(perimeters, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list service perimeters: %v", err)
	}

	return perimeters, nil
}

// ListAccessLevels retrieves all access levels for an access policy
func (s *VPCSCService) ListAccessLevels(policyName string) ([]AccessLevelInfo, error) {
	ctx := context.Background()
	var service *accesscontextmanager.Service
	var err error

	if s.session != nil {
		service, err = accesscontextmanager.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = accesscontextmanager.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Access Context Manager service: %v", err)
	}

	var levels []AccessLevelInfo

	parent := fmt.Sprintf("accessPolicies/%s", policyName)
	req := service.AccessPolicies.AccessLevels.List(parent)
	err = req.Pages(ctx, func(page *accesscontextmanager.ListAccessLevelsResponse) error {
		for _, level := range page.AccessLevels {
			info := s.parseAccessLevel(level, policyName)
			levels = append(levels, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list access levels: %v", err)
	}

	return levels, nil
}

func (s *VPCSCService) parsePerimeter(perimeter *accesscontextmanager.ServicePerimeter, policyName string) ServicePerimeterInfo {
	info := ServicePerimeterInfo{
		Name:          extractPerimeterName(perimeter.Name),
		Title:         perimeter.Title,
		PolicyName:    policyName,
		PerimeterType: perimeter.PerimeterType,
		Description:   perimeter.Description,
		RiskReasons:   []string{},
	}

	// Parse status configuration
	if perimeter.Status != nil {
		info.Resources = perimeter.Status.Resources
		info.RestrictedServices = perimeter.Status.RestrictedServices
		info.AccessLevels = perimeter.Status.AccessLevels

		if perimeter.Status.VpcAccessibleServices != nil {
			info.VPCAccessibleServices = perimeter.Status.VpcAccessibleServices.AllowedServices
		}

		if len(perimeter.Status.IngressPolicies) > 0 {
			info.IngressPolicyCount = len(perimeter.Status.IngressPolicies)
			info.HasIngressRules = true
		}

		if len(perimeter.Status.EgressPolicies) > 0 {
			info.EgressPolicyCount = len(perimeter.Status.EgressPolicies)
			info.HasEgressRules = true
		}
	}

	info.RiskLevel, info.RiskReasons = s.analyzePerimeterRisk(info)

	return info
}

func (s *VPCSCService) parseAccessLevel(level *accesscontextmanager.AccessLevel, policyName string) AccessLevelInfo {
	info := AccessLevelInfo{
		Name:        extractLevelName(level.Name),
		Title:       level.Title,
		PolicyName:  policyName,
		Description: level.Description,
		RiskReasons: []string{},
	}

	if level.Basic != nil && len(level.Basic.Conditions) > 0 {
		for _, condition := range level.Basic.Conditions {
			info.IPSubnetworks = append(info.IPSubnetworks, condition.IpSubnetworks...)
			info.Regions = append(info.Regions, condition.Regions...)
			info.Members = append(info.Members, condition.Members...)
		}
	}

	info.RiskLevel, info.RiskReasons = s.analyzeAccessLevelRisk(info)

	return info
}

func (s *VPCSCService) analyzePerimeterRisk(perimeter ServicePerimeterInfo) (string, []string) {
	var reasons []string
	score := 0

	// No restricted services
	if len(perimeter.RestrictedServices) == 0 {
		reasons = append(reasons, "No services are restricted by perimeter")
		score += 2
	}

	// Permissive ingress rules
	if perimeter.HasIngressRules {
		reasons = append(reasons, fmt.Sprintf("Has %d ingress policies (review for overly permissive rules)", perimeter.IngressPolicyCount))
		score += 1
	}

	// Permissive egress rules
	if perimeter.HasEgressRules {
		reasons = append(reasons, fmt.Sprintf("Has %d egress policies (review for data exfiltration risk)", perimeter.EgressPolicyCount))
		score += 1
	}

	// No resources protected
	if len(perimeter.Resources) == 0 {
		reasons = append(reasons, "No resources are protected by perimeter")
		score += 2
	}

	// Bridge perimeter (less restrictive by design)
	if perimeter.PerimeterType == "PERIMETER_TYPE_BRIDGE" {
		reasons = append(reasons, "Bridge perimeter - allows cross-perimeter access")
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

func (s *VPCSCService) analyzeAccessLevelRisk(level AccessLevelInfo) (string, []string) {
	var reasons []string
	score := 0

	// Check for overly broad IP ranges
	for _, ip := range level.IPSubnetworks {
		if ip == "0.0.0.0/0" || ip == "::/0" {
			reasons = append(reasons, "Access level allows all IP addresses")
			score += 3
			break
		}
	}

	// No IP restrictions
	if len(level.IPSubnetworks) == 0 && len(level.Regions) == 0 && len(level.Members) == 0 {
		reasons = append(reasons, "Access level has no restrictions defined")
		score += 2
	}

	// allUsers or allAuthenticatedUsers
	for _, member := range level.Members {
		if member == "allUsers" || member == "allAuthenticatedUsers" {
			reasons = append(reasons, fmt.Sprintf("Access level includes %s", member))
			score += 3
		}
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

func extractPolicyName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return fullName
}

func extractPerimeterName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return fullName
}

func extractLevelName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return fullName
}
