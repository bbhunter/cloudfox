package cloudarmorservice

import (
	"context"
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
)

type CloudArmorService struct{}

func New() *CloudArmorService {
	return &CloudArmorService{}
}

// SecurityPolicy represents a Cloud Armor security policy
type SecurityPolicy struct {
	Name              string              `json:"name"`
	ProjectID         string              `json:"projectId"`
	Description       string              `json:"description"`
	Type              string              `json:"type"` // CLOUD_ARMOR, CLOUD_ARMOR_EDGE, CLOUD_ARMOR_NETWORK
	RuleCount         int                 `json:"ruleCount"`
	Rules             []SecurityRule      `json:"rules"`
	AdaptiveProtection bool               `json:"adaptiveProtection"`
	DDOSProtection    string              `json:"ddosProtection"`
	AttachedResources []string            `json:"attachedResources"`
	RiskLevel         string              `json:"riskLevel"`
	RiskReasons       []string            `json:"riskReasons"`
	Weaknesses        []string            `json:"weaknesses"`
}

// SecurityRule represents a rule within a security policy
type SecurityRule struct {
	Priority    int64    `json:"priority"`
	Description string   `json:"description"`
	Action      string   `json:"action"` // allow, deny, redirect, rate_based_ban, throttle
	Match       string   `json:"match"`  // Simplified match expression
	Preview     bool     `json:"preview"`
	RateLimitConfig *RateLimitInfo `json:"rateLimitConfig,omitempty"`
}

// RateLimitInfo contains rate limiting configuration
type RateLimitInfo struct {
	ThresholdCount int64  `json:"thresholdCount"`
	IntervalSec    int64  `json:"intervalSec"`
	ExceedAction   string `json:"exceedAction"`
}

// GetSecurityPolicies retrieves all Cloud Armor security policies
func (s *CloudArmorService) GetSecurityPolicies(projectID string) ([]SecurityPolicy, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	var policies []SecurityPolicy

	// List security policies
	resp, err := service.SecurityPolicies.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list security policies: %v", err)
	}

	for _, policy := range resp.Items {
		sp := SecurityPolicy{
			Name:              policy.Name,
			ProjectID:         projectID,
			Description:       policy.Description,
			Type:              policy.Type,
			RuleCount:         len(policy.Rules),
			Rules:             []SecurityRule{},
			AttachedResources: []string{},
			RiskReasons:       []string{},
			Weaknesses:        []string{},
		}

		// Check adaptive protection
		if policy.AdaptiveProtectionConfig != nil &&
		   policy.AdaptiveProtectionConfig.Layer7DdosDefenseConfig != nil {
			sp.AdaptiveProtection = policy.AdaptiveProtectionConfig.Layer7DdosDefenseConfig.Enable
		}

		// Check DDoS protection
		if policy.DdosProtectionConfig != nil {
			sp.DDOSProtection = policy.DdosProtectionConfig.DdosProtection
		}

		// Parse rules
		for _, rule := range policy.Rules {
			sr := SecurityRule{
				Priority:    rule.Priority,
				Description: rule.Description,
				Action:      rule.Action,
				Preview:     rule.Preview,
			}

			// Parse match expression
			if rule.Match != nil {
				if rule.Match.Expr != nil {
					sr.Match = rule.Match.Expr.Expression
				} else if rule.Match.VersionedExpr != "" {
					sr.Match = rule.Match.VersionedExpr
				} else if rule.Match.Config != nil {
					// Source IP ranges
					if len(rule.Match.Config.SrcIpRanges) > 0 {
						sr.Match = fmt.Sprintf("srcIpRanges: %s", strings.Join(rule.Match.Config.SrcIpRanges, ", "))
					}
				}
			}

			// Rate limit config
			if rule.RateLimitOptions != nil {
				sr.RateLimitConfig = &RateLimitInfo{
					ExceedAction: rule.RateLimitOptions.ExceedAction,
				}
				if rule.RateLimitOptions.RateLimitThreshold != nil {
					sr.RateLimitConfig.ThresholdCount = rule.RateLimitOptions.RateLimitThreshold.Count
					sr.RateLimitConfig.IntervalSec = rule.RateLimitOptions.RateLimitThreshold.IntervalSec
				}
			}

			sp.Rules = append(sp.Rules, sr)
		}

		// Find attached resources (backend services using this policy)
		sp.AttachedResources = s.findAttachedResources(ctx, service, projectID, policy.Name)

		// Analyze for weaknesses
		sp.RiskLevel, sp.RiskReasons, sp.Weaknesses = s.analyzePolicy(sp)

		policies = append(policies, sp)
	}

	return policies, nil
}

// findAttachedResources finds backend services using this security policy
func (s *CloudArmorService) findAttachedResources(ctx context.Context, service *compute.Service, projectID, policyName string) []string {
	var resources []string

	// Check backend services
	backendServices, err := service.BackendServices.List(projectID).Context(ctx).Do()
	if err == nil {
		for _, bs := range backendServices.Items {
			if bs.SecurityPolicy != "" && strings.HasSuffix(bs.SecurityPolicy, "/"+policyName) {
				resources = append(resources, fmt.Sprintf("backend-service:%s", bs.Name))
			}
		}
	}

	return resources
}

// analyzePolicy checks for security weaknesses in the policy
func (s *CloudArmorService) analyzePolicy(policy SecurityPolicy) (string, []string, []string) {
	var reasons []string
	var weaknesses []string
	score := 0

	// Check if policy is attached to anything
	if len(policy.AttachedResources) == 0 {
		weaknesses = append(weaknesses, "Policy not attached to any backend service - not protecting anything")
		score += 1
	} else {
		reasons = append(reasons, fmt.Sprintf("Protecting %d resource(s)", len(policy.AttachedResources)))
	}

	// Check for overly permissive rules
	hasDefaultAllow := false
	hasDenyRules := false
	previewOnlyCount := 0
	allowAllIPsCount := 0

	for _, rule := range policy.Rules {
		if rule.Priority == 2147483647 && rule.Action == "allow" {
			hasDefaultAllow = true
		}
		if strings.HasPrefix(rule.Action, "deny") {
			hasDenyRules = true
		}
		if rule.Preview {
			previewOnlyCount++
		}
		// Check for allow rules that match all IPs
		if rule.Action == "allow" && (rule.Match == "*" || rule.Match == "srcIpRanges: *" ||
		   strings.Contains(rule.Match, "0.0.0.0/0") || rule.Match == "true") {
			allowAllIPsCount++
		}
	}

	if hasDefaultAllow && !hasDenyRules {
		weaknesses = append(weaknesses, "Default allow rule with no deny rules - policy does nothing useful")
		score += 2
	}

	if previewOnlyCount > 0 {
		weaknesses = append(weaknesses, fmt.Sprintf("%d rule(s) in preview mode - not actively blocking", previewOnlyCount))
		score += 1
	}

	if allowAllIPsCount > 0 && !hasDenyRules {
		weaknesses = append(weaknesses, "Has allow-all rules without deny rules - effectively no protection")
		score += 2
	}

	// Check adaptive protection
	if !policy.AdaptiveProtection {
		weaknesses = append(weaknesses, "Adaptive protection not enabled - reduced DDoS defense")
		score += 1
	} else {
		reasons = append(reasons, "Adaptive protection enabled")
	}

	// Check for common WAF bypass patterns
	hasOWASPRules := false
	hasGeoRules := false
	hasBotRules := false

	for _, rule := range policy.Rules {
		matchLower := strings.ToLower(rule.Match)
		if strings.Contains(matchLower, "sqli") || strings.Contains(matchLower, "xss") ||
		   strings.Contains(matchLower, "rce") || strings.Contains(matchLower, "lfi") {
			hasOWASPRules = true
		}
		if strings.Contains(matchLower, "origin.region_code") {
			hasGeoRules = true
		}
		if strings.Contains(matchLower, "request.headers") &&
		   (strings.Contains(matchLower, "user-agent") || strings.Contains(matchLower, "bot")) {
			hasBotRules = true
		}
	}

	if !hasOWASPRules {
		weaknesses = append(weaknesses, "No OWASP/WAF rules detected (SQLi, XSS, RCE, LFI)")
	}

	if len(policy.Rules) > 0 {
		reasons = append(reasons, fmt.Sprintf("Has %d rule(s)", len(policy.Rules)))
	}

	if hasGeoRules {
		reasons = append(reasons, "Has geo-blocking rules")
	}

	if hasBotRules {
		reasons = append(reasons, "Has bot protection rules")
	}

	// Determine risk level based on weaknesses
	if score >= 4 {
		return "HIGH", reasons, weaknesses
	} else if score >= 2 {
		return "MEDIUM", reasons, weaknesses
	} else if score >= 1 {
		return "LOW", reasons, weaknesses
	}
	return "INFO", reasons, weaknesses
}

// GetUnprotectedLoadBalancers finds load balancers without Cloud Armor protection
func (s *CloudArmorService) GetUnprotectedLoadBalancers(projectID string) ([]string, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	var unprotected []string

	// Get all backend services
	backendServices, err := service.BackendServices.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, bs := range backendServices.Items {
		if bs.SecurityPolicy == "" {
			unprotected = append(unprotected, bs.Name)
		}
	}

	return unprotected, nil
}
