package loadbalancerservice

import (
	"context"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	compute "google.golang.org/api/compute/v1"
)

type LoadBalancerService struct {
	session *gcpinternal.SafeSession
}

func New() *LoadBalancerService {
	return &LoadBalancerService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *LoadBalancerService {
	return &LoadBalancerService{session: session}
}

// LoadBalancerInfo represents a load balancer configuration
type LoadBalancerInfo struct {
	Name            string   `json:"name"`
	ProjectID       string   `json:"projectId"`
	Type            string   `json:"type"` // HTTP, HTTPS, TCP, SSL, UDP, INTERNAL
	Scheme          string   `json:"scheme"` // EXTERNAL, INTERNAL
	Region          string   `json:"region"` // global or regional
	IPAddress       string   `json:"ipAddress"`
	Port            string   `json:"port"`
	Protocol        string   `json:"protocol"`

	// Backend info
	BackendServices []string `json:"backendServices"`
	BackendBuckets  []string `json:"backendBuckets"`
	HealthChecks    []string `json:"healthChecks"`

	// SSL/TLS config
	SSLPolicy       string   `json:"sslPolicy"`
	SSLCertificates []string `json:"sslCertificates"`
	MinTLSVersion   string   `json:"minTlsVersion"`

	// Security config
	SecurityPolicy  string   `json:"securityPolicy"` // Cloud Armor
}

// SSLPolicyInfo represents an SSL policy
type SSLPolicyInfo struct {
	Name           string   `json:"name"`
	ProjectID      string   `json:"projectId"`
	MinTLSVersion  string   `json:"minTlsVersion"`
	Profile        string   `json:"profile"` // COMPATIBLE, MODERN, RESTRICTED, CUSTOM
	CustomFeatures []string `json:"customFeatures"`
}

// BackendServiceInfo represents a backend service
type BackendServiceInfo struct {
	Name              string   `json:"name"`
	ProjectID         string   `json:"projectId"`
	Protocol          string   `json:"protocol"`
	Port              int64    `json:"port"`
	HealthCheck       string   `json:"healthCheck"`
	SecurityPolicy    string   `json:"securityPolicy"`
	EnableCDN         bool     `json:"enableCdn"`
	SessionAffinity   string   `json:"sessionAffinity"`
	ConnectionDraining int64   `json:"connectionDraining"`
	Backends          []string `json:"backends"`
}

// ListLoadBalancers retrieves all load balancers in a project
func (s *LoadBalancerService) ListLoadBalancers(projectID string) ([]LoadBalancerInfo, error) {
	ctx := context.Background()
	var service *compute.Service
	var err error

	if s.session != nil {
		service, err = compute.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var loadBalancers []LoadBalancerInfo

	// Get global forwarding rules (external HTTP(S), SSL Proxy, TCP Proxy)
	globalFwdRules, err := service.GlobalForwardingRules.List(projectID).Context(ctx).Do()
	if err == nil {
		for _, rule := range globalFwdRules.Items {
			lb := s.parseForwardingRule(rule, projectID, "global")
			loadBalancers = append(loadBalancers, lb)
		}
	}

	// Get regional forwarding rules (internal, network LB)
	regionsResp, err := service.Regions.List(projectID).Context(ctx).Do()
	if err == nil {
		for _, region := range regionsResp.Items {
			regionalRules, err := service.ForwardingRules.List(projectID, region.Name).Context(ctx).Do()
			if err == nil {
				for _, rule := range regionalRules.Items {
					lb := s.parseForwardingRule(rule, projectID, region.Name)
					loadBalancers = append(loadBalancers, lb)
				}
			}
		}
	}

	return loadBalancers, nil
}

// ListSSLPolicies retrieves all SSL policies
func (s *LoadBalancerService) ListSSLPolicies(projectID string) ([]SSLPolicyInfo, error) {
	ctx := context.Background()
	var service *compute.Service
	var err error

	if s.session != nil {
		service, err = compute.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var policies []SSLPolicyInfo

	resp, err := service.SslPolicies.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	for _, policy := range resp.Items {
		info := SSLPolicyInfo{
			Name:           policy.Name,
			ProjectID:      projectID,
			MinTLSVersion:  policy.MinTlsVersion,
			Profile:        policy.Profile,
			CustomFeatures: policy.CustomFeatures,
		}
		policies = append(policies, info)
	}

	return policies, nil
}

// ListBackendServices retrieves all backend services
func (s *LoadBalancerService) ListBackendServices(projectID string) ([]BackendServiceInfo, error) {
	ctx := context.Background()
	var service *compute.Service
	var err error

	if s.session != nil {
		service, err = compute.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = compute.NewService(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	var backends []BackendServiceInfo

	// Global backend services
	globalBackends, err := service.BackendServices.List(projectID).Context(ctx).Do()
	if err == nil {
		for _, backend := range globalBackends.Items {
			info := s.parseBackendService(backend, projectID)
			backends = append(backends, info)
		}
	}

	// Regional backend services
	regionsResp, err := service.Regions.List(projectID).Context(ctx).Do()
	if err == nil {
		for _, region := range regionsResp.Items {
			regionalBackends, err := service.RegionBackendServices.List(projectID, region.Name).Context(ctx).Do()
			if err == nil {
				for _, backend := range regionalBackends.Items {
					info := s.parseRegionalBackendService(backend, projectID, region.Name)
					backends = append(backends, info)
				}
			}
		}
	}

	return backends, nil
}

func (s *LoadBalancerService) parseForwardingRule(rule *compute.ForwardingRule, projectID, region string) LoadBalancerInfo {
	info := LoadBalancerInfo{
		Name:      rule.Name,
		ProjectID: projectID,
		Region:    region,
		IPAddress: rule.IPAddress,
		Port:      rule.PortRange,
		Protocol:  rule.IPProtocol,
	}

	// Determine load balancer type
	if rule.LoadBalancingScheme == "EXTERNAL" || rule.LoadBalancingScheme == "EXTERNAL_MANAGED" {
		info.Scheme = "EXTERNAL"
	} else {
		info.Scheme = "INTERNAL"
	}

	// Determine type based on target
	if rule.Target != "" {
		if strings.Contains(rule.Target, "targetHttpProxies") {
			info.Type = "HTTP"
		} else if strings.Contains(rule.Target, "targetHttpsProxies") {
			info.Type = "HTTPS"
		} else if strings.Contains(rule.Target, "targetSslProxies") {
			info.Type = "SSL_PROXY"
		} else if strings.Contains(rule.Target, "targetTcpProxies") {
			info.Type = "TCP_PROXY"
		} else if strings.Contains(rule.Target, "targetPools") {
			info.Type = "NETWORK"
		} else if strings.Contains(rule.Target, "targetGrpcProxies") {
			info.Type = "GRPC"
		}
	} else if rule.BackendService != "" {
		info.Type = "INTERNAL"
		info.BackendServices = []string{extractName(rule.BackendService)}
	}

	return info
}

func (s *LoadBalancerService) parseBackendService(backend *compute.BackendService, projectID string) BackendServiceInfo {
	info := BackendServiceInfo{
		Name:            backend.Name,
		ProjectID:       projectID,
		Protocol:        backend.Protocol,
		Port:            backend.Port,
		EnableCDN:       backend.EnableCDN,
		SessionAffinity: backend.SessionAffinity,
	}

	if backend.SecurityPolicy != "" {
		info.SecurityPolicy = extractName(backend.SecurityPolicy)
	}

	if len(backend.HealthChecks) > 0 {
		info.HealthCheck = extractName(backend.HealthChecks[0])
	}

	if backend.ConnectionDraining != nil {
		info.ConnectionDraining = backend.ConnectionDraining.DrainingTimeoutSec
	}

	for _, be := range backend.Backends {
		info.Backends = append(info.Backends, extractName(be.Group))
	}

	return info
}

func (s *LoadBalancerService) parseRegionalBackendService(backend *compute.BackendService, projectID, region string) BackendServiceInfo {
	info := s.parseBackendService(backend, projectID)
	return info
}

func extractName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}
