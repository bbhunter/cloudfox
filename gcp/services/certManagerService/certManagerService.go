package certmanagerservice

import (
	"context"
	"fmt"
	"strings"
	"time"

	certificatemanager "google.golang.org/api/certificatemanager/v1"
	compute "google.golang.org/api/compute/v1"
)

type CertManagerService struct{}

func New() *CertManagerService {
	return &CertManagerService{}
}

// Certificate represents an SSL/TLS certificate
type Certificate struct {
	Name            string   `json:"name"`
	ProjectID       string   `json:"projectId"`
	Location        string   `json:"location"`
	Type            string   `json:"type"` // SELF_MANAGED, GOOGLE_MANAGED
	Domains         []string `json:"domains"`
	ExpireTime      string   `json:"expireTime"`
	DaysUntilExpiry int      `json:"daysUntilExpiry"`
	State           string   `json:"state"`
	IssuanceState   string   `json:"issuanceState"`
	AttachedTo      []string `json:"attachedTo"` // LBs or other resources
	RiskLevel       string   `json:"riskLevel"`
	RiskReasons     []string `json:"riskReasons"`
}

// SSLCertificate represents a compute SSL certificate (classic)
type SSLCertificate struct {
	Name            string   `json:"name"`
	ProjectID       string   `json:"projectId"`
	Type            string   `json:"type"` // SELF_MANAGED, MANAGED
	Domains         []string `json:"domains"`
	ExpireTime      string   `json:"expireTime"`
	DaysUntilExpiry int      `json:"daysUntilExpiry"`
	CreationTime    string   `json:"creationTime"`
	RiskLevel       string   `json:"riskLevel"`
	RiskReasons     []string `json:"riskReasons"`
}

// CertificateMap represents a Certificate Manager certificate map
type CertificateMap struct {
	Name         string   `json:"name"`
	ProjectID    string   `json:"projectId"`
	Location     string   `json:"location"`
	EntryCount   int      `json:"entryCount"`
	Certificates []string `json:"certificates"`
	RiskLevel    string   `json:"riskLevel"`
	RiskReasons  []string `json:"riskReasons"`
}

// GetCertificates retrieves Certificate Manager certificates
func (s *CertManagerService) GetCertificates(projectID string) ([]Certificate, error) {
	ctx := context.Background()
	service, err := certificatemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate manager service: %v", err)
	}

	var certificates []Certificate

	// List certificates in all locations (global and regional)
	locations := []string{"global"}

	for _, location := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)
		resp, err := service.Projects.Locations.Certificates.List(parent).Context(ctx).Do()
		if err != nil {
			continue // May not have permissions or no certificates
		}

		for _, cert := range resp.Certificates {
			c := Certificate{
				Name:        extractNameFromPath(cert.Name),
				ProjectID:   projectID,
				Location:    location,
				Domains:     cert.SanDnsnames,
				RiskReasons: []string{},
			}

			// Determine type and state
			if cert.Managed != nil {
				c.Type = "GOOGLE_MANAGED"
				c.State = cert.Managed.State
				c.IssuanceState = cert.Managed.State
			} else if cert.SelfManaged != nil {
				c.Type = "SELF_MANAGED"
				c.State = "ACTIVE" // Self-managed certs are active if they exist
			}

			// Parse expiration
			if cert.ExpireTime != "" {
				c.ExpireTime = cert.ExpireTime
				expTime, err := time.Parse(time.RFC3339, cert.ExpireTime)
				if err == nil {
					c.DaysUntilExpiry = int(time.Until(expTime).Hours() / 24)
				}
			}

			// Analyze risk
			c.RiskLevel, c.RiskReasons = s.analyzeCertRisk(c)

			certificates = append(certificates, c)
		}
	}

	return certificates, nil
}

// GetSSLCertificates retrieves classic Compute Engine SSL certificates
func (s *CertManagerService) GetSSLCertificates(projectID string) ([]SSLCertificate, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	var certificates []SSLCertificate

	// Global SSL certificates
	resp, err := service.SslCertificates.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list SSL certificates: %v", err)
	}

	for _, cert := range resp.Items {
		c := SSLCertificate{
			Name:         cert.Name,
			ProjectID:    projectID,
			Type:         cert.Type,
			CreationTime: cert.CreationTimestamp,
			RiskReasons:  []string{},
		}

		// Get domains from managed certificate
		if cert.Managed != nil {
			c.Domains = cert.Managed.Domains
		}

		// Parse expiration
		if cert.ExpireTime != "" {
			c.ExpireTime = cert.ExpireTime
			expTime, err := time.Parse(time.RFC3339, cert.ExpireTime)
			if err == nil {
				c.DaysUntilExpiry = int(time.Until(expTime).Hours() / 24)
			}
		}

		// Analyze risk
		c.RiskLevel, c.RiskReasons = s.analyzeSSLCertRisk(c)

		certificates = append(certificates, c)
	}

	// Regional SSL certificates
	regionsResp, err := service.Regions.List(projectID).Context(ctx).Do()
	if err == nil {
		for _, region := range regionsResp.Items {
			regionalCerts, err := service.RegionSslCertificates.List(projectID, region.Name).Context(ctx).Do()
			if err != nil {
				continue
			}

			for _, cert := range regionalCerts.Items {
				c := SSLCertificate{
					Name:         fmt.Sprintf("%s (%s)", cert.Name, region.Name),
					ProjectID:    projectID,
					Type:         cert.Type,
					CreationTime: cert.CreationTimestamp,
					RiskReasons:  []string{},
				}

				if cert.Managed != nil {
					c.Domains = cert.Managed.Domains
				}

				if cert.ExpireTime != "" {
					c.ExpireTime = cert.ExpireTime
					expTime, err := time.Parse(time.RFC3339, cert.ExpireTime)
					if err == nil {
						c.DaysUntilExpiry = int(time.Until(expTime).Hours() / 24)
					}
				}

				c.RiskLevel, c.RiskReasons = s.analyzeSSLCertRisk(c)
				certificates = append(certificates, c)
			}
		}
	}

	return certificates, nil
}

// GetCertificateMaps retrieves certificate maps
func (s *CertManagerService) GetCertificateMaps(projectID string) ([]CertificateMap, error) {
	ctx := context.Background()
	service, err := certificatemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate manager service: %v", err)
	}

	var maps []CertificateMap

	locations := []string{"global"}

	for _, location := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)
		resp, err := service.Projects.Locations.CertificateMaps.List(parent).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, certMap := range resp.CertificateMaps {
			cm := CertificateMap{
				Name:        extractNameFromPath(certMap.Name),
				ProjectID:   projectID,
				Location:    location,
				RiskReasons: []string{},
			}

			// Get entries for this map
			entriesResp, err := service.Projects.Locations.CertificateMaps.CertificateMapEntries.List(certMap.Name).Context(ctx).Do()
			if err == nil {
				cm.EntryCount = len(entriesResp.CertificateMapEntries)
				for _, entry := range entriesResp.CertificateMapEntries {
					for _, certRef := range entry.Certificates {
						cm.Certificates = append(cm.Certificates, extractNameFromPath(certRef))
					}
				}
			}

			cm.RiskLevel, cm.RiskReasons = s.analyzeMapRisk(cm)
			maps = append(maps, cm)
		}
	}

	return maps, nil
}

func (s *CertManagerService) analyzeCertRisk(cert Certificate) (string, []string) {
	var reasons []string
	score := 0

	// Check expiration
	if cert.DaysUntilExpiry < 0 {
		reasons = append(reasons, "Certificate has EXPIRED!")
		score += 3
	} else if cert.DaysUntilExpiry <= 7 {
		reasons = append(reasons, fmt.Sprintf("Certificate expires in %d day(s) - CRITICAL", cert.DaysUntilExpiry))
		score += 2
	} else if cert.DaysUntilExpiry <= 30 {
		reasons = append(reasons, fmt.Sprintf("Certificate expires in %d day(s)", cert.DaysUntilExpiry))
		score += 1
	}

	// Check state
	if cert.State == "FAILED" {
		reasons = append(reasons, "Certificate in FAILED state")
		score += 2
	}

	// Check issuance state for managed certs
	if cert.Type == "GOOGLE_MANAGED" && cert.IssuanceState != "ACTIVE" {
		reasons = append(reasons, fmt.Sprintf("Managed certificate issuance state: %s", cert.IssuanceState))
		score += 1
	}

	// Self-managed certs need more attention
	if cert.Type == "SELF_MANAGED" {
		reasons = append(reasons, "Self-managed certificate requires manual renewal")
	}

	// Check for wildcard domains (can be abused if key is compromised)
	for _, domain := range cert.Domains {
		if strings.HasPrefix(domain, "*") {
			reasons = append(reasons, fmt.Sprintf("Wildcard certificate: %s", domain))
			break
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

func (s *CertManagerService) analyzeSSLCertRisk(cert SSLCertificate) (string, []string) {
	var reasons []string
	score := 0

	// Check expiration
	if cert.DaysUntilExpiry < 0 {
		reasons = append(reasons, "Certificate has EXPIRED!")
		score += 3
	} else if cert.DaysUntilExpiry <= 7 {
		reasons = append(reasons, fmt.Sprintf("Certificate expires in %d day(s) - CRITICAL", cert.DaysUntilExpiry))
		score += 2
	} else if cert.DaysUntilExpiry <= 30 {
		reasons = append(reasons, fmt.Sprintf("Certificate expires in %d day(s)", cert.DaysUntilExpiry))
		score += 1
	}

	// Self-managed needs more attention
	if cert.Type == "SELF_MANAGED" {
		reasons = append(reasons, "Self-managed certificate requires manual renewal")
	}

	// Check for wildcard
	for _, domain := range cert.Domains {
		if strings.HasPrefix(domain, "*") {
			reasons = append(reasons, fmt.Sprintf("Wildcard certificate: %s", domain))
			break
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

func (s *CertManagerService) analyzeMapRisk(certMap CertificateMap) (string, []string) {
	var reasons []string

	if certMap.EntryCount == 0 {
		reasons = append(reasons, "Certificate map has no entries")
		return "LOW", reasons
	}

	reasons = append(reasons, fmt.Sprintf("Has %d certificate(s)", len(certMap.Certificates)))
	return "INFO", reasons
}

func extractNameFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}
