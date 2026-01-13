package dnsservice

import (
	"context"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	dns "google.golang.org/api/dns/v1"
)

type DNSService struct{}

func New() *DNSService {
	return &DNSService{}
}

// ZoneInfo holds Cloud DNS managed zone details
type ZoneInfo struct {
	Name              string
	ProjectID         string
	DNSName           string  // The DNS name (e.g., example.com.)
	Description       string
	Visibility        string  // public or private
	CreationTime      string

	// DNSSEC configuration
	DNSSECState       string  // on, off, transfer
	DNSSECKeyType     string

	// Private zone configuration
	PrivateNetworks   []string  // VPC networks for private zones

	// Peering configuration
	PeeringNetwork    string
	PeeringTargetProject string

	// Forwarding configuration
	ForwardingTargets []string

	// Record count
	RecordCount       int64

	// IAM bindings
	IAMBindings       []IAMBinding
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string
	Member string
}

// RecordInfo holds DNS record details
type RecordInfo struct {
	Name        string
	ProjectID   string
	ZoneName    string
	Type        string  // A, AAAA, CNAME, MX, TXT, etc.
	TTL         int64
	RRDatas     []string  // Record data
}

// Zones retrieves all DNS managed zones in a project
func (ds *DNSService) Zones(projectID string) ([]ZoneInfo, error) {
	ctx := context.Background()

	service, err := dns.NewService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	var zones []ZoneInfo

	call := service.ManagedZones.List(projectID)
	err = call.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			info := parseZoneInfo(zone, projectID)
			// Get IAM bindings for the zone
			info.IAMBindings = ds.getZoneIAMBindings(service, ctx, projectID, zone.Name)
			zones = append(zones, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	return zones, nil
}

// Records retrieves all DNS records in a zone
func (ds *DNSService) Records(projectID, zoneName string) ([]RecordInfo, error) {
	ctx := context.Background()

	service, err := dns.NewService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	var records []RecordInfo

	call := service.ResourceRecordSets.List(projectID, zoneName)
	err = call.Pages(ctx, func(page *dns.ResourceRecordSetsListResponse) error {
		for _, rrset := range page.Rrsets {
			info := RecordInfo{
				Name:      rrset.Name,
				ProjectID: projectID,
				ZoneName:  zoneName,
				Type:      rrset.Type,
				TTL:       rrset.Ttl,
				RRDatas:   rrset.Rrdatas,
			}
			records = append(records, info)
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "dns.googleapis.com")
	}

	return records, nil
}

// parseZoneInfo extracts relevant information from a DNS managed zone
func parseZoneInfo(zone *dns.ManagedZone, projectID string) ZoneInfo {
	info := ZoneInfo{
		Name:         zone.Name,
		ProjectID:    projectID,
		DNSName:      zone.DnsName,
		Description:  zone.Description,
		Visibility:   zone.Visibility,
		CreationTime: zone.CreationTime,
	}

	// DNSSEC configuration
	if zone.DnssecConfig != nil {
		info.DNSSECState = zone.DnssecConfig.State
		if len(zone.DnssecConfig.DefaultKeySpecs) > 0 {
			info.DNSSECKeyType = zone.DnssecConfig.DefaultKeySpecs[0].Algorithm
		}
	}

	// Private zone configuration
	if zone.PrivateVisibilityConfig != nil {
		for _, network := range zone.PrivateVisibilityConfig.Networks {
			info.PrivateNetworks = append(info.PrivateNetworks, extractNetworkName(network.NetworkUrl))
		}
	}

	// Peering configuration
	if zone.PeeringConfig != nil && zone.PeeringConfig.TargetNetwork != nil {
		info.PeeringNetwork = extractNetworkName(zone.PeeringConfig.TargetNetwork.NetworkUrl)
		// Extract project from network URL
		if strings.Contains(zone.PeeringConfig.TargetNetwork.NetworkUrl, "/projects/") {
			parts := strings.Split(zone.PeeringConfig.TargetNetwork.NetworkUrl, "/")
			for i, part := range parts {
				if part == "projects" && i+1 < len(parts) {
					info.PeeringTargetProject = parts[i+1]
					break
				}
			}
		}
	}

	// Forwarding configuration
	if zone.ForwardingConfig != nil {
		for _, target := range zone.ForwardingConfig.TargetNameServers {
			info.ForwardingTargets = append(info.ForwardingTargets, target.Ipv4Address)
		}
	}

	return info
}

// extractNetworkName extracts the network name from a network URL
func extractNetworkName(networkURL string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/PROJECT/global/networks/NETWORK
	parts := strings.Split(networkURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return networkURL
}

// getZoneIAMBindings retrieves IAM bindings for a DNS managed zone
func (ds *DNSService) getZoneIAMBindings(service *dns.Service, ctx context.Context, projectID, zoneName string) []IAMBinding {
	var bindings []IAMBinding

	resource := "projects/" + projectID + "/managedZones/" + zoneName
	policy, err := service.ManagedZones.GetIamPolicy(resource, &dns.GoogleIamV1GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		// Return empty bindings if we can't get IAM policy
		return bindings
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}
