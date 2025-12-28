package publicresourcesservice

import (
	"context"
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1"
	run "google.golang.org/api/run/v2"
	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	storage "google.golang.org/api/storage/v1"
)

type PublicResourcesService struct{}

func New() *PublicResourcesService {
	return &PublicResourcesService{}
}

// PublicResource represents any internet-exposed GCP resource
type PublicResource struct {
	ResourceType    string   // compute, cloudsql, cloudrun, function, gke, bucket, lb
	Name            string
	ProjectID       string
	Location        string
	PublicEndpoint  string   // URL or IP
	Port            string   // Port if applicable
	Protocol        string   // HTTP, HTTPS, TCP, etc.
	AccessLevel     string   // allUsers, allAuthenticatedUsers, authorized-networks, etc.
	ServiceAccount  string   // Associated SA if any
	RiskLevel       string   // CRITICAL, HIGH, MEDIUM, LOW
	RiskReasons     []string
	ExploitCommands []string
}

// EnumeratePublicResources finds all public resources in a project
func (s *PublicResourcesService) EnumeratePublicResources(projectID string) ([]PublicResource, error) {
	var resources []PublicResource

	// Enumerate each resource type
	if computeResources, err := s.getPublicComputeInstances(projectID); err == nil {
		resources = append(resources, computeResources...)
	}

	if sqlResources, err := s.getPublicCloudSQL(projectID); err == nil {
		resources = append(resources, sqlResources...)
	}

	if runResources, err := s.getPublicCloudRun(projectID); err == nil {
		resources = append(resources, runResources...)
	}

	if funcResources, err := s.getPublicFunctions(projectID); err == nil {
		resources = append(resources, funcResources...)
	}

	if gkeResources, err := s.getPublicGKE(projectID); err == nil {
		resources = append(resources, gkeResources...)
	}

	if bucketResources, err := s.getPublicBuckets(projectID); err == nil {
		resources = append(resources, bucketResources...)
	}

	if lbResources, err := s.getPublicLoadBalancers(projectID); err == nil {
		resources = append(resources, lbResources...)
	}

	return resources, nil
}

func (s *PublicResourcesService) getPublicComputeInstances(projectID string) ([]PublicResource, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []PublicResource

	// List all instances across all zones
	req := service.Instances.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, instances := range page.Items {
			zoneName := zone
			if strings.HasPrefix(zone, "zones/") {
				zoneName = strings.TrimPrefix(zone, "zones/")
			}

			for _, instance := range instances.Instances {
				for _, nic := range instance.NetworkInterfaces {
					for _, access := range nic.AccessConfigs {
						if access.NatIP != "" {
							resource := PublicResource{
								ResourceType:   "compute",
								Name:           instance.Name,
								ProjectID:      projectID,
								Location:       zoneName,
								PublicEndpoint: access.NatIP,
								Protocol:       "TCP/UDP",
								AccessLevel:    "Public IP",
								RiskLevel:      "MEDIUM",
								RiskReasons:    []string{"Instance has external IP"},
								ExploitCommands: []string{
									fmt.Sprintf("# Scan for open ports:\nnmap -sV %s", access.NatIP),
									fmt.Sprintf("# SSH if port 22 open:\nssh -i ~/.ssh/google_compute_engine %s", access.NatIP),
									fmt.Sprintf("gcloud compute ssh %s --zone=%s --project=%s", instance.Name, zoneName, projectID),
								},
							}

							// Check service account
							if len(instance.ServiceAccounts) > 0 {
								resource.ServiceAccount = instance.ServiceAccounts[0].Email
							}

							resources = append(resources, resource)
						}
					}
				}
			}
		}
		return nil
	})

	return resources, err
}

func (s *PublicResourcesService) getPublicCloudSQL(projectID string) ([]PublicResource, error) {
	ctx := context.Background()
	service, err := sqladmin.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []PublicResource

	resp, err := service.Instances.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, instance := range resp.Items {
		// Check for public IP
		for _, ip := range instance.IpAddresses {
			if ip.Type == "PRIMARY" && ip.IpAddress != "" {
				// Check if authorized networks include 0.0.0.0/0
				worldAccessible := false
				var authNetworks []string
				if instance.Settings != nil && instance.Settings.IpConfiguration != nil {
					for _, net := range instance.Settings.IpConfiguration.AuthorizedNetworks {
						authNetworks = append(authNetworks, net.Value)
						if net.Value == "0.0.0.0/0" {
							worldAccessible = true
						}
					}
				}

				riskLevel := "MEDIUM"
				riskReasons := []string{"Cloud SQL has public IP"}
				if worldAccessible {
					riskLevel = "CRITICAL"
					riskReasons = append(riskReasons, "Authorized networks include 0.0.0.0/0 (world accessible)")
				}

				port := "3306" // MySQL default
				if strings.Contains(strings.ToLower(instance.DatabaseVersion), "postgres") {
					port = "5432"
				} else if strings.Contains(strings.ToLower(instance.DatabaseVersion), "sqlserver") {
					port = "1433"
				}

				resource := PublicResource{
					ResourceType:   "cloudsql",
					Name:           instance.Name,
					ProjectID:      projectID,
					Location:       instance.Region,
					PublicEndpoint: ip.IpAddress,
					Port:           port,
					Protocol:       "TCP",
					AccessLevel:    fmt.Sprintf("AuthNetworks: %s", strings.Join(authNetworks, ", ")),
					RiskLevel:      riskLevel,
					RiskReasons:    riskReasons,
					ExploitCommands: []string{
						fmt.Sprintf("# Connect via Cloud SQL Proxy:\ngcloud sql connect %s --user=root --project=%s", instance.Name, projectID),
						fmt.Sprintf("# Direct connection (if authorized):\nmysql -h %s -u root -p", ip.IpAddress),
						fmt.Sprintf("# List databases:\ngcloud sql databases list --instance=%s --project=%s", instance.Name, projectID),
						fmt.Sprintf("# List users:\ngcloud sql users list --instance=%s --project=%s", instance.Name, projectID),
					},
				}
				resources = append(resources, resource)
			}
		}
	}

	return resources, nil
}

func (s *PublicResourcesService) getPublicCloudRun(projectID string) ([]PublicResource, error) {
	ctx := context.Background()
	service, err := run.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []PublicResource

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := service.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		return nil, err
	}

	for _, svc := range resp.Services {
		// Check if publicly invokable
		isPublic := false
		accessLevel := "Authenticated"

		// Check IAM for allUsers/allAuthenticatedUsers
		iamResp, err := service.Projects.Locations.Services.GetIamPolicy(svc.Name).Do()
		if err == nil {
			for _, binding := range iamResp.Bindings {
				if binding.Role == "roles/run.invoker" {
					for _, member := range binding.Members {
						if member == "allUsers" {
							isPublic = true
							accessLevel = "allUsers (PUBLIC)"
						} else if member == "allAuthenticatedUsers" {
							isPublic = true
							accessLevel = "allAuthenticatedUsers"
						}
					}
				}
			}
		}

		// Check ingress setting
		ingress := svc.Ingress
		if ingress == "INGRESS_TRAFFIC_ALL" && isPublic {
			riskLevel := "HIGH"
			if accessLevel == "allUsers (PUBLIC)" {
				riskLevel = "CRITICAL"
			}

			// Extract location from service name
			parts := strings.Split(svc.Name, "/")
			location := ""
			if len(parts) >= 4 {
				location = parts[3]
			}

			resource := PublicResource{
				ResourceType:   "cloudrun",
				Name:           svc.Name,
				ProjectID:      projectID,
				Location:       location,
				PublicEndpoint: svc.Uri,
				Port:           "443",
				Protocol:       "HTTPS",
				AccessLevel:    accessLevel,
				RiskLevel:      riskLevel,
				RiskReasons:    []string{"Cloud Run service publicly accessible"},
				ExploitCommands: []string{
					fmt.Sprintf("# Invoke the service:\ncurl -s %s", svc.Uri),
					fmt.Sprintf("# Invoke with auth:\ncurl -s -H \"Authorization: Bearer $(gcloud auth print-identity-token)\" %s", svc.Uri),
					fmt.Sprintf("# Describe service:\ngcloud run services describe %s --region=%s --project=%s", svc.Name, location, projectID),
				},
			}

			if svc.Template != nil && len(svc.Template.Containers) > 0 {
				resource.ServiceAccount = svc.Template.ServiceAccount
			}

			resources = append(resources, resource)
		}
	}

	return resources, nil
}

func (s *PublicResourcesService) getPublicFunctions(projectID string) ([]PublicResource, error) {
	ctx := context.Background()
	service, err := cloudfunctions.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []PublicResource

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := service.Projects.Locations.Functions.List(parent).Do()
	if err != nil {
		return nil, err
	}

	for _, fn := range resp.Functions {
		// Check IAM for public access
		iamResp, err := service.Projects.Locations.Functions.GetIamPolicy(fn.Name).Do()
		if err != nil {
			continue
		}

		isPublic := false
		accessLevel := "Authenticated"
		for _, binding := range iamResp.Bindings {
			if binding.Role == "roles/cloudfunctions.invoker" {
				for _, member := range binding.Members {
					if member == "allUsers" {
						isPublic = true
						accessLevel = "allUsers (PUBLIC)"
					} else if member == "allAuthenticatedUsers" {
						isPublic = true
						accessLevel = "allAuthenticatedUsers"
					}
				}
			}
		}

		if isPublic {
			riskLevel := "HIGH"
			if accessLevel == "allUsers (PUBLIC)" {
				riskLevel = "CRITICAL"
			}

			// Extract location
			parts := strings.Split(fn.Name, "/")
			location := ""
			if len(parts) >= 4 {
				location = parts[3]
			}

			// Get URL from service config
			url := ""
			if fn.ServiceConfig != nil {
				url = fn.ServiceConfig.Uri
			}

			resource := PublicResource{
				ResourceType:   "function",
				Name:           fn.Name,
				ProjectID:      projectID,
				Location:       location,
				PublicEndpoint: url,
				Port:           "443",
				Protocol:       "HTTPS",
				AccessLevel:    accessLevel,
				RiskLevel:      riskLevel,
				RiskReasons:    []string{"Cloud Function publicly invokable"},
				ExploitCommands: []string{
					fmt.Sprintf("# Invoke the function:\ncurl -s %s", url),
					fmt.Sprintf("# Invoke with auth:\ncurl -s -H \"Authorization: Bearer $(gcloud auth print-identity-token)\" %s", url),
					fmt.Sprintf("# Describe function:\ngcloud functions describe %s --region=%s --project=%s --gen2", fn.Name, location, projectID),
				},
			}

			if fn.ServiceConfig != nil {
				resource.ServiceAccount = fn.ServiceConfig.ServiceAccountEmail
			}

			resources = append(resources, resource)
		}
	}

	return resources, nil
}

func (s *PublicResourcesService) getPublicGKE(projectID string) ([]PublicResource, error) {
	ctx := context.Background()
	service, err := container.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []PublicResource

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := service.Projects.Locations.Clusters.List(parent).Do()
	if err != nil {
		return nil, err
	}

	for _, cluster := range resp.Clusters {
		isPublic := false
		riskReasons := []string{}

		// Check if cluster has public endpoint
		if cluster.PrivateClusterConfig == nil || !cluster.PrivateClusterConfig.EnablePrivateEndpoint {
			if cluster.Endpoint != "" {
				isPublic = true
				riskReasons = append(riskReasons, "GKE API endpoint is public")
			}
		}

		// Check master authorized networks
		if cluster.MasterAuthorizedNetworksConfig == nil || !cluster.MasterAuthorizedNetworksConfig.Enabled {
			riskReasons = append(riskReasons, "No master authorized networks configured")
		}

		if isPublic {
			riskLevel := "MEDIUM"
			if len(riskReasons) > 1 {
				riskLevel = "HIGH"
			}

			resource := PublicResource{
				ResourceType:   "gke",
				Name:           cluster.Name,
				ProjectID:      projectID,
				Location:       cluster.Location,
				PublicEndpoint: cluster.Endpoint,
				Port:           "443",
				Protocol:       "HTTPS",
				AccessLevel:    "Public API",
				RiskLevel:      riskLevel,
				RiskReasons:    riskReasons,
				ExploitCommands: []string{
					fmt.Sprintf("# Get cluster credentials:\ngcloud container clusters get-credentials %s --location=%s --project=%s", cluster.Name, cluster.Location, projectID),
					"# Check permissions:\nkubectl auth can-i --list",
					"# List namespaces:\nkubectl get namespaces",
					"# List pods:\nkubectl get pods -A",
				},
			}
			resources = append(resources, resource)
		}
	}

	return resources, nil
}

func (s *PublicResourcesService) getPublicBuckets(projectID string) ([]PublicResource, error) {
	ctx := context.Background()
	service, err := storage.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []PublicResource

	resp, err := service.Buckets.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, bucket := range resp.Items {
		// Check IAM policy for public access
		iamResp, err := service.Buckets.GetIamPolicy(bucket.Name).Do()
		if err != nil {
			continue
		}

		isPublic := false
		accessLevel := "Private"
		publicRoles := []string{}

		for _, binding := range iamResp.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					isPublic = true
					accessLevel = member
					publicRoles = append(publicRoles, binding.Role)
				}
			}
		}

		if isPublic {
			riskLevel := "HIGH"
			riskReasons := []string{fmt.Sprintf("Bucket accessible by %s", accessLevel)}
			for _, role := range publicRoles {
				riskReasons = append(riskReasons, fmt.Sprintf("Public role: %s", role))
				if strings.Contains(role, "objectAdmin") || strings.Contains(role, "storage.admin") {
					riskLevel = "CRITICAL"
				}
			}

			resource := PublicResource{
				ResourceType:   "bucket",
				Name:           bucket.Name,
				ProjectID:      projectID,
				Location:       bucket.Location,
				PublicEndpoint: fmt.Sprintf("https://storage.googleapis.com/%s", bucket.Name),
				Protocol:       "HTTPS",
				AccessLevel:    accessLevel,
				RiskLevel:      riskLevel,
				RiskReasons:    riskReasons,
				ExploitCommands: []string{
					fmt.Sprintf("# List bucket contents:\ngsutil ls gs://%s/", bucket.Name),
					fmt.Sprintf("# Download all files:\ngsutil -m cp -r gs://%s/ ./loot/", bucket.Name),
					fmt.Sprintf("# Check for sensitive files:\ngsutil ls -r gs://%s/ | grep -iE '\\.(pem|key|json|env|tfstate|sql|bak)'", bucket.Name),
				},
			}
			resources = append(resources, resource)
		}
	}

	return resources, nil
}

func (s *PublicResourcesService) getPublicLoadBalancers(projectID string) ([]PublicResource, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []PublicResource

	// Get global forwarding rules (external load balancers)
	resp, err := service.GlobalForwardingRules.List(projectID).Do()
	if err != nil {
		return nil, err
	}

	for _, rule := range resp.Items {
		if rule.IPAddress != "" {
			resource := PublicResource{
				ResourceType:   "loadbalancer",
				Name:           rule.Name,
				ProjectID:      projectID,
				Location:       "global",
				PublicEndpoint: rule.IPAddress,
				Port:           rule.PortRange,
				Protocol:       rule.IPProtocol,
				AccessLevel:    "Public",
				RiskLevel:      "LOW",
				RiskReasons:    []string{"External load balancer with public IP"},
				ExploitCommands: []string{
					fmt.Sprintf("# Scan the endpoint:\nnmap -sV %s", rule.IPAddress),
					fmt.Sprintf("# Test HTTP:\ncurl -v http://%s/", rule.IPAddress),
					fmt.Sprintf("# Test HTTPS:\ncurl -vk https://%s/", rule.IPAddress),
				},
			}
			resources = append(resources, resource)
		}
	}

	return resources, nil
}
