package sshosloginservice

import (
	"context"
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
	oslogin "google.golang.org/api/oslogin/v1"
)

type SSHOsLoginService struct{}

func New() *SSHOsLoginService {
	return &SSHOsLoginService{}
}

// OSLoginConfig represents the OS Login configuration for a project
type OSLoginConfig struct {
	ProjectID          string   `json:"projectId"`
	OSLoginEnabled     bool     `json:"osLoginEnabled"`
	OSLogin2FAEnabled  bool     `json:"osLogin2FAEnabled"`
	BlockProjectSSHKeys bool    `json:"blockProjectSSHKeys"`
	RiskLevel          string   `json:"riskLevel"`
	RiskReasons        []string `json:"riskReasons"`
}

// SSHKeyInfo represents an SSH key in project or instance metadata
type SSHKeyInfo struct {
	ProjectID    string   `json:"projectId"`
	Username     string   `json:"username"`
	KeyType      string   `json:"keyType"`      // ssh-rsa, ssh-ed25519, etc.
	KeyFingerprint string `json:"keyFingerprint"`
	Source       string   `json:"source"`       // project, instance
	InstanceName string   `json:"instanceName"` // If from instance metadata
	Zone         string   `json:"zone"`
	ExploitCommands []string `json:"exploitCommands"`
}

// InstanceSSHAccess represents SSH access info for an instance
type InstanceSSHAccess struct {
	InstanceName      string   `json:"instanceName"`
	ProjectID         string   `json:"projectId"`
	Zone              string   `json:"zone"`
	ExternalIP        string   `json:"externalIP"`
	InternalIP        string   `json:"internalIP"`
	OSLoginEnabled    bool     `json:"osLoginEnabled"`
	BlockProjectKeys  bool     `json:"blockProjectKeys"`
	SSHKeysCount      int      `json:"sshKeysCount"`
	ServiceAccount    string   `json:"serviceAccount"`
	RiskLevel         string   `json:"riskLevel"`
	RiskReasons       []string `json:"riskReasons"`
	SSHCommands       []string `json:"sshCommands"`
}

// OSLoginUser represents a user with OS Login access
type OSLoginUser struct {
	Email            string   `json:"email"`
	ProjectID        string   `json:"projectId"`
	PosixAccounts    []string `json:"posixAccounts"`
	SSHPublicKeys    int      `json:"sshPublicKeys"`
	CanSSH           bool     `json:"canSSH"`
	CanSudo          bool     `json:"canSudo"`
	RiskLevel        string   `json:"riskLevel"`
	RiskReasons      []string `json:"riskReasons"`
}

// GetProjectOSLoginConfig retrieves OS Login configuration for a project
func (s *SSHOsLoginService) GetProjectOSLoginConfig(projectID string) (*OSLoginConfig, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	config := &OSLoginConfig{
		ProjectID:   projectID,
		RiskReasons: []string{},
	}

	project, err := service.Projects.Get(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %v", err)
	}

	// Check common instance metadata
	if project.CommonInstanceMetadata != nil {
		for _, item := range project.CommonInstanceMetadata.Items {
			switch item.Key {
			case "enable-oslogin":
				if item.Value != nil && strings.ToLower(*item.Value) == "true" {
					config.OSLoginEnabled = true
				}
			case "enable-oslogin-2fa":
				if item.Value != nil && strings.ToLower(*item.Value) == "true" {
					config.OSLogin2FAEnabled = true
				}
			case "block-project-ssh-keys":
				if item.Value != nil && strings.ToLower(*item.Value) == "true" {
					config.BlockProjectSSHKeys = true
				}
			}
		}
	}

	// Analyze risk
	config.RiskLevel, config.RiskReasons = s.analyzeOSLoginRisk(config)

	return config, nil
}

// GetProjectSSHKeys retrieves SSH keys from project metadata
func (s *SSHOsLoginService) GetProjectSSHKeys(projectID string) ([]SSHKeyInfo, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	var keys []SSHKeyInfo

	project, err := service.Projects.Get(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %v", err)
	}

	if project.CommonInstanceMetadata != nil {
		for _, item := range project.CommonInstanceMetadata.Items {
			if item.Key == "ssh-keys" && item.Value != nil {
				parsedKeys := s.parseSSHKeys(*item.Value, projectID, "project", "", "")
				keys = append(keys, parsedKeys...)
			}
		}
	}

	return keys, nil
}

// GetInstanceSSHAccess retrieves SSH access information for all instances
func (s *SSHOsLoginService) GetInstanceSSHAccess(projectID string) ([]InstanceSSHAccess, []SSHKeyInfo, error) {
	ctx := context.Background()
	service, err := compute.NewService(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	var instances []InstanceSSHAccess
	var instanceKeys []SSHKeyInfo

	req := service.Instances.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, scopedList := range page.Items {
			zoneName := zone
			if strings.HasPrefix(zone, "zones/") {
				zoneName = strings.TrimPrefix(zone, "zones/")
			}

			for _, instance := range scopedList.Instances {
				access := InstanceSSHAccess{
					InstanceName: instance.Name,
					ProjectID:    projectID,
					Zone:         zoneName,
					RiskReasons:  []string{},
					SSHCommands:  []string{},
				}

				// Get IPs
				for _, nic := range instance.NetworkInterfaces {
					if access.InternalIP == "" {
						access.InternalIP = nic.NetworkIP
					}
					for _, accessConfig := range nic.AccessConfigs {
						if accessConfig.NatIP != "" {
							access.ExternalIP = accessConfig.NatIP
						}
					}
				}

				// Get service account
				if len(instance.ServiceAccounts) > 0 {
					access.ServiceAccount = instance.ServiceAccounts[0].Email
				}

				// Check instance metadata
				if instance.Metadata != nil {
					for _, item := range instance.Metadata.Items {
						switch item.Key {
						case "enable-oslogin":
							if item.Value != nil && strings.ToLower(*item.Value) == "true" {
								access.OSLoginEnabled = true
							}
						case "block-project-ssh-keys":
							if item.Value != nil && strings.ToLower(*item.Value) == "true" {
								access.BlockProjectKeys = true
							}
						case "ssh-keys":
							if item.Value != nil {
								keys := s.parseSSHKeys(*item.Value, projectID, "instance", instance.Name, zoneName)
								instanceKeys = append(instanceKeys, keys...)
								access.SSHKeysCount = len(keys)
							}
						}
					}
				}

				// Generate SSH commands
				access.SSHCommands = s.generateSSHCommands(access)

				// Analyze risk
				access.RiskLevel, access.RiskReasons = s.analyzeInstanceSSHRisk(access)

				instances = append(instances, access)
			}
		}
		return nil
	})

	return instances, instanceKeys, err
}

// GetOSLoginUsers gets users with OS Login access (requires oslogin API)
func (s *SSHOsLoginService) GetOSLoginUsers(projectID string) ([]OSLoginUser, error) {
	ctx := context.Background()
	_, err := oslogin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create oslogin service: %v", err)
	}

	// Note: OS Login API requires querying per-user, so we return empty
	// The actual users would need to be enumerated from IAM bindings with
	// roles/compute.osLogin, roles/compute.osAdminLogin, roles/compute.osLoginExternalUser

	return []OSLoginUser{}, nil
}

func (s *SSHOsLoginService) parseSSHKeys(sshKeysValue, projectID, source, instanceName, zone string) []SSHKeyInfo {
	var keys []SSHKeyInfo

	lines := strings.Split(sshKeysValue, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: username:ssh-rsa AAAAB3... comment
		// or: ssh-rsa AAAAB3... username
		parts := strings.SplitN(line, ":", 2)

		var username, keyData string
		if len(parts) == 2 {
			username = parts[0]
			keyData = parts[1]
		} else {
			keyData = line
		}

		keyParts := strings.Fields(keyData)
		if len(keyParts) < 2 {
			continue
		}

		keyType := keyParts[0]
		if username == "" && len(keyParts) >= 3 {
			username = keyParts[2]
		}

		key := SSHKeyInfo{
			ProjectID:    projectID,
			Username:     username,
			KeyType:      keyType,
			Source:       source,
			InstanceName: instanceName,
			Zone:         zone,
		}

		// Generate SSH commands
		if source == "instance" && instanceName != "" {
			key.ExploitCommands = []string{
				fmt.Sprintf("# SSH as %s to instance %s:", username, instanceName),
				fmt.Sprintf("gcloud compute ssh %s@%s --zone=%s --project=%s", username, instanceName, zone, projectID),
			}
		} else {
			key.ExploitCommands = []string{
				fmt.Sprintf("# Project-wide SSH key for user: %s", username),
				fmt.Sprintf("# This key grants access to all instances not blocking project keys"),
			}
		}

		keys = append(keys, key)
	}

	return keys
}

func (s *SSHOsLoginService) generateSSHCommands(access InstanceSSHAccess) []string {
	var commands []string

	commands = append(commands,
		fmt.Sprintf("# SSH to instance %s:", access.InstanceName))

	// gcloud command
	commands = append(commands,
		fmt.Sprintf("gcloud compute ssh %s --zone=%s --project=%s", access.InstanceName, access.Zone, access.ProjectID))

	// Direct SSH if external IP
	if access.ExternalIP != "" {
		commands = append(commands,
			fmt.Sprintf("# Direct SSH (if key is authorized):\nssh -i ~/.ssh/google_compute_engine %s", access.ExternalIP))
	}

	// IAP tunnel if no external IP
	if access.ExternalIP == "" {
		commands = append(commands,
			fmt.Sprintf("# Via IAP tunnel (no external IP):\ngcloud compute ssh %s --zone=%s --project=%s --tunnel-through-iap", access.InstanceName, access.Zone, access.ProjectID))
	}

	return commands
}

func (s *SSHOsLoginService) analyzeOSLoginRisk(config *OSLoginConfig) (string, []string) {
	var reasons []string
	score := 0

	if !config.OSLoginEnabled {
		reasons = append(reasons, "OS Login not enabled - using legacy SSH keys")
		score += 2
	}

	if config.OSLoginEnabled && !config.OSLogin2FAEnabled {
		reasons = append(reasons, "OS Login enabled but 2FA not required")
		score += 1
	}

	if !config.BlockProjectSSHKeys && !config.OSLoginEnabled {
		reasons = append(reasons, "Project-wide SSH keys allowed")
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

func (s *SSHOsLoginService) analyzeInstanceSSHRisk(access InstanceSSHAccess) (string, []string) {
	var reasons []string
	score := 0

	if access.ExternalIP != "" && !access.OSLoginEnabled {
		reasons = append(reasons, "External IP with legacy SSH keys")
		score += 2
	}

	if access.SSHKeysCount > 5 {
		reasons = append(reasons, fmt.Sprintf("Many SSH keys configured (%d)", access.SSHKeysCount))
		score += 1
	}

	if !access.BlockProjectKeys && !access.OSLoginEnabled {
		reasons = append(reasons, "Accepts project-wide SSH keys")
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
