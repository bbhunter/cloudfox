package computeengineservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/internal/gcp/sdk"
	"google.golang.org/api/compute/v1"
)

type ComputeEngineService struct {
	session *gcpinternal.SafeSession
}

// New creates a new ComputeEngineService (legacy - uses ADC directly)
func New() *ComputeEngineService {
	return &ComputeEngineService{}
}

// NewWithSession creates a ComputeEngineService with a SafeSession for managed authentication
func NewWithSession(session *gcpinternal.SafeSession) *ComputeEngineService {
	return &ComputeEngineService{session: session}
}

// ServiceAccountInfo contains service account details for an instance
type ServiceAccountInfo struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

// IAMBinding represents a single IAM role binding
type IAMBinding struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

// ComputeEngineInfo contains instance metadata and security-relevant configuration
type ComputeEngineInfo struct {
	// Basic info
	Name      string `json:"name"`
	ID        string `json:"id"`
	Zone      string `json:"zone"`
	State     string `json:"state"`
	ProjectID string `json:"projectID"`

	// Network configuration
	ExternalIP        string                      `json:"externalIP"`
	InternalIP        string                      `json:"internalIP"`
	NetworkInterfaces []*compute.NetworkInterface `json:"networkInterfaces"`
	CanIPForward      bool                        `json:"canIpForward"` // Can forward packets (router/NAT)

	// Service accounts and scopes
	ServiceAccounts []ServiceAccountInfo `json:"serviceAccounts"`
	HasDefaultSA    bool                 `json:"hasDefaultSA"`   // Uses default compute SA
	HasCloudScopes  bool                 `json:"hasCloudScopes"` // Has cloud-platform or other broad scopes

	// Security configuration
	DeletionProtection  bool `json:"deletionProtection"`  // Protected against deletion
	ShieldedVM          bool `json:"shieldedVM"`          // Shielded VM enabled
	SecureBoot          bool `json:"secureBoot"`          // Secure Boot enabled
	VTPMEnabled         bool `json:"vtpmEnabled"`         // vTPM enabled
	IntegrityMonitoring bool `json:"integrityMonitoring"` // Integrity monitoring enabled
	ConfidentialVM      bool `json:"confidentialVM"`      // Confidential computing enabled

	// Instance metadata
	MachineType string            `json:"machineType"`
	Tags        *compute.Tags     `json:"tags"`
	Labels      map[string]string `json:"labels"`

	// Metadata security
	HasStartupScript    bool `json:"hasStartupScript"`    // Has startup script in metadata
	HasSSHKeys          bool `json:"hasSSHKeys"`          // Has SSH keys in metadata
	BlockProjectSSHKeys bool `json:"blockProjectSSHKeys"` // Blocks project-wide SSH keys
	OSLoginEnabled      bool `json:"osLoginEnabled"`      // OS Login enabled
	OSLogin2FAEnabled   bool `json:"osLogin2FAEnabled"`   // OS Login 2FA enabled
	SerialPortEnabled   bool `json:"serialPortEnabled"`   // Serial port access enabled

	// Pentest-specific fields: actual content extraction
	StartupScriptContent string            `json:"startupScriptContent"` // Actual startup script content
	StartupScriptURL     string            `json:"startupScriptURL"`     // URL to startup script if remote
	SSHKeys              []string          `json:"sshKeys"`              // Extracted SSH keys
	CustomMetadata       []string          `json:"customMetadata"`       // Other custom metadata keys
	RawMetadata          map[string]string `json:"rawMetadata"`          // Full raw metadata key-value pairs
	SensitiveMetadata    []SensitiveItem   `json:"sensitiveMetadata"`    // Detected sensitive items in metadata

	// Disk encryption
	BootDiskEncryption string `json:"bootDiskEncryption"` // "Google-managed", "CMEK", or "CSEK"
	BootDiskKMSKey     string `json:"bootDiskKMSKey"`     // KMS key for CMEK

	// Timestamps
	CreationTimestamp  string `json:"creationTimestamp"`
	LastStartTimestamp string `json:"lastStartTimestamp"`

	// IAM bindings
	IAMBindings []IAMBinding `json:"iamBindings"`
}

// ProjectMetadataInfo contains project-level metadata security info
type ProjectMetadataInfo struct {
	ProjectID               string            `json:"projectId"`
	HasProjectSSHKeys       bool              `json:"hasProjectSSHKeys"`
	ProjectSSHKeys          []string          `json:"projectSSHKeys"`
	HasProjectStartupScript bool              `json:"hasProjectStartupScript"`
	ProjectStartupScript    string            `json:"projectStartupScript"`
	OSLoginEnabled          bool              `json:"osLoginEnabled"`
	OSLogin2FAEnabled       bool              `json:"osLogin2FAEnabled"`
	SerialPortEnabled       bool              `json:"serialPortEnabled"`
	CustomMetadataKeys      []string          `json:"customMetadataKeys"`
	RawMetadata             map[string]string `json:"rawMetadata"`
	SensitiveMetadata       []SensitiveItem   `json:"sensitiveMetadata"`
}

// InstanceIAMInfo contains IAM policy info for an instance
type InstanceIAMInfo struct {
	InstanceName    string   `json:"instanceName"`
	Zone            string   `json:"zone"`
	ProjectID       string   `json:"projectId"`
	ComputeAdmins   []string `json:"computeAdmins"`   // compute.admin or owner
	InstanceAdmins  []string `json:"instanceAdmins"`  // compute.instanceAdmin
	SSHUsers        []string `json:"sshUsers"`        // compute.osLogin or osAdminLogin
	MetadataSetters []string `json:"metadataSetters"` // compute.instances.setMetadata
}

// getService returns a compute service, using session if available
func (ces *ComputeEngineService) getService(ctx context.Context) (*compute.Service, error) {
	if ces.session != nil {
		return sdk.CachedGetComputeService(ctx, ces.session)
	}
	return compute.NewService(ctx)
}

// getInstanceIAMBindings retrieves all IAM bindings for an instance
func (ces *ComputeEngineService) getInstanceIAMBindings(service *compute.Service, projectID, zone, instanceName string) []IAMBinding {
	ctx := context.Background()

	policy, err := service.Instances.GetIamPolicy(projectID, zone, instanceName).Context(ctx).Do()
	if err != nil {
		return nil
	}

	var bindings []IAMBinding
	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}
		for _, member := range binding.Members {
			bindings = append(bindings, IAMBinding{
				Role:   binding.Role,
				Member: member,
			})
		}
	}

	return bindings
}

// Retrieves instances from all regions and zones for a project without using concurrency.
func (ces *ComputeEngineService) Instances(projectID string) ([]ComputeEngineInfo, error) {
	ctx := context.Background()
	computeService, err := ces.getService(ctx)
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	// Use AggregatedList to get all instances across all zones in one call
	// This only requires compute.instances.list permission (not compute.regions.list)
	var instanceInfos []ComputeEngineInfo

	req := computeService.Instances.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for scopeName, scopedList := range page.Items {
			if scopedList.Instances == nil {
				continue
			}
			// Extract zone from scope name (format: "zones/us-central1-a")
			zone := ""
			if strings.HasPrefix(scopeName, "zones/") {
				zone = strings.TrimPrefix(scopeName, "zones/")
			}

			for _, instance := range scopedList.Instances {
				info := ComputeEngineInfo{
					Name:               instance.Name,
					ID:                 fmt.Sprintf("%v", instance.Id),
					Zone:               zone,
					State:              instance.Status,
					ExternalIP:         getExternalIP(instance),
					InternalIP:         getInternalIP(instance),
					NetworkInterfaces:  instance.NetworkInterfaces,
					CanIPForward:       instance.CanIpForward,
					Tags:               instance.Tags,
					Labels:             instance.Labels,
					ProjectID:          projectID,
					DeletionProtection: instance.DeletionProtection,
					CreationTimestamp:  instance.CreationTimestamp,
					LastStartTimestamp: instance.LastStartTimestamp,
				}

				// Parse machine type (extract just the type name)
				info.MachineType = getMachineTypeName(instance.MachineType)

				// Parse service accounts and scopes
				info.ServiceAccounts, info.HasDefaultSA, info.HasCloudScopes = parseServiceAccounts(instance.ServiceAccounts, projectID)

				// Parse shielded VM config
				if instance.ShieldedInstanceConfig != nil {
					info.ShieldedVM = true
					info.SecureBoot = instance.ShieldedInstanceConfig.EnableSecureBoot
					info.VTPMEnabled = instance.ShieldedInstanceConfig.EnableVtpm
					info.IntegrityMonitoring = instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
				}

				// Parse confidential VM config
				if instance.ConfidentialInstanceConfig != nil {
					info.ConfidentialVM = instance.ConfidentialInstanceConfig.EnableConfidentialCompute
				}

				// Parse metadata for security-relevant items including content
				if instance.Metadata != nil {
					metaResult := parseMetadataFull(instance.Metadata)
					info.HasStartupScript = metaResult.HasStartupScript
					info.HasSSHKeys = metaResult.HasSSHKeys
					info.BlockProjectSSHKeys = metaResult.BlockProjectSSHKeys
					info.OSLoginEnabled = metaResult.OSLoginEnabled
					info.OSLogin2FAEnabled = metaResult.OSLogin2FA
					info.SerialPortEnabled = metaResult.SerialPortEnabled
					info.StartupScriptContent = metaResult.StartupScriptContent
					info.StartupScriptURL = metaResult.StartupScriptURL
					info.SSHKeys = metaResult.SSHKeys
					info.CustomMetadata = metaResult.CustomMetadata
					info.RawMetadata = metaResult.RawMetadata
					// Mark source for sensitive items
					for i := range metaResult.SensitiveItems {
						metaResult.SensitiveItems[i].Source = "instance"
					}
					info.SensitiveMetadata = metaResult.SensitiveItems
				}

				// Parse boot disk encryption
				info.BootDiskEncryption, info.BootDiskKMSKey = parseBootDiskEncryption(instance.Disks)

				// Fetch IAM bindings for this instance (may fail silently if no permission)
				info.IAMBindings = ces.getInstanceIAMBindings(computeService, projectID, zone, instance.Name)

				instanceInfos = append(instanceInfos, info)
			}
		}
		return nil
	})

	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	return instanceInfos, nil
}

// Returns the zone from a GCP URL string with the zone in it
func getZoneNameFromURL(zoneURL string) string {
	splits := strings.Split(zoneURL, "/")
	return splits[len(splits)-1]
}

// getExternalIP extracts the external IP address from an instance if available.
func getExternalIP(instance *compute.Instance) string {
	for _, iface := range instance.NetworkInterfaces {
		for _, accessConfig := range iface.AccessConfigs {
			if accessConfig.NatIP != "" {
				return accessConfig.NatIP
			}
		}
	}
	return ""
}

// getInternalIP extracts the internal IP address from an instance.
func getInternalIP(instance *compute.Instance) string {
	if len(instance.NetworkInterfaces) > 0 {
		return instance.NetworkInterfaces[0].NetworkIP
	}
	return ""
}

// getMachineTypeName extracts the machine type name from a full URL
func getMachineTypeName(machineTypeURL string) string {
	parts := strings.Split(machineTypeURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return machineTypeURL
}

// parseServiceAccounts extracts service account info and checks for security concerns
func parseServiceAccounts(sas []*compute.ServiceAccount, projectID string) ([]ServiceAccountInfo, bool, bool) {
	var accounts []ServiceAccountInfo
	hasDefaultSA := false
	hasCloudScopes := false

	defaultSAPattern := fmt.Sprintf("%s-compute@developer.gserviceaccount.com", projectID)

	for _, sa := range sas {
		info := ServiceAccountInfo{
			Email:  sa.Email,
			Scopes: sa.Scopes,
		}
		accounts = append(accounts, info)

		// Check if using default compute service account
		if strings.Contains(sa.Email, "-compute@developer.gserviceaccount.com") ||
			strings.HasSuffix(sa.Email, defaultSAPattern) {
			hasDefaultSA = true
		}

		// Check for broad scopes
		for _, scope := range sa.Scopes {
			if scope == "https://www.googleapis.com/auth/cloud-platform" ||
				scope == "https://www.googleapis.com/auth/compute" ||
				scope == "https://www.googleapis.com/auth/devstorage.full_control" ||
				scope == "https://www.googleapis.com/auth/devstorage.read_write" {
				hasCloudScopes = true
			}
		}
	}

	return accounts, hasDefaultSA, hasCloudScopes
}

// SensitiveItem represents a potentially sensitive metadata item
type SensitiveItem struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Type        string `json:"type"`        // password, api-key, token, credential, connection-string, secret, env-var
	Source      string `json:"source"`      // instance or project
	Truncated   bool   `json:"truncated"`   // Whether value was truncated for display
}

// MetadataParseResult contains all parsed metadata fields
type MetadataParseResult struct {
	HasStartupScript     bool
	HasSSHKeys           bool
	BlockProjectSSHKeys  bool
	OSLoginEnabled       bool
	OSLogin2FA           bool
	SerialPortEnabled    bool
	StartupScriptContent string
	StartupScriptURL     string
	SSHKeys              []string
	CustomMetadata       []string
	RawMetadata          map[string]string
	SensitiveItems       []SensitiveItem
}

// parseMetadata checks instance metadata for security-relevant settings
func parseMetadata(metadata *compute.Metadata) (hasStartupScript, hasSSHKeys, blockProjectSSHKeys, osLoginEnabled, osLogin2FA, serialPortEnabled bool) {
	result := parseMetadataFull(metadata)
	return result.HasStartupScript, result.HasSSHKeys, result.BlockProjectSSHKeys,
		result.OSLoginEnabled, result.OSLogin2FA, result.SerialPortEnabled
}

// sensitivePatterns maps key name patterns to secret types
var sensitivePatterns = map[string]string{
	"PASSWORD":          "password",
	"PASSWD":            "password",
	"SECRET":            "secret",
	"API_KEY":           "api-key",
	"APIKEY":            "api-key",
	"API-KEY":           "api-key",
	"TOKEN":             "token",
	"ACCESS_TOKEN":      "token",
	"AUTH_TOKEN":        "token",
	"BEARER":            "token",
	"CREDENTIAL":        "credential",
	"PRIVATE_KEY":       "credential",
	"PRIVATEKEY":        "credential",
	"CONNECTION_STRING": "connection-string",
	"CONN_STR":          "connection-string",
	"DATABASE_URL":      "connection-string",
	"DB_PASSWORD":       "password",
	"DB_PASS":           "password",
	"MYSQL_PASSWORD":    "password",
	"POSTGRES_PASSWORD": "password",
	"REDIS_PASSWORD":    "password",
	"MONGODB_URI":       "connection-string",
	"AWS_ACCESS_KEY":    "credential",
	"AWS_SECRET":        "credential",
	"AZURE_KEY":         "credential",
	"GCP_KEY":           "credential",
	"ENCRYPTION_KEY":    "credential",
	"SIGNING_KEY":       "credential",
	"JWT_SECRET":        "credential",
	"SESSION_SECRET":    "credential",
	"OAUTH":             "credential",
	"CLIENT_SECRET":     "credential",
}

// detectSensitiveType checks if a key name matches sensitive patterns
func detectSensitiveType(key string) string {
	keyUpper := strings.ToUpper(key)
	for pattern, secretType := range sensitivePatterns {
		if strings.Contains(keyUpper, pattern) {
			return secretType
		}
	}
	return ""
}

// parseMetadataFull extracts all metadata including content
func parseMetadataFull(metadata *compute.Metadata) MetadataParseResult {
	result := MetadataParseResult{
		RawMetadata: make(map[string]string),
	}
	if metadata == nil || metadata.Items == nil {
		return result
	}

	// Known metadata keys to exclude from custom metadata
	knownKeys := map[string]bool{
		"startup-script":                true,
		"startup-script-url":            true,
		"ssh-keys":                      true,
		"sshKeys":                       true,
		"block-project-ssh-keys":        true,
		"enable-oslogin":                true,
		"enable-oslogin-2fa":            true,
		"serial-port-enable":            true,
		"google-compute-default-zone":   true,
		"google-compute-default-region": true,
	}

	for _, item := range metadata.Items {
		if item == nil {
			continue
		}

		// Store all raw metadata
		if item.Value != nil {
			result.RawMetadata[item.Key] = *item.Value
		}

		switch item.Key {
		case "startup-script":
			result.HasStartupScript = true
			if item.Value != nil {
				result.StartupScriptContent = *item.Value
				// Check startup script for sensitive patterns
				sensitiveItems := extractSensitiveFromScript(*item.Value, "startup-script")
				result.SensitiveItems = append(result.SensitiveItems, sensitiveItems...)
			}
		case "startup-script-url":
			result.HasStartupScript = true
			if item.Value != nil {
				result.StartupScriptURL = *item.Value
			}
		case "ssh-keys", "sshKeys":
			result.HasSSHKeys = true
			if item.Value != nil {
				// Parse SSH keys - format is "user:ssh-rsa KEY comment"
				lines := strings.Split(*item.Value, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						result.SSHKeys = append(result.SSHKeys, line)
					}
				}
			}
		case "block-project-ssh-keys":
			if item.Value != nil && *item.Value == "true" {
				result.BlockProjectSSHKeys = true
			}
		case "enable-oslogin":
			if item.Value != nil && strings.ToLower(*item.Value) == "true" {
				result.OSLoginEnabled = true
			}
		case "enable-oslogin-2fa":
			if item.Value != nil && strings.ToLower(*item.Value) == "true" {
				result.OSLogin2FA = true
			}
		case "serial-port-enable":
			if item.Value != nil && *item.Value == "true" {
				result.SerialPortEnabled = true
			}
		default:
			// Track custom metadata keys (may contain secrets)
			if !knownKeys[item.Key] {
				result.CustomMetadata = append(result.CustomMetadata, item.Key)

				// Check if key name suggests sensitive content
				if item.Value != nil {
					if sensitiveType := detectSensitiveType(item.Key); sensitiveType != "" {
						result.SensitiveItems = append(result.SensitiveItems, SensitiveItem{
							Key:   item.Key,
							Value: *item.Value,
							Type:  sensitiveType,
						})
					}
				}
			}
		}
	}

	return result
}

// extractSensitiveFromScript extracts potential sensitive values from scripts
func extractSensitiveFromScript(script, source string) []SensitiveItem {
	var items []SensitiveItem
	lines := strings.Split(script, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for export VAR=value or VAR=value patterns
		if strings.Contains(line, "=") {
			// Handle export statements
			line = strings.TrimPrefix(line, "export ")

			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// Remove quotes from value
				value = strings.Trim(value, "\"'")

				if sensitiveType := detectSensitiveType(key); sensitiveType != "" && value != "" {
					items = append(items, SensitiveItem{
						Key:    key,
						Value:  value,
						Type:   sensitiveType,
						Source: source,
					})
				}
			}
		}
	}

	return items
}

// parseBootDiskEncryption checks the boot disk encryption type
func parseBootDiskEncryption(disks []*compute.AttachedDisk) (encryptionType, kmsKey string) {
	encryptionType = "Google-managed"

	for _, disk := range disks {
		if disk == nil || !disk.Boot {
			continue
		}

		if disk.DiskEncryptionKey != nil {
			if disk.DiskEncryptionKey.KmsKeyName != "" {
				encryptionType = "CMEK"
				kmsKey = disk.DiskEncryptionKey.KmsKeyName
			} else if disk.DiskEncryptionKey.Sha256 != "" {
				encryptionType = "CSEK"
			}
		}
		break // Only check boot disk
	}

	return
}

// FormatScopes formats service account scopes for display
func FormatScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "-"
	}

	// Shorten scope URLs for display
	var shortScopes []string
	for _, scope := range scopes {
		// Extract the scope name from the URL
		parts := strings.Split(scope, "/")
		if len(parts) > 0 {
			shortScopes = append(shortScopes, parts[len(parts)-1])
		}
	}
	return strings.Join(shortScopes, ", ")
}

// GetProjectMetadata retrieves project-level compute metadata
func (ces *ComputeEngineService) GetProjectMetadata(projectID string) (*ProjectMetadataInfo, error) {
	ctx := context.Background()
	computeService, err := ces.getService(ctx)
	if err != nil {
		return nil, err
	}

	project, err := computeService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	info := &ProjectMetadataInfo{
		ProjectID:   projectID,
		RawMetadata: make(map[string]string),
	}

	if project.CommonInstanceMetadata != nil {
		for _, item := range project.CommonInstanceMetadata.Items {
			if item == nil {
				continue
			}

			// Store all raw metadata
			if item.Value != nil {
				info.RawMetadata[item.Key] = *item.Value
			}

			switch item.Key {
			case "ssh-keys", "sshKeys":
				info.HasProjectSSHKeys = true
				if item.Value != nil {
					lines := strings.Split(*item.Value, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" {
							info.ProjectSSHKeys = append(info.ProjectSSHKeys, line)
						}
					}
				}
			case "startup-script":
				info.HasProjectStartupScript = true
				if item.Value != nil {
					info.ProjectStartupScript = *item.Value
					// Check startup script for sensitive patterns
					sensitiveItems := extractSensitiveFromScript(*item.Value, "project-startup-script")
					for i := range sensitiveItems {
						sensitiveItems[i].Source = "project"
					}
					info.SensitiveMetadata = append(info.SensitiveMetadata, sensitiveItems...)
				}
			case "enable-oslogin":
				if item.Value != nil && strings.ToLower(*item.Value) == "true" {
					info.OSLoginEnabled = true
				}
			case "enable-oslogin-2fa":
				if item.Value != nil && strings.ToLower(*item.Value) == "true" {
					info.OSLogin2FAEnabled = true
				}
			case "serial-port-enable":
				if item.Value != nil && *item.Value == "true" {
					info.SerialPortEnabled = true
				}
			default:
				// Track other custom metadata that might contain secrets
				if !isKnownMetadataKey(item.Key) {
					info.CustomMetadataKeys = append(info.CustomMetadataKeys, item.Key)

					// Check if key name suggests sensitive content
					if item.Value != nil {
						if sensitiveType := detectSensitiveType(item.Key); sensitiveType != "" {
							info.SensitiveMetadata = append(info.SensitiveMetadata, SensitiveItem{
								Key:    item.Key,
								Value:  *item.Value,
								Type:   sensitiveType,
								Source: "project",
							})
						}
					}
				}
			}
		}
	}

	return info, nil
}

// isKnownMetadataKey checks if a metadata key is a known system key
func isKnownMetadataKey(key string) bool {
	knownKeys := map[string]bool{
		"ssh-keys":                        true,
		"sshKeys":                         true,
		"startup-script":                  true,
		"startup-script-url":              true,
		"block-project-ssh-keys":          true,
		"enable-oslogin":                  true,
		"enable-oslogin-2fa":              true,
		"serial-port-enable":              true,
		"google-compute-default-zone":     true,
		"google-compute-default-region":   true,
		"google-compute-enable-logging":   true,
		"google-compute-enable-ssh-agent": true,
	}
	return knownKeys[key]
}

// GetInstanceIAMPolicy retrieves IAM policy for a specific instance
func (ces *ComputeEngineService) GetInstanceIAMPolicy(projectID, zone, instanceName string) (*InstanceIAMInfo, error) {
	ctx := context.Background()
	computeService, err := ces.getService(ctx)
	if err != nil {
		return nil, err
	}

	policy, err := computeService.Instances.GetIamPolicy(projectID, zone, instanceName).Do()
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "compute.googleapis.com")
	}

	info := &InstanceIAMInfo{
		InstanceName: instanceName,
		Zone:         zone,
		ProjectID:    projectID,
	}

	for _, binding := range policy.Bindings {
		if binding == nil {
			continue
		}

		switch binding.Role {
		case "roles/compute.admin", "roles/owner":
			info.ComputeAdmins = append(info.ComputeAdmins, binding.Members...)
		case "roles/compute.instanceAdmin", "roles/compute.instanceAdmin.v1":
			info.InstanceAdmins = append(info.InstanceAdmins, binding.Members...)
		case "roles/compute.osLogin", "roles/compute.osAdminLogin":
			info.SSHUsers = append(info.SSHUsers, binding.Members...)
		}

		// Check for specific permissions via custom roles (more complex detection)
		if strings.HasPrefix(binding.Role, "projects/") || strings.HasPrefix(binding.Role, "organizations/") {
			// Custom role - would need to check permissions, but we note the binding
			info.InstanceAdmins = append(info.InstanceAdmins, binding.Members...)
		}
	}

	return info, nil
}

// InstancesWithMetadata retrieves instances with full metadata content
func (ces *ComputeEngineService) InstancesWithMetadata(projectID string) ([]ComputeEngineInfo, *ProjectMetadataInfo, error) {
	instances, err := ces.Instances(projectID)
	if err != nil {
		return nil, nil, err
	}

	projectMeta, err := ces.GetProjectMetadata(projectID)
	if err != nil {
		// Don't fail if we can't get project metadata
		projectMeta = &ProjectMetadataInfo{ProjectID: projectID}
	}

	return instances, projectMeta, nil
}
