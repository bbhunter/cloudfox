package notebooksservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	notebooks "google.golang.org/api/notebooks/v1"
)

type NotebooksService struct {
	session *gcpinternal.SafeSession
}

func New() *NotebooksService {
	return &NotebooksService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *NotebooksService {
	return &NotebooksService{session: session}
}

// NotebookInstanceInfo represents a Vertex AI Workbench or legacy notebook instance
type NotebookInstanceInfo struct {
	Name             string   `json:"name"`
	ProjectID        string   `json:"projectId"`
	Location         string   `json:"location"`
	State            string   `json:"state"`
	MachineType      string   `json:"machineType"`
	ServiceAccount   string   `json:"serviceAccount"`
	Network          string   `json:"network"`
	Subnet           string   `json:"subnet"`
	NoPublicIP       bool     `json:"noPublicIp"`
	NoProxyAccess    bool     `json:"noProxyAccess"`
	CreateTime       string   `json:"createTime"`
	UpdateTime       string   `json:"updateTime"`

	// Disk config
	BootDiskType     string   `json:"bootDiskType"`
	BootDiskSizeGB   int64    `json:"bootDiskSizeGb"`
	DataDiskType     string   `json:"dataDiskType"`
	DataDiskSizeGB   int64    `json:"dataDiskSizeGb"`

	// GPU config
	AcceleratorType  string   `json:"acceleratorType"`
	AcceleratorCount int64    `json:"acceleratorCount"`

	// Security config
	InstallGpuDriver bool     `json:"installGpuDriver"`
	CustomContainer  bool     `json:"customContainer"`

	// Security analysis
	RiskLevel        string   `json:"riskLevel"`
	RiskReasons      []string `json:"riskReasons"`
}

// RuntimeInfo represents a managed notebook runtime
type RuntimeInfo struct {
	Name            string   `json:"name"`
	ProjectID       string   `json:"projectId"`
	Location        string   `json:"location"`
	State           string   `json:"state"`
	RuntimeType     string   `json:"runtimeType"`
	MachineType     string   `json:"machineType"`
	ServiceAccount  string   `json:"serviceAccount"`
	Network         string   `json:"network"`
	Subnet          string   `json:"subnet"`
	RiskLevel       string   `json:"riskLevel"`
	RiskReasons     []string `json:"riskReasons"`
}

// ListInstances retrieves all notebook instances
func (s *NotebooksService) ListInstances(projectID string) ([]NotebookInstanceInfo, error) {
	ctx := context.Background()
	var service *notebooks.Service
	var err error

	if s.session != nil {
		service, err = notebooks.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = notebooks.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Notebooks service: %v", err)
	}

	var instances []NotebookInstanceInfo

	// List across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := service.Projects.Locations.Instances.List(parent)
	err = req.Pages(ctx, func(page *notebooks.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			info := s.parseInstance(instance, projectID)
			instances = append(instances, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list notebook instances: %v", err)
	}

	return instances, nil
}

// ListRuntimes retrieves all managed notebook runtimes
func (s *NotebooksService) ListRuntimes(projectID string) ([]RuntimeInfo, error) {
	ctx := context.Background()
	var service *notebooks.Service
	var err error

	if s.session != nil {
		service, err = notebooks.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = notebooks.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Notebooks service: %v", err)
	}

	var runtimes []RuntimeInfo

	// List across all locations
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	req := service.Projects.Locations.Runtimes.List(parent)
	err = req.Pages(ctx, func(page *notebooks.ListRuntimesResponse) error {
		for _, runtime := range page.Runtimes {
			info := s.parseRuntime(runtime, projectID)
			runtimes = append(runtimes, info)
		}
		return nil
	})
	if err != nil {
		// Runtimes API might not be available in all regions
		return runtimes, nil
	}

	return runtimes, nil
}

func (s *NotebooksService) parseInstance(instance *notebooks.Instance, projectID string) NotebookInstanceInfo {
	info := NotebookInstanceInfo{
		Name:        extractName(instance.Name),
		ProjectID:   projectID,
		Location:    extractLocation(instance.Name),
		State:       instance.State,
		MachineType: extractName(instance.MachineType),
		CreateTime:  instance.CreateTime,
		UpdateTime:  instance.UpdateTime,
		RiskReasons: []string{},
	}

	// Service account
	info.ServiceAccount = instance.ServiceAccount

	// Network config
	info.Network = extractName(instance.Network)
	info.Subnet = extractName(instance.Subnet)
	info.NoPublicIP = instance.NoPublicIp
	info.NoProxyAccess = instance.NoProxyAccess

	// Boot disk
	info.BootDiskType = instance.BootDiskType
	info.BootDiskSizeGB = instance.BootDiskSizeGb

	// Data disk
	info.DataDiskType = instance.DataDiskType
	info.DataDiskSizeGB = instance.DataDiskSizeGb

	// GPU config
	if instance.AcceleratorConfig != nil {
		info.AcceleratorType = instance.AcceleratorConfig.Type
		info.AcceleratorCount = instance.AcceleratorConfig.CoreCount
	}
	info.InstallGpuDriver = instance.InstallGpuDriver

	// Custom container
	if instance.ContainerImage != nil {
		info.CustomContainer = true
	}

	info.RiskLevel, info.RiskReasons = s.analyzeInstanceRisk(info)

	return info
}

func (s *NotebooksService) parseRuntime(runtime *notebooks.Runtime, projectID string) RuntimeInfo {
	info := RuntimeInfo{
		Name:        extractName(runtime.Name),
		ProjectID:   projectID,
		Location:    extractLocation(runtime.Name),
		State:       runtime.State,
		RiskReasons: []string{},
	}

	if runtime.VirtualMachine != nil {
		info.RuntimeType = "VirtualMachine"
		if runtime.VirtualMachine.VirtualMachineConfig != nil {
			config := runtime.VirtualMachine.VirtualMachineConfig
			info.MachineType = config.MachineType
			info.Network = extractName(config.Network)
			info.Subnet = extractName(config.Subnet)
		}
	}

	if runtime.AccessConfig != nil {
		info.ServiceAccount = runtime.AccessConfig.RuntimeOwner
	}

	info.RiskLevel, info.RiskReasons = s.analyzeRuntimeRisk(info)

	return info
}

func (s *NotebooksService) analyzeInstanceRisk(instance NotebookInstanceInfo) (string, []string) {
	var reasons []string
	score := 0

	// Public IP
	if !instance.NoPublicIP {
		reasons = append(reasons, "Has public IP address")
		score += 2
	}

	// Proxy access enabled (allows web access)
	if !instance.NoProxyAccess {
		reasons = append(reasons, "Proxy access enabled (web access)")
		score += 1
	}

	// Default service account
	if instance.ServiceAccount == "" || strings.Contains(instance.ServiceAccount, "compute@developer.gserviceaccount.com") {
		reasons = append(reasons, "Uses default Compute Engine service account")
		score += 2
	}

	// Custom container (potential supply chain risk)
	if instance.CustomContainer {
		reasons = append(reasons, "Uses custom container image")
		score += 1
	}

	// GPU (high-value target, expensive)
	if instance.AcceleratorCount > 0 {
		reasons = append(reasons, fmt.Sprintf("Has GPU attached (%s x%d)", instance.AcceleratorType, instance.AcceleratorCount))
		score += 1
	}

	if score >= 4 {
		return "HIGH", reasons
	} else if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func (s *NotebooksService) analyzeRuntimeRisk(runtime RuntimeInfo) (string, []string) {
	var reasons []string
	score := 0

	// Check for default SA patterns
	if runtime.ServiceAccount == "" {
		reasons = append(reasons, "No explicit service account configured")
		score += 1
	}

	if score >= 2 {
		return "MEDIUM", reasons
	} else if score >= 1 {
		return "LOW", reasons
	}
	return "INFO", reasons
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

func extractLocation(fullName string) string {
	parts := strings.Split(fullName, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
