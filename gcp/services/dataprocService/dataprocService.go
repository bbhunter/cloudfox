package dataprocservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	dataproc "google.golang.org/api/dataproc/v1"
)

type DataprocService struct {
	session *gcpinternal.SafeSession
}

func New() *DataprocService {
	return &DataprocService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *DataprocService {
	return &DataprocService{session: session}
}

// ClusterInfo represents a Dataproc cluster
type ClusterInfo struct {
	Name             string   `json:"name"`
	ProjectID        string   `json:"projectId"`
	Region           string   `json:"region"`
	State            string   `json:"state"`
	StateStartTime   string   `json:"stateStartTime"`
	ClusterUUID      string   `json:"clusterUuid"`

	// Config
	ConfigBucket     string   `json:"configBucket"`
	TempBucket       string   `json:"tempBucket"`
	ImageVersion     string   `json:"imageVersion"`
	ServiceAccount   string   `json:"serviceAccount"`

	// Master config
	MasterMachineType string  `json:"masterMachineType"`
	MasterCount       int64   `json:"masterCount"`
	MasterDiskSizeGB  int64   `json:"masterDiskSizeGb"`

	// Worker config
	WorkerMachineType string  `json:"workerMachineType"`
	WorkerCount       int64   `json:"workerCount"`
	WorkerDiskSizeGB  int64   `json:"workerDiskSizeGb"`

	// Network config
	Network           string   `json:"network"`
	Subnetwork        string   `json:"subnetwork"`
	InternalIPOnly    bool     `json:"internalIpOnly"`
	Zone              string   `json:"zone"`

	// Security config
	KerberosEnabled   bool     `json:"kerberosEnabled"`
	SecureBoot        bool     `json:"secureBoot"`

	// Security analysis
	RiskLevel         string   `json:"riskLevel"`
	RiskReasons       []string `json:"riskReasons"`
}

// JobInfo represents a Dataproc job
type JobInfo struct {
	JobID            string   `json:"jobId"`
	ProjectID        string   `json:"projectId"`
	Region           string   `json:"region"`
	ClusterName      string   `json:"clusterName"`
	Status           string   `json:"status"`
	JobType          string   `json:"jobType"`
	SubmittedBy      string   `json:"submittedBy"`
	StartTime        string   `json:"startTime"`
	EndTime          string   `json:"endTime"`
}

// Common GCP regions for Dataproc
var dataprocRegions = []string{
	"us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
	"europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
	"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
	"asia-south1", "asia-southeast1", "asia-southeast2",
	"australia-southeast1", "southamerica-east1", "northamerica-northeast1",
}

// ListClusters retrieves all Dataproc clusters
func (s *DataprocService) ListClusters(projectID string) ([]ClusterInfo, error) {
	ctx := context.Background()
	var service *dataproc.Service
	var err error

	if s.session != nil {
		service, err = dataproc.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = dataproc.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Dataproc service: %v", err)
	}

	var clusters []ClusterInfo

	// List across common regions
	for _, region := range dataprocRegions {
		regionClusters, err := service.Projects.Regions.Clusters.List(projectID, region).Context(ctx).Do()
		if err != nil {
			continue // Skip regions with errors (API not enabled, no permissions, etc.)
		}

		for _, cluster := range regionClusters.Clusters {
			info := s.parseCluster(cluster, projectID, region)
			clusters = append(clusters, info)
		}
	}

	return clusters, nil
}

// ListJobs retrieves recent Dataproc jobs
func (s *DataprocService) ListJobs(projectID, region string) ([]JobInfo, error) {
	ctx := context.Background()
	var service *dataproc.Service
	var err error

	if s.session != nil {
		service, err = dataproc.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = dataproc.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Dataproc service: %v", err)
	}

	var jobs []JobInfo

	resp, err := service.Projects.Regions.Jobs.List(projectID, region).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %v", err)
	}

	for _, job := range resp.Jobs {
		info := s.parseJob(job, projectID, region)
		jobs = append(jobs, info)
	}

	return jobs, nil
}

func (s *DataprocService) parseCluster(cluster *dataproc.Cluster, projectID, region string) ClusterInfo {
	info := ClusterInfo{
		Name:        cluster.ClusterName,
		ProjectID:   projectID,
		Region:      region,
		ClusterUUID: cluster.ClusterUuid,
		RiskReasons: []string{},
	}

	if cluster.Status != nil {
		info.State = cluster.Status.State
		info.StateStartTime = cluster.Status.StateStartTime
	}

	if cluster.Config != nil {
		info.ConfigBucket = cluster.Config.ConfigBucket
		info.TempBucket = cluster.Config.TempBucket

		// Software config
		if cluster.Config.SoftwareConfig != nil {
			info.ImageVersion = cluster.Config.SoftwareConfig.ImageVersion
		}

		// GCE cluster config
		if cluster.Config.GceClusterConfig != nil {
			gcc := cluster.Config.GceClusterConfig
			info.ServiceAccount = gcc.ServiceAccount
			info.Network = extractName(gcc.NetworkUri)
			info.Subnetwork = extractName(gcc.SubnetworkUri)
			info.InternalIPOnly = gcc.InternalIpOnly
			info.Zone = extractName(gcc.ZoneUri)

			if gcc.ShieldedInstanceConfig != nil {
				info.SecureBoot = gcc.ShieldedInstanceConfig.EnableSecureBoot
			}
		}

		// Master config
		if cluster.Config.MasterConfig != nil {
			mc := cluster.Config.MasterConfig
			info.MasterMachineType = extractName(mc.MachineTypeUri)
			info.MasterCount = mc.NumInstances
			if mc.DiskConfig != nil {
				info.MasterDiskSizeGB = mc.DiskConfig.BootDiskSizeGb
			}
		}

		// Worker config
		if cluster.Config.WorkerConfig != nil {
			wc := cluster.Config.WorkerConfig
			info.WorkerMachineType = extractName(wc.MachineTypeUri)
			info.WorkerCount = wc.NumInstances
			if wc.DiskConfig != nil {
				info.WorkerDiskSizeGB = wc.DiskConfig.BootDiskSizeGb
			}
		}

		// Security config
		if cluster.Config.SecurityConfig != nil && cluster.Config.SecurityConfig.KerberosConfig != nil {
			info.KerberosEnabled = true
		}
	}

	info.RiskLevel, info.RiskReasons = s.analyzeClusterRisk(info)

	return info
}

func (s *DataprocService) parseJob(job *dataproc.Job, projectID, region string) JobInfo {
	info := JobInfo{
		JobID:       job.Reference.JobId,
		ProjectID:   projectID,
		Region:      region,
		ClusterName: job.Placement.ClusterName,
	}

	if job.Status != nil {
		info.Status = job.Status.State
		info.StartTime = job.Status.StateStartTime
	}

	if job.StatusHistory != nil && len(job.StatusHistory) > 0 {
		for _, status := range job.StatusHistory {
			if status.State == "DONE" || status.State == "ERROR" || status.State == "CANCELLED" {
				info.EndTime = status.StateStartTime
				break
			}
		}
	}

	// Determine job type
	if job.HadoopJob != nil {
		info.JobType = "Hadoop"
	} else if job.SparkJob != nil {
		info.JobType = "Spark"
	} else if job.PysparkJob != nil {
		info.JobType = "PySpark"
	} else if job.HiveJob != nil {
		info.JobType = "Hive"
	} else if job.PigJob != nil {
		info.JobType = "Pig"
	} else if job.SparkRJob != nil {
		info.JobType = "SparkR"
	} else if job.SparkSqlJob != nil {
		info.JobType = "SparkSQL"
	} else if job.PrestoJob != nil {
		info.JobType = "Presto"
	} else {
		info.JobType = "Unknown"
	}

	return info
}

func (s *DataprocService) analyzeClusterRisk(cluster ClusterInfo) (string, []string) {
	var reasons []string
	score := 0

	// Public IPs
	if !cluster.InternalIPOnly {
		reasons = append(reasons, "Cluster nodes have public IP addresses")
		score += 2
	}

	// Default service account
	if cluster.ServiceAccount == "" || strings.Contains(cluster.ServiceAccount, "compute@developer.gserviceaccount.com") {
		reasons = append(reasons, "Uses default Compute Engine service account")
		score += 2
	}

	// No Kerberos
	if !cluster.KerberosEnabled {
		reasons = append(reasons, "Kerberos authentication not enabled")
		score += 1
	}

	// No secure boot
	if !cluster.SecureBoot {
		reasons = append(reasons, "Secure Boot not enabled")
		score += 1
	}

	// Old image version (simplified check)
	if cluster.ImageVersion != "" && strings.HasPrefix(cluster.ImageVersion, "1.") {
		reasons = append(reasons, fmt.Sprintf("Using older image version: %s", cluster.ImageVersion))
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

func extractName(fullPath string) string {
	if fullPath == "" {
		return ""
	}
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}
