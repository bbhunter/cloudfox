package memorystoreservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	redis "google.golang.org/api/redis/v1"
)

type MemorystoreService struct {
	session *gcpinternal.SafeSession
}

func New() *MemorystoreService {
	return &MemorystoreService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *MemorystoreService {
	return &MemorystoreService{session: session}
}

// RedisInstanceInfo represents a Redis instance
type RedisInstanceInfo struct {
	Name               string   `json:"name"`
	ProjectID          string   `json:"projectId"`
	Location           string   `json:"location"`
	DisplayName        string   `json:"displayName"`
	Tier               string   `json:"tier"`           // BASIC or STANDARD_HA
	MemorySizeGB       int64    `json:"memorySizeGb"`
	RedisVersion       string   `json:"redisVersion"`
	Host               string   `json:"host"`
	Port               int64    `json:"port"`
	State              string   `json:"state"`
	AuthEnabled        bool     `json:"authEnabled"`
	TransitEncryption  string   `json:"transitEncryption"` // DISABLED, SERVER_AUTHENTICATION
	ConnectMode        string   `json:"connectMode"`       // DIRECT_PEERING or PRIVATE_SERVICE_ACCESS
	AuthorizedNetwork  string   `json:"authorizedNetwork"`
	ReservedIPRange    string   `json:"reservedIpRange"`
	CreateTime         string   `json:"createTime"`
	RiskLevel          string   `json:"riskLevel"`
	RiskReasons        []string `json:"riskReasons"`
}

// ListRedisInstances retrieves all Redis instances in a project
func (s *MemorystoreService) ListRedisInstances(projectID string) ([]RedisInstanceInfo, error) {
	ctx := context.Background()
	var service *redis.Service
	var err error

	if s.session != nil {
		service, err = redis.NewService(ctx, s.session.GetClientOption())
	} else {
		service, err = redis.NewService(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis service: %v", err)
	}

	var instances []RedisInstanceInfo
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	req := service.Projects.Locations.Instances.List(parent)
	err = req.Pages(ctx, func(page *redis.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			info := s.parseRedisInstance(instance, projectID)
			instances = append(instances, info)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list Redis instances: %v", err)
	}

	return instances, nil
}

func (s *MemorystoreService) parseRedisInstance(instance *redis.Instance, projectID string) RedisInstanceInfo {
	info := RedisInstanceInfo{
		Name:              extractName(instance.Name),
		ProjectID:         projectID,
		Location:          instance.LocationId,
		DisplayName:       instance.DisplayName,
		Tier:              instance.Tier,
		MemorySizeGB:      instance.MemorySizeGb,
		RedisVersion:      instance.RedisVersion,
		Host:              instance.Host,
		Port:              instance.Port,
		State:             instance.State,
		AuthEnabled:       instance.AuthEnabled,
		TransitEncryption: instance.TransitEncryptionMode,
		ConnectMode:       instance.ConnectMode,
		AuthorizedNetwork: instance.AuthorizedNetwork,
		ReservedIPRange:   instance.ReservedIpRange,
		CreateTime:        instance.CreateTime,
		RiskReasons:       []string{},
	}

	// Security analysis
	info.RiskLevel, info.RiskReasons = s.analyzeRedisRisk(info)
	return info
}

func (s *MemorystoreService) analyzeRedisRisk(instance RedisInstanceInfo) (string, []string) {
	var reasons []string
	score := 0

	if !instance.AuthEnabled {
		reasons = append(reasons, "Authentication not enabled")
		score += 3
	}

	if instance.TransitEncryption == "DISABLED" || instance.TransitEncryption == "" {
		reasons = append(reasons, "Transit encryption disabled")
		score += 2
	}

	if instance.Tier == "BASIC" {
		reasons = append(reasons, "Basic tier (no HA)")
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

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
