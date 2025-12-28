package filestoreservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	file "google.golang.org/api/file/v1"
)

type FilestoreService struct {
	session *gcpinternal.SafeSession
}

func New() *FilestoreService {
	return &FilestoreService{}
}

type FilestoreInstanceInfo struct {
	Name        string   `json:"name"`
	ProjectID   string   `json:"projectId"`
	Location    string   `json:"location"`
	Tier        string   `json:"tier"`
	State       string   `json:"state"`
	Network     string   `json:"network"`
	IPAddresses []string `json:"ipAddresses"`
	Shares      []ShareInfo `json:"shares"`
	CreateTime  string   `json:"createTime"`
}

type ShareInfo struct {
	Name       string `json:"name"`
	CapacityGB int64  `json:"capacityGb"`
}

func (s *FilestoreService) ListInstances(projectID string) ([]FilestoreInstanceInfo, error) {
	ctx := context.Background()
	service, err := file.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Filestore service: %v", err)
	}

	var instances []FilestoreInstanceInfo
	parent := fmt.Sprintf("projects/%s/locations/-", projectID)

	req := service.Projects.Locations.Instances.List(parent)
	err = req.Pages(ctx, func(page *file.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			info := FilestoreInstanceInfo{
				Name:        extractResourceName(instance.Name),
				ProjectID:   projectID,
				Location:    extractLocation(instance.Name),
				Tier:        instance.Tier,
				State:       instance.State,
				CreateTime:  instance.CreateTime,
			}

			if len(instance.Networks) > 0 {
				info.Network = instance.Networks[0].Network
				info.IPAddresses = instance.Networks[0].IpAddresses
			}

			for _, share := range instance.FileShares {
				info.Shares = append(info.Shares, ShareInfo{
					Name:       share.Name,
					CapacityGB: share.CapacityGb,
				})
			}
			instances = append(instances, info)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return instances, nil
}

func extractResourceName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}

func extractLocation(name string) string {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "locations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
