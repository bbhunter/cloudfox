package bigtableservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	bigtableadmin "google.golang.org/api/bigtableadmin/v2"
)

type BigtableService struct {
	session *gcpinternal.SafeSession
}

func New() *BigtableService {
	return &BigtableService{}
}

type BigtableInstanceInfo struct {
	Name        string   `json:"name"`
	ProjectID   string   `json:"projectId"`
	DisplayName string   `json:"displayName"`
	Type        string   `json:"type"`
	State       string   `json:"state"`
	Tables      []string `json:"tables"`
	Clusters    []ClusterInfo `json:"clusters"`
}

type ClusterInfo struct {
	Name       string `json:"name"`
	Location   string `json:"location"`
	ServeNodes int64  `json:"serveNodes"`
	State      string `json:"state"`
}

func (s *BigtableService) ListInstances(projectID string) ([]BigtableInstanceInfo, error) {
	ctx := context.Background()
	service, err := bigtableadmin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bigtable Admin service: %v", err)
	}

	var instances []BigtableInstanceInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	resp, err := service.Projects.Instances.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, instance := range resp.Instances {
		info := BigtableInstanceInfo{
			Name:        extractName(instance.Name),
			ProjectID:   projectID,
			DisplayName: instance.DisplayName,
			Type:        instance.Type,
			State:       instance.State,
		}

		// Get clusters
		clustersResp, _ := service.Projects.Instances.Clusters.List(instance.Name).Context(ctx).Do()
		if clustersResp != nil {
			for _, cluster := range clustersResp.Clusters {
				info.Clusters = append(info.Clusters, ClusterInfo{
					Name:       extractName(cluster.Name),
					Location:   cluster.Location,
					ServeNodes: cluster.ServeNodes,
					State:      cluster.State,
				})
			}
		}

		// Get tables
		tablesResp, _ := service.Projects.Instances.Tables.List(instance.Name).Context(ctx).Do()
		if tablesResp != nil {
			for _, table := range tablesResp.Tables {
				info.Tables = append(info.Tables, extractName(table.Name))
			}
		}

		instances = append(instances, info)
	}

	return instances, nil
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
