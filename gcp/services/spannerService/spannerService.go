package spannerservice

import (
	"context"
	"fmt"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	spanner "google.golang.org/api/spanner/v1"
)

type SpannerService struct {
	session *gcpinternal.SafeSession
}

func New() *SpannerService {
	return &SpannerService{}
}

type SpannerInstanceInfo struct {
	Name        string   `json:"name"`
	ProjectID   string   `json:"projectId"`
	DisplayName string   `json:"displayName"`
	Config      string   `json:"config"`
	NodeCount   int64    `json:"nodeCount"`
	State       string   `json:"state"`
	Databases   []string `json:"databases"`
}

func (s *SpannerService) ListInstances(projectID string) ([]SpannerInstanceInfo, error) {
	ctx := context.Background()
	service, err := spanner.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Spanner service: %v", err)
	}

	var instances []SpannerInstanceInfo
	parent := fmt.Sprintf("projects/%s", projectID)

	req := service.Projects.Instances.List(parent)
	err = req.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, instance := range page.Instances {
			info := SpannerInstanceInfo{
				Name:        extractName(instance.Name),
				ProjectID:   projectID,
				DisplayName: instance.DisplayName,
				Config:      instance.Config,
				NodeCount:   instance.NodeCount,
				State:       instance.State,
			}

			// Get databases for this instance
			dbs, _ := s.listDatabases(service, ctx, instance.Name)
			info.Databases = dbs

			instances = append(instances, info)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return instances, nil
}

func (s *SpannerService) listDatabases(service *spanner.Service, ctx context.Context, instanceName string) ([]string, error) {
	var databases []string
	req := service.Projects.Instances.Databases.List(instanceName)
	err := req.Pages(ctx, func(page *spanner.ListDatabasesResponse) error {
		for _, db := range page.Databases {
			databases = append(databases, extractName(db.Name))
		}
		return nil
	})
	return databases, err
}

func extractName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
