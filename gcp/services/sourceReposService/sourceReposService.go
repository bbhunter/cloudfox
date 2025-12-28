package sourcereposservice

import (
	"context"
	"fmt"
	"strings"

	sourcerepo "google.golang.org/api/sourcerepo/v1"
)

type SourceReposService struct{}

func New() *SourceReposService {
	return &SourceReposService{}
}

// RepoInfo represents a Cloud Source Repository
type RepoInfo struct {
	Name          string   `json:"name"`
	ProjectID     string   `json:"projectId"`
	URL           string   `json:"url"`
	Size          int64    `json:"size"`
	MirrorConfig  bool     `json:"mirrorConfig"`
	MirrorURL     string   `json:"mirrorUrl"`
	PubsubConfigs int      `json:"pubsubConfigs"`
	RiskLevel     string   `json:"riskLevel"`
	RiskReasons   []string `json:"riskReasons"`
	CloneCommands []string `json:"cloneCommands"`
}

// ListRepos retrieves all Cloud Source Repositories in a project
func (s *SourceReposService) ListRepos(projectID string) ([]RepoInfo, error) {
	ctx := context.Background()
	service, err := sourcerepo.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Source Repo service: %v", err)
	}

	var repos []RepoInfo

	parent := fmt.Sprintf("projects/%s", projectID)
	resp, err := service.Projects.Repos.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list repos: %v", err)
	}

	for _, repo := range resp.Repos {
		info := s.parseRepo(repo, projectID)
		repos = append(repos, info)
	}

	return repos, nil
}

func (s *SourceReposService) parseRepo(repo *sourcerepo.Repo, projectID string) RepoInfo {
	// Extract repo name from full path
	name := repo.Name
	if strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		name = parts[len(parts)-1]
	}

	info := RepoInfo{
		Name:        name,
		ProjectID:   projectID,
		URL:         repo.Url,
		Size:        repo.Size,
		RiskReasons: []string{},
	}

	// Check for mirror configuration
	if repo.MirrorConfig != nil {
		info.MirrorConfig = true
		info.MirrorURL = repo.MirrorConfig.Url
	}

	// Count pubsub configs
	if repo.PubsubConfigs != nil {
		info.PubsubConfigs = len(repo.PubsubConfigs)
	}

	// Generate clone commands
	info.CloneCommands = s.generateCloneCommands(info, projectID)

	// Analyze risk
	info.RiskLevel, info.RiskReasons = s.analyzeRepoRisk(info)

	return info
}

func (s *SourceReposService) generateCloneCommands(repo RepoInfo, projectID string) []string {
	var commands []string

	// Standard gcloud clone
	commands = append(commands,
		fmt.Sprintf("# Clone repository:\ngcloud source repos clone %s --project=%s", repo.Name, projectID))

	// Git clone with credential helper
	commands = append(commands,
		fmt.Sprintf("# Or with git directly:\ngit config credential.helper gcloud.sh && git clone %s", repo.URL))

	// Search for secrets after clone
	commands = append(commands,
		fmt.Sprintf("# Search for secrets in cloned repo:\ncd %s && grep -rE '(password|secret|api_key|private_key|AWS_|GOOGLE_)' .", repo.Name),
		fmt.Sprintf("# Search for credential files:\nfind %s -name '*.pem' -o -name '*.key' -o -name '.env' -o -name 'credentials*'", repo.Name))

	return commands
}

func (s *SourceReposService) analyzeRepoRisk(repo RepoInfo) (string, []string) {
	var reasons []string
	score := 0

	// Large repos might contain more sensitive data
	if repo.Size > 100*1024*1024 { // > 100MB
		reasons = append(reasons, "Large repository (>100MB) - may contain significant code/data")
		score += 1
	}

	// Mirror repos might sync from external sources
	if repo.MirrorConfig {
		reasons = append(reasons, fmt.Sprintf("Mirrors external repo: %s", repo.MirrorURL))
		score += 1
	}

	// Has pubsub triggers (may contain deploy configs)
	if repo.PubsubConfigs > 0 {
		reasons = append(reasons, fmt.Sprintf("Has %d Pub/Sub trigger(s) - may be CI/CD source", repo.PubsubConfigs))
		score += 1
	}

	// All repos are potentially valuable
	reasons = append(reasons, "Source code may contain credentials, API keys, or secrets")

	if score >= 2 {
		return "HIGH", reasons
	} else if score >= 1 {
		return "MEDIUM", reasons
	}
	return "LOW", reasons
}
