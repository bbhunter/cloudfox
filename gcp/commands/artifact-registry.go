package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	ArtifactRegistryService "github.com/BishopFox/cloudfox/gcp/services/artifactRegistryService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPArtifactRegistryCommand = &cobra.Command{
	Use:     globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME,
	Aliases: []string{"ar", "artifacts", "gcr"},
	Short:   "Enumerate GCP Artifact Registry and Container Registry with security configuration",
	Long: `Enumerate GCP Artifact Registry and legacy Container Registry (gcr.io) with security-relevant details.

Features:
- Lists all Artifact Registry repositories with security configuration
- Shows Docker images and package artifacts with tags and digests
- Enumerates IAM policies per repository and identifies public repositories
- Shows encryption type (Google-managed vs CMEK)
- Shows repository mode (standard, virtual, remote)
- Generates gcloud commands for artifact enumeration
- Generates exploitation commands for artifact access
- Enumerates legacy Container Registry (gcr.io) locations

Security Columns:
- Public: Whether the repository has allUsers or allAuthenticatedUsers access
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)
- Mode: STANDARD_REPOSITORY, VIRTUAL_REPOSITORY, or REMOTE_REPOSITORY
- RegistryType: "artifact-registry" or "container-registry" (legacy gcr.io)`,
	Run: runGCPArtifactRegistryCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type ArtifactRegistryModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Artifacts    []ArtifactRegistryService.ArtifactInfo
	Repositories []ArtifactRegistryService.RepositoryInfo
	LootMap      map[string]*internal.LootFile
	client       *artifactregistry.Client
	mu           sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type ArtifactRegistryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ArtifactRegistryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ArtifactRegistryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPArtifactRegistryCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create Artifact Registry client
	client, err := artifactregistry.NewClient(cmdCtx.Ctx)
	if err != nil {
		cmdCtx.Logger.ErrorM(fmt.Sprintf("Failed to create Artifact Registry client: %v", err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return
	}
	defer client.Close()

	// Create module instance
	module := &ArtifactRegistryModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Artifacts:     []ArtifactRegistryService.ArtifactInfo{},
		Repositories:  []ArtifactRegistryService.RepositoryInfo{},
		LootMap:       make(map[string]*internal.LootFile),
		client:        client,
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ArtifactRegistryModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Repositories) == 0 && len(m.Artifacts) == 0 {
		logger.InfoM("No artifact registries found", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d repository(ies) with %d artifact(s)", len(m.Repositories), len(m.Artifacts)), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *ArtifactRegistryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating artifact registries in project: %s", projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	// Create service and fetch data
	ars := ArtifactRegistryService.New(m.client)
	result, err := ars.RepositoriesAndArtifacts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME,
			fmt.Sprintf("Could not enumerate artifact registries in project %s", projectID))
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Repositories = append(m.Repositories, result.Repositories...)
	m.Artifacts = append(m.Artifacts, result.Artifacts...)

	// Generate loot for each repository and artifact
	for _, repo := range result.Repositories {
		m.addRepositoryToLoot(repo)
	}
	for _, artifact := range result.Artifacts {
		m.addArtifactToLoot(artifact)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d repository(ies) and %d artifact(s) in project %s", len(result.Repositories), len(result.Artifacts), projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ArtifactRegistryModule) initializeLootFiles() {
	m.LootMap["artifact-registry-commands"] = &internal.LootFile{
		Name:     "artifact-registry-commands",
		Contents: "# GCP Artifact Registry Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
}

func (m *ArtifactRegistryModule) addRepositoryToLoot(repo ArtifactRegistryService.RepositoryInfo) {
	// Extract repo name from full path
	repoName := repo.Name
	parts := strings.Split(repo.Name, "/")
	if len(parts) > 0 {
		repoName = parts[len(parts)-1]
	}

	// Handle legacy Container Registry differently
	if repo.RegistryType == "container-registry" {
		m.LootMap["artifact-registry-commands"].Contents += fmt.Sprintf(
			"## Legacy Container Registry: %s (Project: %s)\n"+
				"# Note: Consider migrating to Artifact Registry\n"+
				"# Configure Docker authentication:\n"+
				"gcloud auth configure-docker %s\n"+
				"# List images:\n"+
				"gcloud container images list --repository=%s/%s\n"+
				"# Check for public access (via storage bucket):\n"+
				"gsutil iam get gs://artifacts.%s.appspot.com\n\n",
			repo.Name, repo.ProjectID,
			strings.Split(repo.Name, "/")[0], // gcr.io hostname
			strings.Split(repo.Name, "/")[0], repo.ProjectID,
			repo.ProjectID,
		)
		return
	}

	// Repository header and enumeration commands
	m.LootMap["artifact-registry-commands"].Contents += fmt.Sprintf(
		"## Repository: %s (Project: %s, Location: %s)\n"+
			"# Format: %s, Mode: %s, Encryption: %s, Public: %s\n"+
			"# Describe repository:\n"+
			"gcloud artifacts repositories describe %s --project=%s --location=%s\n"+
			"# Get IAM policy:\n"+
			"gcloud artifacts repositories get-iam-policy %s --project=%s --location=%s\n",
		repoName, repo.ProjectID, repo.Location,
		repo.Format, repo.Mode, repo.EncryptionType, repo.PublicAccess,
		repoName, repo.ProjectID, repo.Location,
		repoName, repo.ProjectID, repo.Location,
	)

	// Docker-specific commands
	if repo.Format == "DOCKER" {
		m.LootMap["artifact-registry-commands"].Contents += fmt.Sprintf(
			"# Configure Docker authentication:\n"+
				"gcloud auth configure-docker %s-docker.pkg.dev\n"+
				"# List images:\n"+
				"gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s\n"+
				"# List vulnerabilities:\n"+
				"gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s --show-occurrences --occurrence-filter=\"kind=VULNERABILITY\"\n",
			repo.Location,
			repo.Location, repo.ProjectID, repoName,
			repo.Location, repo.ProjectID, repoName,
		)
	}

	m.LootMap["artifact-registry-commands"].Contents += "\n"
}

func (m *ArtifactRegistryModule) addArtifactToLoot(artifact ArtifactRegistryService.ArtifactInfo) {
	// Exploitation commands for Docker images
	if artifact.Format == "DOCKER" {
		imageBase := fmt.Sprintf("%s-docker.pkg.dev/%s/%s/%s",
			artifact.Location, artifact.ProjectID, artifact.Repository, artifact.Name)

		m.LootMap["artifact-registry-commands"].Contents += fmt.Sprintf(
			"## Docker Image: %s (Project: %s)\n"+
				"# Repository: %s, Location: %s\n"+
				"# Digest: %s\n",
			artifact.Name, artifact.ProjectID,
			artifact.Repository, artifact.Location,
			artifact.Digest,
		)

		// Generate commands for each tag
		if len(artifact.Tags) > 0 {
			for _, tag := range artifact.Tags {
				m.LootMap["artifact-registry-commands"].Contents += fmt.Sprintf(
					"# Tag: %s\n"+
						"docker pull %s:%s\n"+
						"docker inspect %s:%s\n"+
						"docker run -it --entrypoint /bin/sh %s:%s\n\n",
					tag,
					imageBase, tag,
					imageBase, tag,
					imageBase, tag,
				)
			}
		} else {
			// No tags, use digest
			m.LootMap["artifact-registry-commands"].Contents += fmt.Sprintf(
				"# No tags - use digest\n"+
					"docker pull %s@%s\n"+
					"docker inspect %s@%s\n"+
					"docker run -it --entrypoint /bin/sh %s@%s\n\n",
				imageBase, artifact.Digest,
				imageBase, artifact.Digest,
				imageBase, artifact.Digest,
			)
		}
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ArtifactRegistryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Repository table with IAM columns (one row per IAM member)
	repoHeader := []string{
		"Project ID",
		"Project Name",
		"Name",
		"Format",
		"Location",
		"Mode",
		"Public",
		"Encryption",
		"Role",
		"Member Type",
		"Member",
	}

	var repoBody [][]string
	publicCount := 0
	for _, repo := range m.Repositories {
		// Extract repo name from full path
		repoName := repo.Name
		parts := strings.Split(repo.Name, "/")
		if len(parts) > 0 {
			repoName = parts[len(parts)-1]
		}

		// Format public access display
		publicDisplay := ""
		if repo.IsPublic {
			publicDisplay = repo.PublicAccess
			publicCount++
		}

		// Shorten mode for display
		mode := repo.Mode
		mode = strings.TrimPrefix(mode, "REPOSITORY_MODE_")
		mode = strings.TrimSuffix(mode, "_REPOSITORY")

		// One row per IAM member
		if len(repo.IAMBindings) > 0 {
			for _, binding := range repo.IAMBindings {
				for _, member := range binding.Members {
					memberType := ArtifactRegistryService.GetMemberType(member)
					repoBody = append(repoBody, []string{
						repo.ProjectID,
						m.GetProjectName(repo.ProjectID),
						repoName,
						repo.Format,
						repo.Location,
						mode,
						publicDisplay,
						repo.EncryptionType,
						binding.Role,
						memberType,
						member,
					})
				}
			}
		} else {
			// Repository with no IAM bindings
			repoBody = append(repoBody, []string{
				repo.ProjectID,
				m.GetProjectName(repo.ProjectID),
				repoName,
				repo.Format,
				repo.Location,
				mode,
				publicDisplay,
				repo.EncryptionType,
				"-",
				"-",
				"-",
			})
		}
	}

	// Artifact table
	artifactHeader := []string{
		"Project ID",
		"Project Name",
		"Name",
		"Repository",
		"Location",
		"Tags",
		"Digest",
		"Size",
		"Uploaded",
	}

	var artifactBody [][]string
	for _, artifact := range m.Artifacts {
		// Format tags
		tags := "-"
		if len(artifact.Tags) > 0 {
			if len(artifact.Tags) <= 3 {
				tags = strings.Join(artifact.Tags, ", ")
			} else {
				tags = fmt.Sprintf("%s (+%d more)", strings.Join(artifact.Tags[:3], ", "), len(artifact.Tags)-3)
			}
		}

		digest := artifact.Digest

		artifactBody = append(artifactBody, []string{
			artifact.ProjectID,
			m.GetProjectName(artifact.ProjectID),
			artifact.Name,
			artifact.Repository,
			artifact.Location,
			tags,
			digest,
			artifact.SizeBytes,
			artifact.Uploaded,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{
		{
			Name:   fmt.Sprintf("%s-repos", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
			Header: repoHeader,
			Body:   repoBody,
		},
	}

	// Add artifacts table if there are any
	if len(artifactBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   fmt.Sprintf("%s-artifacts", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
			Header: artifactHeader,
			Body:   artifactBody,
		})
	}

	if publicCount > 0 {
		logger.InfoM(fmt.Sprintf("[FINDING] Found %d publicly accessible repository(ies)!", publicCount), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	output := ArtifactRegistryOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",    // scopeType
		m.ProjectIDs, // scopeIdentifiers
		scopeNames,   // scopeNames
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
