package gcpinternal

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

// ------------------------------
// CommandContext holds all common initialization data for GCP commands
// ------------------------------
type CommandContext struct {
	// Context and logger
	Ctx    context.Context
	Logger internal.Logger

	// Project information
	ProjectIDs   []string
	ProjectNames map[string]string // ProjectID -> DisplayName mapping
	Account      string            // Authenticated account email

	// Configuration flags
	Verbosity       int
	WrapTable       bool
	OutputDirectory string
	Format          string
	Goroutines      int
}

// ------------------------------
// BaseGCPModule - Embeddable struct with common fields for all GCP modules
// ------------------------------
// This struct eliminates duplicate field declarations across modules.
// Modules embed this struct instead of declaring these fields individually.
//
// Usage:
//
//	type BucketsModule struct {
//	    gcpinternal.BaseGCPModule  // Embed the base fields
//
//	    // Module-specific fields
//	    Buckets []BucketInfo
//	    mu      sync.Mutex
//	}
type BaseGCPModule struct {
	// Project and identity
	ProjectIDs   []string
	ProjectNames map[string]string // ProjectID -> DisplayName mapping
	Account      string            // Authenticated account email

	// Configuration
	Verbosity       int
	WrapTable       bool
	OutputDirectory string
	Format          string
	Goroutines      int

	// Progress tracking (AWS/Azure style)
	CommandCounter internal.CommandCounter
}

// GetProjectName returns the display name for a project ID, falling back to the ID if not found
func (b *BaseGCPModule) GetProjectName(projectID string) string {
	if b.ProjectNames != nil {
		if name, ok := b.ProjectNames[projectID]; ok {
			return name
		}
	}
	return projectID
}

// ------------------------------
// NewBaseGCPModule - Helper to create BaseGCPModule from CommandContext
// ------------------------------
func NewBaseGCPModule(cmdCtx *CommandContext) BaseGCPModule {
	return BaseGCPModule{
		ProjectIDs:      cmdCtx.ProjectIDs,
		ProjectNames:    cmdCtx.ProjectNames,
		Account:         cmdCtx.Account,
		Verbosity:       cmdCtx.Verbosity,
		WrapTable:       cmdCtx.WrapTable,
		OutputDirectory: cmdCtx.OutputDirectory,
		Format:          cmdCtx.Format,
		Goroutines:      cmdCtx.Goroutines,
	}
}

// ------------------------------
// ProjectProcessor - Callback function type for processing individual projects
// ------------------------------
type ProjectProcessor func(ctx context.Context, projectID string, logger internal.Logger)

// ------------------------------
// RunProjectEnumeration - Orchestrates enumeration across multiple projects with concurrency
// ------------------------------
// This method centralizes the project enumeration orchestration pattern.
// It handles WaitGroup, semaphore, spinner, and CommandCounter management automatically.
//
// Usage:
//
//	func (m *BucketsModule) Execute(ctx context.Context, logger internal.Logger) {
//	    m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_BUCKETS_MODULE_NAME, m.processProject)
//	    m.writeOutput(ctx, logger)
//	}
func (b *BaseGCPModule) RunProjectEnumeration(
	ctx context.Context,
	logger internal.Logger,
	projectIDs []string,
	moduleName string,
	processor ProjectProcessor,
) {
	logger.InfoM(fmt.Sprintf("Enumerating resources for %d project(s)", len(projectIDs)), moduleName)

	// Setup synchronization primitives
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, b.Goroutines)

	// Start progress spinner
	spinnerDone := make(chan bool)
	go internal.SpinUntil(moduleName, &b.CommandCounter, spinnerDone, "projects")

	// Process each project with goroutines
	for _, projectID := range projectIDs {
		b.CommandCounter.Total++
		b.CommandCounter.Pending++
		wg.Add(1)

		go func(project string) {
			defer func() {
				b.CommandCounter.Executing--
				b.CommandCounter.Complete++
				wg.Done()
			}()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			b.CommandCounter.Pending--
			b.CommandCounter.Executing++

			// Call the module-specific processor
			processor(ctx, project, logger)
		}(projectID)
	}

	// Wait for all projects to complete
	wg.Wait()

	// Stop spinner
	spinnerDone <- true
	<-spinnerDone
}

// ------------------------------
// parseMultiValueFlag parses a flag value that can contain comma-separated
// and/or space-separated values
// ------------------------------
func parseMultiValueFlag(flagValue string) []string {
	if flagValue == "" {
		return nil
	}

	// Replace commas with spaces, then split by whitespace
	normalized := strings.ReplaceAll(flagValue, ",", " ")
	fields := strings.Fields(normalized)

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	result := []string{}
	for _, field := range fields {
		if !seen[field] {
			seen[field] = true
			result = append(result, field)
		}
	}
	return result
}

// ------------------------------
// InitializeCommandContext - Eliminates duplicate initialization code across commands
// ------------------------------
// This helper extracts flags, resolves projects and account info.
//
// Usage:
//
//	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_BUCKETS_MODULE_NAME)
//	if err != nil {
//	    return // error already logged
//	}
func InitializeCommandContext(cmd *cobra.Command, moduleName string) (*CommandContext, error) {
	ctx := cmd.Context()
	logger := internal.NewLogger()

	// -------------------- Extract flags --------------------
	parentCmd := cmd.Parent()
	verbosity, _ := parentCmd.PersistentFlags().GetInt("verbosity")
	wrap, _ := parentCmd.PersistentFlags().GetBool("wrap")
	outputDirectory, _ := parentCmd.PersistentFlags().GetString("outdir")
	format, _ := parentCmd.PersistentFlags().GetString("output")

	// -------------------- Get project IDs from context --------------------
	var projectIDs []string
	if value, ok := ctx.Value("projectIDs").([]string); ok && len(value) > 0 {
		projectIDs = value
	} else {
		logger.ErrorM("Could not retrieve projectIDs from context or value is empty", moduleName)
		return nil, fmt.Errorf("no project IDs provided")
	}

	// -------------------- Get project names from context --------------------
	var projectNames map[string]string
	if value, ok := ctx.Value("projectNames").(map[string]string); ok {
		projectNames = value
	} else {
		// Initialize empty map if not provided - modules can still work without names
		projectNames = make(map[string]string)
		for _, id := range projectIDs {
			projectNames[id] = id // fallback to using ID as name
		}
	}

	// -------------------- Get account from context --------------------
	var account string
	if value, ok := ctx.Value("account").(string); ok {
		account = value
	} else {
		logger.ErrorM("Could not retrieve account email from context", moduleName)
		// Don't fail - some modules can continue without account info
	}

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Resolved %d project(s), account: %s", len(projectIDs), account), moduleName)
	}

	// -------------------- Build and return context --------------------
	return &CommandContext{
		Ctx:             ctx,
		Logger:          logger,
		ProjectIDs:      projectIDs,
		ProjectNames:    projectNames,
		Account:         account,
		Verbosity:       verbosity,
		WrapTable:       wrap,
		OutputDirectory: outputDirectory,
		Format:          format,
		Goroutines:      5, // Default concurrency
	}, nil
}
