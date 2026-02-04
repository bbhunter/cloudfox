package gcpinternal

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// AttackPathType represents the type of attack path
type AttackPathType string

const (
	AttackPathPrivesc  AttackPathType = "privesc"
	AttackPathExfil    AttackPathType = "exfil"
	AttackPathLateral  AttackPathType = "lateral"
)

// AttackPathCache holds cached attack path analysis results for all types
// This allows modules to quickly check if a service account or principal has
// privesc/exfil/lateral movement potential without re-running the full analysis
type AttackPathCache struct {
	// ServiceAccountPaths maps service account email -> PathType -> methods
	// Example: "sa@project.iam.gserviceaccount.com" -> "privesc" -> [methods...]
	ServiceAccountPaths map[string]map[AttackPathType][]AttackMethod

	// PrincipalPaths maps any principal (user, group, SA) -> PathType -> methods
	// This includes the full principal string like "serviceAccount:sa@project.iam.gserviceaccount.com"
	PrincipalPaths map[string]map[AttackPathType][]AttackMethod

	// Quick lookups by attack type for summary stats
	PrivescCount  int
	ExfilCount    int
	LateralCount  int

	// Populated indicates whether the cache has been populated with data
	Populated bool

	// RawAttackPathData stores the complete attack path results for modules that need full details
	// This avoids re-enumeration when privesc module runs after --attack-paths flag
	RawAttackPathData interface{}

	mu sync.RWMutex
}

// AttackMethod represents a single attack method (privesc, exfil, or lateral)
type AttackMethod struct {
	Method      string         // e.g., "CreateServiceAccountKey", "ExportCloudSQL"
	PathType    AttackPathType // "privesc", "exfil", "lateral"
	Category    string         // e.g., "SA Impersonation", "Database", "Network"
	RiskLevel   string         // "CRITICAL", "HIGH", "MEDIUM"
	Target      string         // What the method targets
	Permissions []string       // Permissions that enable this method
	ScopeType   string         // "organization", "folder", "project", "resource"
	ScopeID     string         // The scope identifier
}

// NewAttackPathCache creates a new empty attack path cache
func NewAttackPathCache() *AttackPathCache {
	return &AttackPathCache{
		ServiceAccountPaths: make(map[string]map[AttackPathType][]AttackMethod),
		PrincipalPaths:      make(map[string]map[AttackPathType][]AttackMethod),
		Populated:           false,
	}
}

// AddAttackPath adds an attack path to the cache
// principal should be the full member string (e.g., "serviceAccount:sa@project.iam.gserviceaccount.com")
func (c *AttackPathCache) AddAttackPath(principal string, method AttackMethod) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Initialize maps if needed
	if c.PrincipalPaths[principal] == nil {
		c.PrincipalPaths[principal] = make(map[AttackPathType][]AttackMethod)
	}
	c.PrincipalPaths[principal][method.PathType] = append(c.PrincipalPaths[principal][method.PathType], method)

	// Update counts
	switch method.PathType {
	case AttackPathPrivesc:
		c.PrivescCount++
	case AttackPathExfil:
		c.ExfilCount++
	case AttackPathLateral:
		c.LateralCount++
	}

	// If it's a service account, also add to the SA-specific map
	if strings.HasPrefix(principal, "serviceAccount:") {
		email := strings.TrimPrefix(principal, "serviceAccount:")
		if c.ServiceAccountPaths[email] == nil {
			c.ServiceAccountPaths[email] = make(map[AttackPathType][]AttackMethod)
		}
		c.ServiceAccountPaths[email][method.PathType] = append(c.ServiceAccountPaths[email][method.PathType], method)
	}

	// Also check if the principal itself looks like an email (for cleaned member names)
	if strings.Contains(principal, "@") && strings.Contains(principal, ".iam.gserviceaccount.com") {
		if c.ServiceAccountPaths[principal] == nil {
			c.ServiceAccountPaths[principal] = make(map[AttackPathType][]AttackMethod)
		}
		c.ServiceAccountPaths[principal][method.PathType] = append(c.ServiceAccountPaths[principal][method.PathType], method)
	}
}

// MarkPopulated marks the cache as populated
func (c *AttackPathCache) MarkPopulated() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Populated = true
}

// IsPopulated returns whether the cache has been populated
func (c *AttackPathCache) IsPopulated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Populated
}

// HasAttackPath checks if a service account has any attack path of the specified type
// Returns (hasPath bool, methods []AttackMethod)
func (c *AttackPathCache) HasAttackPath(serviceAccount string, pathType AttackPathType) (bool, []AttackMethod) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check direct match
	if pathMap, ok := c.ServiceAccountPaths[serviceAccount]; ok {
		if methods, ok := pathMap[pathType]; ok && len(methods) > 0 {
			return true, methods
		}
	}

	// Check with serviceAccount: prefix
	prefixed := "serviceAccount:" + serviceAccount
	if pathMap, ok := c.PrincipalPaths[prefixed]; ok {
		if methods, ok := pathMap[pathType]; ok && len(methods) > 0 {
			return true, methods
		}
	}

	return false, nil
}

// HasAnyAttackPath checks if a service account has any attack path of any type
// Returns (hasPath bool, pathTypes []AttackPathType)
func (c *AttackPathCache) HasAnyAttackPath(serviceAccount string) (bool, []AttackPathType) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var pathTypes []AttackPathType

	// Check direct match
	if pathMap, ok := c.ServiceAccountPaths[serviceAccount]; ok {
		for pt, methods := range pathMap {
			if len(methods) > 0 {
				pathTypes = append(pathTypes, pt)
			}
		}
	}

	// Check with serviceAccount: prefix if no direct match
	if len(pathTypes) == 0 {
		prefixed := "serviceAccount:" + serviceAccount
		if pathMap, ok := c.PrincipalPaths[prefixed]; ok {
			for pt, methods := range pathMap {
				if len(methods) > 0 {
					pathTypes = append(pathTypes, pt)
				}
			}
		}
	}

	return len(pathTypes) > 0, pathTypes
}

// HasPrivesc checks if a service account has any privilege escalation potential
// Backward compatible with old PrivescCache API
func (c *AttackPathCache) HasPrivesc(serviceAccount string) (bool, []AttackMethod) {
	return c.HasAttackPath(serviceAccount, AttackPathPrivesc)
}

// HasExfil checks if a service account has any data exfiltration potential
func (c *AttackPathCache) HasExfil(serviceAccount string) (bool, []AttackMethod) {
	return c.HasAttackPath(serviceAccount, AttackPathExfil)
}

// HasLateral checks if a service account has any lateral movement potential
func (c *AttackPathCache) HasLateral(serviceAccount string) (bool, []AttackMethod) {
	return c.HasAttackPath(serviceAccount, AttackPathLateral)
}

// HasAttackPathForPrincipal checks if any principal (user, group, SA) has attack path potential
func (c *AttackPathCache) HasAttackPathForPrincipal(principal string, pathType AttackPathType) (bool, []AttackMethod) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if pathMap, ok := c.PrincipalPaths[principal]; ok {
		if methods, ok := pathMap[pathType]; ok && len(methods) > 0 {
			return true, methods
		}
	}

	return false, nil
}

// HasPrivescForPrincipal checks if any principal has privesc potential
// Backward compatible with old PrivescCache API
func (c *AttackPathCache) HasPrivescForPrincipal(principal string) (bool, []AttackMethod) {
	return c.HasAttackPathForPrincipal(principal, AttackPathPrivesc)
}

// GetAllAttackPathsForPrincipal returns all attack paths for a principal across all types
func (c *AttackPathCache) GetAllAttackPathsForPrincipal(principal string) map[AttackPathType][]AttackMethod {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if pathMap, ok := c.PrincipalPaths[principal]; ok {
		// Return a copy to avoid race conditions
		result := make(map[AttackPathType][]AttackMethod)
		for pt, methods := range pathMap {
			result[pt] = append([]AttackMethod{}, methods...)
		}
		return result
	}

	return nil
}

// GetAttackSummary returns a summary string for a service account's attack potential
// Returns: "Yes (P:3 E:2 L:1)" for counts by type, "No" if none, "-" if cache not populated
func (c *AttackPathCache) GetAttackSummary(serviceAccount string) string {
	if !c.IsPopulated() {
		return "-"
	}

	hasAny, pathTypes := c.HasAnyAttackPath(serviceAccount)
	if !hasAny {
		return "No"
	}

	var parts []string
	for _, pt := range pathTypes {
		_, methods := c.HasAttackPath(serviceAccount, pt)
		if len(methods) > 0 {
			switch pt {
			case AttackPathPrivesc:
				parts = append(parts, fmt.Sprintf("P:%d", len(methods)))
			case AttackPathExfil:
				parts = append(parts, fmt.Sprintf("E:%d", len(methods)))
			case AttackPathLateral:
				parts = append(parts, fmt.Sprintf("L:%d", len(methods)))
			}
		}
	}

	if len(parts) == 0 {
		return "No"
	}

	return "Yes (" + strings.Join(parts, " ") + ")"
}

// GetPrivescSummary returns a summary string for privesc only (backward compatible)
func (c *AttackPathCache) GetPrivescSummary(serviceAccount string) string {
	if !c.IsPopulated() {
		return "-"
	}

	hasPrivesc, methods := c.HasPrivesc(serviceAccount)
	if !hasPrivesc || len(methods) == 0 {
		return "No"
	}

	return "Yes"
}

// GetPrivescSummaryWithCount returns a summary with count (backward compatible)
func (c *AttackPathCache) GetPrivescSummaryWithCount(serviceAccount string) string {
	if !c.IsPopulated() {
		return "-"
	}

	hasPrivesc, methods := c.HasPrivesc(serviceAccount)
	if !hasPrivesc || len(methods) == 0 {
		return "No"
	}

	uniqueMethods := make(map[string]bool)
	for _, m := range methods {
		uniqueMethods[m.Method] = true
	}

	return fmt.Sprintf("Yes (%d)", len(uniqueMethods))
}

// GetHighestRiskLevel returns the highest risk level for a service account across all attack types
func (c *AttackPathCache) GetHighestRiskLevel(serviceAccount string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	riskOrder := map[string]int{"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
	highestRisk := ""
	highestOrder := -1

	// Check all path types
	for _, pathType := range []AttackPathType{AttackPathPrivesc, AttackPathExfil, AttackPathLateral} {
		hasPath, methods := c.HasAttackPath(serviceAccount, pathType)
		if !hasPath {
			continue
		}
		for _, m := range methods {
			if order, ok := riskOrder[m.RiskLevel]; ok && order > highestOrder {
				highestOrder = order
				highestRisk = m.RiskLevel
			}
		}
	}

	return highestRisk
}

// GetMethodNames returns a list of unique method names for a service account by attack type
func (c *AttackPathCache) GetMethodNames(serviceAccount string, pathType AttackPathType) []string {
	hasPath, methods := c.HasAttackPath(serviceAccount, pathType)
	if !hasPath {
		return nil
	}

	uniqueMethods := make(map[string]bool)
	var result []string
	for _, m := range methods {
		if !uniqueMethods[m.Method] {
			uniqueMethods[m.Method] = true
			result = append(result, m.Method)
		}
	}

	return result
}

// AttackPathInfo is a minimal representation of an attack path for cache population
// This allows the cache to be populated without importing the service packages
type AttackPathInfo struct {
	Principal     string
	PrincipalType string
	Method        string
	PathType      AttackPathType
	Category      string
	RiskLevel     string
	Target        string
	Permissions   []string
	ScopeType     string
	ScopeID       string
}

// PopulateFromPaths populates the cache from a list of attack path info
func (c *AttackPathCache) PopulateFromPaths(paths []AttackPathInfo) {
	for _, path := range paths {
		method := AttackMethod{
			Method:      path.Method,
			PathType:    path.PathType,
			Category:    path.Category,
			RiskLevel:   path.RiskLevel,
			Target:      path.Target,
			Permissions: path.Permissions,
			ScopeType:   path.ScopeType,
			ScopeID:     path.ScopeID,
		}

		// Build the full principal string
		principal := path.Principal
		if path.PrincipalType == "serviceAccount" && !strings.HasPrefix(principal, "serviceAccount:") {
			principal = "serviceAccount:" + principal
		} else if path.PrincipalType == "user" && !strings.HasPrefix(principal, "user:") {
			principal = "user:" + principal
		} else if path.PrincipalType == "group" && !strings.HasPrefix(principal, "group:") {
			principal = "group:" + principal
		}

		c.AddAttackPath(principal, method)
	}
	c.MarkPopulated()
}

// GetStats returns statistics about the cache
func (c *AttackPathCache) GetStats() (privesc, exfil, lateral int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.PrivescCount, c.ExfilCount, c.LateralCount
}

// SetRawData stores the complete attack path data for modules that need full details
// This is used to avoid re-enumeration when running privesc after --attack-paths flag
func (c *AttackPathCache) SetRawData(data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RawAttackPathData = data
}

// GetRawData retrieves the complete attack path data
// Returns nil if no raw data is stored
func (c *AttackPathCache) GetRawData() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RawAttackPathData
}

// HasRawData returns true if raw attack path data is available
func (c *AttackPathCache) HasRawData() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RawAttackPathData != nil
}

// GetImpersonationTargets returns service accounts that a principal can impersonate
// Looks for SA Impersonation category methods where the target SA is stored in ScopeID
func (c *AttackPathCache) GetImpersonationTargets(principal string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var targets []string
	seen := make(map[string]bool)

	// Check all path types for SA Impersonation category
	checkPaths := func(pathMap map[AttackPathType][]AttackMethod) {
		for _, methods := range pathMap {
			for _, m := range methods {
				if m.Category == "SA Impersonation" && m.ScopeID != "" {
					// ScopeID contains the target SA email when ScopeType is "resource"
					if m.ScopeType == "resource" && strings.Contains(m.ScopeID, "@") {
						if !seen[m.ScopeID] {
							seen[m.ScopeID] = true
							targets = append(targets, m.ScopeID)
						}
					}
				}
			}
		}
	}

	// Check by principal email (for service accounts)
	if pathMap, ok := c.ServiceAccountPaths[principal]; ok {
		checkPaths(pathMap)
	}

	// Check with serviceAccount: prefix
	prefixed := "serviceAccount:" + principal
	if pathMap, ok := c.PrincipalPaths[prefixed]; ok {
		checkPaths(pathMap)
	}

	// Check direct principal match
	if pathMap, ok := c.PrincipalPaths[principal]; ok {
		checkPaths(pathMap)
	}

	return targets
}

// GetTargetsForMethod returns targets for a specific attack method
// This is useful for finding what resources a principal can access via specific permissions
func (c *AttackPathCache) GetTargetsForMethod(principal string, methodName string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var targets []string
	seen := make(map[string]bool)

	checkPaths := func(pathMap map[AttackPathType][]AttackMethod) {
		for _, methods := range pathMap {
			for _, m := range methods {
				if m.Method == methodName && m.ScopeID != "" {
					if !seen[m.ScopeID] {
						seen[m.ScopeID] = true
						targets = append(targets, m.ScopeID)
					}
				}
			}
		}
	}

	// Check all possible locations for this principal
	if pathMap, ok := c.ServiceAccountPaths[principal]; ok {
		checkPaths(pathMap)
	}
	prefixed := "serviceAccount:" + principal
	if pathMap, ok := c.PrincipalPaths[prefixed]; ok {
		checkPaths(pathMap)
	}
	if pathMap, ok := c.PrincipalPaths[principal]; ok {
		checkPaths(pathMap)
	}

	return targets
}

// Context key for attack path cache
type attackPathCacheKey struct{}

// Context key for all-checks mode (skip individual module saves)
type allChecksModeKey struct{}

// GetAttackPathCacheFromContext retrieves the attack path cache from context
func GetAttackPathCacheFromContext(ctx context.Context) *AttackPathCache {
	if cache, ok := ctx.Value(attackPathCacheKey{}).(*AttackPathCache); ok {
		return cache
	}
	return nil
}

// SetAttackPathCacheInContext returns a new context with the attack path cache
func SetAttackPathCacheInContext(ctx context.Context, cache *AttackPathCache) context.Context {
	return context.WithValue(ctx, attackPathCacheKey{}, cache)
}

// IsAllChecksMode returns true if running under all-checks command
// When true, individual modules should skip saving cache to disk
// (all-checks will save consolidated cache at the end)
func IsAllChecksMode(ctx context.Context) bool {
	if mode, ok := ctx.Value(allChecksModeKey{}).(bool); ok {
		return mode
	}
	return false
}

// SetAllChecksMode sets the all-checks mode flag in context
func SetAllChecksMode(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, allChecksModeKey{}, enabled)
}

// Backward compatibility: Keep PrivescCache context functions working
// They now use the unified AttackPathCache under the hood

// GetPrivescCacheFromContext retrieves the attack path cache as a privesc cache interface
// This provides backward compatibility for code using the old PrivescCache
func GetPrivescCacheFromContext(ctx context.Context) *AttackPathCache {
	return GetAttackPathCacheFromContext(ctx)
}

// SetPrivescCacheInContext sets the attack path cache in context
// This provides backward compatibility for code using the old PrivescCache
func SetPrivescCacheInContext(ctx context.Context, cache *AttackPathCache) context.Context {
	return SetAttackPathCacheInContext(ctx, cache)
}
