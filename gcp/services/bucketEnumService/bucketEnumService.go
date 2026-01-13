package bucketenumservice

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"google.golang.org/api/iterator"
	"google.golang.org/api/storage/v1"
)

type BucketEnumService struct {
	session *gcpinternal.SafeSession
}

func New() *BucketEnumService {
	return &BucketEnumService{}
}

func NewWithSession(session *gcpinternal.SafeSession) *BucketEnumService {
	return &BucketEnumService{session: session}
}

// SensitiveFileInfo represents a potentially sensitive file in a bucket
type SensitiveFileInfo struct {
	BucketName   string `json:"bucketName"`
	ObjectName   string `json:"objectName"`
	ProjectID    string `json:"projectId"`
	Size         int64  `json:"size"`
	ContentType  string `json:"contentType"`
	Category     string `json:"category"`     // credential, secret, config, backup, etc.
	RiskLevel    string `json:"riskLevel"`    // CRITICAL, HIGH, MEDIUM, LOW
	Description  string `json:"description"`  // Why it's sensitive
	DownloadCmd  string `json:"downloadCmd"`  // gsutil command to download
	Updated      string `json:"updated"`
	StorageClass string `json:"storageClass"`
	IsPublic     bool   `json:"isPublic"`     // Whether the object has public access
}

// SensitivePatterns defines patterns to search for sensitive files
type SensitivePattern struct {
	Pattern     string
	Category    string
	RiskLevel   string
	Description string
}

// GetSensitivePatterns returns all patterns to check for sensitive files
func GetSensitivePatterns() []SensitivePattern {
	return []SensitivePattern{
		// Credentials - CRITICAL
		{Pattern: ".json", Category: "Credential", RiskLevel: "CRITICAL", Description: "Service account key file"},
		{Pattern: "credentials.json", Category: "Credential", RiskLevel: "CRITICAL", Description: "GCP credentials file"},
		{Pattern: "service-account", Category: "Credential", RiskLevel: "CRITICAL", Description: "Service account key"},
		{Pattern: "keyfile", Category: "Credential", RiskLevel: "CRITICAL", Description: "Key file"},
		{Pattern: ".pem", Category: "Credential", RiskLevel: "CRITICAL", Description: "PEM private key"},
		{Pattern: ".key", Category: "Credential", RiskLevel: "CRITICAL", Description: "Private key file"},
		{Pattern: ".p12", Category: "Credential", RiskLevel: "CRITICAL", Description: "PKCS12 key file"},
		{Pattern: ".pfx", Category: "Credential", RiskLevel: "CRITICAL", Description: "PFX certificate file"},
		{Pattern: "id_rsa", Category: "Credential", RiskLevel: "CRITICAL", Description: "SSH private key"},
		{Pattern: "id_ed25519", Category: "Credential", RiskLevel: "CRITICAL", Description: "SSH private key (ed25519)"},
		{Pattern: "id_ecdsa", Category: "Credential", RiskLevel: "CRITICAL", Description: "SSH private key (ECDSA)"},

		// Secrets - CRITICAL/HIGH
		{Pattern: ".env", Category: "Secret", RiskLevel: "CRITICAL", Description: "Environment variables (may contain secrets)"},
		{Pattern: "secrets", Category: "Secret", RiskLevel: "HIGH", Description: "Secrets file or directory"},
		{Pattern: "password", Category: "Secret", RiskLevel: "HIGH", Description: "Password file"},
		{Pattern: "api_key", Category: "Secret", RiskLevel: "HIGH", Description: "API key file"},
		{Pattern: "apikey", Category: "Secret", RiskLevel: "HIGH", Description: "API key file"},
		{Pattern: "token", Category: "Secret", RiskLevel: "HIGH", Description: "Token file"},
		{Pattern: "auth", Category: "Secret", RiskLevel: "HIGH", Description: "Authentication file"},
		{Pattern: ".htpasswd", Category: "Secret", RiskLevel: "HIGH", Description: "HTTP password file"},
		{Pattern: ".netrc", Category: "Secret", RiskLevel: "HIGH", Description: "FTP/other credentials"},

		// Config files - HIGH/MEDIUM
		{Pattern: "config", Category: "Config", RiskLevel: "MEDIUM", Description: "Configuration file"},
		{Pattern: ".yaml", Category: "Config", RiskLevel: "MEDIUM", Description: "YAML config (may contain secrets)"},
		{Pattern: ".yml", Category: "Config", RiskLevel: "MEDIUM", Description: "YAML config (may contain secrets)"},
		{Pattern: "application.properties", Category: "Config", RiskLevel: "HIGH", Description: "Java app config"},
		{Pattern: "web.config", Category: "Config", RiskLevel: "HIGH", Description: ".NET config"},
		{Pattern: "appsettings.json", Category: "Config", RiskLevel: "HIGH", Description: ".NET app settings"},
		{Pattern: "settings.py", Category: "Config", RiskLevel: "HIGH", Description: "Django settings"},
		{Pattern: "database.yml", Category: "Config", RiskLevel: "HIGH", Description: "Rails database config"},
		{Pattern: "wp-config.php", Category: "Config", RiskLevel: "HIGH", Description: "WordPress config"},
		{Pattern: ".npmrc", Category: "Config", RiskLevel: "HIGH", Description: "NPM config (may contain tokens)"},
		{Pattern: ".dockercfg", Category: "Config", RiskLevel: "HIGH", Description: "Docker registry credentials"},
		{Pattern: "docker-compose", Category: "Config", RiskLevel: "MEDIUM", Description: "Docker compose config"},
		{Pattern: "terraform.tfstate", Category: "Config", RiskLevel: "CRITICAL", Description: "Terraform state (contains secrets)"},
		{Pattern: ".tfstate", Category: "Config", RiskLevel: "CRITICAL", Description: "Terraform state file"},
		{Pattern: "terraform.tfvars", Category: "Config", RiskLevel: "HIGH", Description: "Terraform variables"},
		{Pattern: "kubeconfig", Category: "Config", RiskLevel: "CRITICAL", Description: "Kubernetes config"},
		{Pattern: ".kube/config", Category: "Config", RiskLevel: "CRITICAL", Description: "Kubernetes config"},

		// Backups - HIGH
		{Pattern: ".sql", Category: "Backup", RiskLevel: "HIGH", Description: "SQL database dump"},
		{Pattern: ".dump", Category: "Backup", RiskLevel: "HIGH", Description: "Database dump"},
		{Pattern: ".bak", Category: "Backup", RiskLevel: "MEDIUM", Description: "Backup file"},
		{Pattern: "backup", Category: "Backup", RiskLevel: "MEDIUM", Description: "Backup file/directory"},
		{Pattern: ".tar.gz", Category: "Backup", RiskLevel: "MEDIUM", Description: "Compressed archive"},
		{Pattern: ".zip", Category: "Backup", RiskLevel: "MEDIUM", Description: "ZIP archive"},

		// Source code - MEDIUM
		{Pattern: ".git", Category: "Source", RiskLevel: "MEDIUM", Description: "Git repository data"},
		{Pattern: "source", Category: "Source", RiskLevel: "LOW", Description: "Source code"},

		// Logs - LOW (but may contain sensitive data)
		{Pattern: ".log", Category: "Log", RiskLevel: "LOW", Description: "Log file (may contain sensitive data)"},
		{Pattern: "access.log", Category: "Log", RiskLevel: "MEDIUM", Description: "Access log"},
		{Pattern: "error.log", Category: "Log", RiskLevel: "MEDIUM", Description: "Error log"},

		// Cloud-specific
		{Pattern: "cloudfunctions", Category: "Cloud", RiskLevel: "MEDIUM", Description: "Cloud Functions source"},
		{Pattern: "gcf-sources", Category: "Cloud", RiskLevel: "MEDIUM", Description: "Cloud Functions source bucket"},
		{Pattern: "cloud-build", Category: "Cloud", RiskLevel: "MEDIUM", Description: "Cloud Build artifacts"},
		{Pattern: "artifacts", Category: "Cloud", RiskLevel: "LOW", Description: "Build artifacts"},
	}
}

// EnumerateBucketSensitiveFiles lists potentially sensitive files in a bucket
func (s *BucketEnumService) EnumerateBucketSensitiveFiles(bucketName, projectID string, maxObjects int) ([]SensitiveFileInfo, error) {
	ctx := context.Background()
	var storageService *storage.Service
	var err error

	if s.session != nil {
		storageService, err = storage.NewService(ctx, s.session.GetClientOption())
	} else {
		storageService, err = storage.NewService(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	var sensitiveFiles []SensitiveFileInfo
	patterns := GetSensitivePatterns()

	// List objects in the bucket
	req := storageService.Objects.List(bucketName)
	if maxObjects > 0 {
		req = req.MaxResults(int64(maxObjects))
	}

	err = req.Pages(ctx, func(objects *storage.Objects) error {
		for _, obj := range objects.Items {
			// Check against sensitive patterns
			if info := s.checkObjectSensitivity(obj, bucketName, projectID, patterns); info != nil {
				sensitiveFiles = append(sensitiveFiles, *info)
			}
		}
		return nil
	})

	if err != nil && err != iterator.Done {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	return sensitiveFiles, nil
}

func (s *BucketEnumService) checkObjectSensitivity(obj *storage.Object, bucketName, projectID string, patterns []SensitivePattern) *SensitiveFileInfo {
	if obj == nil {
		return nil
	}

	name := strings.ToLower(obj.Name)
	ext := strings.ToLower(filepath.Ext(obj.Name))
	baseName := strings.ToLower(filepath.Base(obj.Name))

	// Check each pattern
	for _, pattern := range patterns {
		matched := false
		patternLower := strings.ToLower(pattern.Pattern)

		// Check extension match
		if strings.HasPrefix(patternLower, ".") && ext == patternLower {
			matched = true
		}
		// Check name contains pattern
		if strings.Contains(name, patternLower) {
			matched = true
		}
		// Check base name match
		if strings.Contains(baseName, patternLower) {
			matched = true
		}

		if matched {
			// Additional filtering for common false positives
			if s.isFalsePositive(obj.Name, pattern) {
				continue
			}

			// Check if object has public access via ACLs
			isPublic := s.isObjectPublic(obj)

			return &SensitiveFileInfo{
				BucketName:   bucketName,
				ObjectName:   obj.Name,
				ProjectID:    projectID,
				Size:         int64(obj.Size),
				ContentType:  obj.ContentType,
				Category:     pattern.Category,
				RiskLevel:    pattern.RiskLevel,
				Description:  pattern.Description,
				DownloadCmd:  fmt.Sprintf("gsutil cp gs://%s/%s .", bucketName, obj.Name),
				Updated:      obj.Updated,
				StorageClass: obj.StorageClass,
				IsPublic:     isPublic,
			}
		}
	}

	return nil
}

// isObjectPublic checks if an object has public access via ACLs
func (s *BucketEnumService) isObjectPublic(obj *storage.Object) bool {
	if obj == nil || obj.Acl == nil {
		return false
	}

	for _, acl := range obj.Acl {
		// Check for public access entities
		if acl.Entity == "allUsers" || acl.Entity == "allAuthenticatedUsers" {
			return true
		}
	}

	return false
}

func (s *BucketEnumService) isFalsePositive(objectName string, pattern SensitivePattern) bool {
	nameLower := strings.ToLower(objectName)

	// Filter out common false positives
	falsePositivePaths := []string{
		"node_modules/",
		"vendor/",
		".git/objects/",
		"__pycache__/",
		"dist/",
		"build/",
	}

	for _, fp := range falsePositivePaths {
		if strings.Contains(nameLower, fp) {
			return true
		}
	}

	// JSON files that are likely not credentials
	if pattern.Pattern == ".json" {
		// Only flag if it looks like a service account or credential
		if !strings.Contains(nameLower, "service") &&
			!strings.Contains(nameLower, "account") &&
			!strings.Contains(nameLower, "credential") &&
			!strings.Contains(nameLower, "key") &&
			!strings.Contains(nameLower, "secret") &&
			!strings.Contains(nameLower, "auth") {
			return true
		}
	}

	// Filter very small files (likely empty or not useful)
	// This would need to be checked at the object level

	return false
}

// GetBucketsList lists all buckets in a project
func (s *BucketEnumService) GetBucketsList(projectID string) ([]string, error) {
	ctx := context.Background()
	var storageService *storage.Service
	var err error

	if s.session != nil {
		storageService, err = storage.NewService(ctx, s.session.GetClientOption())
	} else {
		storageService, err = storage.NewService(ctx)
	}
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	var buckets []string
	err = storageService.Buckets.List(projectID).Pages(ctx, func(bucketList *storage.Buckets) error {
		for _, bucket := range bucketList.Items {
			buckets = append(buckets, bucket.Name)
		}
		return nil
	})
	if err != nil {
		return nil, gcpinternal.ParseGCPError(err, "storage.googleapis.com")
	}

	return buckets, nil
}
