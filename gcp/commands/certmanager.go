package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	certmanagerservice "github.com/BishopFox/cloudfox/gcp/services/certManagerService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPCertManagerCommand = &cobra.Command{
	Use:     globals.GCP_CERTMANAGER_MODULE_NAME,
	Aliases: []string{"certs", "certificates", "ssl"},
	Short:   "Enumerate SSL/TLS certificates and find expiring or misconfigured certs",
	Long: `Enumerate SSL/TLS certificates from Certificate Manager and Compute Engine.

This module finds all certificates and identifies security issues:
- Expired or soon-to-expire certificates
- Failed certificate issuance
- Wildcard certificates (higher impact if compromised)
- Self-managed certificates that need manual renewal

Security Relevance:
- Expired certificates cause outages and security warnings
- Wildcard certificates can be abused to MITM any subdomain
- Certificate domains reveal infrastructure and services
- Self-managed certs may have exposed private keys

What this module finds:
- Certificate Manager certificates (global)
- Compute Engine SSL certificates (classic)
- Certificate maps
- Expiration status
- Associated domains`,
	Run: runGCPCertManagerCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type CertManagerModule struct {
	gcpinternal.BaseGCPModule

	Certificates    []certmanagerservice.Certificate
	SSLCertificates []certmanagerservice.SSLCertificate
	CertMaps        []certmanagerservice.CertificateMap
	LootMap         map[string]*internal.LootFile
	mu              sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type CertManagerOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o CertManagerOutput) TableFiles() []internal.TableFile { return o.Table }
func (o CertManagerOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPCertManagerCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_CERTMANAGER_MODULE_NAME)
	if err != nil {
		return
	}

	module := &CertManagerModule{
		BaseGCPModule:   gcpinternal.NewBaseGCPModule(cmdCtx),
		Certificates:    []certmanagerservice.Certificate{},
		SSLCertificates: []certmanagerservice.SSLCertificate{},
		CertMaps:        []certmanagerservice.CertificateMap{},
		LootMap:         make(map[string]*internal.LootFile),
	}

	module.initializeLootFiles()
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *CertManagerModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_CERTMANAGER_MODULE_NAME, m.processProject)

	totalCerts := len(m.Certificates) + len(m.SSLCertificates)

	if totalCerts == 0 {
		logger.InfoM("No certificates found", globals.GCP_CERTMANAGER_MODULE_NAME)
		return
	}

	// Count expiring/expired certs
	expiringCount := 0
	expiredCount := 0

	for _, cert := range m.Certificates {
		if cert.DaysUntilExpiry < 0 {
			expiredCount++
		} else if cert.DaysUntilExpiry <= 30 {
			expiringCount++
		}
	}
	for _, cert := range m.SSLCertificates {
		if cert.DaysUntilExpiry < 0 {
			expiredCount++
		} else if cert.DaysUntilExpiry <= 30 {
			expiringCount++
		}
	}

	logger.SuccessM(fmt.Sprintf("Found %d certificate(s), %d map(s)",
		totalCerts, len(m.CertMaps)), globals.GCP_CERTMANAGER_MODULE_NAME)

	if expiredCount > 0 {
		logger.InfoM(fmt.Sprintf("[HIGH] %d certificate(s) have EXPIRED!", expiredCount), globals.GCP_CERTMANAGER_MODULE_NAME)
	}
	if expiringCount > 0 {
		logger.InfoM(fmt.Sprintf("[MEDIUM] %d certificate(s) expire within 30 days", expiringCount), globals.GCP_CERTMANAGER_MODULE_NAME)
	}

	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *CertManagerModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Checking certificates in project: %s", projectID), globals.GCP_CERTMANAGER_MODULE_NAME)
	}

	svc := certmanagerservice.New()

	// Get Certificate Manager certs
	certs, err := svc.GetCertificates(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting certificates for %s: %v", projectID, err), globals.GCP_CERTMANAGER_MODULE_NAME)
		}
	}

	// Get classic SSL certs
	sslCerts, err := svc.GetSSLCertificates(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting SSL certificates for %s: %v", projectID, err), globals.GCP_CERTMANAGER_MODULE_NAME)
		}
	}

	// Get certificate maps
	certMaps, err := svc.GetCertificateMaps(projectID)
	if err != nil {
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error getting certificate maps for %s: %v", projectID, err), globals.GCP_CERTMANAGER_MODULE_NAME)
		}
	}

	m.mu.Lock()
	m.Certificates = append(m.Certificates, certs...)
	m.SSLCertificates = append(m.SSLCertificates, sslCerts...)
	m.CertMaps = append(m.CertMaps, certMaps...)

	for _, cert := range certs {
		m.addCertToLoot(cert)
	}
	for _, cert := range sslCerts {
		m.addSSLCertToLoot(cert)
	}
	m.mu.Unlock()
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *CertManagerModule) initializeLootFiles() {
	m.LootMap["all-certificates"] = &internal.LootFile{
		Name:     "all-certificates",
		Contents: "# SSL/TLS Certificates\n# Generated by CloudFox\n\n",
	}
	m.LootMap["expiring-certificates"] = &internal.LootFile{
		Name:     "expiring-certificates",
		Contents: "# Expiring/Expired Certificates\n# Generated by CloudFox\n# These certificates need immediate attention!\n\n",
	}
	m.LootMap["certificate-domains"] = &internal.LootFile{
		Name:     "certificate-domains",
		Contents: "# Domains from Certificates\n# Generated by CloudFox\n# Useful for subdomain enumeration\n\n",
	}
	m.LootMap["wildcard-certificates"] = &internal.LootFile{
		Name:     "wildcard-certificates",
		Contents: "# Wildcard Certificates\n# Generated by CloudFox\n# High impact if private key is exposed\n\n",
	}
}

func (m *CertManagerModule) addCertToLoot(cert certmanagerservice.Certificate) {
	// All certificates
	m.LootMap["all-certificates"].Contents += fmt.Sprintf(
		"## [%s] %s\n"+
			"## Project: %s | Location: %s\n"+
			"## Type: %s | State: %s\n"+
			"## Domains: %s\n"+
			"## Expires: %s (%d days)\n",
		cert.RiskLevel, cert.Name,
		cert.ProjectID, cert.Location,
		cert.Type, cert.State,
		strings.Join(cert.Domains, ", "),
		cert.ExpireTime, cert.DaysUntilExpiry,
	)
	for _, reason := range cert.RiskReasons {
		m.LootMap["all-certificates"].Contents += fmt.Sprintf("##   - %s\n", reason)
	}
	m.LootMap["all-certificates"].Contents += "\n"

	// Expiring certificates
	if cert.DaysUntilExpiry <= 30 {
		status := "EXPIRING"
		if cert.DaysUntilExpiry < 0 {
			status = "EXPIRED"
		}
		m.LootMap["expiring-certificates"].Contents += fmt.Sprintf(
			"## [%s] %s\n"+
				"## Project: %s\n"+
				"## Domains: %s\n"+
				"## Expires: %s (%d days)\n\n",
			status, cert.Name,
			cert.ProjectID,
			strings.Join(cert.Domains, ", "),
			cert.ExpireTime, cert.DaysUntilExpiry,
		)
	}

	// Domains
	for _, domain := range cert.Domains {
		m.LootMap["certificate-domains"].Contents += domain + "\n"
	}

	// Wildcard certificates
	for _, domain := range cert.Domains {
		if strings.HasPrefix(domain, "*") {
			m.LootMap["wildcard-certificates"].Contents += fmt.Sprintf(
				"## %s (Project: %s)\n"+
					"## Wildcard Domain: %s\n"+
					"## If the private key is compromised, an attacker can MITM any subdomain\n"+
					"## Check for: key material in repos, backups, logs, or developer machines\n\n",
				cert.Name, cert.ProjectID, domain,
			)
			break
		}
	}
}

func (m *CertManagerModule) addSSLCertToLoot(cert certmanagerservice.SSLCertificate) {
	// All certificates
	m.LootMap["all-certificates"].Contents += fmt.Sprintf(
		"## [%s] %s (SSL Certificate)\n"+
			"## Project: %s | Type: %s\n"+
			"## Domains: %s\n"+
			"## Expires: %s (%d days)\n",
		cert.RiskLevel, cert.Name,
		cert.ProjectID, cert.Type,
		strings.Join(cert.Domains, ", "),
		cert.ExpireTime, cert.DaysUntilExpiry,
	)
	for _, reason := range cert.RiskReasons {
		m.LootMap["all-certificates"].Contents += fmt.Sprintf("##   - %s\n", reason)
	}
	m.LootMap["all-certificates"].Contents += "\n"

	// Expiring certificates
	if cert.DaysUntilExpiry <= 30 {
		status := "EXPIRING"
		if cert.DaysUntilExpiry < 0 {
			status = "EXPIRED"
		}
		m.LootMap["expiring-certificates"].Contents += fmt.Sprintf(
			"## [%s] %s\n"+
				"## Project: %s\n"+
				"## Domains: %s\n"+
				"## Expires: %s (%d days)\n\n",
			status, cert.Name,
			cert.ProjectID,
			strings.Join(cert.Domains, ", "),
			cert.ExpireTime, cert.DaysUntilExpiry,
		)
	}

	// Domains
	for _, domain := range cert.Domains {
		m.LootMap["certificate-domains"].Contents += domain + "\n"
	}

	// Wildcard certificates
	for _, domain := range cert.Domains {
		if strings.HasPrefix(domain, "*") {
			m.LootMap["wildcard-certificates"].Contents += fmt.Sprintf(
				"## %s (Project: %s)\n"+
					"## Wildcard Domain: %s\n"+
					"## If the private key is compromised, an attacker can MITM any subdomain\n\n",
				cert.Name, cert.ProjectID, domain,
			)
			break
		}
	}
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CertManagerModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// Combined certificates table
	header := []string{"Risk", "Name", "Type", "Domains", "Expires", "Days Left", "Project Name", "Project ID"}
	var body [][]string

	for _, cert := range m.Certificates {
		domains := strings.Join(cert.Domains, ", ")
		if len(domains) > 40 {
			domains = domains[:37] + "..."
		}

		daysLeft := fmt.Sprintf("%d", cert.DaysUntilExpiry)
		if cert.DaysUntilExpiry < 0 {
			daysLeft = "EXPIRED"
		}

		body = append(body, []string{
			cert.RiskLevel,
			cert.Name,
			cert.Type,
			domains,
			cert.ExpireTime,
			daysLeft,
			m.GetProjectName(cert.ProjectID),
			cert.ProjectID,
		})
	}

	for _, cert := range m.SSLCertificates {
		domains := strings.Join(cert.Domains, ", ")
		if len(domains) > 40 {
			domains = domains[:37] + "..."
		}

		daysLeft := fmt.Sprintf("%d", cert.DaysUntilExpiry)
		if cert.DaysUntilExpiry < 0 {
			daysLeft = "EXPIRED"
		}

		body = append(body, []string{
			cert.RiskLevel,
			cert.Name,
			cert.Type,
			domains,
			cert.ExpireTime,
			daysLeft,
			m.GetProjectName(cert.ProjectID),
			cert.ProjectID,
		})
	}

	if len(body) > 0 {
		tables = append(tables, internal.TableFile{
			Name:   "certificates",
			Header: header,
			Body:   body,
		})
	}

	// Certificate maps table
	if len(m.CertMaps) > 0 {
		mapHeader := []string{"Risk", "Name", "Location", "Entries", "Certificates", "Project Name", "Project ID"}
		var mapBody [][]string

		for _, certMap := range m.CertMaps {
			certs := strings.Join(certMap.Certificates, ", ")
			if len(certs) > 40 {
				certs = certs[:37] + "..."
			}

			mapBody = append(mapBody, []string{
				certMap.RiskLevel,
				certMap.Name,
				certMap.Location,
				fmt.Sprintf("%d", certMap.EntryCount),
				certs,
				m.GetProjectName(certMap.ProjectID),
				certMap.ProjectID,
			})
		}

		tables = append(tables, internal.TableFile{
			Name:   "certificate-maps",
			Header: mapHeader,
			Body:   mapBody,
		})
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	output := CertManagerOutput{
		Table: tables,
		Loot:  lootFiles,
	}

	// Build scopeNames using GetProjectName
	scopeNames := make([]string, len(m.ProjectIDs))
	for i, projectID := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(projectID)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_CERTMANAGER_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
