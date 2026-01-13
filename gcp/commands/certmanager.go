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
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CERTMANAGER_MODULE_NAME,
			fmt.Sprintf("Could not enumerate certificates in project %s", projectID))
	}

	// Get classic SSL certs
	sslCerts, err := svc.GetSSLCertificates(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CERTMANAGER_MODULE_NAME,
			fmt.Sprintf("Could not enumerate SSL certificates in project %s", projectID))
	}

	// Get certificate maps
	certMaps, err := svc.GetCertificateMaps(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_CERTMANAGER_MODULE_NAME,
			fmt.Sprintf("Could not enumerate certificate maps in project %s", projectID))
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
	m.LootMap["certmanager-details"] = &internal.LootFile{
		Name:     "certmanager-details",
		Contents: "# Certificate Manager Details\n# Generated by CloudFox\n\n",
	}
}

func (m *CertManagerModule) addCertToLoot(cert certmanagerservice.Certificate) {
	// Build flags for special attributes
	var flags []string
	if cert.Wildcard {
		flags = append(flags, "WILDCARD")
	}
	if cert.Expired {
		flags = append(flags, "EXPIRED")
	} else if cert.DaysUntilExpiry <= 30 {
		flags = append(flags, "EXPIRING")
	}
	if cert.SelfManaged {
		flags = append(flags, "SELF-MANAGED")
	}

	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, "] [") + "]"
	}

	m.LootMap["certmanager-details"].Contents += fmt.Sprintf(
		"# %s%s\n"+
			"Project: %s | Location: %s\n"+
			"Type: %s | State: %s\n"+
			"Domains: %s\n"+
			"Expires: %s (%d days)\n\n",
		cert.Name, flagStr,
		cert.ProjectID, cert.Location,
		cert.Type, cert.State,
		strings.Join(cert.Domains, ", "),
		cert.ExpireTime, cert.DaysUntilExpiry,
	)
}

func (m *CertManagerModule) addSSLCertToLoot(cert certmanagerservice.SSLCertificate) {
	// Build flags for special attributes
	var flags []string
	if cert.Wildcard {
		flags = append(flags, "WILDCARD")
	}
	if cert.Expired {
		flags = append(flags, "EXPIRED")
	} else if cert.DaysUntilExpiry <= 30 {
		flags = append(flags, "EXPIRING")
	}
	if cert.SelfManaged {
		flags = append(flags, "SELF-MANAGED")
	}

	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, "] [") + "]"
	}

	m.LootMap["certmanager-details"].Contents += fmt.Sprintf(
		"# %s (SSL Certificate)%s\n"+
			"Project: %s | Type: %s\n"+
			"Domains: %s\n"+
			"Expires: %s (%d days)\n\n",
		cert.Name, flagStr,
		cert.ProjectID, cert.Type,
		strings.Join(cert.Domains, ", "),
		cert.ExpireTime, cert.DaysUntilExpiry,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *CertManagerModule) writeOutput(ctx context.Context, logger internal.Logger) {
	var tables []internal.TableFile

	// Combined certificates table
	header := []string{"Project Name", "Project ID", "Name", "Type", "Domains", "Expires", "Days Left", "Wildcard", "Expired", "Self-Managed"}
	var body [][]string

	for _, cert := range m.Certificates {
		wildcard := "No"
		if cert.Wildcard {
			wildcard = "Yes"
		}
		expired := "No"
		if cert.Expired {
			expired = "Yes"
		}
		selfManaged := "No"
		if cert.SelfManaged {
			selfManaged = "Yes"
		}

		body = append(body, []string{
			m.GetProjectName(cert.ProjectID),
			cert.ProjectID,
			cert.Name,
			cert.Type,
			strings.Join(cert.Domains, ", "),
			cert.ExpireTime,
			fmt.Sprintf("%d", cert.DaysUntilExpiry),
			wildcard,
			expired,
			selfManaged,
		})
	}

	for _, cert := range m.SSLCertificates {
		wildcard := "No"
		if cert.Wildcard {
			wildcard = "Yes"
		}
		expired := "No"
		if cert.Expired {
			expired = "Yes"
		}
		selfManaged := "No"
		if cert.SelfManaged {
			selfManaged = "Yes"
		}

		body = append(body, []string{
			m.GetProjectName(cert.ProjectID),
			cert.ProjectID,
			cert.Name,
			cert.Type,
			strings.Join(cert.Domains, ", "),
			cert.ExpireTime,
			fmt.Sprintf("%d", cert.DaysUntilExpiry),
			wildcard,
			expired,
			selfManaged,
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
		mapHeader := []string{"Project Name", "Project ID", "Name", "Location", "Entries", "Certificates"}
		var mapBody [][]string

		for _, certMap := range m.CertMaps {
			mapBody = append(mapBody, []string{
				m.GetProjectName(certMap.ProjectID),
				certMap.ProjectID,
				certMap.Name,
				certMap.Location,
				fmt.Sprintf("%d", certMap.EntryCount),
				strings.Join(certMap.Certificates, ", "),
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
