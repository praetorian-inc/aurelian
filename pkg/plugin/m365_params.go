package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"

	azureauth "github.com/praetorian-inc/aurelian/pkg/azure/auth"
)

// M365CommonParams contains parameters shared by all M365 CIS modules that
// use the Microsoft Graph API.
type M365CommonParams struct {
	AzureReconBase
	TenantID      string                 `param:"tenant-id"      desc:"Entra tenant ID (auto-detected if empty)" default:""`
	TenantDomain  string                 `param:"tenant-domain"  desc:"Primary tenant domain (auto-detected if empty)" default:""`
	Checks        string                 `param:"checks"         desc:"Comma-separated CIS IDs to include" default:""`
	ExcludeChecks string                 `param:"exclude-checks" desc:"Comma-separated CIS IDs to exclude" default:""`
	Concurrency   int                    `param:"concurrency"    desc:"Max concurrent API requests" default:"5"`
	AzureCredential azcore.TokenCredential `param:"-"`
}

func (c *M365CommonParams) PostBind(_ Config, _ Module) error {
	cred, err := azureauth.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("azure authentication failed: %w", err)
	}
	c.AzureCredential = cred
	c.Concurrency = max(1, c.Concurrency)

	// Auto-detect tenant ID and domain via Graph /organization endpoint
	if c.TenantID == "" || c.TenantDomain == "" {
		if err := c.autoDetectTenant(); err != nil {
			slog.Warn("could not auto-detect tenant info, specify --tenant-id and --tenant-domain", "error", err)
		}
	}
	return nil
}

func (c *M365CommonParams) autoDetectTenant() error {
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(c.AzureCredential, nil)
	if err != nil {
		return fmt.Errorf("creating Graph client: %w", err)
	}

	result, err := client.Organization().Get(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("querying /organization: %w", err)
	}

	orgs := result.GetValue()
	if len(orgs) == 0 {
		return fmt.Errorf("no organization found")
	}

	org := orgs[0]
	if c.TenantID == "" && org.GetId() != nil {
		c.TenantID = *org.GetId()
	}
	if c.TenantDomain == "" {
		domains := org.GetVerifiedDomains()
		for _, d := range domains {
			if d.GetIsDefault() != nil && *d.GetIsDefault() && d.GetName() != nil {
				c.TenantDomain = *d.GetName()
				break
			}
		}
		// Fallback to first domain
		if c.TenantDomain == "" && len(domains) > 0 && domains[0].GetName() != nil {
			c.TenantDomain = *domains[0].GetName()
		}
	}

	slog.Info("detected M365 tenant", "tenant_id", c.TenantID, "domain", c.TenantDomain)
	return nil
}

// ParseCheckFilter parses a comma-separated list of CIS IDs into a map.
func ParseCheckFilter(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	result := make(map[string]bool)
	for _, id := range strings.Split(raw, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			result[id] = true
		}
	}
	return result
}

// M365PowerShellParams extends M365CommonParams for modules that require
// PowerShell for data collection (Exchange, Teams, SharePoint).
type M365PowerShellParams struct {
	M365CommonParams
	PowerShellPath       string `param:"powershell-path"       desc:"Path to pwsh binary" default:"pwsh"`
	SkipPowerShell       bool   `param:"skip-powershell"       desc:"Skip checks requiring PowerShell" default:"false"`
	SharePointAdminURL   string `param:"sharepoint-admin-url"  desc:"SharePoint admin URL (e.g. https://contoso-admin.sharepoint.com)" default:""`
	PowerShellAvailable  bool   `param:"-"`
}

func (p *M365PowerShellParams) PostBind(cfg Config, m Module) error {
	// Parent PostBind is invoked automatically by the framework's recursive
	// PostBinder walk, so we only handle PowerShell-specific logic here.

	if p.SkipPowerShell {
		slog.Info("PowerShell collection skipped (--skip-powershell)")
		p.PowerShellAvailable = false
		return nil
	}

	resolved := p.PowerShellPath
	if resolved == "" {
		resolved = "pwsh"
	}

	if filepath.IsAbs(resolved) {
		// Explicit absolute path — check it exists.
		if _, err := exec.LookPath(resolved); err != nil {
			slog.Warn("PowerShell binary not found at explicit path; PowerShell collection will be unavailable",
				"path", resolved, "error", err)
			p.PowerShellAvailable = false
			return nil
		}
	} else {
		// Search PATH for the binary name.
		found, err := exec.LookPath(resolved)
		if err != nil {
			slog.Warn("PowerShell (pwsh) not found on PATH; PowerShell collection will be unavailable. "+
				"Install PowerShell 7+ (https://aka.ms/powershell) or use --skip-powershell",
				"error", err)
			p.PowerShellAvailable = false
			return nil
		}
		resolved = found
	}

	p.PowerShellPath = resolved
	p.PowerShellAvailable = true
	slog.Info("PowerShell available", "path", resolved)

	// Auto-derive SharePoint admin URL from tenant domain if not explicitly set.
	if p.SharePointAdminURL == "" && p.TenantDomain != "" {
		// Convention: contoso.onmicrosoft.com -> https://contoso-admin.sharepoint.com
		parts := strings.SplitN(p.TenantDomain, ".", 2)
		if len(parts) > 0 && parts[0] != "" {
			p.SharePointAdminURL = fmt.Sprintf("https://%s-admin.sharepoint.com", parts[0])
			slog.Info("auto-derived SharePoint admin URL", "url", p.SharePointAdminURL)
		}
	}

	return nil
}
