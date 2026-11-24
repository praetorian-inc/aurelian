package collectors

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/praetorian-inc/aurelian/pkg/m365/scripts"
)

// PowerShellCollector executes PowerShell scripts to collect M365 data
// from Exchange Online, Teams, and SharePoint Online.
type PowerShellCollector struct {
	pwshPath string
}

// NewPowerShellCollector creates a new PowerShellCollector with the given
// path to the pwsh binary. If pwshPath is empty, "pwsh" is used as default.
func NewPowerShellCollector(pwshPath string) *PowerShellCollector {
	if pwshPath == "" {
		pwshPath = "pwsh"
	}
	return &PowerShellCollector{pwshPath: pwshPath}
}

// Available returns true if the configured PowerShell binary can be found.
func (c *PowerShellCollector) Available() bool {
	if filepath.IsAbs(c.pwshPath) {
		_, err := os.Stat(c.pwshPath)
		return err == nil
	}
	_, err := exec.LookPath(c.pwshPath)
	return err == nil
}

// CollectExchangeData runs the Exchange collection script and populates the DataBag.
func (c *PowerShellCollector) CollectExchangeData(ctx context.Context, bag *databag.M365DataBag) error {
	raw, err := c.runScript(ctx, scripts.ExchangeScript, "collect_exchange.ps1", "-TenantDomain", bag.TenantDomain)
	if err != nil {
		return fmt.Errorf("running Exchange collection script: %w", err)
	}
	return parseExchangeJSON(raw, bag)
}

// CollectTeamsData runs the Teams collection script and populates the DataBag.
func (c *PowerShellCollector) CollectTeamsData(ctx context.Context, bag *databag.M365DataBag) error {
	raw, err := c.runScript(ctx, scripts.TeamsScript, "collect_teams.ps1", "-TenantDomain", bag.TenantDomain)
	if err != nil {
		return fmt.Errorf("running Teams collection script: %w", err)
	}
	return parseTeamsJSON(raw, bag)
}

// CollectSharePointData runs the SharePoint collection script and populates the DataBag.
func (c *PowerShellCollector) CollectSharePointData(ctx context.Context, bag *databag.M365DataBag, adminURL string) error {
	raw, err := c.runScript(ctx, scripts.SharePointScript, "collect_sharepoint.ps1", "-AdminUrl", adminURL)
	if err != nil {
		return fmt.Errorf("running SharePoint collection script: %w", err)
	}
	return parseSharePointJSON(raw, bag)
}

// runScript extracts the embedded script to a temp file, executes it with pwsh,
// and returns the stdout output.
func (c *PowerShellCollector) runScript(ctx context.Context, fs embed.FS, scriptPath string, args ...string) ([]byte, error) {
	scriptData, err := fs.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("reading embedded script %s: %w", scriptPath, err)
	}

	tmpDir, err := os.MkdirTemp("", "aurelian-ps-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, filepath.Base(scriptPath))
	if err := os.WriteFile(tmpFile, scriptData, 0600); err != nil {
		return nil, fmt.Errorf("writing temp script: %w", err)
	}

	cmdArgs := []string{"-NoProfile", "-NonInteractive", "-File", tmpFile}
	cmdArgs = append(cmdArgs, args...)

	slog.Info("executing PowerShell script", "script", filepath.Base(scriptPath), "pwsh", c.pwshPath)
	cmd := exec.CommandContext(ctx, c.pwshPath, cmdArgs...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("script %s failed (exit %d): %s", filepath.Base(scriptPath), exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("executing script %s: %w", filepath.Base(scriptPath), err)
	}

	return output, nil
}

// exchangeRawOutput represents the JSON structure output by collect_exchange.ps1.
type exchangeRawOutput struct {
	OrgConfig              json.RawMessage `json:"OrgConfig"`
	TransportRules         json.RawMessage `json:"TransportRules"`
	MailboxAuditConfigs    json.RawMessage `json:"MailboxAuditConfigs"`
	RoleAssignmentPolicies json.RawMessage `json:"RoleAssignmentPolicies"`
	MailboxPolicies        json.RawMessage `json:"MailboxPolicies"`
	SharedMailboxes        json.RawMessage `json:"SharedMailboxes"`
	ExternalInOutlook      json.RawMessage `json:"ExternalInOutlook"`
}

// parseExchangeJSON parses the Exchange PS script output into the DataBag.
func parseExchangeJSON(data []byte, bag *databag.M365DataBag) error {
	var raw exchangeRawOutput
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing Exchange JSON output: %w", err)
	}

	if raw.OrgConfig != nil {
		var orgConfig databag.ExchangeOrgConfig
		if err := json.Unmarshal(raw.OrgConfig, &orgConfig); err != nil {
			slog.Warn("failed to parse OrgConfig", "error", err)
		} else {
			bag.ExchangeConfig = &orgConfig
		}
	}

	if raw.TransportRules != nil {
		var rules []databag.TransportRule
		if err := json.Unmarshal(raw.TransportRules, &rules); err != nil {
			slog.Warn("failed to parse TransportRules", "error", err)
		} else {
			bag.TransportRules = rules
		}
	}

	if raw.MailboxAuditConfigs != nil {
		var audits []databag.MailboxAuditConfig
		if err := json.Unmarshal(raw.MailboxAuditConfigs, &audits); err != nil {
			slog.Warn("failed to parse MailboxAuditConfigs", "error", err)
		} else {
			bag.MailboxAuditConfig = audits
		}
	}

	if raw.RoleAssignmentPolicies != nil {
		var policies []databag.RoleAssignmentPolicy
		if err := json.Unmarshal(raw.RoleAssignmentPolicies, &policies); err != nil {
			slog.Warn("failed to parse RoleAssignmentPolicies", "error", err)
		} else {
			bag.RoleAssignmentPolicies = policies
		}
	}

	if raw.MailboxPolicies != nil {
		var policies []databag.MailboxPolicy
		if err := json.Unmarshal(raw.MailboxPolicies, &policies); err != nil {
			slog.Warn("failed to parse MailboxPolicies", "error", err)
		} else {
			bag.MailboxPolicies = policies
		}
	}

	if raw.SharedMailboxes != nil {
		var mailboxes []databag.SharedMailbox
		if err := json.Unmarshal(raw.SharedMailboxes, &mailboxes); err != nil {
			slog.Warn("failed to parse SharedMailboxes", "error", err)
		} else {
			bag.SharedMailboxes = mailboxes
		}
	}

	if raw.ExternalInOutlook != nil {
		var ext databag.ExternalEmailTagging
		if err := json.Unmarshal(raw.ExternalInOutlook, &ext); err != nil {
			slog.Warn("failed to parse ExternalInOutlook", "error", err)
		} else {
			bag.ExternalEmailTagging = &ext
		}
	}

	slog.Info("parsed Exchange data", "transportRules", len(bag.TransportRules), "mailboxAudits", len(bag.MailboxAuditConfig))
	return nil
}

// teamsRawOutput represents the JSON structure output by collect_teams.ps1.
type teamsRawOutput struct {
	MeetingPolicy     json.RawMessage `json:"MeetingPolicy"`
	ExternalAccess    json.RawMessage `json:"ExternalAccess"`
	ClientConfig      json.RawMessage `json:"ClientConfig"`
	MessagingPolicy   json.RawMessage `json:"MessagingPolicy"`
	SecurityReporting json.RawMessage `json:"SecurityReporting"`
}

// parseTeamsJSON parses the Teams PS script output into the DataBag.
func parseTeamsJSON(data []byte, bag *databag.M365DataBag) error {
	var raw teamsRawOutput
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing Teams JSON output: %w", err)
	}

	if raw.MeetingPolicy != nil {
		var mp databag.TeamsMeetingPolicy
		if err := json.Unmarshal(raw.MeetingPolicy, &mp); err != nil {
			slog.Warn("failed to parse MeetingPolicy", "error", err)
		} else {
			bag.TeamsMeetingPolicy = &mp
		}
	}

	if raw.ExternalAccess != nil {
		var ea databag.TeamsExternalAccessPolicy
		if err := json.Unmarshal(raw.ExternalAccess, &ea); err != nil {
			slog.Warn("failed to parse ExternalAccess", "error", err)
		} else {
			bag.TeamsExternalAccess = &ea
		}
	}

	if raw.ClientConfig != nil {
		var cc databag.TeamsClientConfig
		if err := json.Unmarshal(raw.ClientConfig, &cc); err != nil {
			slog.Warn("failed to parse ClientConfig", "error", err)
		} else {
			bag.TeamsClientConfig = &cc
		}
	}

	if raw.MessagingPolicy != nil {
		var mp databag.TeamsMessagingPolicy
		if err := json.Unmarshal(raw.MessagingPolicy, &mp); err != nil {
			slog.Warn("failed to parse MessagingPolicy", "error", err)
		} else {
			bag.TeamsMessagingPolicy = &mp
		}
	}

	if raw.SecurityReporting != nil {
		var sr databag.TeamsSecurityReporting
		if err := json.Unmarshal(raw.SecurityReporting, &sr); err != nil {
			slog.Warn("failed to parse SecurityReporting", "error", err)
		} else {
			bag.TeamsSecurityReporting = &sr
		}
	}

	slog.Info("parsed Teams data")
	return nil
}

// sharePointRawOutput represents the JSON structure output by collect_sharepoint.ps1.
// The SharePoint script outputs a flat object matching SharePointTenantConfig fields.
type sharePointRawOutput = databag.SharePointTenantConfig

// parseSharePointJSON parses the SharePoint PS script output into the DataBag.
func parseSharePointJSON(data []byte, bag *databag.M365DataBag) error {
	var config databag.SharePointTenantConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing SharePoint JSON output: %w", err)
	}
	bag.SharePointTenant = &config
	slog.Info("parsed SharePoint data", "sharingCapability", config.SharingCapability)
	return nil
}
