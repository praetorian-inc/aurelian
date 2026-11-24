// Package scripts provides embedded PowerShell collection scripts for M365 services.
package scripts

import "embed"

//go:embed collect_exchange.ps1
var ExchangeScript embed.FS

//go:embed collect_teams.ps1
var TeamsScript embed.FS

//go:embed collect_sharepoint.ps1
var SharePointScript embed.FS
