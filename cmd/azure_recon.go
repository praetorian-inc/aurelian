//go:build azure || azure_recon || azure_recon_find_secrets || all

package cmd

import (
	_ "github.com/praetorian-inc/nebula/pkg/modules/azure/recon"
)
