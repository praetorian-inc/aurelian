//go:build aws || aws_recon || aws_recon_find_secrets || all

package cmd

import (
	_ "github.com/praetorian-inc/nebula/pkg/modules/aws/recon"
)
