package cmd

// import modules so their init() functions are called

import (
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/analyze"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/recon"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/recon"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/secrets"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/saas/recon"
)
