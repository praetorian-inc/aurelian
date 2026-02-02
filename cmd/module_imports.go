package cmd

// import modules so their init() functions are called

import (
	_ "github.com/praetorian-inc/diocletian/pkg/modules/aws/analyze"
	_ "github.com/praetorian-inc/diocletian/pkg/modules/aws/recon"
	_ "github.com/praetorian-inc/diocletian/pkg/modules/azure/recon"
	_ "github.com/praetorian-inc/diocletian/pkg/modules/gcp/recon"
	_ "github.com/praetorian-inc/diocletian/pkg/modules/gcp/secrets"
	_ "github.com/praetorian-inc/diocletian/pkg/modules/saas/recon"
)
