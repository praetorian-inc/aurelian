package cmd

// import modules and enrichers so their init() functions are called

import (
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/enrichers"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/enrichers"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/recon"
)
