package opts

import (
	"regexp"

	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/util"
)

func AWSRegions() cfg.Param {
	return cfg.NewParam[[]string]("regions", "AWS regions to scan").
		WithDefault(util.Regions).
		WithRegex(regexp.MustCompile(`(?i)^[a-z]{2}\-([a-z]+\-){1,2}\d|all$`)).
		AsRequired()
}

func AWSProfile() cfg.Param {
	return cfg.NewParam[string]("profile", "AWS profile to use").AsRequired()
}
