package plugin

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSReconBase struct {
	Profile         string `param:"profile"              desc:"AWS profile to use" shortcode:"p"`
	ProfileDir      string `param:"profile-dir"          desc:"Set to override the default AWS profile directory"`
	CacheDir        string `param:"cache-dir"            desc:"Directory to store API response cache files"`
	CacheExt        string `param:"cache-ext"            desc:"Name of AWS API response cache files extension" default:".aws-cache"`
	CacheTTL        int    `param:"cache-ttl"            desc:"TTL for cached responses in seconds" default:"3600"`
	CacheErrorTypes string `param:"cache-error-resp-type" desc:"Comma-separated cache error response types, e.g., TypeNotFoundException, AccessDeniedException. Use all to represent any error."`
	CacheErrorResp  bool   `param:"cache-error-resp"     desc:"Cache error response" default:"false"`
	DisableCache    bool   `param:"disable-cache"        desc:"Disable API response caching" default:"false"`
	OpsecLevel      string `param:"opsec_level"          desc:"Operational security level for AWS operations" default:"none"`
}

func (c *AWSReconBase) ApplyDefaults() {
	if c.CacheDir == "" {
		c.CacheDir = filepath.Join(os.TempDir(), "aurelian-cache")
	}
}

// HelperOpts converts config fields to []*types.Option for internal/helpers compatibility.
func (c *AWSReconBase) HelperOpts() []*types.Option {
	var opts []*types.Option
	if c.ProfileDir != "" {
		opts = append(opts, &types.Option{Name: "profile-dir", Value: c.ProfileDir})
	}
	if c.CacheDir != "" {
		opts = append(opts, &types.Option{Name: "cache-dir", Value: c.CacheDir})
	}
	if c.CacheExt != "" {
		opts = append(opts, &types.Option{Name: "cache-ext", Value: c.CacheExt})
	}
	if c.CacheTTL != 0 {
		opts = append(opts, &types.Option{Name: "cache-ttl", Value: strconv.Itoa(c.CacheTTL)})
	}
	if c.CacheErrorTypes != "" {
		opts = append(opts, &types.Option{Name: "cache-error-resp-type", Value: c.CacheErrorTypes})
	}
	if c.CacheErrorResp {
		opts = append(opts, &types.Option{Name: "cache-error-resp", Value: "true"})
	}
	if c.DisableCache {
		opts = append(opts, &types.Option{Name: "disable-cache", Value: "true"})
	}
	if c.OpsecLevel != "" {
		opts = append(opts, &types.Option{Name: "opsec_level", Value: c.OpsecLevel})
	}
	return opts
}

type AWSCommonRecon struct {
	AWSReconBase
	Concurrency  int      `param:"concurrency" desc:"Maximum concurrent API requests" default:"5"`
	Regions      []string `param:"regions"       desc:"AWS regions to scan" default:"all" shortcode:"r"`
	ResourceType []string `param:"resource-type" desc:"AWS Cloud Control resource type" default:"all" shortcode:"t"`
}
