package plugin

import (
	"os"
	"path/filepath"
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

type AWSCommonRecon struct {
	AWSReconBase
	Concurrency  int      `param:"concurrency"   desc:"Maximum concurrent API requests" default:"5"`
	Regions      []string `param:"regions"        desc:"AWS regions to scan" default:"all" shortcode:"r"`
	ResourceType []string `param:"resource-type"  desc:"AWS Cloud Control resource type" default:"all" shortcode:"t"`
	ResourceID   string   `param:"resource-id"    desc:"Single resource ARN to evaluate (skips enumeration)" shortcode:"i"`
}
