package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
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

func (c *AWSReconBase) PostBind(_ Config, _ Module) error {
	if c.CacheDir == "" {
		c.CacheDir = filepath.Join(os.TempDir(), "aurelian-cache")
	}
	return nil
}

type AWSCommonRecon struct {
	AWSReconBase
	Concurrency  int      `param:"concurrency"    desc:"Maximum concurrent API requests" default:"5"`
	Regions      []string `param:"regions"        desc:"AWS regions to scan" default:"all" shortcode:"r"`
	ResourceType []string `param:"resource-type"  desc:"AWS Cloud Control resource type" default:"all" shortcode:"t"`
	ResourceID   string   `param:"resource-id"    desc:"Single resource ARN to evaluate (skips enumeration)" shortcode:"i"`
}

func (c *AWSCommonRecon) PostBind(_ Config, _ Module) error {
	if len(c.Regions) == 1 && strings.EqualFold(c.Regions[0], "all") {
		resolved, err := helpers.EnabledRegions(c.Profile, c.ProfileDir)
		if err != nil {
			return fmt.Errorf("resolving regions: %w", err)
		}
		c.Regions = resolved
	}
	return nil
}

type OrgPoliciesParam struct {
	OrgPoliciesFile string                   `param:"org-policies-file" desc:"Path to Org Policies JSON file"`
	OrgPolicies     *orgpolicies.OrgPolicies `param:"-"`
}

func (c *OrgPoliciesParam) PostBind(_ Config, _ Module) error {
	orgPoliciesPath := c.OrgPoliciesFile
	if orgPoliciesPath == "" {
		c.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	fi, err := os.Stat(orgPoliciesPath)
	if err != nil {
		return fmt.Errorf("error reading org policies file %q: %w", orgPoliciesPath, err)
	}

	if fi.Size() == 0 {
		c.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	op, err := iam.LoadJSONFile[orgpolicies.OrgPolicies](orgPoliciesPath)
	if err != nil {
		return fmt.Errorf("loading org policies: %w", err)
	}

	c.OrgPolicies = op
	return nil
}

type ResourceARNParam struct {
	ResourceARN []string `param:"resource-arn"   desc:"AWS target resource ARN" shortcode:"a"`
}
