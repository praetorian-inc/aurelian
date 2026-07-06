package enumeration

import (
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AWSConfigProvider caches regional AWS configs and resolves the account ID.
// It is safe for concurrent use.
type AWSConfigProvider struct {
	plugin.AWSCommonRecon
	configs       map[string]*aws.Config
	configMu      sync.RWMutex
	accountID     string
	accountIDOnce sync.Once
	accountIDErr  error
}

func NewAWSConfigProvider(opts plugin.AWSCommonRecon) *AWSConfigProvider {
	return &AWSConfigProvider{
		AWSCommonRecon: opts,
		configs:        make(map[string]*aws.Config),
	}
}

// normalizeConfigRegion maps the region-less sentinels used for global resources
// onto us-east-1. Global-service resources reach the provider either with an empty
// region (CloudControlToAWSResource stamps Region:"") or with the literal "global"
// (the IAM enumerator's sentinel); the SDK accepts neither. Their control planes
// live in us-east-1, so resolve to that rather than warning and defaulting deeper
// in NewAWSConfig. Real regions pass through unchanged.
func normalizeConfigRegion(region string) string {
	if region == "" || region == "global" {
		return "us-east-1"
	}
	return region
}

func (p *AWSConfigProvider) GetAWSConfig(region string) (*aws.Config, error) {
	region = normalizeConfigRegion(region)

	p.configMu.RLock()
	if cfg, ok := p.configs[region]; ok {
		p.configMu.RUnlock()
		return cfg, nil
	}
	p.configMu.RUnlock()

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    p.Profile,
		ProfileDir: p.ProfileDir,
	})
	if err != nil {
		return nil, err
	}

	p.configMu.Lock()
	p.configs[region] = &awsCfg
	p.configMu.Unlock()

	return &awsCfg, nil
}

func (p *AWSConfigProvider) GetAccountID(region string) (string, error) {
	p.accountIDOnce.Do(func() {
		awsCfg, err := p.GetAWSConfig(region)
		if err != nil {
			p.accountIDErr = err
			return
		}
		p.accountID, p.accountIDErr = awshelpers.GetAccountId(*awsCfg)
	})
	return p.accountID, p.accountIDErr
}
