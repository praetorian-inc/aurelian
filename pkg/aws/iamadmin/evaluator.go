package iamadmin

import (
	"fmt"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// Evaluator checks whether IAM principals have administrator access.
type Evaluator struct {
	cfg          plugin.AWSCommonRecon
	iam          *iam.Client
	accountID    string
	initMu       sync.Mutex
	emittedUsers map[string]bool
}

func New(cfg plugin.AWSCommonRecon) *Evaluator {
	return &Evaluator{
		cfg:          cfg,
		emittedUsers: map[string]bool{},
	}
}

func (e *Evaluator) EvaluatePrincipal(principal output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	if err := e.initialize(); err != nil {
		return err
	}

	switch principal.ResourceType {
	case "AWS::IAM::User":
		return e.evaluateUser(principal, out)
	case "AWS::IAM::Role":
		return e.evaluateRole(principal, out)
	case "AWS::IAM::Group":
		return e.evaluateGroup(principal, out)
	default:
		return fmt.Errorf("resource type %s is not a principal", principal.ResourceType)
	}
}

func (e *Evaluator) initialize() error {
	e.initMu.Lock()
	defer e.initMu.Unlock()

	if e.iam != nil {
		return nil
	}

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    e.cfg.Profile,
		ProfileDir: e.cfg.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	accountID, err := awshelpers.GetAccountId(awsCfg)
	if err != nil {
		return fmt.Errorf("get account id: %w", err)
	}

	e.iam = iam.NewFromConfig(awsCfg)
	e.accountID = accountID

	return nil
}
