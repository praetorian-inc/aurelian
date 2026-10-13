//go:build integration

package recon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/aws/extraction"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests characterize how find-secrets reports a resource it could not
// read, against real AWS. They exist to inform ENG-8768: Guard advances a
// per-target "last successful scan" checkpoint whenever a find-secrets run
// returns nil, and the change gate then skips the target until AWS reports a
// newer LastModified. A run that silently skips the target therefore hides it
// from secret scanning until it next changes.
//
// The fixture's scan role denies one layer per locked resource:
//   - locked Lambda: lambda:GetFunction (fails in the ARN lister first)
//   - locked stack:  cloudformation:GetTemplate (lister succeeds, extractor fails)
//
// Two modes are compared:
//   - current: the registered module, exactly as Guard invokes it (v1.0.5).
//   - strict:  the f9cd184 incremental behavior — extractor FailOnError,
//     scanner SetFailOnError, and a failed run when the lister skipped
//     anything. This is the candidate restoration for v1.0.6.

const partialRegion = "us-east-2"

type partialFixture struct {
	profile    string
	profileDir string

	readableFunctionARN string
	lockedFunctionARN   string
	readableStackARN    string
	lockedStackARN      string
}

type runResult struct {
	risks []output.AurelianRisk
	err   error
}

func TestAWSFindSecretsPartialFailure(t *testing.T) {
	fx := setupPartialFixture(t)

	// Guard runs find-secrets once per target: regions = [target region],
	// resource-arn = [target identifier]. The checkpoint is per target, so a
	// run's success/failure only ever affects that one resource's checkpoint.
	t.Run("per-target (Guard invocation shape)", func(t *testing.T) {
		cases := []struct {
			name        string
			arn         string
			wantSecret  bool
			deniedLayer string
		}{
			{name: "readable lambda", arn: fx.readableFunctionARN, wantSecret: true},
			{name: "lambda denied at lister", arn: fx.lockedFunctionARN, deniedLayer: "lister"},
			{name: "readable stack", arn: fx.readableStackARN, wantSecret: true},
			{name: "stack denied at extractor", arn: fx.lockedStackARN, deniedLayer: "extractor"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				args := fx.args(map[string]any{"resource-arn": []string{tc.arn}})

				current := runCurrent(t, args)
				strict := runStrict(t, args)
				logShape(t, "current", current)
				logShape(t, "strict", strict)

				if tc.wantSecret {
					require.NoError(t, current.err)
					require.NoError(t, strict.err)
					assert.True(t, hasRiskForIdentifier(current.risks, resourceName(tc.arn)),
						"current mode should find the secret in %s", tc.arn)
					assert.True(t, hasRiskForIdentifier(strict.risks, resourceName(tc.arn)),
						"strict mode should find the secret in %s", tc.arn)
					return
				}

				// Current behavior: the denial is swallowed and the run
				// reports success with nothing scanned. Guard would record
				// the checkpoint for this target.
				assert.NoError(t, current.err,
					"current mode reports success for an unreadable %s target", tc.deniedLayer)
				assert.Empty(t, current.risks,
					"current mode scanned nothing for the unreadable target")

				// Strict behavior: the run fails, so Guard keeps the old
				// checkpoint and the next list-all retries the target.
				require.Error(t, strict.err,
					"strict mode must fail a run that could not read its only target")
				assert.Empty(t, strict.risks)

				// The failure stays classifiable: a permanent denial is
				// distinguishable from throttling or a 5xx, which is what a
				// transient-vs-permanent split in v1.0.6 would key on.
				code := errorCode(strict.err)
				t.Logf("strict error code=%q err=%v", code, strict.err)
				assert.Contains(t, []string{"AccessDenied", "AccessDeniedException"}, code,
					"strict error should carry the AWS error code (or the skip report's code)")
			})
		}

		// Delivery order alone decides whether Guard sees a lister skip. The
		// literal f9cd184 shape returns the skip error after the inner Pipe
		// has closed `out`, so the caller's out.Wait() returns nil.
		t.Run("lister skip returned after Run's output closes is dropped", func(t *testing.T) {
			args := fx.args(map[string]any{"resource-arn": []string{fx.lockedFunctionARN}})

			legacy := runStrictLegacy(t, args)
			logShape(t, "strict-legacy", legacy)
			assert.NoError(t, legacy.err,
				"characterizes the bug: the f9cd184 skip error is returned after out closes and is lost, "+
					"so Guard would see success and advance the checkpoint for an unread target")
			assert.Empty(t, legacy.risks)

			fixed := runStrict(t, args)
			logShape(t, "strict", fixed)
			require.Error(t, fixed.err,
				"same pipeline, skip error delivered before out closes: the caller sees the failure")
		})

		// A permanent denial fails every strict run identically, so the
		// target's checkpoint never advances and the gate never skips it.
		// The target is rescanned (and fails) on every list-all — correct,
		// but it gets no cost savings.
		t.Run("permanent denial fails every strict run", func(t *testing.T) {
			args := fx.args(map[string]any{"resource-arn": []string{fx.lockedStackARN}})
			for i := 0; i < 2; i++ {
				res := runStrict(t, args)
				require.Error(t, res.err, "strict run %d", i+1)
			}
		})
	})

	// Not how Guard invokes find-secrets, but how the CLI does: one run over
	// whole resource types. Here strict mode lets one locked resource fail
	// the run for every other resource of those types in the region.
	t.Run("account-wide (CLI invocation shape)", func(t *testing.T) {
		args := fx.args(map[string]any{
			"resource-type": []string{"AWS::Lambda::Function", "AWS::CloudFormation::Stack"},
		})

		current := runCurrent(t, args)
		strict := runStrict(t, args)
		logShape(t, "current", current)
		logShape(t, "strict", strict)

		require.NoError(t, current.err, "current mode reports success despite locked resources")
		assert.True(t, hasRiskForIdentifier(current.risks, resourceName(fx.readableFunctionARN)))
		assert.True(t, hasRiskForIdentifier(current.risks, resourceName(fx.readableStackARN)))
		// ListFunctions does not call GetFunction, so in this shape the
		// locked Lambda is listed and denied at the extractor instead.
		assert.False(t, hasRiskForIdentifier(current.risks, resourceName(fx.lockedFunctionARN)))
		assert.False(t, hasRiskForIdentifier(current.risks, resourceName(fx.lockedStackARN)))

		require.Error(t, strict.err, "strict mode fails the whole run on the first locked resource")
		t.Logf("strict run emitted %d of %d current-mode risks before failing",
			len(strict.risks), len(current.risks))
	})
}

// TestFindSecretsBindLeaksUnsetParams characterizes that a reused module
// instance keeps params left unset by a later bind: plugin.Bind skips a param
// that has no value and no default (pkg/plugin/bind.go setFields:
// `if val == nil { continue }`), so the field keeps whatever the previous bind
// wrote. plugin.Get returns a process-wide singleton, so in a warm process
// this carries across jobs. Guard sets resource-arn on every invocation, so it
// is not exposed today, but any param Guard omits would leak across jobs.
// No AWS calls.
func TestFindSecretsBindLeaksUnsetParams(t *testing.T) {
	firstARN := []string{"arn:aws:lambda:us-east-2:111111111111:function:a"}
	m := &AWSFindSecretsModule{}

	require.NoError(t, plugin.Bind(plugin.Config{Args: map[string]any{
		"regions":      []string{partialRegion},
		"resource-arn": firstARN,
	}}, m.Parameters()))
	require.Equal(t, firstARN, m.ResourceARN)

	require.NoError(t, plugin.Bind(plugin.Config{Args: map[string]any{
		"regions":       []string{partialRegion},
		"resource-type": []string{"AWS::Lambda::Function"},
	}}, m.Parameters()))

	assert.Equal(t, firstARN, m.ResourceARN,
		"second bind omitted resource-arn, yet the instance still targets the first run's ARN")
	assert.Equal(t, []string{"AWS::Lambda::Function"}, m.ResourceType)
}

// runCurrent runs find-secrets through the same code path Guard's
// aws_invoke.go uses: plugin.ModuleWrapper.Run, which does Bind, then
// PostBind, then the module's Run. It builds a fresh module instance per run
// instead of using plugin.Get, because plugin.Get returns a process-wide
// singleton and Bind keeps params that a later run leaves unset (see
// TestFindSecretsBindLeaksUnsetParams). With a fresh instance each run is
// independent of the ones before it.
func runCurrent(t *testing.T, args map[string]any) runResult {
	t.Helper()
	mod := &plugin.ModuleWrapper{Module: &AWSFindSecretsModule{}}
	return drain(mod.Run, plugin.Config{Args: args, Context: context.Background()})
}

// skipDelivery selects how the strict runner hands the lister-skip error
// back to its caller. The two modes differ only in ordering relative to the
// moment `out` is closed, which decides whether the caller ever sees it.
type skipDelivery int

const (
	// deliverAfterOutputClosed is the literal f9cd184 shape: the final stage
	// is pipeline.Pipe(scanned, secrets.RiskFromScanResult, out). That inner
	// Pipe owns `out` and calls out.Close() (pkg/pipeline/pipeline.go Close:
	// closes the item channel and `done`) once risks drain. The skip check
	// runs after that, so the error Run returns is written to out.err by the
	// OUTER Pipe (drain's / Guard's) after `done` is already closed. A caller
	// blocked in out.Wait() (pipeline.go Wait: <-done, then read err) has
	// already returned nil, so the error is lost — and the late write races
	// the read. Extractor FailOnError errors survive this shape only because
	// the inner Pipe records them in out.err before it closes `out`.
	deliverAfterOutputClosed skipDelivery = iota

	// deliverBeforeOutputClosed is the candidate shape for v1.0.6: risks go
	// to a private pipeline that Run forwards into `out` itself. `out` is
	// never handed to an inner Pipe, so it is still open when Run returns,
	// and the outer Pipe records the returned error before it closes `out`.
	deliverBeforeOutputClosed
)

// runStrict binds the same args and runs the find-secrets pipeline with the
// f9cd184 incremental guarantees switched on unconditionally, delivering the
// lister-skip error before `out` closes (the correct v1.0.6 candidate).
func runStrict(t *testing.T, args map[string]any) runResult {
	t.Helper()
	return runStrictMode(t, args, deliverBeforeOutputClosed)
}

// runStrictLegacy is runStrict with the literal f9cd184 delivery order: the
// lister-skip error is returned after the final inner Pipe has closed `out`.
func runStrictLegacy(t *testing.T, args map[string]any) runResult {
	t.Helper()
	return runStrictMode(t, args, deliverAfterOutputClosed)
}

func runStrictMode(t *testing.T, args map[string]any, deliver skipDelivery) runResult {
	t.Helper()
	m := &AWSFindSecretsModule{}
	cfg := plugin.Config{Args: args, Context: context.Background(), Log: plugin.DiscardLogger()}
	require.NoError(t, plugin.Bind(cfg, m.Parameters()))
	return drain(m.runStrictWith(deliver), cfg)
}

// runStrictWith mirrors AWSFindSecretsModule.Run, adding FailOnError on the
// extractor, SetFailOnError on the scanner, and the lister skip check. deliver
// picks where that skip check sits relative to `out` being closed.
func (m *AWSFindSecretsModule) runStrictWith(deliver skipDelivery) func(plugin.Config, *pipeline.P[model.AurelianModel]) error {
	return func(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
		return m.runStrictPipeline(out, deliver)
	}
}

func (m *AWSFindSecretsModule) runStrictPipeline(out *pipeline.P[model.AurelianModel], deliver skipDelivery) error {
	c := m.FindSecretsConfig
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	inputs, err := collectInputs(m.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("failed to collect inputs: %w", err)
	}

	var s secrets.SecretScanner
	if err := s.Start(c.ScannerConfig); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	s.SetFailOnError(true)

	lister := cclist.NewEnumerator(c.AWSCommonRecon)
	defer func() { _ = lister.Close() }()
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(pipeline.From(inputs...), lister.List, listed)

	extractor := extraction.NewAWSExtractor(c.AWSCommonRecon, extraction.Config{
		MaxEvents:   c.MaxEvents,
		MaxStreams:  c.MaxStreams,
		FailOnError: true,
	})
	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, extractor.Extract, extracted, &pipeline.PipeOpts{Concurrency: m.Concurrency})

	scanned := pipeline.New[secrets.SecretScanResult]()
	s.ScanFlushAndClose(extracted, scanned)

	switch deliver {
	case deliverAfterOutputClosed:
		// The inner Pipe closes `out`; anything returned below is dropped.
		pipeline.Pipe(scanned, secrets.RiskFromScanResult, out)
		if err := out.Wait(); err != nil {
			return err
		}
	case deliverBeforeOutputClosed:
		risks := pipeline.New[model.AurelianModel]()
		pipeline.Pipe(scanned, secrets.RiskFromScanResult, risks)
		for r := range risks.Range() {
			out.Send(r)
		}
		if err := risks.Wait(); err != nil {
			return err
		}
	}

	if lister.Skipped.Len() > 0 {
		return &incompleteListingError{ops: lister.Skipped.Snapshot(), summary: lister.Skipped.Summary()}
	}
	return nil
}

// incompleteListingError carries the skip report so the test can read the
// AWS error code the lister swallowed.
type incompleteListingError struct {
	ops     []cclist.SkippedOp
	summary string
}

func (e *incompleteListingError) Error() string {
	return "resource enumeration was incomplete: " + e.summary
}

func drain(run func(plugin.Config, *pipeline.P[model.AurelianModel]) error, cfg plugin.Config) runResult {
	out := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(pipeline.From(cfg), run, out)

	var res runResult
	for m := range out.Range() {
		if r, ok := m.(output.AurelianRisk); ok {
			res.risks = append(res.risks, r)
		}
	}
	res.err = out.Wait()
	return res
}

func errorCode(err error) string {
	var incomplete *incompleteListingError
	if errors.As(err, &incomplete) && len(incomplete.ops) > 0 {
		return incomplete.ops[0].ErrorCode
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

func logShape(t *testing.T, mode string, res runResult) {
	t.Helper()
	ids := make([]string, 0, len(res.risks))
	for _, r := range res.risks {
		ids = append(ids, r.ImpactedResourceID)
	}
	t.Logf("%s: err=%v risks=%d resources=%v", mode, res.err, len(res.risks), ids)
}

// resourceName returns the human name in a Lambda or CloudFormation ARN,
// which risk ImpactedResourceIDs contain.
func resourceName(arn string) string {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return arn
	}
	if parts := strings.Split(parsed.Resource, ":"); len(parts) >= 2 && parts[0] == "function" {
		return parts[1]
	}
	if parts := strings.Split(parsed.Resource, "/"); len(parts) >= 2 && parts[0] == "stack" {
		return parts[1]
	}
	return arn
}

func (fx partialFixture) args(extra map[string]any) map[string]any {
	args := map[string]any{
		"regions":     []string{partialRegion},
		"profile":     fx.profile,
		"profile-dir": fx.profileDir,
		"concurrency": 5,
		"output-dir":  filepath.Join(fx.profileDir, "out"),
	}
	for k, v := range extra {
		args[k] = v
	}
	return args
}

// setupPartialFixture applies the fixture, assumes the scan role, writes its
// credentials to a private profile directory, and waits until IAM reports the
// denies as effective.
func setupPartialFixture(t *testing.T) partialFixture {
	t.Helper()
	fixture := testutil.NewAWSFixture(t, "aws/recon/find-secrets-partial")
	fixture.Setup()

	fx := partialFixture{
		profile:             "aurelian-partial-scan",
		profileDir:          t.TempDir(),
		readableFunctionARN: fixture.Output("readable_function_arn"),
		lockedFunctionARN:   fixture.Output("locked_function_arn"),
		readableStackARN:    fixture.Output("readable_stack_arn"),
		lockedStackARN:      fixture.Output("locked_stack_arn"),
	}

	ctx := context.Background()
	baseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(partialRegion))
	require.NoError(t, err)

	roleARN := fixture.Output("scan_role_arn")
	var creds *sts.AssumeRoleOutput
	stsClient := sts.NewFromConfig(baseCfg)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		out, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(roleARN),
			RoleSessionName: aws.String("aurelian-partial-test"),
			DurationSeconds: aws.Int32(3600),
		})
		if assert.NoError(c, err, "assume scan role %s", roleARN) {
			creds = out
		}
	}, 90*time.Second, 5*time.Second, "assume scan role %s", roleARN)

	writeProfile(t, fx, creds)

	scanCfg := aws.Config{
		Region: partialRegion,
		Credentials: credentials.NewStaticCredentialsProvider(
			*creds.Credentials.AccessKeyId, *creds.Credentials.SecretAccessKey, *creds.Credentials.SessionToken),
	}
	lambdaClient := lambda.NewFromConfig(scanCfg)
	cfnClient := cloudformation.NewFromConfig(scanCfg)

	// IAM is eventually consistent: wait until the readable twins are
	// readable and the locked twins are denied before characterizing.
	// EventuallyWithT reports the last attempt's failed assertions, so a
	// timeout names which of the four probes had not converged.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, readErr := lambdaClient.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(fx.readableFunctionARN)})
		_, lockErr := lambdaClient.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(fx.lockedFunctionARN)})
		_, readTpl := cfnClient.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: aws.String(fx.readableStackARN)})
		_, lockTpl := cfnClient.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: aws.String(fx.lockedStackARN)})
		assert.NoError(c, readErr, "readable lambda GetFunction")
		assert.NoError(c, readTpl, "readable stack GetTemplate")
		assert.True(c, isAccessDenied(lockErr), "locked lambda GetFunction should be AccessDenied, got %v", lockErr)
		assert.True(c, isAccessDenied(lockTpl), "locked stack GetTemplate should be AccessDenied, got %v", lockTpl)
	}, 5*time.Minute, 10*time.Second, "scan role permissions did not converge")

	return fx
}

func isAccessDenied(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return strings.Contains(apiErr.ErrorCode(), "AccessDenied")
}

func writeProfile(t *testing.T, fx partialFixture, creds *sts.AssumeRoleOutput) {
	t.Helper()
	credFile := fmt.Sprintf("[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\naws_session_token = %s\n",
		fx.profile, *creds.Credentials.AccessKeyId, *creds.Credentials.SecretAccessKey, *creds.Credentials.SessionToken)
	cfgFile := fmt.Sprintf("[profile %s]\nregion = %s\n", fx.profile, partialRegion)
	require.NoError(t, os.WriteFile(filepath.Join(fx.profileDir, "credentials"), []byte(credFile), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fx.profileDir, "config"), []byte(cfgFile), 0o600))
}
