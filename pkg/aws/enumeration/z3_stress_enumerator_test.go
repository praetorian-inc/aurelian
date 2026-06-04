package enumeration

// z3_stress_enumerator_test.go contains adversarial error-handling patterns
// for testing the Z3-based ClassifySkippable exactly-once verification.
//
// "Correct" patterns (stressCorrect_) must pass the exactly-once check:
// - errors stored in struct fields and retrieved later
// - errors passed through helper methods (interprocedural tracing)
// - multiple independent SDK calls with separate classify paths
// - two SDK calls whose errors merge at a phi node
// - closures that classify internally
// - goroutines that classify internally
// - deep fmt.Errorf wrapping chains before classification
// - errors returned from a closure and classified by the caller
//
// "Bug" patterns (stressBug_) must be detected as violations:
// - silent drop (count=0)
// - double classify (count=2)
// - classify then leak (missing return, count=2)
// - classify wrong error (real error has count=0)
// - one caller drops (same closure, different handling at two call sites)
// - double classify through helper (inner + outer both classify)

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// stressEnumerator is NOT registered in the dispatcher. It exists solely
// so its methods appear in the SSA and the Z3 test must analyze them.
type stressEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport

	// Function-value field: the classify strategy is assigned at construction
	// time. VTA must resolve this to trace through it.
	classifyFn func(error, string, string, string) *SkippedOp
}

func newStressEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, sr *SkipReport) *stressEnumerator {
	return &stressEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     sr,
		classifyFn:     ClassifySkippable, // assigned at construction, not literal
	}
}

// ---------------------------------------------------------------------------
// CORRECT patterns (should PASS) — the error reaches ClassifySkippable exactly
// once on every path WITHIN THE FUNCTION, through unusual channels.
// ---------------------------------------------------------------------------

// stressCorrect_errorThroughStructField stores the error in a struct field,
// retrieves it later, and classifies it. The error takes a detour through
// memory instead of flowing directly.
func (s *stressEnumerator) stressCorrect_errorThroughStructField(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := lambda.NewFromConfig(*cfg)

	type holder struct {
		err error
	}
	var h holder
	_, h.err = client.ListFunctions(context.Background(), &lambda.ListFunctionsInput{})
	if h.err != nil {
		if op := ClassifySkippable(h.err, "lambda", "ListFunctions", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable ListFunctions error", "error", h.err)
	}
}

// stressCorrect_errorThroughHelper passes the error to a helper method
// that classifies it. The error flows across function boundaries without
// being the return value. Tests interprocedural tracing through call arguments.
func (s *stressEnumerator) stressCorrect_errorThroughHelper(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := lambda.NewFromConfig(*cfg)

	result, err := client.GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: aws.String("nonexistent"),
	})
	if err != nil {
		s.classifyAndLog(err, "lambda", "GetFunction", region)
		return
	}
	_ = result
}

// classifyAndLog is a helper that classifies an error and logs the result.
func (s *stressEnumerator) classifyAndLog(err error, service, op, region string) {
	if op := ClassifySkippable(err, service, op, region); op != nil {
		s.skipReport.RecordBatch([]SkippedOp{*op})
		return
	}
	slog.Warn("unclassifiable error", "service", service, "op", op, "error", err)
}

// stressCorrect_errorMultipleSDKCalls makes two SDK calls independently and
// classifies each error separately. Tests that the analysis tracks each
// error independently through separate value chains.
func (s *stressEnumerator) stressCorrect_errorMultipleSDKCalls(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	// First SDK call — classified independently
	_, err1 := client.DescribeVpcs(context.Background(), &ec2.DescribeVpcsInput{})
	if err1 != nil {
		if op := ClassifySkippable(err1, "ec2", "DescribeVpcs", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
		} else {
			slog.Warn("unclassifiable DescribeVpcs error", "error", err1)
		}
	}

	// Second SDK call — classified independently (different value chain)
	_, err2 := client.DescribeVpcEndpoints(context.Background(), &ec2.DescribeVpcEndpointsInput{})
	if err2 != nil {
		if op := ClassifySkippable(err2, "ec2", "DescribeVpcEndpoints", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
		} else {
			slog.Warn("unclassifiable DescribeVpcEndpoints error", "error", err2)
		}
	}
}

// stressCorrect_multiCallPhiMerge makes two different SDK calls whose errors
// merge at a phi node (only one executes based on a condition). The merged
// error is then classified once. SSA creates a Phi instruction.
func (s *stressEnumerator) stressCorrect_multiCallPhiMerge(region string, useDescribe bool) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	var sdkErr error
	if useDescribe {
		_, sdkErr = client.DescribeSubnets(context.Background(), &ec2.DescribeSubnetsInput{})
	} else {
		_, sdkErr = client.DescribeSecurityGroups(context.Background(), &ec2.DescribeSecurityGroupsInput{})
	}
	// sdkErr is a Phi of the two SDK call errors.
	if sdkErr != nil {
		if op := ClassifySkippable(sdkErr, "ec2", "DescribeSubnetsOrSGs", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable subnet/SG error", "error", sdkErr)
	}
}

// stressCorrect_closureClassifiesInternally uses a closure that makes the
// SDK call AND classifies the error internally, then returns status.
// The error never leaves the closure — classification happens inside.
func (s *stressEnumerator) stressCorrect_closureClassifiesInternally(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := lambda.NewFromConfig(*cfg)

	classify := func() bool {
		_, err := client.ListLayers(context.Background(), &lambda.ListLayersInput{})
		if err != nil {
			if op := ClassifySkippable(err, "lambda", "ListLayers", region); op != nil {
				s.skipReport.RecordBatch([]SkippedOp{*op})
				return true
			}
			slog.Warn("unclassifiable ListLayers error", "error", err)
			return false
		}
		return true
	}
	classify()
}

// stressCorrect_goroutineClassifies launches a goroutine that makes the SDK
// call and classifies the error within the goroutine. The error never crosses
// goroutine boundaries — classification is co-located with the SDK call.
func (s *stressEnumerator) stressCorrect_goroutineClassifies(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := client.DescribeRouteTables(context.Background(), &ec2.DescribeRouteTablesInput{})
		if err != nil {
			if op := ClassifySkippable(err, "ec2", "DescribeRouteTables", region); op != nil {
				s.skipReport.RecordBatch([]SkippedOp{*op})
				return
			}
			slog.Warn("unclassifiable DescribeRouteTables error", "error", err)
		}
	}()
	wg.Wait()
	close(done)
}

// stressCorrect_deepWrapChain wraps the error multiple times before classifying.
// The error goes through 3 layers of fmt.Errorf wrapping.
func (s *stressEnumerator) stressCorrect_deepWrapChain(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	_, err = client.DescribeAddresses(context.Background(), &ec2.DescribeAddressesInput{})
	if err != nil {
		wrapped := fmt.Errorf("layer1: %w", err)
		wrapped = fmt.Errorf("layer2: %w", wrapped)
		wrapped = fmt.Errorf("layer3: %w", wrapped)
		if op := ClassifySkippable(wrapped, "ec2", "DescribeAddresses", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable DescribeAddresses error", "error", wrapped)
	}
}

// stressCorrect_errorReturnedAndClassifiedByCaller tests the pattern where
// a function makes an SDK call, wraps and returns the error, and the caller
// classifies it. The SDK call and ClassifySkippable are in different functions.
// The error flows: SDK call → fmt.Errorf → return → caller → ClassifySkippable.
func (s *stressEnumerator) stressCorrect_errorReturnedAndClassifiedByCaller(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	// SDK call and wrap in an inline helper — returns error for caller to classify.
	doDescribe := func() error {
		_, err := client.DescribeSnapshots(context.Background(), &ec2.DescribeSnapshotsInput{
			OwnerIds: []string{"self"},
		})
		if err != nil {
			return fmt.Errorf("describe snapshots: %w", err)
		}
		return nil
	}

	if err := doDescribe(); err != nil {
		if op := ClassifySkippable(err, "ec2", "DescribeSnapshots", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable snapshot error", "error", err)
	}
}

// ---------------------------------------------------------------------------
// BUG patterns (should FAIL) — deliberately broken error handling.
// ---------------------------------------------------------------------------

// stressBug_silentDrop calls an AWS SDK method and silently drops the error.
// No ClassifySkippable, no propagation. Count = 0.
func (s *stressEnumerator) stressBug_silentDrop(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	_, err = client.DescribeNatGateways(context.Background(), &ec2.DescribeNatGatewaysInput{})
	if err != nil {
		slog.Debug("oops", "error", err)
		// BUG: error silently dropped — no ClassifySkippable, no return
	}
}

// stressBug_doubleClassify classifies the same error twice. Count = 2.
func (s *stressEnumerator) stressBug_doubleClassify(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	_, err = client.DescribeInternetGateways(context.Background(), &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		// BUG: classify twice — once standalone (result ignored), once checked
		ClassifySkippable(err, "ec2", "DescribeInternetGateways-1st", region)
		if op := ClassifySkippable(err, "ec2", "DescribeInternetGateways-2nd", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable error", "error", err)
	}
}

// stressBug_classifyThenLeak classifies and records but does NOT return —
// the error falls through and ClassifySkippable is called AGAIN. Count = 2.
func (s *stressEnumerator) stressBug_classifyThenLeak(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	_, err = client.DescribeNetworkInterfaces(context.Background(), &ec2.DescribeNetworkInterfacesInput{})
	if err != nil {
		// BUG: classified but not returned — falls through to second classify
		if op := ClassifySkippable(err, "ec2", "DescribeNetworkInterfaces", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			// missing: return
		}
		// Second classify — this shouldn't be reached if the first one returned
		if op := ClassifySkippable(err, "ec2", "DescribeNetworkInterfaces-2nd", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable ENI error", "error", err)
	}
}

// stressBug_classifyWrongError classifies a different error than the SDK one.
// The SDK error is never classified. Count = 0 for the SDK error.
func (s *stressEnumerator) stressBug_classifyWrongError(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	_, err = client.DescribeVolumes(context.Background(), &ec2.DescribeVolumesInput{})
	if err != nil {
		// BUG: classifies a fabricated error, not the SDK error
		fakeErr := fmt.Errorf("synthetic error")
		if op := ClassifySkippable(fakeErr, "ec2", "DescribeVolumes", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable DescribeVolumes error", "error", err)
	}
}

// stressBug_oneCallerDrops makes an SDK call in a closure, calls it twice.
// First call: classifies correctly. Second call: silently drops. Count = 0
// on the second call's path.
func (s *stressEnumerator) stressBug_oneCallerDrops(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	doDescribe := func() error {
		_, err := client.DescribeKeyPairs(context.Background(), &ec2.DescribeKeyPairsInput{})
		if err != nil {
			return fmt.Errorf("describe key pairs: %w", err)
		}
		return nil
	}

	// Call A: classifies correctly.
	if err := doDescribe(); err != nil {
		if op := ClassifySkippable(err, "ec2", "DescribeKeyPairs", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
		} else {
			slog.Warn("unclassifiable key pairs error (caller A)", "error", err)
		}
	}

	// Call B: BUG — silently drops the error.
	if err := doDescribe(); err != nil {
		slog.Debug("ignoring key pairs error", "error", err)
		// BUG: no ClassifySkippable, error silently dropped
	}
}

// stressBug_doubleClassifyThroughHelper classifies in an inline helper AND
// in the caller — the error hits ClassifySkippable twice. Count = 2.
func (s *stressEnumerator) stressBug_doubleClassifyThroughHelper(region string) {
	cfg, err := s.provider.GetAWSConfig(region)
	if err != nil {
		return
	}
	client := ec2.NewFromConfig(*cfg)

	// Inline helper: classifies but returns the error instead of swallowing.
	classifyAndReturn := func() error {
		_, err := client.DescribeNetworkAcls(context.Background(), &ec2.DescribeNetworkAclsInput{})
		if err != nil {
			if op := ClassifySkippable(err, "ec2", "DescribeNetworkAcls-inner", region); op != nil {
				s.skipReport.RecordBatch([]SkippedOp{*op})
			}
			return fmt.Errorf("describe NACLs: %w", err)
		}
		return nil
	}

	if err := classifyAndReturn(); err != nil {
		// BUG: caller classifies AGAIN — inner already classified
		if op := ClassifySkippable(err, "ec2", "DescribeNetworkAcls-outer", region); op != nil {
			s.skipReport.RecordBatch([]SkippedOp{*op})
			return
		}
		slog.Warn("unclassifiable NACLs error (caller)", "error", err)
	}
}

// Ensure the types are used (prevent unused import errors).
var _ = (*pipeline.P[output.AWSResource])(nil)
