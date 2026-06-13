package gaad

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	smithy "github.com/aws/smithy-go"
	"golang.org/x/sync/errgroup"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/store"
	iampkg "github.com/praetorian-inc/aurelian/pkg/types"
)

// userEnrichConcurrency bounds the per-user ListAccessKeys/GetLoginProfile calls
// so a large account does not burst IAM's (low) global rate limit.
const userEnrichConcurrency = 5

// iamGlobalRegion is the region key the per-user enrichment shares with the rest of
// the recon path's IAM calls (the IAM enumerator classifies its skips under "global").
// CrossRegionActor keys its package-global limiter by region string, so acting under
// the same key coordinates this enrichment burst with any other "global" IAM work.
const iamGlobalRegion = "global"

// userEnrichClient is the subset of the IAM API the per-user enrichment pass uses.
// Extracted so the enrichment logic (NoSuchEntity classification, active-only
// counting, fail-open-on-error) can be unit-tested with a mock.
type userEnrichClient interface {
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
}

// GAAD wraps the collection of AWS IAM Account Authorization Details.
type GAAD struct {
	opts         plugin.AWSReconBase
	accountID    string
	iamClient    *iam.Client
	iamPaginator *iam.GetAccountAuthorizationDetailsPaginator
}

// New creates a new GAAD instance.
func New(opts plugin.AWSReconBase) *GAAD {
	return &GAAD{opts: opts}
}

// Get collects all IAM users, roles, groups,
// and policies for the AWS account.
func (g *GAAD) Get() (*iampkg.AuthorizationAccountDetails, error) {
	ctx := context.Background()

	if err := g.initializeGAADClient(); err != nil {
		return nil, err
	}

	gaadData := &iampkg.AuthorizationAccountDetails{
		AccountID: g.accountID,
		Users:     store.NewMap[iampkg.UserDetail](),
		Groups:    store.NewMap[iampkg.GroupDetail](),
		Roles:     store.NewMap[iampkg.RoleDetail](),
		Policies:  store.NewMap[iampkg.ManagedPolicyDetail](),
	}

	paginator := ratelimit.NewAWSPaginator()
	err := paginator.Paginate(func() (bool, error) {
		if !g.iamPaginator.HasMorePages() {
			return false, nil
		}

		page, err := g.iamPaginator.NextPage(ctx)
		if err != nil {
			return false, err
		}

		if err := convertSDKItems(page.UserDetailList, gaadData.Users, func(u iampkg.UserDetail) string { return u.Arn }); err != nil {
			return false, err
		}
		if err := convertSDKItems(page.GroupDetailList, gaadData.Groups, func(g iampkg.GroupDetail) string { return g.Arn }); err != nil {
			return false, err
		}
		if err := convertSDKItems(page.RoleDetailList, gaadData.Roles, func(r iampkg.RoleDetail) string { return r.Arn }); err != nil {
			return false, err
		}
		if err := convertSDKItems(page.Policies, gaadData.Policies, func(p iampkg.ManagedPolicyDetail) string { return p.Arn }); err != nil {
			return false, err
		}

		return g.iamPaginator.HasMorePages(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("error retrieving authorization details: %w", err)
	}

	// GAAD does not return access keys or login profiles. Enrich each user with
	// those signals out-of-band so privesc methods can guard on real data.
	enrichUsers(ctx, g.iamClient, gaadData.Users)

	return gaadData, nil
}

// enrichUsers augments each collected user with AccessKeyCount (active keys) and
// HasLoginProfile via per-user IAM calls GAAD itself does not surface. The pass is
// rate-limited and resilient: a per-user error (AccessDenied, throttle, etc.) is
// logged and the affected field is left nil (tri-state "unknown" → fail-open) so it
// never fails the whole collection. A confirmed result (NoSuchEntity for the login
// profile, a successful key listing) is recorded as a non-nil value so the guard reads
// the real signal rather than falling open.
//
// Concurrency and rate limiting are delegated to a CrossRegionActor acting under the
// shared "global" IAM region key, so the per-user burst is bounded AND coordinated with
// the rest of the recon path's IAM calls instead of bursting an isolated errgroup.
func enrichUsers(ctx context.Context, client userEnrichClient, users store.Map[iampkg.UserDetail]) {
	var enriched []iampkg.UserDetail
	users.Range(func(_ string, u iampkg.UserDetail) bool {
		enriched = append(enriched, u)
		return true
	})

	// Each goroutine writes only its own slice slot, so the parallel ListAccessKeys/
	// GetLoginProfile calls need no lock; the Set write-back happens sequentially after.
	actor := ratelimit.NewCrossRegionActor(userEnrichConcurrency)
	grp := errgroup.Group{}
	grp.SetLimit(userEnrichConcurrency)
	for i := range enriched {
		grp.Go(func() error {
			return actor.ActInRegion(iamGlobalRegion, func() error {
				enriched[i].AccessKeyCount = countActiveAccessKeys(ctx, client, enriched[i].UserName)
				enriched[i].HasLoginProfile = hasLoginProfile(ctx, client, enriched[i].UserName)
				return nil
			})
		})
	}
	_ = grp.Wait() // grp.Go funcs never return an error; per-user failures are handled inline.

	for _, u := range enriched {
		users.Set(u.Arn, u)
	}
}

// countActiveAccessKeys returns a non-nil count of ACTIVE access keys on the user,
// or nil when the count is unknown (empty user name, or the call failed). A nil
// return serializes to an absent node prop so the guard fails open; a non-nil 0/1/2+
// records the real count so the guard reads it.
func countActiveAccessKeys(ctx context.Context, client userEnrichClient, userName string) *int {
	if userName == "" {
		return nil
	}
	out, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &userName})
	if err != nil {
		slog.Warn("gaad: ListAccessKeys failed; treating access-key count as unknown",
			"user", userName, "error", err)
		return nil
	}
	count := 0
	for _, k := range out.AccessKeyMetadata {
		if k.Status == iamtypes.StatusTypeActive {
			count++
		}
	}
	return &count
}

// hasLoginProfile reports whether the user has a console login profile as a
// tri-state: non-nil true (profile exists), non-nil false (confirmed NoSuchEntity —
// no profile), or nil (unknown: empty user name or any non-NoSuchEntity error such
// as AccessDenied/throttle). nil serializes to an absent node prop so the guard
// fails open; a non-nil false serializes present so the guard suppresses.
func hasLoginProfile(ctx context.Context, client userEnrichClient, userName string) *bool {
	if userName == "" {
		return nil
	}
	_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: &userName})
	if err == nil {
		return boolPtr(true)
	}
	if isNoSuchEntity(err) {
		return boolPtr(false)
	}
	slog.Warn("gaad: GetLoginProfile failed; treating login profile as unknown",
		"user", userName, "error", err)
	return nil
}

func boolPtr(b bool) *bool { return &b }

// isNoSuchEntity reports whether err is IAM's NoSuchEntity (the expected response
// when a user has no login profile).
func isNoSuchEntity(err error) bool {
	var notFound *iamtypes.NoSuchEntityException
	if errors.As(err, &notFound) {
		return true
	}
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity"
}

// initializeGAADClient sets up the AWS config, resolves the account ID,
// and creates the IAM GAAD paginator.
func (g *GAAD) initializeGAADClient() error {
	// IAM is a global service - always use us-east-1
	region := "us-east-1"

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    g.opts.Profile,
		ProfileDir: g.opts.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}

	accountID, err := awshelpers.GetAccountId(awsCfg)
	if err != nil {
		return fmt.Errorf("failed to get account ID: %w", err)
	}
	g.accountID = accountID

	g.iamClient = iam.NewFromConfig(awsCfg)
	maxItems := int32(1000)
	g.iamPaginator = iam.NewGetAccountAuthorizationDetailsPaginator(g.iamClient, &iam.GetAccountAuthorizationDetailsInput{
		MaxItems: &maxItems,
	})

	return nil
}

// convertSDKItems converts a slice of AWS SDK types into internal types and stores
// them in the destination cache, keyed by ARN. The getArn function extracts the
// map key from each converted item.
func convertSDKItems[From any, To any](source []From, dest store.Map[To], getArn func(To) string) error {
	for _, item := range source {
		converted, err := convertOne[From, To](item)
		if err != nil {
			return err
		}
		dest.Set(getArn(converted), converted)
	}
	return nil
}

// convertOne marshals an AWS SDK type to JSON, URL-decodes any embedded policy
// documents, and unmarshals into the corresponding internal type.
func convertOne[From any, To any](src From) (To, error) {
	var zero To
	data, err := json.Marshal(src)
	if err != nil {
		return zero, fmt.Errorf("marshaling: %w", err)
	}
	data, err = decodeURLEncodedPolicies(data)
	if err != nil {
		return zero, fmt.Errorf("decoding policies: %w", err)
	}
	var dst To
	if err := json.Unmarshal(data, &dst); err != nil {
		return zero, fmt.Errorf("unmarshaling: %w", err)
	}
	return dst, nil
}

// decodeURLEncodedPolicies recursively finds and decodes URL-encoded policy documents
func decodeURLEncodedPolicies(data []byte) ([]byte, error) {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Recursively decode URL-encoded strings
	var decode func(interface{}) interface{}
	decode = func(v interface{}) interface{} {
		switch val := v.(type) {
		case map[string]interface{}:
			for k, v := range val {
				if str, ok := v.(string); ok {
					// Check if string is URL-encoded (starts with %7B = "{")
					if len(str) > 0 && str[0] == '%' {
						decoded, err := url.QueryUnescape(str)
						if err == nil {
							// Try parsing as JSON policy
							var policy interface{}
							if err := json.Unmarshal([]byte(decoded), &policy); err == nil {
								val[k] = policy
								continue
							}
						}
					}
				}
				val[k] = decode(v)
			}
			return val
		case []interface{}:
			for i, item := range val {
				val[i] = decode(item)
			}
			return val
		default:
			return v
		}
	}

	jsonData = decode(jsonData)
	return json.Marshal(jsonData)
}
