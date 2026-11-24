package enrichers

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/praetorian-inc/aurelian/pkg/software/imageconfig"
)

// imageConfigFetcher is process-wide on purpose.
//
// The enricher runs inside the shared concurrent pipeline stage
// (pipeline.Pipe with PipeOpts.Concurrency, see list_all_resources.go), so
// every worker enriching every resource shares this one cache. Fifty task
// definitions on one image are one fetch no matter which workers pick them
// up, and a reference that cannot be pulled is attempted once for the whole
// scan rather than once per resource that names it.
var imageConfigFetcher = imageconfig.New(nil)

// ecrRegistry matches a private ECR registry host, which is the only kind
// needing credentials. Public ECR and every other registry are read
// anonymously.
var ecrRegistry = regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$`)

// ecrAuthCache memoises one GetAuthorizationToken per registry host. The token
// is valid for twelve hours, and a scan of a thousand images in one account
// should make one call for them all, not a thousand.
var ecrAuthCache sync.Map // registry host -> authn.Authenticator

// imageConfigTechnologies reads the config blob of every image a resource
// references and returns the technologies identifiable from it.
//
// Returns nothing, never an error. An image that cannot be pulled contributes
// no technology; it is not a reason to fail a scan.
func imageConfigTechnologies(cfg plugin.EnricherConfig, r *output.AWSResource) []output.Technology {
	refs := software.ImageReferences(r.ResourceType, r.Properties)
	if len(refs) == 0 {
		return nil
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	var out []output.Technology
	for _, ref := range refs {
		conf := imageConfigFetcher.Fetch(ctx, ref, authFor(ctx, cfg, ref))
		if conf.Empty() {
			continue
		}
		out = append(out, software.TechnologiesFromImageConfig(conf)...)
	}
	return out
}

// authFor returns credentials for a private ECR registry, or nil for anything
// else. nil means anonymous, which is what public registries want.
func authFor(ctx context.Context, cfg plugin.EnricherConfig, ref string) authn.Authenticator {
	host, _, _ := strings.Cut(ref, "/")
	m := ecrRegistry.FindStringSubmatch(host)
	if m == nil {
		return nil
	}

	if cached, ok := ecrAuthCache.Load(host); ok {
		auth, _ := cached.(authn.Authenticator)
		return auth
	}

	// The reference names its own region, which is not always the region the
	// resource lives in — a task definition can pull from anywhere.
	awsCfg := cfg.AWSConfig.Copy()
	awsCfg.Region = m[2]

	auth, err := ecrAuth(ctx, ecr.NewFromConfig(awsCfg))
	if err != nil {
		slog.Debug("ECR authorization failed; image config will not be read",
			"registry", host, "error", err)
		// Cached as nil so a registry we cannot authenticate to is not
		// re-attempted per image.
		ecrAuthCache.Store(host, authn.Authenticator(nil))
		return nil
	}
	ecrAuthCache.Store(host, auth)
	return auth
}

type ecrAuthClient interface {
	GetAuthorizationToken(ctx context.Context, in *ecr.GetAuthorizationTokenInput, opts ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

func ecrAuth(ctx context.Context, client ecrAuthClient) (authn.Authenticator, error) {
	resp, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("GetAuthorizationToken: %w", err)
	}
	if len(resp.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no authorization data returned")
	}

	decoded, err := base64.StdEncoding.DecodeString(aws.ToString(resp.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return nil, fmt.Errorf("decoding auth token: %w", err)
	}

	// The token decodes to "AWS:<password>".
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return nil, fmt.Errorf("unexpected auth token format")
	}
	return authn.FromConfig(authn.AuthConfig{Username: user, Password: pass}), nil
}
