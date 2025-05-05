package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/praetorian-inc/nebula/pkg/outputters"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type JanusAWSAuthorizationDetails struct {
	*base.AwsReconBaseLink
}

func NewJanusAWSAuthorizationDetails(configs ...cfg.Config) chain.Link {
	slog.Debug("Creating JanusAWSAuthorizationDetails link")
	ad := &JanusAWSAuthorizationDetails{}
	slog.Debug("config:", "config", configs)
	ad.AwsReconBaseLink = base.NewAwsReconBaseLink(ad, configs...)
	return ad
}

func (ad *JanusAWSAuthorizationDetails) Initialize() error {
	slog.Debug("Initializing JanusAWSAuthorizationDetails")
	if err := ad.AwsReconBaseLink.Initialize(); err != nil {
		return err
	}
	return nil
}

func (ad *JanusAWSAuthorizationDetails) Process(resource string) error {
	slog.Debug("Beging processing JanusAWSAuthorizationDetails", "profile", ad.Profile)
	return ad.GetAccountAuthorizationDetails()
}

// replaceURLEncodedPolicies decodes URL-encoded JSON policy strings in AWS IAM policy documents
func replaceURLEncodedPolicies(data []byte) ([]byte, error) {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	var decode func(interface{}) interface{}
	decode = func(v interface{}) interface{} {
		switch val := v.(type) {
		case map[string]interface{}:
			for k, v := range val {
				if str, ok := v.(string); ok && strings.HasPrefix(str, "%7B") {
					decoded, err := url.QueryUnescape(str)
					if err == nil {
						var policy interface{}
						if err := json.Unmarshal([]byte(decoded), &policy); err == nil {
							val[k] = policy
						}
					}
				} else {
					val[k] = decode(v)
				}
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

// GetOutputterFromContext safely extracts the JSONOutputter from the context
func GetOutputterFromContext(ctx context.Context) (chain.Outputter, bool) {
	// Simply try to get the outputter directly from the context
	outputter, ok := ctx.Value("jsonOutputter").(chain.Outputter)

	return outputter, ok
}

func (a *JanusAWSAuthorizationDetails) GetAccountAuthorizationDetails() error {
	slog.Debug("Getting Account Authorization Details", "profile", a.Profile)
	print("Getting Account Authorization Details", "profile", a.Profile)

	// We'll use us-east-1 for IAM since it's a global service
	region := "us-east-1"

	slog.Debug("Getting Account Authorization Details: Set region to ", "region", region)

	config, err := a.GetConfig(region, options.JanusParamAdapter(a.Params()))
	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return err
	}

	accountId, err := helpers.GetAccountId(config)
	if err != nil {
		slog.Error("Failed to get account ID", "error", err, "region", region)
		return err
	}

	iamClient := iam.NewFromConfig(config)
	var completeOutput *iam.GetAccountAuthorizationDetailsOutput
	maxItems := int32(1000)
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(iamClient, &iam.GetAccountAuthorizationDetailsInput{
		// You can specify which types to fetch or leave nil to get all
		// Filter: []types.EntityType{
		// 	types.EntityTypeUser,
		// 	types.EntityTypeRole,
		// 	types.EntityTypeGroup,
		// 	types.EntityTypeLocalManagedPolicy,
		// },
		MaxItems: &maxItems,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			slog.Error("Error retrieving authorization details page", "error", err)
			return err
		}

		if completeOutput == nil {
			completeOutput = page
		} else {
			completeOutput.UserDetailList = append(completeOutput.UserDetailList, page.UserDetailList...)
			completeOutput.GroupDetailList = append(completeOutput.GroupDetailList, page.GroupDetailList...)
			completeOutput.RoleDetailList = append(completeOutput.RoleDetailList, page.RoleDetailList...)
			completeOutput.Policies = append(completeOutput.Policies, page.Policies...)
		}
	}

	// Marshal and decode the output
	rawData, err := json.Marshal(completeOutput)
	if err != nil {
		slog.Error("Error marshaling authorization details", "profile", a.Profile, "error", err)
		return err
	}

	decodedData, err := replaceURLEncodedPolicies(rawData)
	if err != nil {
		slog.Error("Error replacing URL-encoded policies", "profile", a.Profile, "error", err)
		return err
	}

	// Unmarshal the decoded data back into a Go structure that can be sent to the outputter
	var authDetails interface{}
	if err := json.Unmarshal(decodedData, &authDetails); err != nil {
		slog.Error("Error unmarshaling decoded data", "error", err)
		return err
	}

	filename := fmt.Sprintf("authorization-details-%s-%s-gaad.json", a.Profile, accountId)

	outputData := outputters.NamedOutputData{
		OutputFilename: filename,
		Data:           authDetails,
	}

	a.Send(outputData)

	slog.Info("Generated authorization details", "filename", filename)

	return nil
}

func (ad *JanusAWSAuthorizationDetails) Permissions() []cfg.Permission {
	return []cfg.Permission{
		{
			Platform:   "aws",
			Permission: "iam:GetAccountAuthorizationDetails",
		},
	}
}
