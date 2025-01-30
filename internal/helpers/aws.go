//go:generate go run aws_type_gen.go

package helpers

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"reflect"
	"strings"
)

// TODO this should be combined with roseta
const (
	CCCloudFormationStack string = "AWS::CloudFormation::Stack"
	CCEc2Instance         string = "AWS::EC2::Instance"
	CCEcs                 string = "AWS::ECS::TaskDefinition"
	CCSsmDocument         string = "AWS::SSM::Document"
)

var CloudControlTypeNames = map[string]string{
	"AWS::CloudFormation::Stack": "cloudformation",
	"AWS::S3::Bucket":            "s3",
	"AWS::EC2::Instance":         "ec2",
	"AWS::Lambda::Function":      "lambda",
	"AWS::DynamoDB::Table":       "dynamodb",
	"AWS::RDS::DBInstance":       "rds",
}

type ArnIdentifier struct {
	ARN       string
	Partition string
	Service   string
	Region    string
	AccountID string
	Resource  string
}

func NewArn(identifier string) (arn.ARN, error) {
	valid := arn.IsARN(identifier)
	if !valid {
		return arn.ARN{}, fmt.Errorf("this is not a valid arn %v", identifier)
	}

	a, err := arn.Parse(identifier)
	if err != nil {
		return arn.ARN{}, err
	}

	return a, nil
}

func MakeArnIdentifiers(identifiers []string) ([]arn.ARN, error) {
	var arnIdentifiers []arn.ARN
	for _, identifier := range identifiers {
		arn, err := NewArn(identifier)
		if err != nil {
			return nil, err
		}
		arnIdentifiers = append(arnIdentifiers, arn)
	}
	return arnIdentifiers, nil
}

// Useful if identifier returned from CloudControl API is an ARN
func MapArnByRegions(identifiers []string) (map[string][]arn.ARN, error) {
	regionToArnIdentifiers := make(map[string][]arn.ARN)
	for _, identifier := range identifiers {
		arn, err := NewArn(identifier)
		if err != nil {
			return nil, err
		}
		regionToArnIdentifiers[arn.Region] = append(regionToArnIdentifiers[arn.Region], arn)
	}
	return regionToArnIdentifiers, nil
}

// Some resources do not return ARN as identifiers so need to be processed differently
func MapIdentifiersByRegions(resourceDescriptions []types.EnrichedResourceDescription) map[string][]string {
	regionToIdentifiers := make(map[string][]string)
	for _, description := range resourceDescriptions {
		regionToIdentifiers[description.Region] = append(regionToIdentifiers[description.Region], description.Identifier)
	}
	return regionToIdentifiers
}

func GetAWSCfg(region string, profile string, opts []*types.Option) (aws.Config, error) {

	// stack := middleware.NewStack("CacheStack", middleware.StackSend)

	// cacheMiddleware := &CacheMiddleware{
	// 	CacheDir: options.GetOptionByName(options.LogLevelOpt.Name, opts).Value,
	// }
	// stack.Deserialize.Add(cacheMiddleware, middleware.After)

	// cacheFunc := []func(*middleware.Stack) error{
	// 	func(stack *middleware.Stack) error {
	// 		// Add cache middleware after service metadata is registered to ensure we can access service info
	// 		// return stack.Initialize.Insert(&fileCacheMiddleware{config: fc},
	// 		// 	"RegisterServiceMetadata",
	// 		// 	middleware.After)
	// 		return stack.Deserialize.Insert(cacheMiddleware, "RegisterServiceMetadata", middleware.After)
	// 	},
	// }

	var testMiddleware = middleware.InitializeMiddlewareFunc("TestMiddleware", func(ctx context.Context, input middleware.InitializeInput, handler middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {

		fmt.Println("\n=== Initialize Debug ===")

		// Print Context details
		fmt.Println("\n=== Context Details ===")
		fmt.Printf("Context: %#v\n", ctx)

		// Print Input details
		fmt.Println("\n=== Input Details ===")
		fmt.Printf("Parameters Type: %T\n", input.Parameters)
		if input.Parameters != nil {
			v := reflect.ValueOf(input.Parameters).Elem()
			t := v.Type()

			fmt.Println("Parameters Content:")
			for i := 0; i < v.NumField(); i++ {
				field := v.Field(i)
				fieldName := t.Field(i).Name

				// Handle string pointers
				if field.Kind() == reflect.Pointer && field.Type().Elem().Kind() == reflect.String {
					if !field.IsNil() {
						fmt.Printf("  %s: %q\n", fieldName, field.Elem().String())
					} else {
						fmt.Printf("  %s: nil\n", fieldName)
					}
					continue
				}

				// Handle other types
				if field.CanInterface() {
					fmt.Printf("  %s: %#v\n", fieldName, field.Interface())
				}
			}
		}

		// Print Handler details
		fmt.Println("\n=== Handler Details ===")
		handlerValue := reflect.ValueOf(handler)
		fmt.Printf("Handler Type: %T\n", handler)

		if handlerValue.Kind() == reflect.Struct {
			for i := 0; i < handlerValue.NumField(); i++ {
				field := handlerValue.Field(i)
				fieldType := handlerValue.Type().Field(i)
				if field.CanInterface() {
					fmt.Printf("Field: %s, Type: %s, Value: %#v\n",
						fieldType.Name, field.Type(), field.Interface())
				} else {
					fmt.Printf("Field: %s, Type: %s (unexported)\n",
						fieldType.Name, field.Type())
				}
			}
		}

		// Execute the handler and save results
		output, metadata, err := handler.HandleInitialize(ctx, input)

		// Print the results
		fmt.Println("\n=== Handler Output ===")
		fmt.Printf("Output: %#v\n", output)
		fmt.Printf("Metadata: %#v\n", metadata)
		fmt.Printf("Error: %v\n", err)

		return output, metadata, err
	})

	var testMiddleware2 = middleware.DeserializeMiddlewareFunc("TestMiddleware2", func(ctx context.Context, input middleware.DeserializeInput, handler middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
		fmt.Println("\n=== Deserialize Debug ===")

		// Print Context details
		fmt.Println("\n=== Context Details ===")
		fmt.Printf("Context: %#v\n", ctx)

		// Print Input details
		fmt.Println("\n=== Input Details ===")
		fmt.Printf("Parameters Type: %T\n", input)

		// Execute the handler and save results
		output, metadata, err := handler.HandleDeserialize(ctx, input)

		fmt.Println("\n=== Output Details ===")

		if err != nil {
			fmt.Printf("Error occurred: %v\n", err)
		}
		fmt.Printf("Output: %#v\n", output)
		fmt.Printf("Metadata: %#v\n", metadata)
		fmt.Printf("Error: %v\n", err)

		resp := awsmiddleware.GetRawResponse(metadata)
		fmt.Printf("resp: %#v\n", resp)

		if resp, ok := output.RawResponse.(*smithyhttp.Response); ok {
			standardResp := resp.Response
			respBytes, dumpErr := httputil.DumpResponse(standardResp, true)
			if dumpErr != nil {
				fmt.Printf("Failed to dump response: %v\n", dumpErr)
			} else {
				fmt.Printf("HTTP Response:\n%s\n", string(respBytes))
			}
		}

		// Access the raw HTTP response
		if httpResp, ok := resp.(*http.Response); ok {
			respBytes, dumpErr := httputil.DumpResponse(httpResp, true)
			if dumpErr != nil {
				fmt.Printf("Failed to dump response: %v\n", dumpErr)
			} else {
				fmt.Printf("HTTP Response:\n%s\n", string(respBytes))
			}
		} else {
			fmt.Println("Raw response is not an HTTP response")
			fmt.Printf("Raw response type: %T\n", resp)
			fmt.Printf("Raw response: %v\n", resp)
			fmt.Printf("Raw response2: %s\n", resp)
		}

		return output, metadata, err
	})

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithClientLogMode(
			aws.LogRetries|
				aws.LogRequestWithBody|
				aws.LogRequestEventMessage|
				aws.LogResponseEventMessage),
		config.WithLogger(logs.AwsCliLogger()),
		config.WithRegion(region),
		config.WithSharedConfigProfile(profile),
		config.WithRetryMode(aws.RetryModeAdaptive),
		// config.WithAPIOptions(cacheFunc),
	)
	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		// Add custom middlewares
		if err := stack.Initialize.Add(testMiddleware, middleware.After); err != nil {
			return err
		}
		if err := stack.Deserialize.Insert(testMiddleware2, "OperationDeserializer", middleware.After); err != nil {
			return err
		}
		fmt.Printf("Middleware Stack: %v\n", stack.List())
		return nil
	})
	//stack := middleware.NewStack("CacheStack", nil)
	//// Simulate applying the options to the stack
	//for _, opt := range cfg.APIOptions {
	//	err := opt(stack)
	//	if err != nil {
	//		fmt.Printf("Error adding middleware: %v\n", err)
	//	}
	//}
	//
	//// List the middleware in the Initialize phase
	//fmt.Printf("Middleware in Initialize phase: %v\n", stack.Initialize.List())

	if err != nil {
		return aws.Config{}, err
	}

	return cfg, nil

}

func GetAccountId(cfg aws.Config) (string, error) {
	if strings.ToLower(cfg.Region) == "all" {
		cfg.Region = "us-east-1"
	}
	client := sts.NewFromConfig(cfg)
	input := &sts.GetCallerIdentityInput{}

	result, err := client.GetCallerIdentity(context.TODO(), input)
	if err != nil {
		return "", err
	}

	return *result.Account, nil
}

// Parses regions with 2 primary outcomes
// if "ALL" is provided, then it detects all Enabled Regions
// else it just reads the list of regions provided

func ParseRegionsOption(regionsOpt string, profile string, opts []*types.Option) ([]string, error) {
	if strings.ToLower(regionsOpt) == "all" {
		slog.Debug("Gathering enabled regions")
		enabledRegions, err := EnabledRegions(profile, opts)
		if err != nil {
			return nil, err
		}
		slog.Debug("Enabled regions: " + strings.Join(enabledRegions, ", "))
		return enabledRegions, nil
	} else {
		regions := strings.Split(regionsOpt, ",")
		return regions, nil
	}
}

func ParseSecretsResourceType(secretsOpt string) []string {

	allSupportedTypes := options.AwsFindSecretsResourceType.ValueList
	var resourceTypes []string
	if secretsOpt == "ALL" {
		resourceTypes = allSupportedTypes
	} else {
		resourceTypes = strings.Split(secretsOpt, ",")
	}
	return resourceTypes

}

// TODO this needs to use the `output` parameter for the leading path segment
func CreateFilePath(cloudProvider, service, account, command, region, resource string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s-%s-%s.json", cloudProvider, string(os.PathSeparator), service, string(os.PathSeparator), account, string(os.PathSeparator), command, region, resource)
}

func CreateFileName(parts ...string) string {
	return strings.Join(parts, "-")
}
