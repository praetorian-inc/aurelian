module github.com/praetorian-inc/nebula

go 1.24

toolchain go1.24.2

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.16.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.7.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation v0.9.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph v0.9.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions v1.3.0
	github.com/aws/aws-sdk-go v1.55.5
	github.com/aws/aws-sdk-go-v2 v1.36.5
	github.com/aws/aws-sdk-go-v2/config v1.29.6
	github.com/aws/aws-sdk-go-v2/service/account v1.24.0
	github.com/aws/aws-sdk-go-v2/service/backup v1.39.3
	github.com/aws/aws-sdk-go-v2/service/cloudcontrol v1.23.11
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.57.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.42.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.46.3
	github.com/aws/aws-sdk-go-v2/service/costexplorer v1.38.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.202.4
	github.com/aws/aws-sdk-go-v2/service/ecr v1.36.2
	github.com/aws/aws-sdk-go-v2/service/ecrpublic v1.27.2
	github.com/aws/aws-sdk-go-v2/service/efs v1.33.2
	github.com/aws/aws-sdk-go-v2/service/elasticsearchservice v1.32.3
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.35.2
	github.com/aws/aws-sdk-go-v2/service/glacier v1.26.2
	github.com/aws/aws-sdk-go-v2/service/glue v1.100.3
	github.com/aws/aws-sdk-go-v2/service/iam v1.34.3
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.2
	github.com/aws/aws-sdk-go-v2/service/lambda v1.57.0
	github.com/aws/aws-sdk-go-v2/service/mediastore v1.24.3
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.41.2
	github.com/aws/aws-sdk-go-v2/service/pinpointsmsvoice v1.24.2
	github.com/aws/aws-sdk-go-v2/service/rds v1.89.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.66.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.34.2
	github.com/aws/aws-sdk-go-v2/service/serverlessapplicationrepository v1.24.2
	github.com/aws/aws-sdk-go-v2/service/ses v1.28.3
	github.com/aws/aws-sdk-go-v2/service/sfn v1.34.11
	github.com/aws/aws-sdk-go-v2/service/sns v1.33.3
	github.com/aws/aws-sdk-go-v2/service/sqs v1.36.3
	github.com/aws/aws-sdk-go-v2/service/ssm v1.56.10
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.14
	github.com/aws/aws-sdk-go-v2/service/timestreamquery v1.31.0
	github.com/aws/smithy-go v1.22.4
	github.com/docker/docker v28.0.1+incompatible
	github.com/fatih/color v1.18.0
	github.com/google/uuid v1.6.0
	github.com/itchyny/gojq v0.12.17
	github.com/lmittmann/tint v1.1.2
	github.com/mark3labs/mcp-go v0.29.0
	github.com/mattn/go-isatty v0.0.20
	github.com/microsoftgraph/msgraph-sdk-go v1.53.0
	github.com/mpvl/unique v0.0.0-20150818121801-cbe035fff7de
	github.com/neo4j/neo4j-go-driver/v5 v5.28.1
	github.com/ollama/ollama v0.2.7
	github.com/praetorian-inc/janus v0.0.0-20250728200524-145c85684130
	github.com/praetorian-inc/konstellation v0.0.0-20250609145306-636c2e50b157
	github.com/praetorian-inc/tabularium v0.1.3-0.20250728152811-58090c11d2de
	github.com/spf13/cobra v1.9.1
	github.com/stretchr/testify v1.10.0
	golang.org/x/oauth2 v0.30.0
	google.golang.org/api v0.240.0
)

require (
	cloud.google.com/go/auth v0.16.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.7.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/Ullaakut/nmap/v3 v3.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue v1.18.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.42.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.4.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.10.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.2 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cjlapao/common-go v0.0.39 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.6 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.14.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.1 // indirect
	github.com/itchyny/timefmt-go v0.1.6 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/knqyf263/go-cpe v0.0.0-20230627041855-cb0794d06872 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mfonda/simhash v0.0.0-20151007195837-79f94a1100d6 // indirect
	github.com/microsoft/kiota-abstractions-go v1.8.1 // indirect
	github.com/microsoft/kiota-authentication-azure-go v1.1.0 // indirect
	github.com/microsoft/kiota-http-go v1.4.4 // indirect
	github.com/microsoft/kiota-serialization-form-go v1.0.0 // indirect
	github.com/microsoft/kiota-serialization-json-go v1.0.8 // indirect
	github.com/microsoft/kiota-serialization-multipart-go v1.0.0 // indirect
	github.com/microsoft/kiota-serialization-text-go v1.0.0 // indirect
	github.com/microsoftgraph/msgraph-sdk-go-core v1.2.1 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/std-uritemplate/std-uritemplate/go/v2 v2.0.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.36.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.35.0 // indirect
	go.opentelemetry.io/otel/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	go.opentelemetry.io/proto/otlp v1.5.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/grpc v1.73.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.17.59 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/organizations v1.38.3
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.14 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/spf13/pflag v1.0.6
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/praetorian-inc/tabularium => ../tabularium
