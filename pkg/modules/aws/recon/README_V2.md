# AWS Find Secrets V2 - Plain Go Implementation

## Overview

The V2 implementation (`find_secrets_v2.go`) uses plain Go patterns instead of janus-framework chains. It leverages the new `pkg/orchestrator` and `pkg/dispatcher` packages for cleaner, more maintainable code.

## Architecture Comparison

### V1 (Janus Framework)

```
AWSFindSecrets Module (chain.NewModule)
  ├── ResourceTypePreprocessor (link)
  ├── CloudControl (link)
  ├── AWSFindSecrets (link)
  ├── AWSResourceChainProcessor (link)
  └── NoseyParkerScanner (link)
```

### V2 (Plain Go)

```
FindAWSSecretsV2 struct
  ├── enumerateResources() → resourceCh
  ├── orchestrator.ProcessAWSSecrets()
  │   ├── dispatcher.GetAWSSecretProcessor()
  │   └── errgroup with bounded concurrency
  └── NoseyParker integration (future)
```

## Key Improvements

1. **No Framework Dependency**: Pure Go, no chain abstractions
2. **Channel-Based Streaming**: Resources stream through channels instead of link chains
3. **Bounded Concurrency**: errgroup with SetLimit for predictable resource usage
4. **Dispatcher Registry**: ProcessFunc registration pattern for extensibility
5. **Clearer Error Handling**: Explicit error propagation and context

## Usage Example

### Basic Usage

```go
package main

import (
    "context"
    "log"

    "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

func main() {
    ctx := context.Background()

    // Create finder with default settings
    finder := recon.NewFindAWSSecretsV2(
        "my-aws-profile",
        []string{"us-east-1", "us-west-2"},
    )

    // Run the scan
    results, err := finder.Run(ctx)
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    log.Printf("Found %d secrets across %d regions", len(results), len(finder.Regions))
}
```

### Advanced Configuration

```go
finder := recon.NewFindAWSSecretsV2("my-profile", []string{"us-east-1"})

// Customize CloudWatch Logs processing
finder.MaxEvents = 5000      // Fetch up to 5000 log events per log group
finder.MaxStreams = 20       // Sample up to 20 log streams per group
finder.NewestFirst = true    // Fetch newest events first

// Limit to specific resource types
finder.ResourceTypes = []string{
    "AWS::Lambda::Function",
    "AWS::EC2::Instance",
    "AWS::ECS::TaskDefinition",
}

results, err := finder.Run(context.Background())
```

## How It Works

### 1. Resource Enumeration (CloudControl)

The `enumerateResources()` method lists AWS resources using CloudControl API:

```go
func (f *FindAWSSecretsV2) enumerateResources(ctx context.Context, resourceCh chan<- *types.EnrichedResourceDescription) error {
    // For each resource type and region:
    //   1. List resources via CloudControl API
    //   2. Convert to EnrichedResourceDescription
    //   3. Send to channel
}
```

**Key Features:**
- Parallel enumeration across resource types and regions
- Graceful handling of unsupported resource types
- Rate limiting via semaphores
- Context cancellation support

### 2. Resource Processing (Orchestrator)

The `orchestrator.ProcessAWSSecrets()` function processes resources:

```go
orchestrator.ProcessAWSSecrets(ctx, resourceCh, resultCh,
    orchestrator.WithConcurrencyLimit(25),
    orchestrator.WithProcessOptions(&dispatcher.ProcessOptions{
        AWSProfile:  f.Profile,
        Regions:     f.Regions,
        MaxEvents:   f.MaxEvents,
        MaxStreams:  f.MaxStreams,
        NewestFirst: f.NewestFirst,
    }),
)
```

**Key Features:**
- Bounded concurrency (default: 25 concurrent processors)
- errgroup for error propagation and cleanup
- Dispatcher registry for processor lookup
- Per-resource-type processing logic

### 3. Dispatcher Registry

Processors register themselves using `init()` pattern:

```go
// In pkg/dispatcher/aws_lambda_function.go
func init() {
    RegisterAWSSecretProcessor("AWS::Lambda::Function", ProcessLambdaFunction)
}

func ProcessLambdaFunction(
    ctx context.Context,
    resource *types.EnrichedResourceDescription,
    opts *ProcessOptions,
    resultCh chan<- types.NpInput,
) error {
    // Extract Lambda code, environment variables, etc.
    // Send secrets to resultCh
}
```

**Supported Resource Types:**
- `AWS::Lambda::Function` - Function code and environment variables
- `AWS::EC2::Instance` - User data and metadata
- `AWS::ECS::TaskDefinition` - Container environment and secrets
- `AWS::CloudFormation::Stack` - Template and parameters
- `AWS::CloudWatch::LogGroup` - Log events
- `AWS::ECR::Repository` - Container images
- `AWS::SSM::Document` - Document content
- `AWS::StepFunctions::StateMachine` - State machine definition

## Testing

### Unit Tests

```bash
GOWORK=off go test ./pkg/modules/aws/recon/... -v -run V2
```

Tests cover:
- Constructor defaults
- Error handling logic
- Global service detection
- CloudControl error classification

### Integration Tests

Integration tests are skipped by default (require AWS credentials):

```bash
GOWORK=off go test ./pkg/modules/aws/recon/... -v -run Integration
```

To run integration tests:
1. Configure AWS credentials (`aws configure` or environment variables)
2. Remove the `t.Skip()` line in `TestFindAWSSecretsV2_Run_Integration`
3. Run tests with actual AWS account

## Migration from V1

### Step 1: Replace Module Usage

**Before (V1):**
```go
import "github.com/praetorian-inc/janus-framework/pkg/chain"

module := recon.AWSFindSecrets
result := module.Run(ctx)
```

**After (V2):**
```go
import "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"

finder := recon.NewFindAWSSecretsV2("my-profile", []string{"us-east-1"})
results, err := finder.Run(ctx)
```

### Step 2: Update Configuration

**Before (V1 - Chain Params):**
```go
module.WithInputParam(options.AwsProfile())
module.WithParam(cfg.NewParam[int]("max-events").WithDefault(10000))
```

**After (V2 - Struct Fields):**
```go
finder := recon.NewFindAWSSecretsV2("my-profile", regions)
finder.MaxEvents = 10000
finder.MaxStreams = 10
finder.NewestFirst = false
```

## Performance Characteristics

### Concurrency

- **Enumeration**: Parallel across resource types and regions (unbounded, limited by AWS API rate limits)
- **Processing**: Bounded concurrency via errgroup (default: 25 concurrent processors)
- **Memory**: Buffered channels (100 items) to balance throughput and memory usage

### Resource Usage

Typical scan of 1000 resources across 2 regions:

- **Memory**: ~50-100MB (depending on resource sizes)
- **Time**: 2-5 minutes (depending on CloudControl API latency and secret extraction complexity)
- **API Calls**:
  - CloudControl ListResources: ~10 calls per resource type per region
  - Resource-specific APIs: Varies by processor (e.g., Lambda GetFunction, CloudWatch FilterLogEvents)

## Extending with New Processors

To add support for a new AWS resource type:

### 1. Create Processor File

```go
// pkg/dispatcher/aws_my_resource.go
package dispatcher

import (
    "context"
    "github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
    RegisterAWSSecretProcessor("AWS::MyService::MyResource", ProcessMyResource)
}

func ProcessMyResource(
    ctx context.Context,
    resource *types.EnrichedResourceDescription,
    opts *ProcessOptions,
    resultCh chan<- types.NpInput,
) error {
    // 1. Extract properties from resource.PropertiesAsMap()
    // 2. Fetch additional data via AWS API (if needed)
    // 3. Identify potential secrets
    // 4. Send to resultCh
    return nil
}
```

### 2. Add Tests

```go
// pkg/dispatcher/aws_my_resource_test.go
func TestProcessMyResource(t *testing.T) {
    // Test secret extraction logic
}
```

### 3. Update Documentation

Add to supported resource types list above.

## Troubleshooting

### "TypeNotFoundException" errors

Some resource types are not available in all regions. The V2 implementation automatically skips these and logs at DEBUG level:

```
slog.Debug("Resource type not available", "type", "AWS::...", "region", "us-west-2")
```

### "AccessDeniedException" errors

IAM permissions are required for CloudControl ListResources and resource-specific APIs. Ensure your AWS credentials have:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudformation:ListResources",
                "cloudformation:GetResource",
                "lambda:GetFunction",
                "logs:FilterLogEvents",
                // ... other resource-specific permissions
            ],
            "Resource": "*"
        }
    ]
}
```

### High memory usage

If processing very large resources (e.g., massive CloudWatch log groups), adjust:

```go
finder.MaxEvents = 1000   // Reduce from default 10000
finder.MaxStreams = 5     // Reduce from default 10
```

Or reduce concurrency:

```go
// In orchestrator call (requires modifying Run() method):
orchestrator.WithConcurrencyLimit(10)  // Down from 25
```

## Future Enhancements

- [ ] NoseyParker integration (currently uses result channel, but NoseyParker scanner not yet integrated)
- [ ] Progress reporting (emit progress events via channel or callback)
- [ ] Resume capability (checkpoint enumeration state for large scans)
- [ ] Filtering (skip resources by tag, name pattern, etc.)
- [ ] Output formatting (JSON, CSV, custom outputters)

## References

- [Orchestrator Package](../../orchestrator/aws_secrets.go)
- [Dispatcher Registry](../../dispatcher/registry.go)
- [Processor Examples](../../dispatcher/)
- [Original V1 Module](./find_secrets.go)
