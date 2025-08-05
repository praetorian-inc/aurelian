# Nebula Development Guide

Nebula is built on the [Janus Framework](https://github.com/praetorian-inc/janus-framework), a modular chain-based architecture for building composable workflows that implement go's pipeline pattern. This guide covers developing links, modules, and extending the platform.

## Architecture Overview

Nebula uses the Janus framework with these core concepts:

- **Links**: Individual processing units that can be chained together
- **Modules**: Pre-configured chains of links for specific use cases  
- **Chains**: Connected sequences of links that process data
- **Registry**: Dynamic module discovery and CLI command generation
- **Outputters**: Pluggable output processors for different formats

## Quick Start

Generate a new module skeleton:
```bash
go run cmd/generator.go -platform aws -category recon -name MyModule
```

## Janus Framework Concepts

### Links

Links are the fundamental building blocks. Each link:
- Embeds `chain.Base` 
- Implements `Process(input any) error`
- Defines parameters via `Params() []cfg.Param`
- Uses `l.Send(data)` to pass data to the next link

**Example Link:**
```go
type MyLink struct {
    *chain.Base
}

func NewMyLink(configs ...cfg.Config) chain.Link {
    l := &MyLink{}
    l.Base = chain.NewBase(l, configs...)
    return l
}

func (l *MyLink) Process(input any) error {
    // Process the input
    result := processData(input)
    
    // Send to next link in chain
    l.Send(result)
    return nil
}

func (l *MyLink) Params() []cfg.Param {
    return []cfg.Param{
        cfg.NewParam[string]("my-param", "Description").AsRequired(),
    }
}
```

### Link Organization

Links are organized by platform in `pkg/links/`:
```
pkg/links/
├── aws/           # AWS-specific links
├── azure/         # Azure-specific links  
├── gcp/           # GCP-specific links
├── docker/        # Docker container processing
├── general/       # Platform-agnostic utilities
└── options/       # Parameter definitions
```

### Modules

Modules are pre-configured chains of links using `chain.NewModule()`:

```go
var MyModule = chain.NewModule(
    cfg.NewMetadata("Module Name", "Description").WithProperties(map[string]any{
        "id":          "unique-id",
        "platform":    "aws",
        "opsec_level": "moderate", 
        "authors":     []string{"Praetorian"},
    }),
).WithLinks(
    link1.NewLink1,
    link2.NewLink2,
    link3.NewLink3,
).WithOutputters(
    outputter.NewOutputter,
)

func init() {
    registry.Register("aws", "recon", "unique-id", *MyModule)
}
```

### Parameters and Options

Parameters are defined in `pkg/links/options/` files:

```go
// In options file
var MyParam = cfg.NewParam[string]("my-param", "Parameter description").
    WithDefault("default-value").
    AsRequired().
    WithShortcode("p")

// In link
func (l *MyLink) Params() []cfg.Param {
    return []cfg.Param{
        options.AwsRegion(),     // Pre-defined parameter
        options.MyParam,         // Custom parameter
    }
}

// Access in Process method
func (l *MyLink) Process(input any) error {
    region, _ := cfg.As[string](l.Arg("aws-region"))
    myValue, _ := cfg.As[string](l.Arg("my-param"))
    // Use values...
}
```

## Development Patterns

### AWS Links
AWS links typically embed `base.AwsReconLink`:

```go
type MyAWSLink struct {
    *base.AwsReconLink
}

func NewMyAWSLink(configs ...cfg.Config) chain.Link {
    l := &MyAWSLink{}
    l.AwsReconLink = base.NewAwsReconLink(l, configs...)
    return l
}
```

### Azure Links  
Azure links use helper functions from `internal/helpers/azure.go`:

```go
func (l *MyAzureLink) Process(input any) error {
    // Get Azure credentials
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    
    // Use helper functions
    subscriptions, err := helpers.ListSubscriptions(l.Context(), nil)
    
    // Process and send results
    for _, sub := range subscriptions {
        l.Send(processSubscription(sub))
    }
    return nil
}
```

### Chain Construction

Links can construct sub-chains for complex processing:

```go
func (l *MyLink) Process(input any) error {
    // Create a sub-chain
    subChain := chain.NewChain(
        link1.NewLink1(),
        link2.NewLink2(),
    )
    
    // Configure and run
    subChain.WithConfigs(cfg.WithArgs(l.Args()))
    subChain.Send(input)
    subChain.Close()
    
    // Collect results
    for result := range chain.RecvAll(subChain) {
        l.Send(result)
    }
    return nil
}
```

## Context and Logging

Always use the link's context for operations:

```go
func (l *MyLink) Process(input any) error {
    ctx := l.Context()  // Never use context.Background()
    
    // Use slog for structured logging
    slog.InfoContext(ctx, "Processing input", "type", fmt.Sprintf("%T", input))
    
    // Make HTTP requests with context
    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    
    return nil
}
```

## Output Processing

### Built-in Outputters

Nebula provides several outputters in `pkg/outputters/`:
- `erd_console.go` - Console output for enriched resource descriptions
- `markdown_table_console.go` - Console markdown tables
- `runtime_json.go` - JSON file output
- `runtime_markdown.go` - Markdown file output

### Custom Outputters

Create custom outputters by implementing the output interface:

```go 
type MyOutputter struct {
    *outputter.Base
}

func NewMyOutputter(configs ...cfg.Config) chain.Outputter {
    o := &MyOutputter{}
    o.Base = outputter.NewBase(o, configs...)
    return o
}

func (o *MyOutputter) Output(val any) error {
    // Process the output value
    return nil
}
```

## Testing

Write tests for links using the testutils:

```go
func TestMyLink(t *testing.T) {
    link := NewMyLink()
    
    input := "test-input"
    err := link.Process(input)
    
    assert.NoError(t, err)
    // Test output...
}
```

## Registry and CLI Integration

Modules automatically generate CLI commands via the registry:

```go
func init() {
    // This creates: nebula aws recon my-module
    registry.Register("aws", "recon", "my-module", *MyModule)
}
```

The registry system:
1. Scans module definitions at startup
2. Generates CLI command hierarchy  
3. Extracts parameters for flag definitions
4. Handles module execution and output

## Platform-Specific Patterns

### AWS CloudControl Integration
Use the cloudcontrol links for resource discovery:

```go
).WithLinks(
    cloudcontrol.NewCloudControlList,
    general.NewPreprocessResources,  // Type filtering
    mylink.NewMyProcessing,
)
```

### Azure Resource Graph
Use ARG templates for Azure resource queries:

```go
).WithLinks(
    azure.NewArgTemplate,
    azure.NewResourceLister,
    azure.NewResourceAggregator,
)
```

### Docker Processing
For container security scanning:

```go
).WithLinks(
    ecr.NewECRListImages,
    docker.NewDockerPull,
    docker.NewDockerSave,
    docker.NewDockerExtractToFS,
)
```

## Best Practices

1. **Parameter Management**: Define parameters in options files, not inline
2. **Context Usage**: Always use `l.Context()`, never `context.Background()`
3. **Error Handling**: Return errors from `Process()`, don't panic
4. **Resource Cleanup**: Close resources properly in deferred functions
5. **Structured Logging**: Use slog with context for debugging
6. **Type Safety**: Use generics and type assertions carefully
7. **OPSEC Awareness**: Set appropriate opsec_level in module metadata

## Common Issues

**Link Hanging**: Ensure data flows through the chain - use `l.Send()` to pass data forward.

**Parameter Not Found**: Check parameter name matches between definition and access:
```go
cfg.NewParam[string]("my-param", "...")  // Definition
cfg.As[string](l.Arg("my-param"))        // Access - names must match
```

**Context Timeouts**: Use link context for operations that might timeout.

For more examples, explore the existing links in `pkg/links/` and modules in `pkg/modules/`.