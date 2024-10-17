# Module Development

This doc outlines the major components of a module, the type definition, metadata, options, and output providers.


For the impatient, use the `template` command to generate a module skeleton and get started.

```shell
nebula template -c recon -p aws -n FooBar > modules/recon/aws/foo_bar.go
```

If you get an `EOF` error, refer to the `KNOWN ISSUES` section below. 

## Module Categories

**Recon:** Directly interact with a cloud service provider (CSP) to gather information.
**Analyze:** Offline analysis of data.


### Module Type Definition

Every module is a unique type that embeds the `BaseModule`.

```go
type ModuleName struct {
	modules.BaseModule
}
```

### Metadata

A module's metadata is used to identify and describe the module. Some of the values are used to expose the module in the CLI in the module registry.

- **Id:** Id is used as an identifier for the module and is converted to the CLI subcommand name.
- **Name:** Name of the module
- **Description:** Description of the module. This is used as the CLI subcommand description.
- **Platform:** A platform string used to denote a CSP or similar type of provider.
- **Authors:** A list of module developers/contributors.
- **OpsecLevel:** Provide a rough idea of the OPSEC safety of a module. Stealth, Moderate, or None are the current values. A future feature will configure a global OPSEC level to act as a safety mechanism during an offensive engagement.
- **References:** Giving credit where it's due. Blog posts, tweets, vendor docs, etc.


Example metadata:
```go
var <module name>Metadata = modules.Metadata{
	Id:          "module-id", 
	Name:        "Readable name",
	Description: "Description",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{},
}
```

### Options
Each module configures its own non-global options. These options are used to provide configuration to the `Invoke` function, handle output

Options are defined in the `modules/options` package. Generic and provider-specific options can be used to create a list of options required for the module. Defined options have a pre-configured `Required` value, but can be changed with the `SetRequired` function. Below is an example of 

```go
var AwsFooOptions= []*options.Option{
	&options.AwsRegionOpt,
	o.SetRequired(&o.FileNameOpt, false), // don't require the file name
}
```

### Output Providers

Output providers process the results of a module. They abstract the mechanics of handling results processing. Modules define one or more output providers, and all results returned by the module will be processed by the output provider.

Two providers have been currently implemented, `ConsoleProvider` and `FileProvider`.

### Factory Function

The factory function returns a stage and input channel ready for invocation. The naming convention is `New<module name>` and must have the following method signature.

```go
func NewFoo (opts []*types.Option) (<-chan string, stages.Stage[string, int], error) 
```

### Invoke Function

The `Invoke` function does the work of the module. Once the module has gathered, analyzed, or completed its processing, the results should be sent to the results channel. The data is read from the channel by the output providers and handled accordingly.

#### Results

Modules will typically have some results from their invocation. The results are returned by the module using an output channel which is automatically processed by the configured output providers. 

**Note:** The output channel must be closed, if not the module will hang as the module runner is waiting for more data to be sent on the channel.


### Module Registration

You've built a module, but how do you call it? Modules are registered in `cmd/registry.go` using the `RegisterModule` function. The `RegisterModule` function uses the module metadata, required options, and factory function to create the CLI subcommand for 

`RegisterModule(awsAnalyzeCmd, analyze.AccessKeyIdToAccountIdMetadata, analyze.AwsAccessKeyIdToAccountIdOptions, noCommon, analyze.NewAccessKeyIdToAccountId)`

## Module Template

The template command will generate a bare-bones template based on the parameters passed in.

```
nebula template -c recon -p aws -n FooBar > modules/recon/aws/foo_bar.go
```

## FAQ

### Why is my module hanging?

Modules will hang if the output channel is not closed. Add `defer close(out)` to your module to close the channel, otherwise explicitly close it when you're done.


## KNOWN ISSUES
If you see receive a `modules/recon/aws/foo_bar.go:1:1: expected 'package', found 'EOF'` when trying to run `go run main.go template -c recon -p aws -n FooBar > modules/recon/aws/foo_bar.go`, then you have to run `go build .` to build the binary and that should solve it. 

## Stages

Modules use stages to build their capabilities. Stages are like go versions of Unix utilities. They take a context, configuration options, and an input channel, perform a single function on the input data, and return an output channel.

### Chaining Stages

Stages are intended to be chained together to enable the [pipeline](https://go.dev/blog/pipelines) pattern. Stages allow for composable pipelines with code reuse. 

The `ChainStages` function handles the pipeline assembly. It uses generics to specify the input and output of the rendered pipeline. It verifies that the initial stage's input matches the specified input type, the last stage's output matches the output type, and all chained stages have compatible types.

The example below uses AWS Cloud Control to list resources, convert the type to JSON, filter out the `.PublicIp` value, and converts the value to a string.

```go
pipelne, err = ChainStages[string, string](
	CloudControlListResources,
	ToJson[types.EnrichedResourceDescription],
	JqFilter(".Properties | fromjson | select(.PublicIp != null) | .PublicIp"),
	ToString[[]byte],
)
```

`ChainStages` returns the pipeline (function) which can be executed to as a single function like the following example.
```go
for s := range pipeline(ctx, opts, Generator([]string{rtype})) {
	out <- s
}
```

### Helpful Stage Utilities

- `Echo` - A useful debugging stage that will print the values received on the input channel to stdout and send the values unchanged to the output channel.
- `ToJsonBytes` - Marshals the input channel value to JSON and returns the resulting `[]byte`.
- `ToString` - Casts the input value to a string.