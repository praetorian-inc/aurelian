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

The factory function returns an instance of the module that's ready for invocation. All of the metadata, options, and providers are configured here. The naming convention is `New<module name>` and must have the following method signature.

```go
func New<module name>(options []*options.Option, run modules.Run) (modules.Module, error)
```

### Invoke Function

The `Invoke` function does the work of the module. Once the module has gathered, analyzed, or completed its processing, the results should be sent to the results channel. The data is read from the channel by the output providers and handled accordingly.

#### Results

Modules will typically have some results from their invocation. The results are returned by the module using a results channel which is automatically processed by the configured output providers. 

Once all results have been processed, the results channel must be closed or the module will hang.

```go
m.Run.Data <- m.MakeResult(output)
close(m.Run.Data)
```

To specify a file name, pass the option using the `WithFilename` option.

```go
m.Run.Data <- m.MakeResult(stack, modules.WithFilename(filepath))
```

**Note:** The results channel must be closed, if not the module will hang as the module runner is waiting for more data to be sent on the channel.



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

Modules will hang if the results channel is not closed. Add `defer close(m.Run.Data)` to your module to close the channel, otherwise explicitly close it when you're done.



## KNOWN ISSUES
If you see receive a `modules/recon/aws/foo_bar.go:1:1: expected 'package', found 'EOF'` when trying to run `go run main.go template -c recon -p aws -n FooBar > modules/recon/aws/foo_bar.go`, then you have to run `go build .` to build the binary and that should solve it. 