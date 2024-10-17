# Nebula

Nebula is a CLI tool for testing the offensive security of cloud services.

## Build

```shell
go build .
```

## Usage

Nebula's modules are broken into module families `analyze` and `recon`. Module details are documented in [docs](docs/nebula.md).

* [aws analyze](docs/nebula_aws_analyze.md)
* [aws recon](docs/nebula_aws_recon.md)

### Authentication to Cloud Providers

Nebula uses the cloud SDKs to connect to cloud providers. Configuring your environment in the same manner as the cloud provider CLI tooling will allow Nebula to use those credentials.

#### AWS

The `--profile` option is supported to use a specified profile in the `.aws/credentials` file. Otherwise, the default search order is used to identify credentials.