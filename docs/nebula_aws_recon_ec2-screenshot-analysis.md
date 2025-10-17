## nebula aws recon ec2-screenshot-analysis

Capture EC2 console screenshots and analyze them for sensitive information using Claude AI

```
nebula aws recon ec2-screenshot-analysis [flags]
```

### Options

```
      --analysis-prompt string         Custom analysis prompt (uses EC2-optimized default if not specified) (default "You are a security expert analyzing an AWS EC2 console screenshot for sensitive information exposure. This screenshot was automatically captured during a security assessment.\n\nANALYSIS FOCUS:\nExamine this EC2 console screenshot for any sensitive information that should not be visible in production environments.\n\nCRITICAL ITEMS TO DETECT:\n1. **Credentials & Secrets**:\n   - Passwords, passphrases, or authentication tokens visible on screen\n   - AWS access keys, secret keys, or temporary credentials\n   - API keys, tokens, or service account credentials\n   - Database connection strings or authentication details\n   - SSH private keys, certificates, or keypairs displayed in text\n   - OAuth tokens, JWT tokens, or session identifiers\n\n2. **AWS-Specific Information**:\n   - EC2 instance metadata service (IMDS) responses containing sensitive data\n   - User data scripts with embedded secrets or credentials\n   - Environment variables containing AWS keys or database passwords\n   - CloudFormation or Terraform output showing secrets\n   - AWS CLI configuration files with credentials\n   - IAM role assumption commands with sensitive parameters\n\n3. **System & Application Data**:\n   - Database hostnames, connection ports, schema names, or connection strings\n   - Service endpoints, internal URLs, or system paths\n   - Configuration files displaying credentials or sensitive parameters\n   - Log files showing authentication details or system internals\n   - Application console output containing API keys or tokens\n\n   **Note**: Do not flag standard IP addresses, VPC CIDRs, or basic network information as sensitive unless they're part of connection strings or credential contexts.\n\n4. **Infrastructure Secrets**:\n   - Container registry credentials or deployment keys\n   - CI/CD pipeline secrets, build tokens, or automation credentials\n   - SSL/TLS certificates, private keys, or security credentials\n   - Backup encryption keys or disaster recovery credentials\n   - Third-party service integration keys or webhooks\n\n5. **Personal & Business Data**:\n   - Personal Identifiable Information (PII) in logs or application output\n   - Financial information, payment details, or customer data\n   - Internal employee information, contact details, or org charts\n   - Business-sensitive data that should not be exposed\n\nEC2-SPECIFIC SECURITY CONCERNS:\n- Pay special attention to terminal windows showing AWS CLI commands\n- Look for EC2 instance connect sessions with visible authentication\n- Check for systems manager (SSM) session outputs containing credentials\n- Examine any displayed user data or bootstrap scripts\n- Review console logs that might contain sensitive startup information\n- Look for Docker containers or applications displaying environment variables\n\nRESPONSE FORMAT:\nRespond with a JSON object containing:\n{\n  \"sensitive_info_found\": boolean,\n  \"confidence_score\": float (0.0-1.0),\n  \"summary\": \"Brief description of findings or 'No sensitive information detected'\",\n  \"findings\": [\n    {\n      \"type\": \"aws_credential|api_key|password|secret|pii|financial|infrastructure|system_info\",\n      \"description\": \"Detailed description of what was found and why it's concerning\",\n      \"confidence\": float (0.0-1.0),\n      \"location\": \"Description of where in the screenshot it appears (top-left, terminal window, etc.)\",\n      \"severity\": \"low|medium|high|critical\"\n    }\n  ]\n}\n\nSEVERITY GUIDELINES:\n- Critical: AWS root credentials, production database passwords, or widespread system access\n- High: Service-specific API keys, database connections, or significant infrastructure access\n- Medium: Development credentials, internal URLs, or limited-scope secrets\n- Low: Non-sensitive system information or low-impact configuration details\n\nIf no sensitive information is detected, respond with \"sensitive_info_found\": false and provide a brief summary confirming the screenshot appears secure.")
      --anthropic-api-key string       Anthropic API key for Claude analysis (optional)
      --anthropic-model string         Claude model to use for analysis (default "claude-3-7-sonnet-latest")
      --cache-dir string               Directory to store API response cache files (default "/tmp/nebula-cache")
      --cache-error-resp               Cache error response
      --cache-error-resp-type string   A comma-separated list of strings specifying cache error response types, e.g., TypeNotFoundException, AccessDeniedException. Use all to represent any error.
      --cache-ext string               Name of AWS API response cache files extension (default ".aws-cache")
      --cache-ttl int                  TTL for cached responses in seconds (default 3600)
      --disable-cache                  Disable API response caching
  -h, --help                           help for ec2-screenshot-analysis
      --indent int                     the number of spaces to use for the JSON indentation
      --max-tokens int                 Maximum tokens for Claude response (default 1000)
      --module-name string             name of the module for dynamic file naming
      --opsec_level string             Operational security level for AWS operations (default "none")
      --outfile string                 the default file to write the JSON to (can be changed at runtime) (default "out.json")
  -o, --output string                  output directory (default "nebula-output")
  -p, --profile string                 AWS profile to use
      --profile-dir string             Set to override the default AWS profile directory
  -r, --regions strings                AWS regions to scan (default [all])
  -t, --resource-type strings          AWS Cloud Control resource type (default [all])
```

### SEE ALSO

* [nebula aws recon](nebula_aws_recon.md)	 - recon commands for aws

###### Auto generated by spf13/cobra
