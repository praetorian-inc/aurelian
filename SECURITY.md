# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Aurelian, please report it responsibly.

### How to Report

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via one of these methods:

1. **Email**: Send details to security@praetorian.com
2. **Private Disclosure**: Use GitHub's [private vulnerability reporting](https://github.com/praetorian-inc/aurelian/security/advisories/new)

### What to Include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Based on severity (Critical: 7 days, High: 30 days, Medium: 90 days)

### Scope

This security policy applies to:

- The Aurelian CLI tool
- Cloud reconnaissance modules
- Documentation and examples

### Recognition

We appreciate responsible disclosure and will acknowledge security researchers who help improve Aurelian's security (with your permission) in our release notes.

## Security Best Practices

When using Aurelian:

1. **Credential Security**: Use least-privilege cloud credentials scoped to read-only access where possible
2. **Authorization**: Only run Aurelian against cloud environments you own or have explicit authorization to assess
3. **Output Handling**: Treat scan results as sensitive — they may contain cloud resource details, configurations, and potential weaknesses
4. **Environment Isolation**: Run Aurelian in isolated environments when integrating into CI/CD pipelines
