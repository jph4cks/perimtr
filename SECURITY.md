# Security Policy

## Responsible Use

Perimtr is designed for **authorized security assessments only**. You must have explicit written permission to scan any network or domain. Unauthorized scanning may violate laws including the Computer Fraud and Abuse Act (CFAA) and equivalent legislation in other jurisdictions.

**Always:**
- Obtain written authorization before scanning any target
- Scope your scans to only authorized networks and domains
- Use rate limiting to avoid disrupting production services
- Store assessment data securely and limit access
- Follow your organization's security assessment policies

**Never:**
- Scan networks or domains without authorization
- Use findings to exploit vulnerabilities without permission
- Share assessment reports containing sensitive findings publicly
- Disable rate limiting against production systems

## Data Security

### Assessment Data

- All data is stored locally in JSON files under the configured `data_dir`
- No data is sent to external services unless LLM integration is configured
- Assessment files may contain sensitive information about your infrastructure
- Protect the `data/` directory with appropriate file permissions

### LLM Integration

When LLM integration is enabled:
- Assessment summaries (not raw data) are sent to the configured LLM provider
- API keys are stored in the local `perimtr.yaml` configuration file
- Protect your configuration file — it may contain API keys
- Consider using environment variables for API keys in production
- Review your LLM provider's data retention and privacy policies

### Configuration Security

- The `perimtr.yaml` file may contain API keys and network information
- Set appropriate file permissions: `chmod 600 perimtr.yaml`
- Do not commit configuration files with API keys to version control
- Use `.gitignore` to exclude `perimtr.yaml` and `data/` from repositories

## Reporting Vulnerabilities

If you discover a security vulnerability in Perimtr itself, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email security findings to: japd06@gmail.com
3. Include a description of the vulnerability and steps to reproduce
4. Allow reasonable time for a fix before public disclosure

## Dependencies

Perimtr relies on several third-party libraries. We recommend:

- Keeping dependencies up to date (`pip install --upgrade`)
- Reviewing dependency security advisories regularly
- Using virtual environments to isolate the tool

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
