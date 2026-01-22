# Nuclei Template-Based Vulnerability Scanning

## Overview
Use the `nuclei_scan` tool for fast, template-based vulnerability scanning. Nuclei excels at detecting CVEs, misconfigurations, exposed services, and security issues across web applications and infrastructure.

## When to Use Nuclei

### Primary Use Cases
- **CVE Detection**: Scan for known vulnerabilities (CVEs) in web applications and services
- **Exposed Panels**: Discover admin panels, dashboards, and login pages
- **Misconfigurations**: Identify security misconfigurations in web servers and applications
- **Technology Detection**: Fingerprint technologies and versions running on target
- **Exposed Data**: Find exposed sensitive files, backups, and configuration files
- **Default Credentials**: Test for default/weak credentials on common services

### When NOT to Use Nuclei
- Deep application logic testing (use manual testing or specialized tools)
- Authenticated scanning beyond default credentials (use proxy/browser tools)
- Binary analysis or reverse engineering (use other tools)

## Usage Patterns

### 1. Initial Reconnaissance - Technology Detection
Start by identifying what technologies are running:
```
nuclei_scan(
    target="https://target.com",
    scan_type="technologies"
)
```

### 2. CVE Scanning - High Priority Vulnerabilities
After identifying technologies, scan for known CVEs:
```
nuclei_scan(
    target="https://target.com",
    scan_type="cve",
    severity="critical,high"
)
```

### 3. Configuration Issues
Check for common misconfigurations:
```
nuclei_scan(
    target="https://target.com",
    scan_type="misconfigurations",
    severity="high,medium"
)
```

### 4. Exposed Panels and Services
Discover hidden admin panels and dashboards:
```
nuclei_scan(
    target="https://target.com",
    scan_type="exposed_panels"
)
```

### 5. Sensitive Data Exposure
Look for exposed files and data:
```
nuclei_scan(
    target="https://target.com",
    scan_type="exposures",
    tags="config,backup,git"
)
```

### 6. Comprehensive Vulnerability Scan
Run a broad vulnerability scan:
```
nuclei_scan(
    target="https://target.com",
    scan_type="vulnerabilities",
    severity="critical,high,medium"
)
```

## Advanced Usage

### Targeted Scanning with Tags
Use tags to focus on specific vulnerability types:
```
nuclei_scan(
    target="https://api.target.com",
    scan_type="vulnerabilities",
    tags="sqli,xss,rce,ssrf"
)
```

### API Security Testing
Target API endpoints:
```
nuclei_scan(
    target="https://api.target.com",
    scan_type="vulnerabilities",
    tags="api,graphql,swagger,openapi"
)
```

### Rate Limiting for Stealthy Scanning
Reduce scan speed to avoid detection:
```
nuclei_scan(
    target="https://target.com",
    scan_type="cve",
    rate_limit=50  # Lower rate = more stealthy
)
```

## Interpreting Results

### Result Structure
Each finding includes:
- **Template ID**: Identifies the specific vulnerability template
- **Info**: Metadata including name, severity, description, tags
- **Matcher Status**: Whether the vulnerability was confirmed
- **Extracted Results**: Any data extracted from the target
- **CURL Command**: Request that triggered the finding
- **Request/Response**: Full HTTP request and response

### Severity Levels
- **Critical**: Immediate action required (RCE, SQLi, etc.)
- **High**: Significant security risk (authentication bypass, XSS, etc.)
- **Medium**: Notable security concerns (information disclosure, etc.)
- **Low**: Minor issues or hardening recommendations
- **Info**: Informational findings (version detection, etc.)

### Summary Analysis
The tool provides a summary with counts by severity:
```
{
    "summary": {
        "critical": 2,
        "high": 5,
        "medium": 8,
        "low": 3,
        "info": 12
    },
    "total_findings": 30
}
```

## Best Practices

### 1. Start Broad, Then Narrow
Begin with technology detection and general scans, then focus on specific vulnerabilities.

### 2. Respect Rate Limits
Use appropriate rate limiting to avoid overwhelming targets or triggering WAFs.

### 3. Filter by Severity
Focus on critical and high severity findings first:
```
nuclei_scan(target="https://target.com", scan_type="cve", severity="critical,high")
```

### 4. Combine with Other Tools
- Use Nuclei for broad scanning
- Use browser/proxy tools for deeper manual testing of findings
- Use terminal tools for exploiting discovered vulnerabilities

### 5. Scan Progressively
```
# Step 1: Technology detection
nuclei_scan(target="https://target.com", scan_type="technologies")

# Step 2: CVE scanning based on detected tech
nuclei_scan(target="https://target.com", scan_type="cve", severity="critical,high")

# Step 3: Configuration checks
nuclei_scan(target="https://target.com", scan_type="misconfigurations")

# Step 4: Exposed services/panels
nuclei_scan(target="https://target.com", scan_type="exposed_panels")
```

## Common Scan Types by Phase

### Discovery Phase
- `scan_type="technologies"` - Fingerprint tech stack
- `scan_type="exposures"` - Find exposed data/files

### Vulnerability Assessment Phase
- `scan_type="cve"` - Known vulnerabilities
- `scan_type="vulnerabilities"` - General security issues
- `scan_type="misconfigurations"` - Config problems

### Exploitation Preparation
- `scan_type="default_logins"` - Test default creds
- `scan_type="exposed_panels"` - Find entry points

## Error Handling

### Nuclei Not Installed
If you get an installation error, inform the user:
"Nuclei is not installed. It can be installed with: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`"

### Timeouts
For large scans that timeout, recommend:
- Reducing scope (fewer scan types)
- Increasing timeout parameter
- Using more specific templates/tags

### No Findings
If no findings are returned:
- Try different scan types
- Check if target is accessible
- Verify target URL format
- Consider if target may have security measures blocking scans

## Integration with Workflow

Nuclei fits into the security testing workflow as:
1. **Post-Reconnaissance**: After identifying targets with other tools
2. **Pre-Manual Testing**: Before deep-dive manual analysis
3. **Validation**: Confirming potential issues found by other means
4. **Broad Coverage**: Ensuring common vulnerabilities aren't missed

## Notes
- Nuclei requires network access to the target
- Some templates may trigger WAFs or IDS systems
- Always respect scope and rules of engagement
- Nuclei templates are regularly updated; keep installation current
