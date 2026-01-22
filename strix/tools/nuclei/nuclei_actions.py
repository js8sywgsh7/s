from typing import Any, Literal
import subprocess
import json
from pathlib import Path

from strix.tools.registry import register_tool


NucleiScanType = Literal[
    "vulnerabilities",
    "cve",
    "exposed_panels",
    "misconfigurations",
    "exposures",
    "technologies",
    "default_logins",
    "takeovers",
]


@register_tool
def nuclei_scan(
    target: str,
    scan_type: NucleiScanType = "vulnerabilities",
    severity: str | None = None,
    tags: str | None = None,
    templates: str | None = None,
    rate_limit: int = 150,
    timeout: int = 600,
) -> dict[str, Any]:
    """Execute Nuclei template-based vulnerability scans for comprehensive security testing.

    Nuclei is a fast and customizable vulnerability scanner based on simple YAML templates.
    It enables security teams to scan for a wide variety of security issues including CVEs,
    misconfigurations, exposed panels, and more.

    Args:
        target: Target URL or host to scan (e.g., "https://example.com" or "example.com")
        scan_type: Category of templates to use:
            - "vulnerabilities": General vulnerability templates
            - "cve": CVE-specific templates (known vulnerabilities)
            - "exposed_panels": Admin panels, dashboards, login pages
            - "misconfigurations": Security misconfigurations
            - "exposures": Exposed sensitive files and data
            - "technologies": Technology detection and fingerprinting
            - "default_logins": Default credentials testing
            - "takeovers": Subdomain takeover detection
        severity: Filter by severity level (comma-separated: "critical,high,medium,low,info")
        tags: Filter by specific tags (comma-separated, e.g., "xss,sqli,rce")
        templates: Path to custom template directory or specific template file
        rate_limit: Maximum requests per second (default: 150)
        timeout: Maximum scan time in seconds (default: 600)

    Returns:
        dict containing:
            - findings: List of discovered vulnerabilities with details
            - summary: Count of findings by severity
            - output: Raw scan output
            - target: Target that was scanned
            - scan_type: Type of scan performed
            - exit_code: Command exit code
            - error: Error message (if failed)

    Example:
        # Scan for CVEs with high/critical severity
        nuclei_scan(
            target="https://example.com",
            scan_type="cve",
            severity="critical,high"
        )

        # Scan for exposed panels
        nuclei_scan(
            target="https://example.com",
            scan_type="exposed_panels"
        )

        # Custom templates with specific tags
        nuclei_scan(
            target="https://api.example.com",
            scan_type="vulnerabilities",
            tags="api,graphql,swagger"
        )
    """
    # Build nuclei command
    cmd = ["nuclei", "-u", target, "-json"]

    # Add scan type specific templates
    scan_type_mapping = {
        "vulnerabilities": ["-t", "vulnerabilities/"],
        "cve": ["-t", "cves/"],
        "exposed_panels": ["-t", "exposed-panels/"],
        "misconfigurations": ["-t", "misconfigurations/"],
        "exposures": ["-t", "exposures/"],
        "technologies": ["-t", "technologies/"],
        "default_logins": ["-t", "default-logins/"],
        "takeovers": ["-t", "takeovers/"],
    }

    if scan_type in scan_type_mapping:
        cmd.extend(scan_type_mapping[scan_type])

    # Add custom templates if specified
    if templates:
        cmd.extend(["-t", templates])

    # Add severity filter
    if severity:
        cmd.extend(["-s", severity])

    # Add tags filter
    if tags:
        cmd.extend(["-tags", tags])

    # Add rate limiting
    cmd.extend(["-rl", str(rate_limit)])

    # Add silent mode to reduce output noise
    cmd.append("-silent")

    try:
        # Execute nuclei with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        # Parse JSON output
        findings = []
        output_lines = result.stdout.strip().split("\n")

        for line in output_lines:
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except json.JSONDecodeError:
                    # Skip non-JSON lines
                    continue

        # Generate summary
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity_level = finding.get("info", {}).get("severity", "info").lower()
            if severity_level in summary:
                summary[severity_level] += 1

        return {
            "findings": findings,
            "summary": summary,
            "total_findings": len(findings),
            "output": result.stdout,
            "target": target,
            "scan_type": scan_type,
            "exit_code": result.returncode,
            "error": result.stderr if result.returncode != 0 else None,
        }

    except subprocess.TimeoutExpired:
        return {
            "findings": [],
            "summary": {},
            "total_findings": 0,
            "output": "",
            "target": target,
            "scan_type": scan_type,
            "exit_code": -1,
            "error": f"Scan timed out after {timeout} seconds",
        }
    except FileNotFoundError:
        return {
            "findings": [],
            "summary": {},
            "total_findings": 0,
            "output": "",
            "target": target,
            "scan_type": scan_type,
            "exit_code": -1,
            "error": "Nuclei is not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        }
    except (PermissionError, OSError) as e:
        return {
            "findings": [],
            "summary": {},
            "total_findings": 0,
            "output": "",
            "target": target,
            "scan_type": scan_type,
            "exit_code": -1,
            "error": f"Failed to execute nuclei: {str(e)}",
        }
