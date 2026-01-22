# Adding External Security Tools to Strix

This guide explains how to integrate external security tools (like Nmap, SQLMap, custom scripts, etc.) into Strix so AI agents can use them during security assessments.

## Overview

Strix uses a **tool registry pattern** where each tool is registered with metadata describing its capabilities. The AI uses this metadata to decide when and how to invoke tools.

## Quick Start: Adding a Simple Tool

### 1. Create a Tool Module

Create a new directory in `strix/tools/` for your tool:

```bash
mkdir strix/tools/nmap
touch strix/tools/nmap/__init__.py
touch strix/tools/nmap/nmap_actions.py
```

### 2. Implement the Tool Action

In `strix/tools/nmap/nmap_actions.py`:

```python
from typing import Any, Literal
from strix.tools.registry import register_tool
import subprocess
import json

NmapScanType = Literal["port_scan", "service_scan", "os_detection", "vuln_scan"]


@register_tool
def nmap_scan(
    target: str,
    scan_type: NmapScanType = "port_scan",
    ports: str | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """Execute Nmap scans for network reconnaissance and vulnerability discovery.

    This tool provides comprehensive network scanning capabilities including
    port discovery, service enumeration, OS detection, and vulnerability scanning.

    Args:
        target: Target host or network (IP, hostname, or CIDR notation)
        scan_type: Type of scan to perform:
            - "port_scan": Fast SYN scan of common ports
            - "service_scan": Detailed service/version detection
            - "os_detection": Operating system fingerprinting
            - "vuln_scan": Vulnerability scanning with NSE scripts
        ports: Port specification (e.g., "80,443" or "1-1000", None = default ports)
        timeout: Maximum scan time in seconds (default: 300)

    Returns:
        dict containing:
            - output: Scan results in text format
            - json_output: Parsed JSON results (if available)
            - exit_code: Command exit code
            - error: Error message (if failed)

    Example:
        # Quick port scan
        nmap_scan(target="192.168.1.1", scan_type="port_scan")

        # Detailed service scan on specific ports
        nmap_scan(target="example.com", scan_type="service_scan", ports="80,443,8080")

        # Vulnerability scan
        nmap_scan(target="192.168.1.0/24", scan_type="vuln_scan")
    """
    # Build nmap command based on scan type
    cmd = ["nmap"]
    
    # Add scan type specific flags
    if scan_type == "port_scan":
        cmd.extend(["-sS", "-F"])  # SYN scan, fast mode
    elif scan_type == "service_scan":
        cmd.extend(["-sV", "-sC"])  # Service detection + default scripts
    elif scan_type == "os_detection":
        cmd.extend(["-O", "-sV"])  # OS detection + service detection
    elif scan_type == "vuln_scan":
        cmd.extend(["--script", "vuln", "-sV"])  # Vulnerability scripts
    
    # Add port specification
    if ports:
        cmd.extend(["-p", ports])
    
    # Add output format and target
    cmd.extend(["-oX", "-", target])  # XML output to stdout
    
    try:
        # Execute nmap with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Don't raise on non-zero exit
        )
        
        # Parse results
        return {
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "exit_code": result.returncode,
            "scan_type": scan_type,
            "target": target,
        }
        
    except subprocess.TimeoutExpired:
        return {
            "output": "",
            "error": f"Scan timed out after {timeout} seconds",
            "exit_code": -1,
            "scan_type": scan_type,
            "target": target,
        }
    except (FileNotFoundError, PermissionError) as e:
        return {
            "output": "",
            "error": f"Failed to execute nmap: {str(e)}. Ensure nmap is installed and accessible.",
            "exit_code": -1,
            "scan_type": scan_type,
            "target": target,
        }
```

### 3. Export the Tool

In `strix/tools/nmap/__init__.py`:

```python
from .nmap_actions import nmap_scan

__all__ = ["nmap_scan"]
```

### 4. Register in Main Tools Module

Add your tool to `strix/tools/__init__.py`:

```python
# Add at the appropriate location based on SANDBOX_MODE
if not SANDBOX_MODE:
    from .nmap import nmap_scan
    # ... other imports
```

Also add to `__all__`:

```python
__all__ = [
    # ... existing exports
    "nmap_scan",
]
```

## Advanced Integration

### Tool with State Management

For tools that need persistent state (like sessions):

```python
from strix.tools.registry import register_tool

class ToolManager:
    def __init__(self):
        self._sessions = {}
    
    def create_session(self, session_id: str | None = None):
        # Session management logic
        pass
    
    def execute_in_session(self, session_id: str, command: str):
        # Execution logic
        pass

# Global manager instance
_manager = None

def get_tool_manager() -> ToolManager:
    global _manager
    if _manager is None:
        _manager = ToolManager()
    return _manager

@register_tool
def my_tool_action(action: str, **kwargs):
    manager = get_tool_manager()
    # Use manager for stateful operations
    return manager.execute_in_session(**kwargs)
```

### Tool with Docker Container

For tools that need isolated environments:

```python
import docker
from strix.tools.registry import register_tool

@register_tool
def container_tool_action(target: str, options: dict[str, Any]):
    """Execute tool in Docker container for isolation."""
    client = docker.from_env()
    
    try:
        container = client.containers.run(
            image="tool-image:latest",
            command=f"tool-command {target}",
            detach=False,
            remove=True,
            network_mode="host",
        )
        
        return {
            "output": container.decode("utf-8"),
            "exit_code": 0,
        }
    except docker.errors.ContainerError as e:
        return {
            "output": "",
            "error": str(e),
            "exit_code": e.exit_status,
        }
```

### Adding Tool Skills/Prompts

To help the AI understand when and how to use your tool, create a skill file in `strix/skills/`:

Create `strix/skills/nmap.md`:

```markdown
# Nmap Network Scanning

## Overview
Use the `nmap_scan` tool for network reconnaissance, port discovery, service enumeration, and vulnerability scanning.

## When to Use
- **Port Scanning**: Discover open ports on target systems
- **Service Detection**: Identify running services and versions
- **OS Fingerprinting**: Determine target operating system
- **Vulnerability Scanning**: Find known vulnerabilities in services

## Usage Patterns

### Initial Reconnaissance
Start with a quick port scan to identify attack surface:
\`\`\`
nmap_scan(target="192.168.1.1", scan_type="port_scan")
\`\`\`

### Service Enumeration
After finding open ports, enumerate services:
\`\`\`
nmap_scan(target="192.168.1.1", scan_type="service_scan", ports="80,443,22")
\`\`\`

### Vulnerability Discovery
Scan for known vulnerabilities:
\`\`\`
nmap_scan(target="192.168.1.1", scan_type="vuln_scan", ports="80,443")
\`\`\`

## Best Practices
1. Start with fast scans to avoid detection
2. Use service detection to identify vulnerable versions
3. Combine with other tools for comprehensive assessment
4. Always respect scope and permissions
```

## Tool Integration Checklist

- [ ] Tool action function implemented with proper type hints
- [ ] Comprehensive docstring with parameters and examples
- [ ] Error handling for common failures (timeout, not installed, permission denied)
- [ ] Return consistent dictionary structure
- [ ] Tool exported in module `__init__.py`
- [ ] Tool registered in main `strix/tools/__init__.py`
- [ ] Skill/documentation added to `strix/skills/`
- [ ] Tool respects security boundaries and permissions
- [ ] Input validation and sanitization implemented
- [ ] Timeout and resource limits configured

## Common Security Tools to Add

Here are some popular security tools you might want to integrate:

- **SQLMap**: SQL injection exploitation
- **Nuclei**: Template-based vulnerability scanning
- **FFuf**: Web fuzzing and directory brute forcing
- **Gobuster**: Directory/DNS brute forcing
- **WPScan**: WordPress vulnerability scanning
- **Nikto**: Web server scanning
- **Metasploit**: Exploitation framework integration
- **Hashcat**: Password cracking
- **John the Ripper**: Password cracking
- **Hydra**: Network authentication brute forcing
- **Recon-ng**: Reconnaissance framework
- **theHarvester**: OSINT gathering
- **Sublist3r**: Subdomain enumeration
- **Amass**: Attack surface mapping

## Tool Architecture

```
strix/tools/
├── your_tool/
│   ├── __init__.py          # Exports tool functions
│   ├── tool_actions.py      # Main tool implementation
│   ├── tool_manager.py      # State management (if needed)
│   └── tool_parser.py       # Output parsing (if needed)
└── ...

strix/skills/
└── your_tool.md             # AI guidance for using the tool
```

## Testing Your Tool

Create tests in `tests/tools/test_your_tool.py`:

```python
import pytest
from strix.tools.your_tool import your_tool_action

def test_basic_execution():
    result = your_tool_action(target="example.com")
    assert "output" in result
    assert result["exit_code"] == 0

def test_error_handling():
    result = your_tool_action(target="invalid-target")
    assert "error" in result
    assert result["exit_code"] != 0
```

## Additional Resources

- [Strix Tool Registry](../strix/tools/registry.py) - Tool registration system
- [Existing Tools](../strix/tools/) - Reference implementations
- [Skills Directory](../strix/skills/) - AI guidance examples
