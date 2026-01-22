from typing import Any

from strix.tools.registry import register_tool


@register_tool
def terminal_execute(
    command: str,
    is_input: bool = False,
    timeout: float | None = None,
    terminal_id: str | None = None,
    no_enter: bool = False,
) -> dict[str, Any]:
    """Execute shell commands in persistent terminal sessions.

    This tool provides full terminal access for running reconnaissance tools,
    executing exploits, and interacting with the target system. Supports
    multiple concurrent sessions and interactive command input.

    Args:
        command: The command or input to execute/send to the terminal
        is_input: If True, sends input to running command instead of executing new command
        timeout: Maximum time to wait for command output in seconds (None = wait indefinitely)
        terminal_id: Identifier for the terminal session (None = use default session)
        no_enter: If True, doesn't press Enter after sending the command (useful for prompts)

    Returns:
        dict containing:
            - content: Terminal output from the command
            - command: The command that was executed
            - terminal_id: The session identifier
            - status: Execution status ("success" or "error")
            - exit_code: Command exit code (if available)
            - working_dir: Current working directory in the session

    Example:
        # Execute a command
        terminal_execute("ls -la /tmp")

        # Send input to interactive command
        terminal_execute("yes", is_input=True)

        # Create new session
        terminal_execute("cd /opt && pwd", terminal_id="session2")
    """
    from .terminal_manager import get_terminal_manager

    manager = get_terminal_manager()

    try:
        return manager.execute_command(
            command=command,
            is_input=is_input,
            timeout=timeout,
            terminal_id=terminal_id,
            no_enter=no_enter,
        )
    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "command": command,
            "terminal_id": terminal_id or "default",
            "content": "",
            "status": "error",
            "exit_code": None,
            "working_dir": None,
        }
