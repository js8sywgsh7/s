from typing import Any, Literal

from strix.tools.registry import register_tool


PythonAction = Literal["new_session", "execute", "close", "list_sessions"]


@register_tool
def python_action(
    action: PythonAction,
    code: str | None = None,
    timeout: int = 30,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Execute Python code in isolated sessions for testing and exploitation.

    This tool allows agents to run Python code in persistent sessions, enabling
    multi-step attacks, custom exploit development, and data processing.

    Args:
        action: The action to perform:
            - "new_session": Create a new Python session
            - "execute": Run code in an existing or new session
            - "close": Terminate a session
            - "list_sessions": List all active sessions
        code: Python code to execute (required for "new_session" and "execute" actions)
        timeout: Maximum execution time in seconds (default: 30)
        session_id: Identifier for the session (optional, auto-generated if not provided)

    Returns:
        dict containing:
            - stdout: Standard output from code execution
            - stderr: Standard error from code execution
            - session_id: The session identifier
            - is_running: Whether the session is still active

    Raises:
        ValueError: If action is invalid or required parameters are missing
    """
    from .python_manager import get_python_session_manager

    def _validate_code(action_name: str, code: str | None) -> None:
        if not code:
            raise ValueError(f"code parameter is required for {action_name} action")

    def _validate_action(action_name: str) -> None:
        raise ValueError(f"Unknown action: {action_name}")

    manager = get_python_session_manager()

    try:
        match action:
            case "new_session":
                return manager.create_session(session_id, code, timeout)

            case "execute":
                _validate_code(action, code)
                # _validate_code raises ValueError if code is None, so it's guaranteed non-None
                return manager.execute_code(session_id, code, timeout)  # type: ignore[arg-type]

            case "close":
                return manager.close_session(session_id)

            case "list_sessions":
                return manager.list_sessions()

            case _:
                _validate_action(action)  # type: ignore[unreachable]

    except (ValueError, RuntimeError) as e:
        return {"stderr": str(e), "session_id": session_id, "stdout": "", "is_running": False}
