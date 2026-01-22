import os

from strix.config import Config

from .executor import (
    execute_tool,
    execute_tool_invocation,
    execute_tool_with_validation,
    extract_screenshot_from_result,
    process_tool_invocations,
    remove_screenshot_from_result,
    validate_tool_availability,
)
from .registry import (
    ImplementedInClientSideOnlyError,
    get_tool_by_name,
    get_tool_names,
    get_tools_prompt,
    needs_agent_state,
    register_tool,
    tools,
)


SANDBOX_MODE = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"

HAS_PERPLEXITY_API = bool(Config.get("perplexity_api_key"))

DISABLE_BROWSER = (Config.get("strix_disable_browser") or "false").lower() == "true"

if not SANDBOX_MODE:
    from .agents_graph import (
        agent_finish,
        create_agent,
        send_message_to_agent,
        view_agent_graph,
        wait_for_message,
    )

    if not DISABLE_BROWSER:
        from .browser import browser_action
    from .file_edit import list_files, search_files, str_replace_editor
    from .finish import finish_scan
    from .notes import create_note, delete_note, list_notes, update_note
    from .nuclei import nuclei_scan
    from .proxy import (
        list_requests,
        list_sitemap,
        repeat_request,
        scope_rules,
        send_request,
        view_request,
        view_sitemap_entry,
    )
    from .python import python_action
    from .reporting import create_vulnerability_report
    from .terminal import terminal_execute
    from .thinking import think
    from .todo import (
        create_todo,
        delete_todo,
        list_todos,
        mark_todo_done,
        mark_todo_pending,
        update_todo,
    )

    if HAS_PERPLEXITY_API:
        from .web_search import web_search
else:
    if not DISABLE_BROWSER:
        from .browser import browser_action
    from .file_edit import list_files, search_files, str_replace_editor
    from .proxy import (
        list_requests,
        list_sitemap,
        repeat_request,
        scope_rules,
        send_request,
        view_request,
        view_sitemap_entry,
    )
    from .python import python_action
    from .terminal import terminal_execute

__all__ = [
    "ImplementedInClientSideOnlyError",
    "execute_tool",
    "execute_tool_invocation",
    "execute_tool_with_validation",
    "extract_screenshot_from_result",
    "get_tool_by_name",
    "get_tool_names",
    "get_tools_prompt",
    "needs_agent_state",
    "process_tool_invocations",
    "register_tool",
    "remove_screenshot_from_result",
    "tools",
    "validate_tool_availability",
]
