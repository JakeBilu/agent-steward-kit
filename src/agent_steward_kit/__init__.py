"""Agent Steward Kit: deterministic hooks, atomic queues, vault sync, and anti-slop GC."""

from .atomic_queue import atomic_write_json, enqueue_payload, get_status, list_pending, mark_done
from .config import StewardConfig, load_config
from .pre_tool_guard import evaluate_tool_call, extract_target_path
from .session_digest import build_session_payload
from .slop_gc import run_gc
from .vault_sync import atomic_write_vault, build_digest, find_vault_root

__all__ = [
    "StewardConfig",
    "atomic_write_json",
    "atomic_write_vault",
    "build_digest",
    "build_session_payload",
    "enqueue_payload",
    "evaluate_tool_call",
    "extract_target_path",
    "find_vault_root",
    "get_status",
    "list_pending",
    "load_config",
    "mark_done",
    "run_gc",
]
__version__ = "0.1.0"
