"""Configuration loader for agent-steward-kit."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class StewardConfig:
    """Centralized configuration loaded from steward.toml or defaults."""

    # Vault settings
    vault_root: str = ""
    vault_env_var: str = "STEWARD_VAULT_ROOT"
    vault_marker_file: str = "AGENT_ONBOARDING.md"
    vault_relative_candidates: list[str] = field(
        default_factory=lambda: ["Obsidian Vault", "Documents/Obsidian Vault"]
    )
    vault_drive_letters: list[str] = field(
        default_factory=lambda: [chr(c) for c in range(ord("D"), ord("Z") + 1)]
    )
    protected_meta_files: list[str] = field(
        default_factory=lambda: [
            "KNOWLEDGE_INDEX.md",
            "AGENT_ONBOARDING.md",
            "TEAM_RULES.md",
        ]
    )
    protected_vault_dirs: list[str] = field(
        default_factory=lambda: [".obsidian", ".trash", ".git"]
    )

    # Guard settings
    guard_scope_substrings: list[str] = field(default_factory=lambda: ["vault"])

    # Queue / consolidation settings
    state_dir: str = "./.steward_state"
    session_tag: str = "[STEWARD_CONSOLIDATION_SESSION]"
    min_delta_bytes: int = 256
    head_scan_bytes: int = 8192

    # Garbage collector settings
    ttl_days: int = 14
    tmp_hours: float = 24.0
    pycache_days: int = 7
    large_dir_mb: int = 500
    scratch_roots: list[str] = field(default_factory=list)
    task_copy_roots: list[str] = field(default_factory=list)
    pycache_dirs: list[str] = field(default_factory=list)
    protected_scratch_names: list[str] = field(default_factory=list)
    gc_receipt_file: str = "./.steward_state/last_gc_receipt.json"

    # SessionStart digest settings
    digest_max_chars: int = 1750
    pending_items_file: str = ""


def _expand_path(raw: str) -> str:
    if not raw:
        return ""
    return os.path.expanduser(os.path.expandvars(raw))


def load_config(config_path: str | Path | None = None) -> StewardConfig:
    """Load StewardConfig from explicit TOML path, STEWARD_CONFIG env, or defaults."""
    cfg = StewardConfig()
    resolved: Path | None = None

    if config_path is not None:
        resolved = Path(config_path)
        if not resolved.is_file():
            raise FileNotFoundError(f"Config file not found: {resolved}")
    else:
        env_cfg = os.environ.get("STEWARD_CONFIG", "").strip()
        if env_cfg:
            cand = Path(_expand_path(env_cfg))
            if cand.is_file():
                resolved = cand
        elif Path("steward.toml").is_file():
            resolved = Path("steward.toml")

    if resolved is None:
        return cfg

    data: dict[str, Any] = tomllib.loads(resolved.read_text(encoding="utf-8"))

    vault = data.get("vault", {})
    if isinstance(vault, dict):
        if "root" in vault:
            cfg.vault_root = _expand_path(str(vault["root"]))
        if "env_var" in vault:
            cfg.vault_env_var = str(vault["env_var"])
        if "marker_file" in vault:
            cfg.vault_marker_file = str(vault["marker_file"])
        if "relative_candidates" in vault:
            cfg.vault_relative_candidates = [str(x) for x in vault["relative_candidates"]]
        if "drive_letters" in vault:
            cfg.vault_drive_letters = [str(x).upper() for x in vault["drive_letters"]]
        if "protected_meta_files" in vault:
            cfg.protected_meta_files = [str(x) for x in vault["protected_meta_files"]]
        if "protected_dirs" in vault:
            cfg.protected_vault_dirs = [str(x) for x in vault["protected_dirs"]]

    guard = data.get("guard", {})
    if isinstance(guard, dict):
        if "scope_substrings" in guard:
            cfg.guard_scope_substrings = [str(x).lower() for x in guard["scope_substrings"]]
        if "protected_meta_files" in guard:
            cfg.protected_meta_files = [str(x) for x in guard["protected_meta_files"]]

    queue = data.get("queue", {})
    if isinstance(queue, dict):
        if "state_dir" in queue:
            cfg.state_dir = _expand_path(str(queue["state_dir"]))
        if "session_tag" in queue:
            cfg.session_tag = str(queue["session_tag"])
        if "min_delta_bytes" in queue:
            cfg.min_delta_bytes = int(queue["min_delta_bytes"])

    gc = data.get("gc", {})
    if isinstance(gc, dict):
        if "ttl_days" in gc:
            cfg.ttl_days = int(gc["ttl_days"])
        if "tmp_hours" in gc:
            cfg.tmp_hours = float(gc["tmp_hours"])
        if "pycache_days" in gc:
            cfg.pycache_days = int(gc["pycache_days"])
        if "large_dir_mb" in gc:
            cfg.large_dir_mb = int(gc["large_dir_mb"])
        if "scratch_roots" in gc:
            cfg.scratch_roots = [_expand_path(str(x)) for x in gc["scratch_roots"]]
        if "task_copy_roots" in gc:
            cfg.task_copy_roots = [_expand_path(str(x)) for x in gc["task_copy_roots"]]
        if "pycache_dirs" in gc:
            cfg.pycache_dirs = [_expand_path(str(x)) for x in gc["pycache_dirs"]]
        if "protected_scratch_names" in gc:
            cfg.protected_scratch_names = [str(x).lower() for x in gc["protected_scratch_names"]]
        if "receipt_file" in gc:
            cfg.gc_receipt_file = _expand_path(str(gc["receipt_file"]))

    session = data.get("session", {})
    if isinstance(session, dict):
        if "digest_max_chars" in session:
            cfg.digest_max_chars = int(session["digest_max_chars"])
        if "pending_items_file" in session:
            cfg.pending_items_file = _expand_path(str(session["pending_items_file"]))

    return cfg
