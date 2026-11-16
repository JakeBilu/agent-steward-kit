"""PreToolUse hook guard blocking direct agent edits to protected meta-files."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .config import StewardConfig, load_config


def extract_target_path(payload: dict[str, Any]) -> str:
    """Extract target file path from common agent hook payload schemas."""
    candidate_args: list[dict[str, Any]] = []
    tool_call = payload.get("toolCall")
    if isinstance(tool_call, dict) and isinstance(tool_call.get("args"), dict):
        candidate_args.append(tool_call["args"])
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        candidate_args.append(tool_input)
    if isinstance(payload.get("args"), dict):
        candidate_args.append(payload["args"])

    for args in candidate_args:
        for key in ("Path", "path", "TargetFile", "target_file", "filePath", "file_path"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return ""


def evaluate_tool_call(
    payload: dict[str, Any], config: StewardConfig | None = None
) -> dict[str, str]:
    """Return {'decision': 'deny'|'ask', ...} for a PreToolUse hook payload."""
    cfg = config or load_config()
    target_path = extract_target_path(payload)
    norm = target_path.replace("\\", "/")
    norm_lower = norm.lower()
    basename = os.path.basename(norm).lower()

    protected_names = {name.lower() for name in cfg.protected_meta_files}
    scope_tokens = [s.lower() for s in cfg.guard_scope_substrings if s.strip()]
    in_scope = True if not scope_tokens else any(tok in norm_lower for tok in scope_tokens)

    if in_scope and basename in protected_names:
        protected_list = " / ".join(cfg.protected_meta_files)
        return {
            "decision": "deny",
            "reason": (
                f"Blocked by agent-steward-kit: protected meta-files ({protected_list}) "
                "must not be directly edited by agents (multi-agent conflict rule)."
            ),
        }
    return {"decision": "ask"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PreToolUse protected-file guard hook")
    parser.add_argument("--config", help="Path to steward.toml")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        out = evaluate_tool_call(payload, cfg)
        print(json.dumps(out, ensure_ascii=False))
    except Exception:
        print('{"decision": "ask"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
