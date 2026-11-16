"""SessionStart hook injecting a compact Vault catchup and optional pending digest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import vault_sync
from .config import StewardConfig, load_config


def _load_pending_items(config: StewardConfig) -> list[dict[str, Any]]:
    if not config.pending_items_file:
        return []
    p = Path(config.pending_items_file)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return [x for x in data["items"] if isinstance(x, dict)]
    except Exception:
        pass
    return []


def build_session_payload(config: StewardConfig | None = None) -> dict[str, Any]:
    """Construct the SessionStart injectSteps JSON payload."""
    cfg = config or load_config()
    digest = vault_sync.build_digest(max_chars=cfg.digest_max_chars, config=cfg)

    pending = _load_pending_items(cfg)
    if pending:
        lines = [f"\n[Pending Patrol] Count={len(pending)}"]
        for it in pending[:3]:
            src = it.get("source", "patrol")
            summary = it.get("summary", "")
            lines.append(f"  - [{src}] {summary}")
        combined = digest + "\n" + "\n".join(lines)
        digest = combined[: cfg.digest_max_chars + 400]

    return {
        "injectSteps": [
            {
                "systemMessage": {
                    "systemMessage": digest,
                }
            }
        ]
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SessionStart digest hook")
    parser.add_argument("--config", help="Path to steward.toml")
    args = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty():
            sys.stdin.read()
        cfg = load_config(args.config)
        print(json.dumps(build_session_payload(cfg), ensure_ascii=False))
    except Exception:
        print("{}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
