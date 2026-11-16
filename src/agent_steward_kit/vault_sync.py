"""Config-driven Markdown Vault locator, digest builder, and SHA-256 verified atomic writer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .config import StewardConfig, load_config

DATE_FILE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.md$")


def find_vault_root(config: StewardConfig | None = None) -> Path | None:
    """Resolve the local Vault root via env override, config path, home candidates, or Windows drives."""
    cfg = config or load_config()
    env_override = os.environ.get(cfg.vault_env_var, "").strip()
    if env_override:
        p = Path(os.path.expanduser(env_override))
        if p.is_dir() and (not cfg.vault_marker_file or (p / cfg.vault_marker_file).is_file()):
            return p

    if cfg.vault_root:
        p = Path(cfg.vault_root)
        if p.is_dir() and (not cfg.vault_marker_file or (p / cfg.vault_marker_file).is_file()):
            return p

    home = Path.home()
    for rel in cfg.vault_relative_candidates:
        cand = home / rel
        if cand.is_dir() and (not cfg.vault_marker_file or (cand / cfg.vault_marker_file).is_file()):
            return cand

    if os.name == "nt":
        for letter in cfg.vault_drive_letters:
            drive_root = f"{letter}:\\"
            if not os.path.exists(drive_root):
                continue
            for rel in cfg.vault_relative_candidates:
                cand = Path(drive_root) / rel
                if cand.is_dir() and (not cfg.vault_marker_file or (cand / cfg.vault_marker_file).is_file()):
                    return cand
    return None


def _latest_dated_file(folder: Path) -> Path | None:
    if not folder.is_dir():
        return None
    dated = [p for p in folder.iterdir() if p.is_file() and DATE_FILE_RE.match(p.name)]
    if not dated:
        return None
    dated.sort(key=lambda p: p.name, reverse=True)
    return dated[0]


def get_status(config: StewardConfig | None = None) -> dict[str, Any]:
    """Return resolved vault path and latest daily/decisions filenames."""
    cfg = config or load_config()
    root = find_vault_root(cfg)
    if not root:
        return {
            "mounted": False,
            "vault_root": None,
            "latest_daily": None,
            "latest_decision": None,
        }
    latest_daily = _latest_dated_file(root / "daily")
    latest_dec = _latest_dated_file(root / "decisions")
    return {
        "mounted": True,
        "vault_root": str(root),
        "latest_daily": latest_daily.name if latest_daily else None,
        "latest_decision": latest_dec.name if latest_dec else None,
    }


def is_protected_meta(rel_path: str, config: StewardConfig | None = None) -> bool:
    """Check whether a vault-relative path targets a protected shared meta-file."""
    cfg = config or load_config()
    protected = {name.lower() for name in cfg.protected_meta_files}
    norm = rel_path.replace("\\", "/").strip("/")
    return norm.lower() in protected or Path(norm).name.lower() in protected


def atomic_write_vault(
    rel_path: str, content: str, config: StewardConfig | None = None
) -> dict[str, Any]:
    """Write via local temp file, copy to Vault, and verify SHA-256 readback."""
    cfg = config or load_config()
    root = find_vault_root(cfg)
    if not root:
        raise RuntimeError("Vault root not found. Configure [vault].root or STEWARD_VAULT_ROOT.")

    clean_rel = rel_path.replace("\\", "/").lstrip("/")
    if is_protected_meta(clean_rel, cfg):
        raise PermissionError(f"Refused: '{clean_rel}' is a protected multi-agent meta-file.")

    target = (root / clean_rel).resolve()
    root_resolved = root.resolve()
    if root_resolved not in target.parents:
        raise ValueError(f"Path escapes Vault root: {rel_path}")

    raw = content.encode("utf-8")
    expected_sha = hashlib.sha256(raw).hexdigest()
    target.parent.mkdir(parents=True, exist_ok=True)

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".md", prefix="steward_vault_", delete=False
        ) as tf:
            tmp_path = Path(tf.name)
            tf.write(raw)
        shutil.copyfile(tmp_path, target)
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

    readback = target.read_bytes()
    actual_sha = hashlib.sha256(readback).hexdigest()
    if len(readback) != len(raw) or actual_sha != expected_sha:
        raise IOError(
            f"Readback verification failed for {target}: "
            f"expected {len(raw)}B/{expected_sha}, got {len(readback)}B/{actual_sha}"
        )

    return {
        "path": str(target),
        "rel_path": clean_rel,
        "bytes": len(readback),
        "sha256": actual_sha,
        "verified": True,
    }


def _extract_daily_highlights(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[str] = []
    in_pending = False
    for line in lines:
        s = line.strip()
        if s.startswith("## "):
            in_pending = any(k in s.lower() for k in ("pending", "todo", "blocked", "handoff"))
            out.append(s)
        elif in_pending and (s.startswith("|") or s.startswith("- ")):
            if not s.startswith("|---"):
                out.append(s[:140])
        if len(out) >= 14:
            break
    return out


def _extract_decision_highlights(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out = [line.strip() for line in lines if line.strip().startswith("## DEC-")]
    return out[-8:]


def build_digest(max_chars: int | None = None, config: StewardConfig | None = None) -> str:
    """Build a compact catchup summary for SessionStart injection."""
    cfg = config or load_config()
    budget = max_chars if max_chars is not None else cfg.digest_max_chars
    status = get_status(cfg)
    if not status["mounted"]:
        return "[Steward Vault Auto-Catchup] Local Vault root not detected."

    root = Path(status["vault_root"])
    protected_str = "/".join(cfg.protected_meta_files)
    parts = [
        "[Steward Vault Auto-Catchup]",
        f"VaultRoot: {root}",
        f"Rules: never directly edit protected meta-files ({protected_str}).",
    ]

    if status["latest_daily"]:
        d_path = root / "daily" / status["latest_daily"]
        parts.append(f"Latest Daily ({status['latest_daily']}):")
        parts.extend(f"  {item}" for item in _extract_daily_highlights(d_path))

    if status["latest_decision"]:
        dec_path = root / "decisions" / status["latest_decision"]
        parts.append(f"Latest Decisions ({status['latest_decision']}):")
        parts.extend(f"  {item}" for item in _extract_decision_highlights(dec_path))

    text = "\n".join(parts)
    if len(text) > budget:
        text = text[: max(24, budget - 24)].rstrip() + "\n...(truncated)"
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Config-driven Markdown Vault bridge")
    parser.add_argument("--config", help="Path to steward.toml")
    parser.add_argument("--status", action="store_true", help="Print Vault status JSON")
    parser.add_argument("--digest", action="store_true", help="Print compact catchup digest")
    parser.add_argument("--write", metavar="REL_PATH", help="Atomic write relative path in Vault")
    parser.add_argument("--from-file", metavar="FILE", help="Source file path for --write")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    if args.status:
        print(json.dumps(get_status(cfg), ensure_ascii=False, indent=2))
        return 0
    if args.digest:
        print(build_digest(config=cfg))
        return 0
    if args.write:
        if not args.from_file:
            print("Error: --from-file is required with --write", file=sys.stderr)
            return 2
        content = Path(args.from_file).read_text(encoding="utf-8")
        receipt = atomic_write_vault(args.write, content, config=cfg)
        print(json.dumps(receipt, ensure_ascii=False, indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
