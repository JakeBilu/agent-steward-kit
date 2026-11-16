"""Config-driven deterministic anti-slop garbage collector for agent workspaces."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from . import vault_sync
from .atomic_queue import atomic_write_json
from .config import StewardConfig, load_config

IMMEDIATE_VAULT_PROBES = {"_write_probe.tmp", ".probe_tmp.md"}
STEP_TMP_RE = re.compile(r"^.+_step\d+\.md$", re.IGNORECASE)
TMP_BAK_RE = re.compile(r"^.+\.(tmp|bak)$", re.IGNORECASE)
STATE_TMP_RE = re.compile(r"^.+\.(tmp|bak)(\.\d+)?$", re.IGNORECASE)


def active_process_cmdlines() -> list[dict[str, Any]]:
    """Query active process command lines to avoid removing directories in active use."""
    if os.name == "nt":
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Compress",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode != 0 or not proc.stdout.strip():
                return []
            parsed = json.loads(proc.stdout)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            return []

    try:
        proc = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return []
        rows: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines()[1:]:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                rows.append({"ProcessId": parts[0], "CommandLine": parts[1]})
        return rows
    except Exception:
        return []


def is_locked_by_process(path: Path, procs: list[dict[str, Any]]) -> bool:
    """Return True if any active process command line references the target path."""
    needle_native = str(path).lower()
    needle_posix = needle_native.replace("\\", "/")
    for p in procs:
        cmdline = str(p.get("CommandLine") or "").lower()
        if not cmdline:
            continue
        if needle_native in cmdline or needle_posix in cmdline:
            return True
    return False


def dir_size_and_latest_mtime(path: Path) -> tuple[int, float, int]:
    """Return (total_bytes, max_mtime, file_count) across a directory tree."""
    total_bytes = 0
    max_mtime = path.stat().st_mtime
    file_count = 0
    for root, _, files in os.walk(path):
        for fname in files:
            fpath = Path(root) / fname
            try:
                st = fpath.stat()
                total_bytes += st.st_size
                file_count += 1
                if st.st_mtime > max_mtime:
                    max_mtime = st.st_mtime
            except OSError:
                pass
    return total_bytes, max_mtime, file_count


def collect_vault_slop(
    vault_root: Path,
    now_ts: float,
    tmp_hours: float,
    procs: list[dict[str, Any]],
    config: StewardConfig,
) -> list[dict[str, Any]]:
    """Find temporary/probe artifacts inside the Vault safely."""
    candidates: list[dict[str, Any]] = []
    cutoff = now_ts - tmp_hours * 3600.0
    protected_dirs = set(config.protected_vault_dirs)
    protected_files = {name.lower() for name in config.protected_meta_files}

    for root, dirs, files in os.walk(vault_root):
        dirs[:] = [d for d in dirs if d not in protected_dirs]
        for fname in files:
            lower = fname.lower()
            if lower in protected_files:
                continue
            fpath = Path(root) / fname
            try:
                st = fpath.stat()
            except OSError:
                continue
            is_probe = lower in IMMEDIATE_VAULT_PROBES
            is_aged_tmp = bool(TMP_BAK_RE.match(fname) or STEP_TMP_RE.match(fname)) and st.st_mtime < cutoff
            if not (is_probe or is_aged_tmp):
                continue
            if is_locked_by_process(fpath, procs):
                continue
            rel = str(fpath.relative_to(vault_root)).replace("\\", "/")
            candidates.append(
                {
                    "kind": "vault_temp",
                    "path": str(fpath),
                    "rel_path": rel,
                    "bytes": st.st_size,
                    "age_hours": round((now_ts - st.st_mtime) / 3600.0, 2),
                }
            )
    return candidates


def collect_state_slop(
    state_dir: Path,
    now_ts: float,
    procs: list[dict[str, Any]],
    min_age_seconds: float = 60.0,
) -> list[dict[str, Any]]:
    """Collect orphaned temporary files (e.g., *.tmp.<PID>) in state directory."""
    candidates: list[dict[str, Any]] = []
    if not state_dir.is_dir():
        return candidates
    cutoff = now_ts - min_age_seconds
    for fpath in state_dir.iterdir():
        if not fpath.is_file() or not STATE_TMP_RE.match(fpath.name):
            continue
        try:
            st = fpath.stat()
        except OSError:
            continue
        if st.st_mtime >= cutoff or is_locked_by_process(fpath, procs):
            continue
        candidates.append(
            {
                "kind": "state_tmp",
                "path": str(fpath),
                "bytes": st.st_size,
                "age_minutes": round((now_ts - st.st_mtime) / 60.0, 2),
            }
        )
    return candidates


def collect_pycache_slop(
    pycache_dirs: list[str],
    now_ts: float,
    procs: list[dict[str, Any]],
    pycache_days: int = 7,
) -> list[dict[str, Any]]:
    """Collect stale __pycache__ folders whose files are all older than pycache_days."""
    candidates: list[dict[str, Any]] = []
    cutoff = now_ts - pycache_days * 86400.0
    for raw_dir in pycache_dirs:
        pdir = Path(raw_dir)
        if not pdir.is_dir() or is_locked_by_process(pdir, procs):
            continue
        total_b, max_mt, fcount = dir_size_and_latest_mtime(pdir)
        if fcount > 0 and max_mt < cutoff:
            candidates.append(
                {
                    "kind": "pycache",
                    "path": str(pdir),
                    "bytes": total_b,
                    "files": fcount,
                    "age_days": round((now_ts - max_mt) / 86400.0, 2),
                }
            )
    return candidates


def collect_expired_dirs(
    roots: list[str],
    kind: str,
    now_ts: float,
    ttl_days: int,
    procs: list[dict[str, Any]],
    protected_names: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Collect subdirectories under configured roots older than ttl_days."""
    candidates: list[dict[str, Any]] = []
    locked: list[dict[str, Any]] = []
    cutoff = now_ts - ttl_days * 86400.0
    wl = protected_names or set()

    for raw_root in roots:
        base = Path(raw_root)
        if not base.is_dir():
            continue
        for sub in base.iterdir():
            if not sub.is_dir() or sub.name.lower() in wl:
                continue
            total_b, max_mt, fcount = dir_size_and_latest_mtime(sub)
            if max_mt >= cutoff:
                continue
            if is_locked_by_process(sub, procs):
                locked.append({"kind": kind, "path": str(sub), "bytes": total_b})
                continue
            candidates.append(
                {
                    "kind": kind,
                    "path": str(sub),
                    "bytes": total_b,
                    "files": fcount,
                    "age_days": round((now_ts - max_mt) / 86400.0, 2),
                }
            )
    return candidates, locked


def collect_large_dir_alerts(config: StewardConfig) -> list[dict[str, Any]]:
    """Flag non-whitelisted directories above threshold without deleting."""
    alerts: list[dict[str, Any]] = []
    threshold = config.large_dir_mb * 1024 * 1024
    wl = {name.lower() for name in config.protected_scratch_names}

    for raw_root, whitelist in (
        [(r, wl) for r in config.scratch_roots]
        + [(r, set()) for r in config.task_copy_roots]
    ):
        base = Path(raw_root)
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if not entry.is_dir() or entry.name.lower() in whitelist:
                continue
            total_b, _, fcount = dir_size_and_latest_mtime(entry)
            if total_b > threshold:
                alerts.append(
                    {
                        "path": str(entry),
                        "mb": round(total_b / 1048576.0, 2),
                        "files": fcount,
                    }
                )
    alerts.sort(key=lambda item: item["mb"], reverse=True)
    return alerts


def run_gc(
    apply: bool = False,
    ttl_days: int | None = None,
    tmp_hours: float | None = None,
    config: StewardConfig | None = None,
    procs: list[dict[str, Any]] | None = None,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Scan configured targets, optionally delete Tier 1 slop, and record receipt."""
    cfg = config or load_config()
    eff_ttl = ttl_days if ttl_days is not None else cfg.ttl_days
    eff_tmp = tmp_hours if tmp_hours is not None else cfg.tmp_hours
    ts = now_ts if now_ts is not None else time.time()
    proc_list = procs if procs is not None else active_process_cmdlines()
    vault_root = vault_sync.find_vault_root(cfg)

    vault_items = collect_vault_slop(vault_root, ts, eff_tmp, proc_list, cfg) if vault_root else []
    state_items = collect_state_slop(Path(cfg.state_dir), ts, proc_list)
    pycache_items = collect_pycache_slop(cfg.pycache_dirs, ts, proc_list, cfg.pycache_days)
    scratch_items, scratch_locked = collect_expired_dirs(
        cfg.scratch_roots,
        "scratch_dir",
        ts,
        eff_ttl,
        proc_list,
        protected_names={n.lower() for n in cfg.protected_scratch_names},
    )
    task_items, task_locked = collect_expired_dirs(
        cfg.task_copy_roots,
        "task_copy",
        ts,
        eff_ttl,
        proc_list,
    )

    tier1_candidates = vault_items + state_items + pycache_items + scratch_items + task_items
    active_locks = scratch_locked + task_locked
    large_dir_alerts = collect_large_dir_alerts(cfg)

    deleted: list[dict[str, Any]] = []
    delete_errors: list[dict[str, str]] = []
    freed_bytes = 0

    if apply:
        for item in tier1_candidates:
            target = Path(item["path"])
            try:
                if target.is_dir():
                    shutil.rmtree(target)
                elif target.is_file():
                    target.unlink()
                deleted.append(item)
                freed_bytes += int(item.get("bytes", 0))
            except Exception as exc:
                delete_errors.append({"path": item["path"], "error": str(exc)})

    receipt = {
        "mode": "apply" if apply else "dry_run",
        "timestamp_epoch": int(ts),
        "ttl_days": eff_ttl,
        "tmp_hours": eff_tmp,
        "vault_root": str(vault_root) if vault_root else None,
        "tier1_candidate_count": len(tier1_candidates),
        "tier1_candidate_bytes": sum(int(x.get("bytes", 0)) for x in tier1_candidates),
        "tier1_candidates": tier1_candidates,
        "deleted_count": len(deleted),
        "freed_bytes": freed_bytes,
        "freed_mb": round(freed_bytes / 1048576.0, 2),
        "delete_errors": delete_errors,
        "active_process_locks": active_locks,
        "flagged_large_dirs": large_dir_alerts,
    }

    if cfg.gc_receipt_file:
        atomic_write_json(cfg.gc_receipt_file, receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic anti-slop workspace GC")
    parser.add_argument("--config", help="Path to steward.toml")
    parser.add_argument("--dry-run", action="store_true", help="Scan and report without deleting (default).")
    parser.add_argument("--apply", action="store_true", help="Delete verified Tier 1 slop.")
    parser.add_argument("--ttl-days", type=int, default=None, help="Age threshold in days for expired dirs.")
    parser.add_argument("--tmp-hours", type=float, default=None, help="Age threshold in hours for *.tmp/*.bak.")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    do_apply = bool(args.apply and not args.dry_run)
    receipt = run_gc(
        apply=do_apply,
        ttl_days=args.ttl_days,
        tmp_hours=args.tmp_hours,
        config=cfg,
    )
    print(json.dumps(receipt, indent=2, ensure_ascii=False))
    return 1 if receipt["delete_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
