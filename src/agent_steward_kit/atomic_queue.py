"""Windows-safe atomic JSON queue & scheduled session consolidation tracker."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import StewardConfig, load_config

ALLOWED_STOP_REASONS = {"NO_TOOL_CALL", "MAX_INVOCATIONS"}

_TOKEN_PREFIXES = "|".join(
    [
        "sk" + "-",
        "ghp" + "_",
        "github" + "_pat_",
        "gho" + "_",
        "x" + "oxb-",
        "AI" + "za",
    ]
)

_SECRET_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{12,}", re.I), r"\1[REDACTED]"),
    (re.compile(rf"\b({_TOKEN_PREFIXES})[A-Za-z0-9_\-]{{10,}}"), r"\1[REDACTED]"),
    (
        re.compile(
            r"((?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?)"
            r"[A-Za-z0-9._\-/+]{8,}",
            re.I,
        ),
        r"\1[REDACTED]",
    ),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scrub_secrets(text: str) -> str:
    """Redact common token/secret patterns before persisting digests."""
    out = text
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


def atomic_write_json(path: str | Path, data: dict[str, Any], max_attempts: int = 5) -> None:
    """Write JSON atomically via PID temp file, retrying Windows PermissionError on replace."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = Path(f"{target}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        for attempt in range(max_attempts):
            try:
                os.replace(tmp_path, target)
                break
            except PermissionError:
                if attempt == max_attempts - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _queue_paths(config: StewardConfig) -> tuple[Path, Path]:
    state_dir = Path(config.state_dir)
    return state_dir / "dream_queue.json", state_dir / "dream_history.jsonl"


def _load_queue(queue_file: Path) -> dict[str, Any]:
    if not queue_file.is_file():
        return {"version": 1, "items": {}}
    try:
        data = json.loads(queue_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("items"), dict):
            return data
    except Exception:
        pass
    return {"version": 1, "items": {}}


def _inspect_transcript_meta(
    transcript_path: str, session_tag: str, head_scan_bytes: int
) -> tuple[bool, bool, int]:
    """Return (is_dream_tagged, has_user_explicit, line_count)."""
    with open(transcript_path, "rb") as fb:
        head_text = fb.read(head_scan_bytes).decode("utf-8", errors="replace")
    if session_tag in head_text:
        return True, False, 0

    has_user_explicit = False
    line_count = 0
    with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw_s = raw.strip()
            if not raw_s:
                continue
            line_count += 1
            try:
                rec = json.loads(raw_s)
            except Exception:
                continue
            content = rec.get("content", "")
            if isinstance(content, str) and session_tag in content and line_count <= 5:
                return True, False, line_count
            if rec.get("source") == "USER_EXPLICIT":
                has_user_explicit = True
    return False, has_user_explicit, line_count


def _extract_user_request_text(content: str) -> str:
    m = re.search(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", content, re.S)
    text = m.group(1) if m else content
    return scrub_secrets(re.sub(r"\s+", " ", text).strip())


def _extract_delta_digest(
    transcript_path: str, from_line: int, max_chars: int
) -> tuple[int, str]:
    """Extract concise USER_INPUT and PLANNER_RESPONSE delta lines from from_line."""
    lines_out: list[str] = []
    total_lines = 0
    with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw_s = raw.strip()
            if not raw_s:
                continue
            idx = total_lines
            total_lines += 1
            if idx < from_line:
                continue
            try:
                rec = json.loads(raw_s)
            except Exception:
                continue
            rtype = rec.get("type")
            content = rec.get("content")
            if not isinstance(content, str) or not content.strip():
                continue
            if rtype == "USER_INPUT" and rec.get("source") == "USER_EXPLICIT":
                lines_out.append(f"[USER L{idx}] {_extract_user_request_text(content)}")
            elif rtype == "PLANNER_RESPONSE" and rec.get("source") == "MODEL":
                cleaned = scrub_secrets(re.sub(r"\s+", " ", content).strip())
                if len(cleaned) > 600:
                    cleaned = cleaned[:600] + "..."
                lines_out.append(f"[AGENT L{idx}] {cleaned}")

    digest = "\n".join(lines_out)
    if len(digest) > max_chars:
        digest = digest[-max_chars:]
        nl = digest.find("\n")
        if nl != -1 and nl < len(digest) - 1:
            digest = "...(earlier turns omitted)...\n" + digest[nl + 1 :]
    return total_lines, digest


def enqueue_payload(payload: dict[str, Any], config: StewardConfig | None = None) -> bool:
    """Enqueue an eligible conversation payload; returns True if persisted."""
    cfg = config or load_config()
    queue_file, _ = _queue_paths(cfg)
    cid = str(payload.get("conversationId") or "").strip()
    tpath = str(payload.get("transcriptPath") or "").strip()
    last_user = str(payload.get("lastUserInput") or "")
    reason = str(payload.get("terminationReason") or "").strip()

    if not cid or not tpath or cfg.session_tag in last_user:
        return False
    if not os.path.isfile(tpath):
        return False
    if reason not in ALLOWED_STOP_REASONS:
        return False

    live_size = os.path.getsize(tpath)
    queue = _load_queue(queue_file)
    existing = queue["items"].get(cid, {})
    processed_size = int(existing.get("processedSize") or 0)
    if live_size <= processed_size + cfg.min_delta_bytes:
        return False

    is_dream, has_user_explicit, line_count = _inspect_transcript_meta(
        tpath, cfg.session_tag, cfg.head_scan_bytes
    )
    if is_dream or not has_user_explicit:
        return False

    entry = {
        "conversationId": cid,
        "transcriptPath": tpath,
        "artifactDirectoryPath": str(payload.get("artifactDirectoryPath") or ""),
        "cwd": str(payload.get("cwd") or ""),
        "status": "pending",
        "processedSize": processed_size,
        "lastProcessedLine": int(existing.get("lastProcessedLine") or 0),
        "observedSize": live_size,
        "observedLines": line_count,
        "terminationReason": reason,
        "lastUserPreview": scrub_secrets(last_user.strip())[:160],
        "lastEnqueuedAt": _utc_now(),
        "lastDreamedAt": existing.get("lastDreamedAt"),
    }
    queue["items"][cid] = entry
    queue["updatedAt"] = _utc_now()
    atomic_write_json(queue_file, queue)
    return True


def list_pending(max_chars: int = 12000, config: StewardConfig | None = None) -> dict[str, Any]:
    """Return pending conversations with live byte delta and scrubbed turn digest."""
    cfg = config or load_config()
    queue_file, _ = _queue_paths(cfg)
    queue = _load_queue(queue_file)
    pending_entries: list[tuple[str, dict[str, Any], int]] = []
    for cid, entry in queue.get("items", {}).items():
        if entry.get("status") != "pending":
            continue
        tpath = entry.get("transcriptPath", "")
        if not tpath or not os.path.isfile(tpath):
            continue
        live_size = os.path.getsize(tpath)
        proc_size = int(entry.get("processedSize") or 0)
        if live_size <= proc_size + cfg.min_delta_bytes:
            continue
        pending_entries.append((cid, entry, live_size))

    if not pending_entries:
        return {"pending_count": 0, "items": []}

    per_item_chars = max(1200, max_chars // len(pending_entries))
    out_items: list[dict[str, Any]] = []
    for cid, entry, live_size in pending_entries:
        tpath = entry["transcriptPath"]
        from_line = int(entry.get("lastProcessedLine") or 0)
        to_line, digest = _extract_delta_digest(tpath, from_line, per_item_chars)
        out_items.append(
            {
                "conversationId": cid,
                "transcriptPath": tpath,
                "fromLine": from_line,
                "toLine": to_line,
                "deltaBytes": live_size - int(entry.get("processedSize") or 0),
                "digest": digest,
            }
        )
    return {"pending_count": len(out_items), "items": out_items}


def mark_done(
    cid: str,
    notes: str = "",
    skills: str = "",
    config: StewardConfig | None = None,
) -> dict[str, Any]:
    """Mark a queued conversation processed up to its live size & line count."""
    cfg = config or load_config()
    queue_file, history_file = _queue_paths(cfg)
    queue = _load_queue(queue_file)
    entry = queue.get("items", {}).get(cid)
    if not entry:
        return {"ok": False, "error": f"Unknown conversationId: {cid}"}

    tpath = entry.get("transcriptPath", "")
    live_size = (
        os.path.getsize(tpath)
        if tpath and os.path.isfile(tpath)
        else int(entry.get("observedSize") or 0)
    )
    line_count = int(entry.get("observedLines") or 0)
    if tpath and os.path.isfile(tpath):
        with open(tpath, "r", encoding="utf-8", errors="replace") as f:
            line_count = sum(1 for raw in f if raw.strip())

    prev_line = int(entry.get("lastProcessedLine") or 0)
    now = _utc_now()
    entry["processedSize"] = live_size
    entry["lastProcessedLine"] = line_count
    entry["observedSize"] = live_size
    entry["observedLines"] = line_count
    entry["status"] = "done"
    entry["lastDreamedAt"] = now
    queue["updatedAt"] = now
    atomic_write_json(queue_file, queue)

    notes_list = [s.strip() for s in notes.split(",") if s.strip()] if notes else []
    skills_list = [s.strip() for s in skills.split(",") if s.strip()] if skills else []
    audit = {
        "timestamp": now,
        "conversationId": cid,
        "fromLine": prev_line,
        "toLine": line_count,
        "processedSize": live_size,
        "notes": notes_list,
        "skills": skills_list,
    }
    _append_jsonl(history_file, audit)
    return {"ok": True, **audit}


def get_status(config: StewardConfig | None = None) -> dict[str, Any]:
    """Return queue summary counts and entries."""
    cfg = config or load_config()
    queue_file, history_file = _queue_paths(cfg)
    queue = _load_queue(queue_file)
    items = queue.get("items", {})
    pending = [k for k, v in items.items() if v.get("status") == "pending"]
    done = [k for k, v in items.items() if v.get("status") == "done"]
    return {
        "queue_file": str(queue_file),
        "history_file": str(history_file),
        "total": len(items),
        "pending_count": len(pending),
        "done_count": len(done),
        "items": items,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Atomic consolidation queue CLI")
    parser.add_argument("--config", help="Path to steward.toml")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--enqueue-from-stdin", action="store_true")
    group.add_argument("--pending", action="store_true")
    group.add_argument("--mark-done", metavar="CONVERSATION_ID")
    group.add_argument("--status", action="store_true")
    parser.add_argument("--max-chars", type=int, default=12000)
    parser.add_argument("--notes", default="")
    parser.add_argument("--skills", default="")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    if args.enqueue_from_stdin:
        try:
            raw = sys.stdin.read()
            payload = json.loads(raw) if raw.strip() else {}
            enqueue_payload(payload, cfg)
        except Exception:
            pass
        print(json.dumps({"decision": "stop"}))
        return 0
    if args.pending:
        print(json.dumps(list_pending(args.max_chars, cfg), ensure_ascii=False, indent=2))
        return 0
    if args.mark_done:
        res = mark_done(args.mark_done, args.notes, args.skills, cfg)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1
    print(json.dumps(get_status(cfg), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
