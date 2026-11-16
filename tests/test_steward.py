"""Unit tests for agent-steward-kit (atomic queue, PreToolUse guard, TTL GC, vault sync)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agent_steward_kit import (  # noqa: E402
    StewardConfig,
    atomic_queue,
    pre_tool_guard,
    session_digest,
    slop_gc,
    vault_sync,
)


class TestAtomicQueue(unittest.TestCase):
    def test_atomic_write_retries_permission_error_and_cleans_tmp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "queue.json"
            real_replace = os.replace
            attempts = {"count": 0}

            def flaky_replace(src, dst):
                attempts["count"] += 1
                if attempts["count"] < 3:
                    raise PermissionError("simulated file lock")
                return real_replace(src, dst)

            with mock.patch.object(atomic_queue.os, "replace", side_effect=flaky_replace):
                atomic_queue.atomic_write_json(target, {"ok": True, "n": 42})

            self.assertEqual(attempts["count"], 3)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"ok": True, "n": 42})
            leftovers = list(Path(tmp).glob("*.tmp.*"))
            self.assertEqual(leftovers, [])

    def test_atomic_write_cleans_tmp_when_retries_exhausted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "queue.json"
            with mock.patch.object(
                atomic_queue.os, "replace", side_effect=PermissionError("locked")
            ):
                with self.assertRaises(PermissionError):
                    atomic_queue.atomic_write_json(target, {"ok": False}, max_attempts=2)

            leftovers = list(Path(tmp).glob("*.tmp.*"))
            self.assertEqual(leftovers, [])

    def test_enqueue_pending_and_mark_done_scrubs_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            transcript = tmp_dir / "conv.jsonl"
            fake_api_key = "sk" + "-demo0000000000000000"
            records = [
                {
                    "type": "USER_INPUT",
                    "source": "USER_EXPLICIT",
                    "content": f"<USER_REQUEST>Use token {fake_api_key}</USER_REQUEST>",
                },
                {
                    "type": "PLANNER_RESPONSE",
                    "source": "MODEL",
                    "content": "Completed check with Bearer mysecrettokenvalue12345 " + ("x" * 240),
                },
            ]
            transcript.write_text(
                "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
            )
            cfg = StewardConfig(state_dir=str(tmp_dir / "state"))

            enqueued = atomic_queue.enqueue_payload(
                {
                    "conversationId": "conv-1",
                    "transcriptPath": str(transcript),
                    "lastUserInput": "Run task",
                    "terminationReason": "NO_TOOL_CALL",
                },
                config=cfg,
            )
            self.assertTrue(enqueued)

            pending = atomic_queue.list_pending(config=cfg)
            self.assertEqual(pending["pending_count"], 1)
            digest = pending["items"][0]["digest"]
            self.assertNotIn("demo0000000000000000", digest)
            self.assertNotIn("mysecrettokenvalue12345", digest)
            self.assertIn("[REDACTED]", digest)

            done = atomic_queue.mark_done("conv-1", notes="tested", skills="demo", config=cfg)
            self.assertTrue(done["ok"])
            self.assertEqual(atomic_queue.list_pending(config=cfg)["pending_count"], 0)

            # Dream-tagged session must be rejected cleanly
            dream_transcript = tmp_dir / "dream.jsonl"
            dream_transcript.write_text(
                json.dumps(
                    {
                        "type": "USER_INPUT",
                        "source": "USER_EXPLICIT",
                        "content": f"{cfg.session_tag} run " + ("y" * 300),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertFalse(
                atomic_queue.enqueue_payload(
                    {
                        "conversationId": "conv-dream",
                        "transcriptPath": str(dream_transcript),
                        "lastUserInput": f"{cfg.session_tag} run",
                        "terminationReason": "NO_TOOL_CALL",
                    },
                    config=cfg,
                )
            )


class TestPreToolGuard(unittest.TestCase):
    def test_blocks_protected_meta_files_inside_vault_scope(self) -> None:
        cfg = StewardConfig(
            guard_scope_substrings=["obsidian vault"],
            protected_meta_files=["KNOWLEDGE_INDEX.md", "AGENT_ONBOARDING.md"],
        )
        blocked_payload = {
            "toolCall": {
                "args": {
                    "TargetFile": "/data/Obsidian Vault/KNOWLEDGE_INDEX.md",
                }
            }
        }
        res = pre_tool_guard.evaluate_tool_call(blocked_payload, cfg)
        self.assertEqual(res["decision"], "deny")
        self.assertIn("KNOWLEDGE_INDEX.md", res["reason"])

        blocked_alt = {"tool_input": {"file_path": r"E:\Docs\Obsidian Vault\AGENT_ONBOARDING.md"}}
        self.assertEqual(pre_tool_guard.evaluate_tool_call(blocked_alt, cfg)["decision"], "deny")

        allowed_daily = {"args": {"path": "/data/Obsidian Vault/daily/2026-11-16.md"}}
        self.assertEqual(pre_tool_guard.evaluate_tool_call(allowed_daily, cfg)["decision"], "ask")

        outside_scope = {"args": {"path": "/repo/docs/KNOWLEDGE_INDEX.md"}}
        self.assertEqual(pre_tool_guard.evaluate_tool_call(outside_scope, cfg)["decision"], "ask")


class TestSlopGCAndVault(unittest.TestCase):
    def test_ttl_gc_dry_run_and_apply_with_locks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "Obsidian Vault"
            vault.mkdir()
            (vault / "AGENT_ONBOARDING.md").write_text("# Onboarding\n", encoding="utf-8")
            (vault / "_write_probe.tmp").write_text("probe", encoding="utf-8")
            (vault / "daily").mkdir()
            (vault / "daily" / "2026-11-16.md").write_text("## Pending\n- Item 1\n", encoding="utf-8")

            scratch = root / "scratch"
            scratch.mkdir()
            expired_dir = scratch / "old_run"
            expired_dir.mkdir()
            old_file = expired_dir / "cache.bin"
            old_file.write_bytes(b"0" * 1024)

            locked_dir = scratch / "active_run"
            locked_dir.mkdir()
            locked_file = locked_dir / "work.bin"
            locked_file.write_bytes(b"1" * 512)

            fresh_dir = scratch / "fresh_run"
            fresh_dir.mkdir()
            fresh_file = fresh_dir / "new.bin"
            fresh_file.write_bytes(b"2" * 256)

            state_dir = root / "state"
            state_dir.mkdir()
            orphan_tmp = state_dir / "queue.json.tmp.99999"
            orphan_tmp.write_text("{}", encoding="utf-8")

            now = time.time()
            old_ts = now - 20 * 86400
            os.utime(old_file, (old_ts, old_ts))
            os.utime(expired_dir, (old_ts, old_ts))
            os.utime(locked_file, (old_ts, old_ts))
            os.utime(locked_dir, (old_ts, old_ts))
            os.utime(orphan_tmp, (now - 3600, now - 3600))

            cfg = StewardConfig(
                vault_root=str(vault),
                state_dir=str(state_dir),
                scratch_roots=[str(scratch)],
                gc_receipt_file=str(state_dir / "last_gc_receipt.json"),
                ttl_days=14,
            )
            fake_procs = [{"ProcessId": 100, "CommandLine": f"worker --dir {locked_dir}"}]

            dry = slop_gc.run_gc(apply=False, config=cfg, procs=fake_procs, now_ts=now)
            self.assertEqual(dry["mode"], "dry_run")
            self.assertEqual(dry["deleted_count"], 0)
            self.assertEqual(dry["tier1_candidate_count"], 3)  # probe + orphan_tmp + expired_dir
            self.assertEqual(len(dry["active_process_locks"]), 1)
            self.assertTrue(expired_dir.exists())

            applied = slop_gc.run_gc(apply=True, config=cfg, procs=fake_procs, now_ts=now)
            self.assertEqual(applied["mode"], "apply")
            self.assertEqual(applied["deleted_count"], 3)
            self.assertFalse(expired_dir.exists())
            self.assertFalse(orphan_tmp.exists())
            self.assertFalse((vault / "_write_probe.tmp").exists())
            self.assertTrue(locked_dir.exists())
            self.assertTrue(fresh_dir.exists())

            # Verify vault atomic write & session digest
            write_res = vault_sync.atomic_write_vault("notes/test.md", "# Hello\n", config=cfg)
            self.assertTrue(write_res["verified"])
            with self.assertRaises(PermissionError):
                vault_sync.atomic_write_vault("AGENT_ONBOARDING.md", "overwrite", config=cfg)

            session_payload = session_digest.build_session_payload(cfg)
            msg = session_payload["injectSteps"][0]["systemMessage"]["systemMessage"]
            self.assertIn("2026-11-16.md", msg)


if __name__ == "__main__":
    unittest.main()
