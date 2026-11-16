# agent-steward-kit

A zero-dependency, config-driven Python toolkit for multi-agent hygiene and deterministic lifecycle guardrails:

1. **`pre_tool_guard` (`steward-pretool-guard`)**: `PreToolUse` hook physically blocking agents from overwriting shared index/onboarding meta-files.
2. **`session_digest` (`steward-session-start`)**: `SessionStart` hook injecting bounded daily/decision digests and pending patrol items.
3. **`atomic_queue` (`steward-queue`)**: Incremental conversation consolidation queue with 3-layer recursion guards, secret scrubbing, and Windows-safe `os.replace()` retry + `finally` `.tmp.<PID>` cleanup.
4. **`vault_sync` (`steward-vault`)**: Cross-drive Markdown vault locator and SHA-256 readback-verified atomic writer.
5. **`slop_gc` (`steward-gc`)**: Deterministic 4-tier anti-slop garbage collector with live-process lock checks, configurable TTL retention, and dry-run reporting.

## Installation

```bash
pip install -e .
```

Zero third-party dependencies — built strictly on the Python 3.11+ standard library (`tomllib`, `pathlib`, `json`, `hashlib`, `subprocess`).

## Configuration

Copy `steward.example.toml` to `steward.toml` (or export `STEWARD_CONFIG=/path/to/steward.toml`):

```bash
cp steward.example.toml steward.toml
```

## Usage

```bash
# Dry-run garbage collection scan
steward-gc --config steward.toml --dry-run

# Apply Tier 1 cleanup
steward-gc --config steward.toml --apply

# Check Vault mount status and digest
steward-vault --config steward.toml --status
steward-vault --config steward.toml --digest

# Inspect atomic consolidation queue
steward-queue --config steward.toml --status
```

## License

MIT — see [LICENSE](LICENSE).
