"""Unit and integration tests for the Centralium CLI (Typer)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from centralium import __version__
from centralium.agent.main import app
from centralium.agent.storage import Database

runner = CliRunner()


def _parse_json(text_or_res: Any) -> Any:
    if hasattr(text_or_res, "stdout") and text_or_res.stdout.strip():
        text = text_or_res.stdout
    elif hasattr(text_or_res, "output"):
        text = text_or_res.output
    else:
        text = str(text_or_res)
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    for line in text.splitlines():
        line = line.strip()
        if (line.startswith("{") and line.endswith("}")) or (line.startswith("[") and line.endswith("]")):
            try:
                return json.loads(line)
            except Exception:
                continue
    for i, ch in enumerate(text):
        if ch in ("{", "["):
            for j in range(len(text), i, -1):
                try:
                    return json.loads(text[i:j])
                except Exception:
                    continue
    return json.loads(text)


def test_cli_version():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert __version__ in res.output


def test_cli_show_config(tmp_path: Path):
    cfg_file = tmp_path / "test_config.toml"
    cfg_file.write_text("[paths]\ndata_dir = '/tmp/test_centralium'\n", encoding="utf-8")
    res = runner.invoke(app, ["show-config", "--config", str(cfg_file)])
    assert res.exit_code == 0
    data = _parse_json(res)
    assert data["paths"]["data_dir"] == "/tmp/test_centralium"


def test_cli_init_db(tmp_path: Path):
    db_file = tmp_path / "test.db"
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'[paths]\ndb_path = "{db_file}"\n', encoding="utf-8")

    res = runner.invoke(app, ["init-db", "-c", str(cfg_file)])
    assert res.exit_code == 0
    assert db_file.exists()
    payload = _parse_json(res)
    assert payload["schema_version"] >= 1


def test_cli_audit_verify(tmp_path: Path):
    db_file = tmp_path / "audit.db"
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'[paths]\ndb_path = "{db_file}"\n', encoding="utf-8")

    with Database(db_file) as db:
        db.audit.append("test_actor", "login", {"status": "ok"})
        db.audit.append("test_actor", "mode_change", {"mode": "PASSIVE"})

    res = runner.invoke(app, ["audit", "verify", "-c", str(cfg_file)])
    assert res.exit_code == 0
    payload = _parse_json(res)
    assert payload["ok"] is True
    assert payload["entries"] == 2

    # Now tamper with the database to verify tampering detection
    with Database(db_file) as db:
        db.execute("UPDATE audit_log SET actor = 'tampered' WHERE seq = 1")

    res_tampered = runner.invoke(app, ["audit", "verify", "-c", str(cfg_file)])
    assert res_tampered.exit_code == 1
    tampered_payload = _parse_json(res_tampered)
    assert tampered_payload["ok"] is False


def test_cli_mode_show_and_set(tmp_path: Path):
    db_file = tmp_path / "mode.db"
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'[paths]\ndb_path = "{db_file}"\n', encoding="utf-8")

    # Initial show
    res_show = runner.invoke(app, ["mode", "show", "-c", str(cfg_file)])
    assert res_show.exit_code == 0
    show_data = _parse_json(res_show)
    assert show_data["configured_mode"] == "PASSIVE"
    assert show_data["persisted_mode"] is None

    # Set mode to LEARNING
    res_set = runner.invoke(
        app,
        ["mode", "set", "LEARNING", "--reason", "initial calibration", "-c", str(cfg_file)],
    )
    assert res_set.exit_code == 0
    set_data = _parse_json(res_set)
    assert set_data["mode"] == "LEARNING"
    assert set_data["audited"] is True

    # Check show again
    res_show2 = runner.invoke(app, ["mode", "show", "-c", str(cfg_file)])
    assert res_show2.exit_code == 0
    show_data2 = _parse_json(res_show2)
    assert show_data2["persisted_mode"] == "LEARNING"
    assert len(show_data2["recent_changes"]) >= 1


def test_cli_mode_aliases(tmp_path: Path):
    db_file = tmp_path / "mode_aliases.db"
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'[paths]\ndb_path = "{db_file}"\n', encoding="utf-8")

    # Test STRICT_PREVENT alias (maps to ACTIVE, requires --confirm)
    res_refuse = runner.invoke(
        app,
        ["mode", "set", "STRICT_PREVENT", "--reason", "enforce", "-c", str(cfg_file)],
    )
    assert res_refuse.exit_code == 2

    res_strict = runner.invoke(
        app,
        ["mode", "set", "STRICT_PREVENT", "--confirm", "--reason", "enforce", "-c", str(cfg_file)],
    )
    assert res_strict.exit_code == 0
    data_strict = _parse_json(res_strict)
    assert data_strict["mode"] == "ACTIVE"

    # Test BALANCED alias (maps to PASSIVE)
    res_bal = runner.invoke(
        app,
        ["mode", "set", "BALANCED", "--reason", "normal", "-c", str(cfg_file)],
    )
    assert res_bal.exit_code == 0
    assert _parse_json(res_bal)["mode"] == "PASSIVE"

    # Test AUDIT_ONLY alias (maps to PASSIVE)
    res_audit = runner.invoke(
        app,
        ["mode", "set", "AUDIT_ONLY", "--reason", "audit", "-c", str(cfg_file)],
    )
    assert res_audit.exit_code == 0
    assert _parse_json(res_audit)["mode"] == "PASSIVE"

    # Test ISOLATED alias (maps to PANIC, requires --confirm)
    res_iso = runner.invoke(
        app,
        ["mode", "set", "ISOLATED", "--confirm", "--reason", "emergency", "-c", str(cfg_file)],
    )
    assert res_iso.exit_code == 0
    assert _parse_json(res_iso)["mode"] == "PANIC"

    # Test invalid mode name
    res_bad = runner.invoke(
        app,
        ["mode", "set", "NON_EXISTENT_MODE", "--reason", "bad", "-c", str(cfg_file)],
    )
    assert res_bad.exit_code == 2


def test_cli_ml_status():
    res = runner.invoke(app, ["ml", "status"])
    assert res.exit_code == 0
    data = _parse_json(res)
    assert "models_dir" in data
    assert "feature_schema_version" in data
    assert "models" in data
    assert "anomaly" in data["models"]
    assert "classifier" in data["models"]


def test_cli_scan_file(tmp_path: Path):
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("harmless content\n", encoding="utf-8")

    res = runner.invoke(app, ["scan", str(clean_file)])
    assert res.exit_code == 0
    data = _parse_json(res)
    assert data["known_malicious_detected"] is False
    assert data["results"]["known_malicious"] is False


def test_cli_scan_directory(tmp_path: Path):
    test_dir = tmp_path / "scan_dir"
    test_dir.mkdir()
    (test_dir / "f1.txt").write_text("file 1 content", encoding="utf-8")
    (test_dir / "f2.txt").write_text("file 2 content", encoding="utf-8")

    res = runner.invoke(app, ["scan", str(test_dir)])
    assert res.exit_code == 0
    assert "Scan complete: 2 files inspected" in res.output

    # With --json output
    res_json = runner.invoke(app, ["scan", str(test_dir), "--json"])
    assert res_json.exit_code == 0
    payload = _parse_json(res_json)
    assert payload["total_scanned"] == 2
    assert payload["known_malicious_detected"] is False


def test_cli_quarantine_list(tmp_path: Path):
    qdir = tmp_path / "quarantine"
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'[paths]\nquarantine_dir = "{qdir}"\n', encoding="utf-8")

    res = runner.invoke(app, ["quarantine", "list", "-c", str(cfg_file)])
    assert res.exit_code == 0
    items = _parse_json(res)
    assert isinstance(items, list)


def test_cli_demo_mode(tmp_path: Path):
    data_dir = tmp_path / "demo_data"
    json_summary = tmp_path / "demo_summary.json"

    # Replay demo scenarios in non-destructive mode
    res = runner.invoke(
        app,
        [
            "demo",
            "--data-dir",
            str(data_dir),
            "--replay-only",
            "--llm",
            "mock",
            "--json",
            str(json_summary),
        ],
    )
    assert res.exit_code == 0
    assert "CENTRALIUM DEMO SUMMARY" in res.output
    assert "destructive_allowed=False" in res.output
    assert "executor_simulate=True" in res.output
    assert "safety_ok=True" in res.output

    # Verify JSON summary was written
    assert json_summary.exists()
    summary = json.loads(json_summary.read_text(encoding="utf-8"))
    assert summary["safety_ok"] is True
    assert summary["destructive_allowed"] is False
    assert len(summary["scenarios"]) == 11


def test_cli_quarantine_restore(tmp_path: Path):
    import getpass

    from centralium.agent.quarantine import FileQuarantineManager

    qdir = tmp_path / "quarantine"
    source_file = tmp_path / "threat.exe"
    source_file.write_text("suspicious code", encoding="utf-8")
    cfg_file = tmp_path / "config.toml"
    db_file = tmp_path / "quarantine.db"
    cfg_file.write_text(
        f'[paths]\nquarantine_dir = "{qdir}"\ndb_path = "{db_file}"\n',
        encoding="utf-8",
    )

    user = getpass.getuser()
    qm = FileQuarantineManager(qdir, authorized_users=[user])
    rec = qm.quarantine(source_file, reasons=["test threat"], sources=["test"])

    # Refuse without --yes
    res_no_yes = runner.invoke(
        app,
        ["quarantine", "restore", rec.quarantine_id, "--reason", "false positive", "-c", str(cfg_file)],
    )
    assert res_no_yes.exit_code == 2

    # Restore with --yes
    # Remove original file so it can restore cleanly
    if source_file.exists():
        source_file.unlink()
    res_restore = runner.invoke(
        app,
        [
            "quarantine",
            "restore",
            rec.quarantine_id,
            "--reason",
            "false positive",
            "--yes",
            "-c",
            str(cfg_file),
        ],
    )
    assert res_restore.exit_code == 0
    restore_data = _parse_json(res_restore.output)
    assert "restored_to" in restore_data
    assert source_file.exists()


def test_cli_rag_ingest_and_query(tmp_path: Path):
    docs_dir = tmp_path / "rag" / "documents"
    docs_dir.mkdir(parents=True)
    (docs_dir / "doc1.md").write_text(
        "# Ransomware Playbook\nStop process and isolate host.\n", encoding="utf-8"
    )
    index_db = tmp_path / "rag_index.db"

    # Ingest
    res_ingest = runner.invoke(
        app,
        ["rag", "ingest", "--rag-dir", str(tmp_path / "rag"), "--index", str(index_db)],
    )
    assert res_ingest.exit_code == 0
    assert index_db.exists()

    # Query
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        f'[paths]\nrag_dir = "{tmp_path / "rag"}"\ndata_dir = "{tmp_path}"\n',
        encoding="utf-8",
    )
    res_query = runner.invoke(app, ["rag", "query", "ransomware", "-c", str(cfg_file)])
    assert res_query.exit_code == 0
    assert "doc1" in res_query.output


def test_cli_run_short_duration(tmp_path: Path):
    db_file = tmp_path / "run.db"
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        f'[paths]\ndb_path = "{db_file}"\ndata_dir = "{tmp_path}"\n',
        encoding="utf-8",
    )

    res = runner.invoke(
        app,
        [
            "run",
            "--duration",
            "0.2",
            "--collector",
            "psutil",
            "--llm",
            "off",
            "-c",
            str(cfg_file),
        ],
    )
    assert res.exit_code == 0


def test_cli_benchmark(tmp_path: Path):
    out_md = tmp_path / "BENCHMARKS.md"
    out_json = tmp_path / "benchmarks.json"
    res = runner.invoke(
        app,
        [
            "benchmark",
            "--events",
            "10",
            "--llm-runs",
            "0",
            "--out-md",
            str(out_md),
            "--out-json",
            str(out_json),
        ],
    )
    assert res.exit_code == 0
    assert out_md.exists()
    assert out_json.exists()
