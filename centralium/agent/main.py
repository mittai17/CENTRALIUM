"""Centralium CLI (Typer).

Commands: version, show-config, init-db, run, demo, e2e (alias test-mode), dashboard, mode
(show|set), ml (pass-through to the ML pipeline CLI), rag (ingest|query), scan, quarantine
(list|restore), audit (verify), benchmark.

Safety: ``demo`` and ``e2e`` force demo/test mode (simulated executor, destructive gate closed);
``run`` refuses to start with enforcement enabled unless ``--enable-enforcement`` is given;
mode changes are always explicit, audited and persisted - nothing switches mode silently.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Annotated, Any

import typer

from centralium import __version__
from centralium.agent.config import CentraliumConfig, ModeChangeError, ResourceProfileName, load_config
from centralium.agent.models import EventType, NormalizedEvent, OperatingMode
from centralium.agent.privacy.redaction import install_log_redaction
from centralium.agent.storage import Database

app = typer.Typer(help="Centralium EDR/EPP", no_args_is_help=True, add_completion=False)
audit_app = typer.Typer(help="Audit log commands", no_args_is_help=True)
mode_app = typer.Typer(help="Operating mode (explicit, audited, persisted)", no_args_is_help=True)
rag_app = typer.Typer(help="Local RAG knowledge base", no_args_is_help=True)
quarantine_app = typer.Typer(help="Quarantine management", no_args_is_help=True)
ml_app = typer.Typer(help="Machine learning pipeline and model management", no_args_is_help=True)
eval_app = typer.Typer(help="Evaluation harnesses (RAG, LLM, prompt-injection)", no_args_is_help=True)
app.add_typer(audit_app, name="audit")
app.add_typer(mode_app, name="mode")
app.add_typer(rag_app, name="rag")
app.add_typer(quarantine_app, name="quarantine")
app.add_typer(ml_app, name="ml")
app.add_typer(eval_app, name="eval")

ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="TOML config file")]
ProfileOpt = Annotated[
    ResourceProfileName | None, typer.Option("--profile", help="low-resource | balanced | analysis")
]
log = logging.getLogger("centralium.cli")


# --------------------------------------------------------------------------- helpers
def _setup_logging(cfg: CentraliumConfig, quiet_alerts: bool = False) -> None:
    logging.basicConfig(
        level=getattr(logging, cfg.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
        force=True,
    )
    install_log_redaction()
    if quiet_alerts:
        logging.getLogger("centralium.response").setLevel(logging.ERROR)


def make_config(
    path: Path | None = None,
    *,
    profile: ResourceProfileName | None = None,
    demo: bool = False,
    test: bool = False,
    mode: OperatingMode | None = None,
    data_dir: Path | None = None,
) -> CentraliumConfig:
    overrides: dict[str, Any] = {}
    if profile is not None:
        overrides["profile"] = profile.value
    if demo:
        overrides["demo_mode"] = True
    if test:
        overrides["test_mode"] = True
    if mode is not None:
        overrides["mode"] = mode.value
    if data_dir is not None:
        overrides["paths"] = {"data_dir": str(data_dir)}
    cfg = load_config(path, **overrides)
    if profile is not None:
        cfg = cfg.apply_resource_profile()
    return cfg


def _db_path(cfg: CentraliumConfig) -> Path:
    assert cfg.paths.db_path is not None
    return Path(cfg.paths.db_path)


def _audit_to(db: Database) -> Any:
    def _fn(actor: str, event_type: str, details: dict[str, Any]) -> None:
        db.audit.append(actor, event_type, details)

    return _fn


# --------------------------------------------------------------------------- basics
@app.command()
def version() -> None:
    """Print version."""
    typer.echo(__version__)


@app.command("show-config")
def show_config(config: ConfigOpt = None) -> None:
    """Print the effective configuration as JSON."""
    cfg = load_config(config)
    typer.echo(cfg.model_dump_json(indent=2))


@app.command("init-db")
def init_db(config: ConfigOpt = None) -> None:
    """Create/migrate the SQLite database."""
    cfg = load_config(config)
    _db_path(cfg).parent.mkdir(parents=True, exist_ok=True)
    with Database(_db_path(cfg)) as db:
        typer.echo(
            json.dumps(
                {"db": db.path, "schema_version": db.schema_version(), "journal_mode": db.journal_mode()}
            )
        )


@audit_app.command("verify")
def audit_verify(config: ConfigOpt = None) -> None:
    """Verify the hash-chained audit log; exit 1 if tampering is detected."""
    cfg = load_config(config)
    with Database(_db_path(cfg)) as db:
        res = db.audit.verify()
    typer.echo(
        json.dumps(
            {"ok": res.ok, "entries": res.entries, "first_bad_seq": res.first_bad_seq, "reason": res.reason}
        )
    )
    raise typer.Exit(code=0 if res.ok else 1)


# --------------------------------------------------------------------------- run (live agent)
def _make_collectors(rt: Any, which: str) -> list[Any]:
    from centralium.agent.collectors.linux import AuditdCollector, PsutilCollector

    cfg: CentraliumConfig = rt.config
    rate = float(cfg.resource_profile.max_events_per_sec)
    host, qsize = cfg.host_id, cfg.resource_profile.event_queue_size
    out: list[Any] = []
    tokens = [t.strip().lower() for t in which.split(",") if t.strip()]
    if any(t in ("auto", "psutil") for t in tokens):
        out.append(
            PsutilCollector(
                emit_existing=True,
                skip_loopback=False,
                poll_interval=2.0,
                host_id=host,
                max_events_per_sec=rate,
                queue_size=qsize,
            )
        )
    if sys.platform.startswith("linux") and any(t in ("auto", "auditd") for t in tokens):
        ac = AuditdCollector(host_id=host, max_events_per_sec=rate, queue_size=qsize)
        ok, why = ac.health()
        if ok or "auditd" in tokens:
            out.append(ac)
        else:
            log.info("auditd collector not started: %s", why)
    if sys.platform.startswith("win") and any(t in ("auto", "eventlog") for t in tokens):
        from centralium.agent.collectors.windows import EventLogCollector

        out.append(
            EventLogCollector(host_id=host, max_events_per_sec=rate, queue_size=qsize)
        )  # untested on real Windows (see docs/ACCEPTANCE.md)
    return out


@app.command()
def run(
    config: ConfigOpt = None,
    profile: ProfileOpt = None,
    mode: Annotated[OperatingMode | None, typer.Option(help="LEARNING | PASSIVE | ACTIVE")] = None,
    duration: Annotated[float, typer.Option(help="stop after N seconds (0 = run until signalled)")] = 0.0,
    collector: Annotated[
        str,
        typer.Option(
            "--collector", "--collectors", help="auto | psutil | auditd | eventlog (or comma-separated)"
        ),
    ] = "auto",
    daemon: Annotated[
        bool, typer.Option("--daemon", "-d", help="run agent as background daemon process")
    ] = False,
    pidfile: Annotated[Path | None, typer.Option("--pidfile", help="write daemon PID to this file")] = None,
    llm: Annotated[str, typer.Option(help="auto | real | off (a mock is never used in a live run)")] = "auto",
    enable_enforcement: Annotated[
        bool, typer.Option(help="REQUIRED to start in ACTIVE mode (real response actions)")
    ] = False,
    auto_install_models: Annotated[
        bool, typer.Option(help="train default synthetic ML models if missing")
    ] = False,
    status_every: Annotated[float, typer.Option(help="print a status line every N seconds (0 = off)")] = 15.0,
) -> None:
    """Run the live agent: collectors -> bounded queue -> pipeline. Works with the dashboard,
    internet and LLM all down. Default mode PASSIVE (detect + alert; nothing destructive)."""
    from centralium.agent.runtime import build_runtime, set_mode_audited

    if mode in (OperatingMode.PANIC,):
        typer.echo(
            "PANIC cannot be started via 'run'; use 'centralium mode set PANIC --confirm' explicitly.",
            err=True,
        )
        raise typer.Exit(2)

    if daemon:
        if not hasattr(os, "fork"):
            typer.echo("Daemon mode is only supported on Unix/Linux systems.", err=True)
            raise typer.Exit(1)
        pid = os.fork()
        if pid > 0:
            if pidfile:
                pidfile.parent.mkdir(parents=True, exist_ok=True)
                pidfile.write_text(str(pid), encoding="utf-8")
            typer.echo(json.dumps({"event": "daemon_started", "pid": pid}))
            raise typer.Exit(0)
        os.setsid()
        pid2 = os.fork()
        if pid2 > 0:
            sys.exit(0)
        if pidfile:
            pidfile.parent.mkdir(parents=True, exist_ok=True)
            pidfile.write_text(str(os.getpid()), encoding="utf-8")
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, sys.stdin.fileno())
        os.close(devnull)

    cfg = make_config(config, profile=profile, mode=None)
    _setup_logging(cfg, quiet_alerts=False)
    _db_path(cfg).parent.mkdir(parents=True, exist_ok=True)
    rt = build_runtime(
        cfg,
        llm_mode=llm if llm in ("auto", "real", "off") else "auto",
        auto_install_models=auto_install_models,
        config_files=[config] if config else [],
    )
    stop = threading.Event()
    collectors: list[Any] = []
    try:
        if mode is not None and mode != rt.modes.mode:
            set_mode_audited(rt, mode, "cli:run", f"--mode {mode.value} given at start")
        if rt.config.destructive_allowed(rt.modes.mode) and not enable_enforcement:
            typer.echo(
                f"Refusing to start: mode {rt.modes.mode.value} would enable real response actions. "
                "Re-run with --enable-enforcement, or choose --mode PASSIVE/LEARNING "
                "(see 'centralium mode show').",
                err=True,
            )
            raise typer.Exit(2)
        rt.start_background()
        assert rt.loop is not None
        collectors = _make_collectors(rt, collector)
        for c in collectors:
            c.start(rt.loop.submit)
            if rt.selfprot is not None:
                rt.selfprot.register_component(f"collector:{c.name}", c.health)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        typer.echo(
            json.dumps(
                {
                    "event": "agent_started",
                    "mode": rt.modes.mode.value,
                    "profile": cfg.profile.value,
                    "collectors": [c.name for c in collectors],
                    "llm": {"kind": rt.llm_kind, "label": rt.llm_label},
                    "ml": rt.ml.model_version,
                    "notes": rt.notes,
                }
            ),
            err=True,
        )
        t0 = time.monotonic()
        last = t0
        while not stop.wait(0.5):
            now = time.monotonic()
            if duration and now - t0 >= duration:
                break
            if status_every and now - last >= status_every:
                last = now
                typer.echo(json.dumps({"event": "status", **rt.status()}, default=str), err=True)
    finally:
        stop.set()
        for c in collectors:
            try:
                c.stop()
            except Exception:
                log.exception("collector stop failed")
        final = rt.status() if rt.loop else {}
        rt.close()
        typer.echo(json.dumps({"event": "agent_stopped", **final}, default=str), err=True)


# --------------------------------------------------------------------------- demo
@app.command()
def demo(
    config: ConfigOpt = None,
    data_dir: Annotated[Path, typer.Option(help="demo data directory (recreated each run)")] = Path(
        "data/demo"
    ),
    llm: Annotated[
        str, typer.Option(help="auto (real if reachable else labelled mock) | mock | real")
    ] = "auto",
    serve: Annotated[bool, typer.Option(help="serve the dashboard on the demo DB afterwards")] = False,
    port: Annotated[int, typer.Option(help="dashboard port")] = 8765,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="write the machine-readable summary here")
    ] = None,
    keep: Annotated[bool, typer.Option(help="do not wipe an existing demo directory first")] = False,
    replay: Annotated[
        Path | None,
        typer.Option("--replay", "-r", help="JSONL replay file to run instead of default scenarios"),
    ] = None,
    replay_only: Annotated[
        bool,
        typer.Option("--replay-only", help="run only demo_replay.jsonl scenarios"),
    ] = False,
    scenarios_only: Annotated[
        bool,
        typer.Option("--scenarios-only", help="run only synthetic built-in scenarios"),
    ] = False,
    include_replay: Annotated[
        bool,
        typer.Option(
            "--include-replay",
            help="include ml/datasets/replay/demo_replay.jsonl alongside scenarios",
        ),
    ] = False,
) -> None:
    """Replay safe synthetic events through the full pipeline (destructive response disabled)."""
    from centralium.agent.demo import build_scenarios, load_replay_scenarios, run_demo
    from centralium.agent.runtime import build_runtime

    cfg = make_config(config, demo=True, mode=OperatingMode.ACTIVE, data_dir=data_dir)
    _setup_logging(cfg, quiet_alerts=True)
    _prepare_sandbox_dir(Path(cfg.paths.data_dir), keep, ".centralium-demo")
    rt = build_runtime(cfg, llm_mode=llm if llm in ("auto", "mock", "real") else "auto")
    try:
        if replay is not None:
            scenarios = load_replay_scenarios(replay)
        elif replay_only:
            scenarios = load_replay_scenarios()
        elif scenarios_only:
            scenarios = build_scenarios()
        else:
            # Default: replay both built-in scenarios + replay dataset
            scenarios = build_scenarios() + load_replay_scenarios()

        typer.echo(f"Starting Centralium demo replay ({len(scenarios)} scenarios, simulated only)...")

        def _on_scenario_done(res: Any, current: int, total: int) -> None:
            acts = ", ".join(f"{k} x{v}" for k, v in res.actions.items()) if res.actions else "none"
            typer.echo(
                f"[{current:02d}/{total:02d}] {res.name:<28} "
                f"events={res.events:<3} risk={res.max_risk:<4.0f} ({res.max_band.value:<8}) "
                f"findings={res.findings:<2} incidents={len(set(res.incident_ids)):<2} "
                f"actions: {acts}"
            )

        report = run_demo(rt, scenarios=scenarios, on_scenario_complete=_on_scenario_done)
    finally:
        rt.close()

    typer.echo("\n" + report.format_text())
    if json_out is not None:
        json_out.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
    if serve:
        from dashboard.backend.run import serve as serve_dashboard

        typer.echo(f"Serving dashboard on http://127.0.0.1:{port} (demo DB {_db_path(cfg)}); Ctrl+C to stop.")
        serve_dashboard(db_path=_db_path(cfg), port=port, config_path=str(config) if config else None)


def _prepare_sandbox_dir(path: Path, keep: bool, marker: str) -> None:
    """Create a demo/test data dir. An existing dir is only ever wiped if it carries our marker file."""
    path = path.resolve()
    if path.exists() and not keep:
        if (path / marker).exists():
            shutil.rmtree(path)
        elif any(path.iterdir()):
            typer.echo(
                f"Refusing to wipe {path}: no {marker} marker (not a Centralium sandbox dir).", err=True
            )
            raise typer.Exit(2)
    path.mkdir(parents=True, exist_ok=True)
    (path / marker).write_text("created by centralium demo/test mode\n", encoding="utf-8")


# --------------------------------------------------------------------------- e2e / test mode
def _project_root() -> Path:
    from centralium.agent.runtime import PROJECT_ROOT

    return PROJECT_ROOT


@app.command("e2e")
def e2e(
    extra: Annotated[list[str] | None, typer.Argument(help="extra pytest arguments")] = None,
) -> None:
    """Run the isolated end-to-end scenario suite (tests/e2e; demo/test mode only, never destructive)."""
    root = _project_root()
    tests = root / "tests" / "e2e"
    if not tests.is_dir():
        typer.echo("tests/e2e not found (run from a source checkout).", err=True)
        raise typer.Exit(2)
    cp = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests), "-q", *(extra or [])], cwd=root, check=False
    )
    raise typer.Exit(cp.returncode)


app.command("test-mode")(e2e)


# --------------------------------------------------------------------------- dashboard
@app.command()
def dashboard(
    config: ConfigOpt = None,
    db: Annotated[Path | None, typer.Option(help="SQLite DB to show (default: configured agent DB)")] = None,
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8765,
) -> None:
    """Serve the SOC dashboard (FastAPI + built UI). Tokens are generated once and printed once."""
    from dashboard.backend.run import serve

    cfg = load_config(config)
    serve(db_path=db or _db_path(cfg), host=host, port=port, config_path=str(config) if config else None)


# --------------------------------------------------------------------------- mode
MODE_ALIASES: dict[str, OperatingMode] = {
    "LEARNING": OperatingMode.LEARNING,
    "PASSIVE": OperatingMode.PASSIVE,
    "ACTIVE": OperatingMode.ACTIVE,
    "PANIC": OperatingMode.PANIC,
    "STRICT_PREVENT": OperatingMode.ACTIVE,
    "BALANCED": OperatingMode.PASSIVE,
    "AUDIT_ONLY": OperatingMode.PASSIVE,
    "ISOLATED": OperatingMode.PANIC,
}


@mode_app.command("show")
def mode_show(config: ConfigOpt = None) -> None:
    """Show configured + persisted mode and the recent mode audit trail."""
    from centralium.agent.runtime import load_persisted_mode

    cfg = load_config(config)
    with Database(_db_path(cfg)) as db:
        persisted = load_persisted_mode(db)
        rows = db.query(
            "SELECT seq, timestamp, actor, event_type, details FROM audit_log "
            "WHERE event_type IN ('mode_change','mode_change_refused') ORDER BY seq DESC LIMIT 10"
        )
        typer.echo(
            json.dumps(
                {
                    "configured_mode": cfg.mode.value,
                    "persisted_mode": persisted.value if persisted else None,
                    "effective_on_next_start": (persisted or cfg.mode).value,
                    "destructive_response_allowed": cfg.destructive_allowed(persisted or cfg.mode),
                    "aliases": {
                        "STRICT_PREVENT": OperatingMode.ACTIVE.value,
                        "BALANCED": OperatingMode.PASSIVE.value,
                        "AUDIT_ONLY": OperatingMode.PASSIVE.value,
                        "ISOLATED": OperatingMode.PANIC.value,
                    },
                    "recent_changes": [dict(r) for r in rows],
                },
                indent=2,
            )
        )


@mode_app.command("set")
def mode_set(
    new_mode: Annotated[
        str,
        typer.Argument(help="LEARNING | PASSIVE | ACTIVE | PANIC (or aliases: STRICT_PREVENT, etc.)"),
    ],
    reason: Annotated[str, typer.Option(help="why (required, audited)")],
    actor: Annotated[str, typer.Option(help="who (default: OS user)")] = "",
    confirm: Annotated[bool, typer.Option(help="required for ACTIVE/PANIC (enables real responses)")] = False,
    config: ConfigOpt = None,
) -> None:
    """Change the persisted operating mode. Always audited; never silent."""
    from centralium.agent.config import ModeManager
    from centralium.agent.runtime import MODE_POLICY_ID, load_persisted_mode

    clean_key = new_mode.strip().upper()
    if clean_key not in MODE_ALIASES:
        valid_modes = ", ".join(sorted(MODE_ALIASES.keys()))
        typer.echo(f"Invalid mode '{new_mode}'. Valid choices: {valid_modes}", err=True)
        raise typer.Exit(2)
    target_mode = MODE_ALIASES[clean_key]

    who = actor or f"cli:{getpass.getuser()}"
    if target_mode in (OperatingMode.ACTIVE, OperatingMode.PANIC) and not confirm:
        typer.echo(f"{target_mode.value} enables real response actions: re-run with --confirm.", err=True)
        raise typer.Exit(2)
    cfg = load_config(config)
    _db_path(cfg).parent.mkdir(parents=True, exist_ok=True)
    with Database(_db_path(cfg)) as db:
        base = load_persisted_mode(db) or cfg.mode
        mm = ModeManager(cfg.model_copy(update={"mode": base}), _audit_to(db))
        try:
            result = mm.set_mode(target_mode, actor=who, reason=reason)
        except ModeChangeError as exc:
            typer.echo(f"refused: {exc}", err=True)
            raise typer.Exit(2) from exc
        db.insert(
            "policies",
            {
                "policy_id": MODE_POLICY_ID,
                "name": "Operating mode",
                "version": 1,
                "enabled": 1,
                "body": json.dumps({"mode": result.value, "actor": who, "reason": reason, "alias": new_mode}),
                "updated_at": Database.now(),
            },
            on_conflict="REPLACE",
        )
    typer.echo(
        json.dumps(
            {
                "mode": result.value,
                "input_mode": new_mode,
                "previous": base.value,
                "actor": who,
                "audited": True,
            }
        )
    )


# --------------------------------------------------------------------------- ML
@ml_app.command("train")
def ml_train(
    data: Annotated[Path, typer.Option("--data", help="dataset directory")] = Path("ml/datasets/data"),
    models: Annotated[Path, typer.Option("--models", help="models directory")] = Path("data/models"),
    seed: Annotated[int, typer.Option("--seed")] = 42,
    kind: Annotated[str, typer.Option("--kind", help="all | anomaly | classifier")] = "all",
    scale: Annotated[float, typer.Option("--scale", help="synthetic dataset scale multiplier")] = 1.0,
) -> None:
    """Train ML models (anomaly detector and/or classifier)."""
    from ml.datasets.synthetic import write_dataset
    from ml.training.data import extract_features, load_dataset, split_dataset
    from ml.training.train import train_anomaly, train_classifier

    samples_file = data / "samples.jsonl"
    features_file = data / "features.npz"
    if not samples_file.exists():
        typer.echo(f"Preparing dataset in {data} (seed={seed}, scale={scale})...")
        write_dataset(data, seed=seed, scale=scale)
    if not features_file.exists():
        typer.echo(f"Extracting features into {features_file}...")
        extract_features(data)

    parts = split_dataset(load_dataset(data), seed=seed)
    results: dict[str, Any] = {}

    if kind in ("all", "anomaly"):
        results["anomaly"] = train_anomaly(parts["train"], parts["val"], models, seed=seed)
    if kind in ("all", "classifier"):
        results["classifier"] = train_classifier(parts["train"], models, seed=seed)

    typer.echo(json.dumps(results, indent=2, default=str))


@ml_app.command("evaluate")
def ml_evaluate(
    data: Annotated[Path, typer.Option("--data", help="dataset directory")] = Path("ml/datasets/data"),
    models: Annotated[Path, typer.Option("--models", help="models directory")] = Path("data/models"),
    split: Annotated[str, typer.Option("--split", help="val | test")] = "test",
) -> None:
    """Evaluate trained ML models against validation or held-out test split."""
    from ml.evaluation.evaluate import evaluate, write_report

    rep = evaluate(models, data, split)
    out_path = write_report(rep)
    typer.echo(f"Report written to {out_path}")
    typer.echo(json.dumps(rep, indent=2, default=str))


@ml_app.command("status")
def ml_status(
    models: Annotated[Path | None, typer.Option("--models", help="models directory")] = None,
    config: ConfigOpt = None,
) -> None:
    """Show current status, versions, and schema compatibility of ML models."""
    from ml.features.schema import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
    from ml.training.pipeline import DEFAULT_MODELS_DIR
    from ml.training.train import ANOMALY_FILE, CLASSIFIER_FILE, load_bundle

    cfg = load_config(config)
    target_models = models or Path(cfg.paths.data_dir) / "models"
    if not target_models.exists():
        target_models = DEFAULT_MODELS_DIR

    status_info: dict[str, Any] = {
        "models_dir": str(target_models),
        "exists": target_models.is_dir(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(FEATURE_NAMES),
        "models": {},
    }

    for name, fname in (("anomaly", ANOMALY_FILE), ("classifier", CLASSIFIER_FILE)):
        mpath = target_models / fname
        if mpath.exists():
            try:
                _, meta = load_bundle(target_models, fname)
                status_info["models"][name] = {
                    "installed": True,
                    "file": fname,
                    "size_bytes": mpath.stat().st_size,
                    "version": meta.get("model_version", "unknown"),
                    "schema_version": meta.get("feature_schema_version"),
                    "compatible": meta.get("feature_schema_version") == FEATURE_SCHEMA_VERSION,
                    "metrics": meta.get("metrics", {}),
                    "training_timestamp": meta.get("training_timestamp"),
                }
            except Exception as exc:
                status_info["models"][name] = {
                    "installed": True,
                    "file": fname,
                    "corrupt": True,
                    "error": str(exc),
                }
        else:
            status_info["models"][name] = {
                "installed": False,
                "file": fname,
            }

    onnx_dir = target_models / "onnx"
    status_info["onnx"] = {
        "installed": onnx_dir.is_dir() and any(onnx_dir.glob("*.onnx")),
        "files": [p.name for p in onnx_dir.glob("*.onnx")] if onnx_dir.is_dir() else [],
    }

    typer.echo(json.dumps(status_info, indent=2, default=str))


@ml_app.command("prepare-dataset")
def ml_prepare_dataset(
    data: Annotated[Path, typer.Option("--data", help="dataset directory")] = Path("ml/datasets/data"),
    seed: Annotated[int, typer.Option("--seed")] = 42,
    scale: Annotated[float, typer.Option("--scale")] = 1.0,
    replay: Annotated[
        Path | None, typer.Option("--replay", help="also write replay-event JSONL here")
    ] = None,
) -> None:
    """Generate synthetic labelled dataset."""
    from ml.cli import prepare_dataset as _prep

    _prep(data=data, seed=seed, scale=scale, replay=replay)


@ml_app.command("extract-features")
def ml_extract_features(
    data: Annotated[Path, typer.Option("--data", help="dataset directory")] = Path("ml/datasets/data"),
) -> None:
    """Extract features: samples.jsonl -> features.npz."""
    from ml.cli import extract as _ext

    _ext(data=data)


@ml_app.command("export")
def ml_export(
    models: Annotated[Path, typer.Option("--models", help="models directory")] = Path("data/models"),
) -> None:
    """Export models to ONNX."""
    from ml.cli import export as _exp

    _exp(models=models)


@ml_app.command("benchmark")
def ml_benchmark(
    data: Annotated[Path, typer.Option("--data", help="dataset directory")] = Path("ml/datasets/data"),
    models: Annotated[Path, typer.Option("--models", help="models directory")] = Path("data/models"),
    n: Annotated[int, typer.Option("-n")] = 3000,
) -> None:
    """Run ML inference latency and throughput benchmark."""
    from ml.cli import benchmark as _bench

    _bench(data=data, models=models, n=n)


@ml_app.command("all")
def ml_all(
    data: Annotated[Path, typer.Option("--data", help="dataset directory")] = Path("ml/datasets/data"),
    models: Annotated[Path, typer.Option("--models", help="models directory")] = Path("data/models"),
    seed: Annotated[int, typer.Option("--seed")] = 42,
) -> None:
    """Run full pipeline: prepare -> extract -> train -> validate -> test -> benchmark."""
    from ml.cli import run_all as _all

    _all(data=data, models=models, seed=seed)


# --------------------------------------------------------------------------- RAG
@rag_app.command("ingest")
def rag_ingest(
    config: ConfigOpt = None,
    rag_dir: Annotated[Path | None, typer.Option(help="RAG directory (contains documents/)")] = None,
    index: Annotated[
        Path | None, typer.Option(help="index DB path (default <data_dir>/rag_index.db)")
    ] = None,
    force: Annotated[bool, typer.Option(help="re-embed everything")] = False,
) -> None:
    """Ingest rag/documents into the local vector index (incremental)."""
    from centralium.agent.rag import build_retriever
    from centralium.agent.runtime import resolve_project_path

    cfg = load_config(config)
    rdir = resolve_project_path(rag_dir or cfg.paths.rag_dir)
    idx = index or (Path(cfg.paths.data_dir) / "rag_index.db")
    idx.parent.mkdir(parents=True, exist_ok=True)
    retriever, report = build_retriever(rdir, idx, force_reindex=force)
    typer.echo(
        json.dumps(
            {"index": str(idx), "report": str(report), "info": retriever.info()}, default=str, indent=2
        )
    )
    retriever.close()


@rag_app.command("query")
def rag_query(
    text: Annotated[str, typer.Argument()],
    k: Annotated[int, typer.Option()] = 4,
    config: ConfigOpt = None,
) -> None:
    """Query the local index (debug aid)."""
    from centralium.agent.rag import build_retriever
    from centralium.agent.runtime import resolve_project_path

    cfg = load_config(config)
    retriever, _ = build_retriever(
        resolve_project_path(cfg.paths.rag_dir), Path(cfg.paths.data_dir) / "rag_index.db"
    )
    for d in retriever.retrieve(text, k):
        typer.echo(f"{d.score:.3f}  [{d.source}] {d.doc_id}  {d.title}")
    retriever.close()


# --------------------------------------------------------------------------- scan
@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="file or directory to scan (never executed)")],
    config: ConfigOpt = None,
    recursive: Annotated[bool, typer.Option("--recursive", "-r", help="scan directory recursively")] = True,
    max_files: Annotated[int, typer.Option("--max-files", help="max files to scan if directory")] = 500,
    json_out: Annotated[bool, typer.Option("--json", help="force machine-readable JSON output")] = False,
) -> None:
    """Scan file or directory: EPP IOC/blocklist + YARA + static analysis + threat intel.
    Exit 1 if any file is known-malicious."""
    from centralium.agent.epp import build_epp_stack
    from centralium.agent.epp.hashing import sha256_file
    from centralium.agent.models import Finding, FindingSource, Severity
    from centralium.agent.runtime import resolve_project_path
    from centralium.agent.threat_intel.store import CachedIOCStore

    cfg = load_config(config)
    try:
        real = path.expanduser().resolve(strict=True)
    except OSError as exc:
        typer.echo(f"cannot read {path}: {exc}", err=True)
        raise typer.Exit(2) from exc

    files_to_scan: list[Path] = []
    if real.is_file():
        files_to_scan.append(real)
    elif real.is_dir():
        pattern = "**/*" if recursive else "*"
        for p in sorted(real.glob(pattern)):
            if p.is_file():
                files_to_scan.append(p)
                if len(files_to_scan) >= max_files:
                    break
    else:
        typer.echo(f"{real} is not a regular file or directory", err=True)
        raise typer.Exit(2)

    prof = cfg.resource_profile
    max_bytes = prof.max_scan_file_mb * 1024 * 1024
    db_target = _db_path(cfg) if _db_path(cfg).exists() else ":memory:"

    with Database(db_target) as db:
        stack = build_epp_stack(
            db, resolve_project_path(cfg.paths.rules_dir), max_scan_mb=prof.max_scan_file_mb
        )
        ti_store = CachedIOCStore(db)

        scan_results: list[dict[str, Any]] = []
        any_known_malicious = False

        for f in files_to_scan:
            try:
                sz = f.stat().st_size
            except OSError:
                continue
            if sz > max_bytes:
                scan_results.append(
                    {
                        "path": str(f),
                        "skipped": True,
                        "reason": f"file larger than {prof.max_scan_file_mb} MB limit",
                    }
                )
                continue

            sha = sha256_file(f, max_bytes=max_bytes)
            ev = NormalizedEvent(
                event_type=EventType.FILE_CREATE,
                file_path=str(f),
                hash_sha256=sha,
                source="scan",
                host_id=cfg.host_id,
            )
            findings = list(stack.epp.inspect(ev))
            yara_f = stack.yara.scan_file(f, ev)
            static = stack.static.analyze(f)

            # Check threat intel
            ti_matches = ti_store.match_hash(sha) if sha else []
            for m in ti_matches:
                findings.append(
                    Finding(
                        event_id=ev.event_id,
                        rule_id=f"ti:{m.threat_type or 'hash'}",
                        source=FindingSource.HASH,
                        title=f"Threat-intel hash match: {m.threat_type or 'malicious'}",
                        severity=Severity.CRITICAL if m.confidence >= 0.8 else Severity.HIGH,
                        score=round(m.confidence * 100.0, 1),
                        confidence=m.confidence,
                        known_malicious=True,
                        details=m.metadata,
                    )
                )

            all_f = findings + [yf for yf in yara_f if yf.rule_id not in {x.rule_id for x in findings}]
            is_mal = any(ff.known_malicious for ff in all_f)
            if is_mal:
                any_known_malicious = True

            scan_results.append(
                {
                    "path": str(f),
                    "sha256": sha,
                    "known_malicious": is_mal,
                    "threat_intel_matches": len(ti_matches),
                    "findings": [
                        {
                            "source": ff.source.value,
                            "rule_id": ff.rule_id,
                            "title": ff.title,
                            "severity": ff.severity.value,
                            "score": ff.score,
                            "known_malicious": ff.known_malicious,
                        }
                        for ff in all_f
                    ],
                    "static": static.model_dump(mode="json"),
                }
            )

    output_payload = {
        "target": str(real),
        "total_scanned": len(files_to_scan),
        "known_malicious_detected": any_known_malicious,
        "results": scan_results if len(files_to_scan) > 1 else (scan_results[0] if scan_results else {}),
    }

    if json_out or len(files_to_scan) == 1:
        typer.echo(json.dumps(output_payload, indent=2, default=str))
    else:
        typer.echo(f"Scan complete: {len(files_to_scan)} files inspected under {real}")
        mal_count = sum(1 for r in scan_results if r.get("known_malicious"))
        typer.echo(f"Malicious files detected: {mal_count}")
        for r in scan_results:
            if r.get("known_malicious") or r.get("findings"):
                nf = len(r.get("findings", []))
                typer.echo(f"  [MALICIOUS: {r.get('known_malicious')}] {r['path']} (findings: {nf})")

    raise typer.Exit(1 if any_known_malicious else 0)


# --------------------------------------------------------------------------- quarantine
def _qm(cfg: CentraliumConfig, users: list[str] | None = None) -> Any:
    from centralium.agent.quarantine import FileQuarantineManager

    assert cfg.paths.quarantine_dir is not None
    return FileQuarantineManager(
        cfg.paths.quarantine_dir,
        authorized_users=users if users is not None else [getpass.getuser()],
        protected_paths=cfg.policy.protected_paths,
    )


@quarantine_app.command("list")
def quarantine_list(config: ConfigOpt = None) -> None:
    """List quarantined items."""
    cfg = load_config(config)
    _setup_logging(cfg, quiet_alerts=True)
    recs = _qm(cfg).list()
    typer.echo(json.dumps([r.model_dump(mode="json") for r in recs], indent=2))


@quarantine_app.command("restore")
def quarantine_restore(
    quarantine_id: Annotated[str, typer.Argument()],
    reason: Annotated[str, typer.Option(help="why (required, audited)")],
    authorized_by: Annotated[str, typer.Option(help="must be an authorized user (default: OS user)")] = "",
    yes: Annotated[bool, typer.Option(help="confirm restoring a file that was flagged malicious")] = False,
    config: ConfigOpt = None,
) -> None:
    """Restore a quarantined file (authorized + audited; refuses to overwrite)."""
    from centralium.agent.quarantine import QuarantineAuthError, QuarantineError

    if not yes:
        typer.echo("Restoring quarantined (potentially malicious) files requires --yes.", err=True)
        raise typer.Exit(2)
    cfg = load_config(config)
    _setup_logging(cfg, quiet_alerts=True)
    who = authorized_by or getpass.getuser()
    with Database(_db_path(cfg)) as db:
        qm = _qm(cfg)
        qm._audit = lambda a, e, d: db.audit.append(a, e, d)
        try:
            dest = qm.restore(quarantine_id, authorized_by=who, reason=reason)
        except (QuarantineAuthError, QuarantineError, KeyError, ValueError) as exc:
            typer.echo(f"restore refused: {exc}", err=True)
            raise typer.Exit(1) from exc
    typer.echo(json.dumps({"restored_to": str(dest), "authorized_by": who}))


# --------------------------------------------------------------------------- benchmark
@app.command()
def benchmark(
    config: ConfigOpt = None,
    events: Annotated[int, typer.Option(help="synthetic events for throughput/latency runs")] = 2000,
    out_md: Annotated[Path, typer.Option(help="markdown report")] = Path("docs/BENCHMARKS.md"),
    out_json: Annotated[Path, typer.Option(help="JSON results")] = Path("docs/benchmarks.json"),
    llm_runs: Annotated[int, typer.Option(help="real-LLM analyses to time (0 = skip)")] = 3,
) -> None:
    """Measure ingestion, per-stage latency, funnel, CPU/RAM/DB size... Only measured numbers are written."""
    from centralium.agent.benchmark import run_benchmark, write_reports

    cfg = make_config(config, test=True)
    _setup_logging(cfg, quiet_alerts=True)
    result = run_benchmark(cfg, events=events, llm_runs=llm_runs)
    write_reports(result, out_md, out_json)
    typer.echo(f"wrote {out_md} and {out_json}")
    typer.echo(json.dumps(result.get("headline", {}), indent=2))


# --------------------------------------------------------------------------- purple-team simulate
@app.command("simulate")
def simulate(
    techniques: Annotated[
        str,
        typer.Option("--techniques", "-t", help="Comma-separated ATT&CK IDs (e.g. T1059.001,T1486) or 'all'"),
    ] = "all",
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Report output path (.md or .json)")] = None,
    config: ConfigOpt = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
) -> None:
    """Safe purple-team attack emulation harness for MITRE ATT&CK coverage verification."""
    from centralium.agent.simulate.purple_team import PurpleTeamSimulator

    cfg = make_config(config, test=True)
    _setup_logging(cfg, quiet_alerts=not verbose)

    tech_list = [t.strip() for t in techniques.split(",") if t.strip()]
    simulator = PurpleTeamSimulator(config=cfg)
    report = simulator.run(tech_list)

    typer.echo(report.to_markdown())

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.suffix.lower() == ".json":
            out.write_text(report.to_json(), encoding="utf-8")
        else:
            out.write_text(report.to_markdown(), encoding="utf-8")
        typer.echo(f"\nWrote purple-team report to {out}")


# --------------------------------------------------------------------------- eval harnesses
@eval_app.command("rag")
def eval_rag(
    rag_dir: Annotated[Path, typer.Option(help="path to rag directory")] = Path("rag"),
    index: Annotated[Path | None, typer.Option(help="path to index.db")] = None,
    out: Annotated[Path | None, typer.Option(help="report output path (.md or .json)")] = None,
) -> None:
    """Evaluate RAG retrieval across golden queries.
    Reports Recall@k and MRR comparing BM25 vs Vector vs Hybrid.
    """
    from centralium.agent.eval.rag_eval import run_rag_eval

    rep = run_rag_eval(rag_dir=rag_dir, db_path=index, out_path=out)
    typer.echo(rep.to_markdown())
    if out:
        typer.echo(f"\nWrote report to {out}")


@eval_app.command("llm")
def eval_llm(
    config: ConfigOpt = None,
    out: Annotated[Path | None, typer.Option(help="report output path (.md or .json)")] = None,
) -> None:
    """Evaluate LLM on golden incidents measuring verdict agreement, valid JSON rate, and latency."""
    from dataclasses import asdict

    from centralium.agent.eval.llm_eval import evaluate_llm
    from centralium.agent.interfaces import LLMClient
    from centralium.agent.llm.client import build_llm_client

    cfg = load_config(config)
    client: LLMClient
    if cfg.test_mode or cfg.demo_mode or not cfg.llm.enabled:
        from centralium.agent.llm.mock import MockLLM

        client = MockLLM()
    else:
        client = build_llm_client(cfg.llm)
        if not client.available():
            from centralium.agent.llm.mock import MockLLM

            client = MockLLM()
    rep = evaluate_llm(client)
    typer.echo(rep.to_markdown())
    if out:
        p = Path(out)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.suffix.lower() == ".json":
            p.write_text(json.dumps(asdict(rep), indent=2), encoding="utf-8")
        else:
            p.write_text(rep.to_markdown(), encoding="utf-8")
        typer.echo(f"\nWrote report to {out}")


@eval_app.command("injection")
def eval_injection(
    config: ConfigOpt = None,
    out: Annotated[Path | None, typer.Option(help="report output path (.md or .json)")] = None,
) -> None:
    """Evaluate prompt injection resilience across adversarial command lines, filenames, domains, and text."""
    from dataclasses import asdict

    from centralium.agent.eval.injection_eval import evaluate_injection
    from centralium.agent.interfaces import LLMClient
    from centralium.agent.llm.client import build_llm_client

    cfg = load_config(config)
    client: LLMClient
    if cfg.test_mode or cfg.demo_mode or not cfg.llm.enabled:
        from centralium.agent.llm.mock import MockLLM

        client = MockLLM()
    else:
        client = build_llm_client(cfg.llm)
        if not client.available():
            from centralium.agent.llm.mock import MockLLM

            client = MockLLM()
    rep = evaluate_injection(client)
    typer.echo(rep.to_markdown())
    if out:
        p = Path(out)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.suffix.lower() == ".json":
            p.write_text(json.dumps(asdict(rep), indent=2), encoding="utf-8")
        else:
            p.write_text(rep.to_markdown(), encoding="utf-8")
        typer.echo(f"\nWrote report to {out}")


if __name__ == "__main__":
    app()
