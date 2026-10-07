# ruff: noqa: B008
"""Typer CLI: ``python -m ml.cli <command>`` (also scripts/ml_cli.py)."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from ml.benchmarks.bench import run_benchmark, write_result
from ml.datasets.replay import write_replay
from ml.datasets.synthetic import DEFAULT_SEED, write_dataset
from ml.evaluation.evaluate import evaluate, write_report
from ml.training.data import extract_features, load_dataset, split_dataset
from ml.training.export import export_onnx
from ml.training.pipeline import DEFAULT_DATA_DIR, DEFAULT_MODELS_DIR
from ml.training.train import train_anomaly, train_classifier

app = typer.Typer(
    help="Centralium ML pipeline (synthetic data unless stated otherwise)", no_args_is_help=True
)

DataOpt = typer.Option(DEFAULT_DATA_DIR, "--data", help="dataset directory")
ModelsOpt = typer.Option(DEFAULT_MODELS_DIR, "--models", help="models directory")
SeedOpt = typer.Option(DEFAULT_SEED, "--seed")


def _show(obj: object) -> None:
    typer.echo(json.dumps(obj, indent=2, sort_keys=True, default=str))


@app.command("prepare-dataset")
def prepare_dataset(
    data: Path = DataOpt,
    seed: int = SeedOpt,
    scale: float = 1.0,
    replay: Path | None = typer.Option(None, help="also write replay-event JSONL here"),
) -> None:
    """Generate the SYNTHETIC labelled dataset (+ optional replay events)."""
    meta = write_dataset(data, seed, scale)
    if replay:
        meta["replay_events"] = write_replay(replay, seed)
    _show(meta)


@app.command("extract-features")
def extract(data: Path = DataOpt) -> None:
    """samples.jsonl -> features.npz (schema validated)."""
    typer.echo(str(extract_features(data)))


@app.command("train-anomaly")
def cmd_train_anomaly(data: Path = DataOpt, models: Path = ModelsOpt, seed: int = SeedOpt) -> None:
    parts = split_dataset(load_dataset(data), seed)
    _show(train_anomaly(parts["train"], parts["val"], models, seed))


@app.command("train-classifier")
def cmd_train_classifier(data: Path = DataOpt, models: Path = ModelsOpt, seed: int = SeedOpt) -> None:
    parts = split_dataset(load_dataset(data), seed)
    _show(train_classifier(parts["train"], models, seed))


@app.command("validate")
def validate(data: Path = DataOpt, models: Path = ModelsOpt) -> None:
    """Metrics on the validation split."""
    rep = evaluate(models, data, "val")
    typer.echo(f"wrote {write_report(rep)}")
    _show(rep)


@app.command("test")
def test(data: Path = DataOpt, models: Path = ModelsOpt) -> None:
    """Metrics on the held-out test split (run once, after model selection)."""
    rep = evaluate(models, data, "test")
    typer.echo(f"wrote {write_report(rep)}")
    _show(rep)


@app.command("export")
def export(models: Path = ModelsOpt) -> None:
    """Optional ONNX export."""
    _show(export_onnx(models))


@app.command("benchmark")
def benchmark(data: Path = DataOpt, models: Path = ModelsOpt, n: int = 3000) -> None:
    res = run_benchmark(models, data, n)
    typer.echo(f"wrote {write_result(res)}")
    _show(res)


@app.command("all")
def run_all(data: Path = DataOpt, models: Path = ModelsOpt, seed: int = SeedOpt) -> None:
    """prepare -> extract -> train -> validate -> test -> benchmark."""
    write_dataset(data, seed)
    extract_features(data)
    parts = split_dataset(load_dataset(data), seed)
    train_anomaly(parts["train"], parts["val"], models, seed)
    train_classifier(parts["train"], models, seed)
    for split in ("val", "test"):
        write_report(evaluate(models, data, split))
    write_result(run_benchmark(models, data))
    typer.echo("done: reports in ml/evaluation/reports, benchmark in ml/benchmarks/results")


if __name__ == "__main__":
    app()
