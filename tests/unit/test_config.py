from __future__ import annotations

import pytest
from pydantic import ValidationError

from centralium.agent.config import (
    CentraliumConfig,
    ModeChangeError,
    ModeManager,
    ResourceProfileName,
    load_config,
)
from centralium.agent.models import OperatingMode, RiskBand
from centralium.agent.storage import Database


def test_defaults_match_spec():
    c = CentraliumConfig()
    assert c.mode == OperatingMode.PASSIVE
    assert c.risk.weights() == {
        "behavioral_ml": 0.25,
        "deterministic_evidence": 0.20,
        "attack_graph": 0.20,
        "threat_intel": 0.15,
        "static_malware": 0.10,
        "ai_assessment": 0.10,
    }
    assert sum(c.risk.weights().values()) == pytest.approx(1.0)
    assert c.llm.concurrency == 1
    assert c.llm.retries_on_invalid_json == 1
    assert c.paths.db_path is not None and c.paths.db_path.name == "centralium.db"


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0, RiskBand.SAFE),
        (19.9, RiskBand.SAFE),
        (20, RiskBand.LOW),
        (39, RiskBand.LOW),
        (40, RiskBand.MEDIUM),
        (59, RiskBand.MEDIUM),
        (60, RiskBand.HIGH),
        (79, RiskBand.HIGH),
        (80, RiskBand.CRITICAL),
        (100, RiskBand.CRITICAL),
    ],
)
def test_risk_bands(score, band):
    assert CentraliumConfig().risk.band_for(score) == band


def test_invalid_bands_and_weights_rejected():
    with pytest.raises(ValidationError):
        CentraliumConfig.model_validate({"risk": {"band_low": 50, "band_medium": 40}})
    with pytest.raises(ValidationError):
        CentraliumConfig.model_validate(
            {
                "risk": {
                    "weight_behavioral_ml": 0,
                    "weight_deterministic_evidence": 0,
                    "weight_attack_graph": 0,
                    "weight_threat_intel": 0,
                    "weight_static_malware": 0,
                    "weight_ai_assessment": 0,
                }
            }
        )
    with pytest.raises(ValidationError):
        CentraliumConfig.model_validate({"unknown_key": 1})


def test_toml_and_env_precedence(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text('mode = "LEARNING"\n[llm]\nmax_tokens = 100\ntimeout_sec = 5\n')
    env = {
        "CENTRALIUM_LLM__MAX_TOKENS": "200",
        "CENTRALIUM_DEMO_MODE": "1",
        "CENTRALIUM_RISK__WEIGHT_THREAT_INTEL": "0.3",
    }
    c = load_config(f, env=env)
    assert c.mode == OperatingMode.LEARNING  # toml
    assert c.llm.timeout_sec == 5  # toml
    assert c.llm.max_tokens == 200  # env beats toml
    assert c.demo_mode is True
    assert c.risk.weight_threat_intel == 0.3
    assert load_config(f, env=env, mode="ACTIVE").mode == OperatingMode.ACTIVE  # kwargs win


def test_missing_config_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.toml", env={})


def test_demo_and_test_mode_force_destructive_off():
    assert CentraliumConfig(mode=OperatingMode.ACTIVE).destructive_response_enabled
    assert CentraliumConfig(mode=OperatingMode.PANIC).destructive_response_enabled
    assert not CentraliumConfig(mode=OperatingMode.ACTIVE, demo_mode=True).destructive_response_enabled
    assert not CentraliumConfig(mode=OperatingMode.PANIC, test_mode=True).destructive_allowed(
        OperatingMode.PANIC
    )
    assert not CentraliumConfig(mode=OperatingMode.LEARNING).destructive_response_enabled
    assert not CentraliumConfig(mode=OperatingMode.PASSIVE).destructive_response_enabled
    passive_ok = CentraliumConfig(mode=OperatingMode.PASSIVE, policy={"passive_destructive_allowed": True})
    assert passive_ok.destructive_response_enabled


def test_resource_profiles():
    low = CentraliumConfig(profile=ResourceProfileName.LOW_RESOURCE)
    assert not low.resource_profile.llm_enabled
    applied = CentraliumConfig(profile=ResourceProfileName.ANALYSIS).apply_resource_profile()
    assert applied.llm.max_ctx == 4096
    assert not low.llm_effective_enabled  # no model path


def test_mode_manager_audits_and_validates(db: Database):
    cfg = CentraliumConfig()
    mm = ModeManager(cfg, lambda a, e, d: db.audit.append(a, e, d))
    assert mm.mode == OperatingMode.PASSIVE
    with pytest.raises(ModeChangeError):
        mm.set_mode(OperatingMode.ACTIVE, actor="", reason="x")
    assert mm.mode == OperatingMode.PASSIVE  # unchanged
    mm.set_mode(OperatingMode.ACTIVE, actor="admin", reason="go live")
    assert mm.mode == OperatingMode.ACTIVE
    entries = db.audit.entries()
    assert entries[0]["event_type"] == "mode_change"
    assert entries[0]["details"] == {"from": "PASSIVE", "to": "ACTIVE", "reason": "go live"}


def test_panic_refused_in_demo_mode_and_audited(db: Database):
    mm = ModeManager(CentraliumConfig(demo_mode=True), lambda a, e, d: db.audit.append(a, e, d))
    with pytest.raises(ModeChangeError):
        mm.set_mode(OperatingMode.PANIC, actor="admin", reason="test")
    assert mm.mode == OperatingMode.PASSIVE
    assert db.audit.entries()[0]["event_type"] == "mode_change_refused"


def test_module_env_vars_are_not_treated_as_config_fields():
    """CENTRALIUM_LLM_SERVER_URL / CENTRALIUM_SYNC_* are read by other modules; they must not break load_config."""
    cfg = load_config(
        None,
        env={
            "CENTRALIUM_LLM_SERVER_URL": "http://127.0.0.1:8080",
            "CENTRALIUM_SYNC_TOKEN": "x",
            "CENTRALIUM_DEMO_MODE": "1",
        },
    )
    assert cfg.demo_mode is True
