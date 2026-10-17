"""Tests for W&B-specific GCP Workload Identity Federation behaviour.

Shared behaviour (token file, refresh, idempotency) is covered in test_gcp_wif.
"""

import logging
import os

import pytest
from hackbot_runtime import wandb_wif

pytestmark = pytest.mark.usefixtures("clean_wif_env")

_AUDIENCE = "https://example.wandb.example/federation"


def test_configure_passes_audience_to_fetch(monkeypatch, tmp_path, fetch_calls):
    monkeypatch.setenv("WANDB_FEDERATION_AUDIENCE", _AUDIENCE)
    monkeypatch.setenv(wandb_wif.TOKEN_FILE_ENV, str(tmp_path / "tok"))

    assert wandb_wif.configure() is True
    assert fetch_calls == [_AUDIENCE]


def test_rule_id_alone_does_not_enable(monkeypatch):
    # W&B has no federation rule; only the audience turns WIF on.
    monkeypatch.setenv("WANDB_FEDERATION_RULE_ID", "anything")
    assert wandb_wif.is_enabled() is False


def test_configure_refuses_when_api_key_set(monkeypatch, tmp_path, caplog, fetch_calls):
    monkeypatch.setenv("WANDB_FEDERATION_AUDIENCE", _AUDIENCE)
    monkeypatch.setenv(wandb_wif.TOKEN_FILE_ENV, str(tmp_path / "tok"))
    monkeypatch.setenv("WANDB_API_KEY", "leftover")

    with caplog.at_level(logging.ERROR, logger=wandb_wif.log.name):
        assert wandb_wif.configure() is False

    assert any(
        rec.levelno == logging.ERROR and "WANDB_API_KEY" in rec.message
        for rec in caplog.records
    )
    assert os.environ["WANDB_API_KEY"] == "leftover"
    assert fetch_calls == []
    assert wandb_wif._auth._refresher is None
