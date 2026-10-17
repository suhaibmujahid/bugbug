"""Tests for Anthropic-specific GCP Workload Identity Federation behaviour.

Shared behaviour (token file, refresh, idempotency) is covered in test_gcp_wif.
"""

import logging
import os

import pytest
from hackbot_runtime import anthropic_wif

pytestmark = pytest.mark.usefixtures("clean_wif_env")


def test_configure_uses_anthropic_audience(monkeypatch, tmp_path, fetch_calls):
    monkeypatch.setenv("ANTHROPIC_FEDERATION_RULE_ID", "fdrl_abc")
    monkeypatch.setenv(anthropic_wif.TOKEN_FILE_ENV, str(tmp_path / "tok"))

    assert anthropic_wif.configure() is True
    assert fetch_calls == [anthropic_wif.ANTHROPIC_AUDIENCE]


def test_configure_refuses_when_api_key_set(monkeypatch, tmp_path, caplog, fetch_calls):
    monkeypatch.setenv("ANTHROPIC_FEDERATION_RULE_ID", "fdrl_abc")
    monkeypatch.setenv(anthropic_wif.TOKEN_FILE_ENV, str(tmp_path / "tok"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-leftover")

    with caplog.at_level(logging.ERROR, logger=anthropic_wif.log.name):
        assert anthropic_wif.configure() is False

    # A key set alongside federation is flagged as an error and left untouched.
    assert any(
        rec.levelno == logging.ERROR and "ANTHROPIC_API_KEY" in rec.message
        for rec in caplog.records
    )
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-leftover"
    assert fetch_calls == []
    assert anthropic_wif._auth._refresher is None
