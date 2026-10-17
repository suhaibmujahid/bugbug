"""Tests for OpenAI-specific GCP Workload Identity Federation behaviour.

Shared behaviour (token file, refresh, idempotency) is covered in test_gcp_wif.
"""

import logging
import os

import pytest
from hackbot_runtime import openai_wif

pytestmark = pytest.mark.usefixtures("clean_wif_env")


def test_configure_uses_default_audience(monkeypatch, tmp_path, fetch_calls):
    monkeypatch.setenv("OPENAI_FEDERATION_RULE_ID", "idpm_abc")
    monkeypatch.setenv(openai_wif.TOKEN_FILE_ENV, str(tmp_path / "tok"))

    assert openai_wif.configure() is True
    assert fetch_calls == [openai_wif.OPENAI_AUDIENCE]


def test_configure_honours_audience_override(monkeypatch, tmp_path, fetch_calls):
    monkeypatch.setenv("OPENAI_FEDERATION_RULE_ID", "idpm_abc")
    monkeypatch.setenv("OPENAI_WIF_AUDIENCE", "https://custom.example")
    monkeypatch.setenv(openai_wif.TOKEN_FILE_ENV, str(tmp_path / "tok"))

    assert openai_wif.configure() is True
    assert fetch_calls == ["https://custom.example"]


def test_configure_warns_but_proceeds_when_api_key_set(
    monkeypatch, tmp_path, caplog, fetch_calls
):
    token_file = tmp_path / "tok"
    monkeypatch.setenv("OPENAI_FEDERATION_RULE_ID", "idpm_abc")
    monkeypatch.setenv(openai_wif.TOKEN_FILE_ENV, str(token_file))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-leftover")

    with caplog.at_level(logging.WARNING, logger=openai_wif.log.name):
        assert openai_wif.configure() is True

    # Codex prefers federation, so a leftover key is only a warning.
    assert any(
        rec.levelno == logging.WARNING and "OPENAI_API_KEY" in rec.message
        for rec in caplog.records
    )
    assert token_file.read_text() == "google.jwt.token"
    assert os.environ["OPENAI_API_KEY"] == "sk-leftover"
