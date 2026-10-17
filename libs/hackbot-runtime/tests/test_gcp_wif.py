"""Tests for the shared GCP Workload Identity Federation plumbing.

Behaviour common to every provider is parametrized over all of them here; the
per-provider test modules only cover what differs (audience, API-key policy).
"""

import os

import pytest
from google.auth.exceptions import GoogleAuthError
from hackbot_runtime import anthropic_wif, gcp_wif, openai_wif, wandb_wif
from hackbot_runtime.providers import ProviderError
from pydantic import ValidationError

# (provider module, env prefix, env var + value that enables WIF)
PROVIDERS = [
    pytest.param(
        anthropic_wif,
        "ANTHROPIC_",
        ("ANTHROPIC_FEDERATION_RULE_ID", "fdrl_abc"),
        id="anthropic",
    ),
    pytest.param(
        openai_wif,
        "OPENAI_",
        ("OPENAI_FEDERATION_RULE_ID", "idpm_abc"),
        id="openai",
    ),
    pytest.param(
        wandb_wif,
        "WANDB_",
        ("WANDB_FEDERATION_AUDIENCE", "https://example.wandb.example/federation"),
        id="wandb",
    ),
]

pytestmark = pytest.mark.usefixtures("clean_wif_env")


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
def test_is_enabled_follows_enable_env(module, prefix, enable, monkeypatch):
    assert module.is_enabled() is False
    monkeypatch.setenv(*enable)
    assert module.is_enabled() is True


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
def test_empty_enable_env_counts_as_disabled(module, prefix, enable, monkeypatch):
    monkeypatch.setenv(enable[0], "")
    assert module.is_enabled() is False


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
def test_configure_is_inert_without_federation(module, prefix, enable, fetch_calls):
    assert module.configure() is False
    assert fetch_calls == []
    assert module.TOKEN_FILE_ENV not in os.environ


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
def test_configure_writes_token_and_sets_env(
    module, prefix, enable, monkeypatch, tmp_path, fetch_calls
):
    token_file = tmp_path / "identity-token"
    monkeypatch.setenv(*enable)
    monkeypatch.setenv(module.TOKEN_FILE_ENV, str(token_file))

    assert module.configure() is True

    assert token_file.read_text() == "google.jwt.token"
    assert os.environ[module.TOKEN_FILE_ENV] == str(token_file)


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
def test_configure_is_idempotent(
    module, prefix, enable, monkeypatch, tmp_path, fetch_calls
):
    monkeypatch.setenv(*enable)
    monkeypatch.setenv(module.TOKEN_FILE_ENV, str(tmp_path / "tok"))

    assert module.configure() is True
    assert module.configure() is True
    # Second call short-circuits: no new refresher, no extra fetch.
    assert len(fetch_calls) == 1


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
def test_configure_defaults_token_path_when_unset(
    module, prefix, enable, monkeypatch, fetch_calls
):
    monkeypatch.setenv(*enable)

    assert module.configure() is True

    path = os.environ[module.TOKEN_FILE_ENV]
    assert f"{prefix.rstrip('_').lower()}-wif-" in path
    # Codex requires an absolute path; keep it that way for everyone.
    assert os.path.isabs(path)
    assert os.path.exists(path)


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
def test_configure_uses_refresh_interval_env(
    module, prefix, enable, monkeypatch, tmp_path, fetch_calls
):
    monkeypatch.setenv(*enable)
    monkeypatch.setenv(module.TOKEN_FILE_ENV, str(tmp_path / "tok"))
    monkeypatch.setenv(f"{prefix}IDENTITY_TOKEN_REFRESH_SECONDS", "900")

    assert module.configure() is True
    assert module._auth._refresher._interval == 900


@pytest.mark.parametrize("module, prefix, enable", PROVIDERS)
@pytest.mark.parametrize("raw", ["not-a-number", "0", "-5"])
def test_configure_rejects_invalid_refresh_interval(
    module, prefix, enable, raw, monkeypatch
):
    monkeypatch.setenv(*enable)
    monkeypatch.setenv(f"{prefix}IDENTITY_TOKEN_REFRESH_SECONDS", raw)

    with pytest.raises(ValidationError, match="identity_token_refresh_seconds"):
        module.configure()


def test_resolved_audience_requires_a_value():
    class _NoDefault(gcp_wif.WifSettings):
        provider_name = "Test"
        env_prefix = "TEST_"

    with pytest.raises(ProviderError, match="no audience is set"):
        _ = _NoDefault(federation_rule_id="x").resolved_audience


def test_fetch_uses_google_auth_with_audience(monkeypatch):
    captured = {}

    def _fake_fetch(request, audience):
        captured["request"] = request
        captured["audience"] = audience
        return "signed.jwt.value"

    monkeypatch.setattr(gcp_wif.google.oauth2.id_token, "fetch_id_token", _fake_fetch)

    token = gcp_wif.fetch_gcp_identity_token("https://aud.example")

    assert token == "signed.jwt.value"
    assert captured["audience"] == "https://aud.example"
    assert captured["request"] is not None


def test_fetch_wraps_google_auth_error(monkeypatch):
    def _raise(*_a, **_k):
        raise GoogleAuthError("metadata server unreachable")

    monkeypatch.setattr(gcp_wif.google.oauth2.id_token, "fetch_id_token", _raise)
    with pytest.raises(
        ProviderError,
        match="Failed to fetch a Google identity token for Anthropic federation",
    ):
        gcp_wif.fetch_gcp_identity_token("https://aud.example", "Anthropic")


def test_fetch_rejects_empty(monkeypatch):
    monkeypatch.setattr(
        gcp_wif.google.oauth2.id_token, "fetch_id_token", lambda *a, **k: ""
    )
    with pytest.raises(ProviderError, match="empty identity token"):
        gcp_wif.fetch_gcp_identity_token("https://aud.example")


def test_token_file_write_is_atomic_and_clean(tmp_path, fetch_calls):
    token_file = tmp_path / "identity-token"
    refresher = gcp_wif._TokenFileRefresher(
        token_file, interval=1800, audience="https://aud.example"
    )

    refresher._write_token()

    assert token_file.read_text() == "google.jwt.token"
    assert fetch_calls == ["https://aud.example"]
    # No leftover temp files from the atomic replace.
    assert list(tmp_path.iterdir()) == [token_file]


def test_refresh_loop_survives_provider_error(monkeypatch, tmp_path):
    refresher = gcp_wif._TokenFileRefresher(
        tmp_path / "tok", interval=0, audience="https://aud.example"
    )
    calls = []

    def _boom(*_a, **_k):
        calls.append(1)
        # Stop after the first failure so the loop exits on its next tick.
        refresher.stop()
        raise ProviderError("transient")

    monkeypatch.setattr(gcp_wif, "fetch_gcp_identity_token", _boom)

    # A ProviderError mid-run is logged and swallowed, not raised out of _loop.
    refresher._loop()

    assert calls == [1]
