"""Shared fixtures for the GCP Workload Identity Federation tests."""

import pytest
from hackbot_runtime import anthropic_wif, gcp_wif, openai_wif, wandb_wif

_WIF_ENV_VARS = [
    f"{prefix}{suffix}"
    for prefix in ("ANTHROPIC_", "OPENAI_", "WANDB_")
    for suffix in (
        "FEDERATION_RULE_ID",
        "FEDERATION_AUDIENCE",
        "WIF_AUDIENCE",
        "AUDIENCE",
        "IDENTITY_TOKEN_FILE",
        "IDENTITY_TOKEN_REFRESH_SECONDS",
        "API_KEY",
    )
]


@pytest.fixture
def clean_wif_env(monkeypatch):
    """Start in API-key mode for every provider and stop any refresher started."""
    for var in _WIF_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield
    for module in (anthropic_wif, openai_wif, wandb_wif):
        module._auth.stop()


@pytest.fixture
def fetch_calls(monkeypatch):
    """Stub the metadata-server fetch and record each audience requested."""
    calls = []

    def _fetch(audience, provider_name="provider"):
        calls.append(audience)
        return "google.jwt.token"

    monkeypatch.setattr(gcp_wif, "fetch_gcp_identity_token", _fetch)
    return calls
