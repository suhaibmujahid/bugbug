"""GCP Workload Identity Federation for OpenAI API auth.

The Codex CLI exchanges a Google identity token for a short-lived OpenAI access
token itself, driven entirely by environment variables:

  ``OPENAI_FEDERATION_RULE_ID``             federation rule (``idpm_…``)  ── set by deploy
  ``OPENAI_WIF_AUDIENCE``                   audience override (optional)  ── set by deploy
  ``OPENAI_IDENTITY_TOKEN_REFRESH_SECONDS`` refresh cadence (optional)    ── set by deploy
  ``OPENAI_IDENTITY_TOKEN_FILE``            path to the Google JWT        ── managed here

The deploy provisions the federation rule id; :mod:`hackbot_runtime.gcp_wif` owns
the token file (as an absolute path, which Codex requires) and keeps it fresh.

When ``OPENAI_FEDERATION_RULE_ID`` is absent the runtime is in API-key mode and
this module is inert, so local/compose runs keep using ``OPENAI_API_KEY``.

See https://developers.openai.com/api/docs/guides/workload-identity-federation
"""

from __future__ import annotations

import logging

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from hackbot_runtime.gcp_wif import WifAuth, WifSettings

log = logging.getLogger("hackbot_runtime.openai_wif")

# Default audience the metadata token is minted for; must match the federation
# rule's audience on the OpenAI side. Overridable via ``OPENAI_WIF_AUDIENCE``.
OPENAI_AUDIENCE = "https://api.openai.com/v1"


class OpenAIWifSettings(WifSettings):
    provider_name = "OpenAI"
    env_prefix = "OPENAI_"
    default_audience = OPENAI_AUDIENCE
    # Codex prefers federation over OPENAI_API_KEY, so a leftover key is only
    # worth a warning rather than a reason to skip WIF.
    api_key_shadows_wif = False

    audience: str | None = Field(default=None, validation_alias="OPENAI_WIF_AUDIENCE")

    @classmethod
    def from_env(cls) -> OpenAIWifSettings:
        return _OpenAIWifEnvSettings()


class _OpenAIWifEnvSettings(OpenAIWifSettings, BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=OpenAIWifSettings.env_prefix,
        env_ignore_empty=True,
        extra="ignore",
    )


TOKEN_FILE_ENV = OpenAIWifSettings.token_file_env()

_auth = WifAuth(OpenAIWifSettings.from_env, log)
configure = _auth.configure
is_enabled = _auth.is_enabled
