"""GCP Workload Identity Federation for Anthropic API auth.

The Anthropic SDK and the Claude Code CLI (which the claude-agent-sdk spawns)
exchange a Google identity token for a short-lived Anthropic access token
themselves, driven entirely by environment variables:

  ``ANTHROPIC_FEDERATION_RULE_ID``   federation rule (``fdrl_…``)   ── set by deploy
  ``ANTHROPIC_ORGANIZATION_ID``      Anthropic org id               ── set by deploy
  ``ANTHROPIC_SERVICE_ACCOUNT_ID``   target service account         ── set by deploy
  ``ANTHROPIC_WORKSPACE_ID``         workspace (optional)           ── set by deploy
  ``ANTHROPIC_IDENTITY_TOKEN_FILE``  path to the Google JWT         ── managed here

The deploy provisions the four federation ids; :mod:`hackbot_runtime.gcp_wif`
owns the fifth and keeps the token fresh.

When ``ANTHROPIC_FEDERATION_RULE_ID`` is absent the runtime is in API-key mode
and this module is inert, so local/compose runs keep using ``ANTHROPIC_API_KEY``.

See https://platform.claude.com/docs/en/manage-claude/wif-providers/gcp
"""

from __future__ import annotations

import logging

from pydantic_settings import BaseSettings, SettingsConfigDict

from hackbot_runtime.gcp_wif import WifAuth, WifSettings

log = logging.getLogger("hackbot_runtime.anthropic_wif")

# Audience the metadata token is minted for; must match the federation rule's
# ``audience`` matcher on the Anthropic side.
ANTHROPIC_AUDIENCE = "https://api.anthropic.com"


class AnthropicWifSettings(WifSettings):
    provider_name = "Anthropic"
    env_prefix = "ANTHROPIC_"
    default_audience = ANTHROPIC_AUDIENCE

    @classmethod
    def from_env(cls) -> AnthropicWifSettings:
        return _AnthropicWifEnvSettings()


class _AnthropicWifEnvSettings(AnthropicWifSettings, BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=AnthropicWifSettings.env_prefix,
        env_ignore_empty=True,
        extra="ignore",
    )


TOKEN_FILE_ENV = AnthropicWifSettings.token_file_env()

_auth = WifAuth(AnthropicWifSettings.from_env, log)
configure = _auth.configure
is_enabled = _auth.is_enabled
