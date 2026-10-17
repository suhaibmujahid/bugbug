"""GCP Workload Identity Federation for Weights & Biases (Weave) auth.

W&B identity federation lets the wandb/weave SDK authenticate from a short-lived
JWT instead of a long-lived ``WANDB_API_KEY``: the SDK reads a JWT from the file
named by ``WANDB_IDENTITY_TOKEN_FILE`` and exchanges it for a W&B access token. On
GCP we mint that JWT as a Google-signed OIDC identity token, so the agent
container holds no W&B credential at all.

  ``WANDB_FEDERATION_AUDIENCE``            audience for the Google JWT  ── set by deploy
  ``WANDB_IDENTITY_TOKEN_FILE``            path to the Google JWT       ── managed here
  ``WANDB_IDENTITY_TOKEN_REFRESH_SECONDS`` refresh cadence (optional)   ── set by deploy

The deploy provisions the audience (which must match the W&B org's federation
trust config); :mod:`hackbot_runtime.gcp_wif` owns the token file and keeps it
fresh.

When ``WANDB_FEDERATION_AUDIENCE`` is absent the runtime is in API-key mode and
this module is inert, so local/compose runs keep using ``WANDB_API_KEY``.

See https://docs.wandb.ai/platform/hosting/iam/identity_federation
"""

from __future__ import annotations

import logging

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from hackbot_runtime.gcp_wif import WifAuth, WifSettings

log = logging.getLogger("hackbot_runtime.wandb_wif")


class WandbWifSettings(WifSettings):
    provider_name = "W&B"
    env_prefix = "WANDB_"
    # W&B has no federation rule id: presence of the audience is what flips the
    # runtime to WIF mode, and its value is what the Google token is minted for.
    enable_field = "audience"

    audience: str | None = Field(
        default=None, validation_alias="WANDB_FEDERATION_AUDIENCE"
    )

    @classmethod
    def from_env(cls) -> WandbWifSettings:
        return _WandbWifEnvSettings()


class _WandbWifEnvSettings(WandbWifSettings, BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=WandbWifSettings.env_prefix,
        env_ignore_empty=True,
        extra="ignore",
    )


TOKEN_FILE_ENV = WandbWifSettings.token_file_env()

_auth = WifAuth(WandbWifSettings.from_env, log)
configure = _auth.configure
is_enabled = _auth.is_enabled
