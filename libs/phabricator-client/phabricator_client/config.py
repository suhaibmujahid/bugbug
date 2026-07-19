"""Configuration for :class:`PhabricatorClient`."""

from typing import Annotated

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class PhabricatorSettings(BaseSettings):
    url: str = "https://phabricator.services.mozilla.com"
    timeout_seconds: int = 60

    api_key: Annotated[str, Field(min_length=32, max_length=32)]

    model_config = SettingsConfigDict(env_prefix="PHABRICATOR_", extra="ignore")
