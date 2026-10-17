"""GCP Workload Identity Federation plumbing shared by the provider modules.

On GCP (Cloud Run, Cloud Functions, GCE, GKE) a workload can fetch a
Google-signed OIDC identity token from the instance metadata server (via the
``google-auth`` library) and exchange it for a short-lived provider access token,
instead of shipping a static API key. The provider SDKs/CLIs do the exchange and
refresh themselves; all they need is a file holding a fresh Google JWT, named by
a ``<PREFIX>IDENTITY_TOKEN_FILE`` env var.

This module owns that file: it fetches the Google identity token, writes it to a
private file, points the env var at it, and keeps it fresh in a background
thread. Google identity tokens live ~1h and the SDKs re-read the file on every
exchange, so a periodically-rewritten file transparently keeps auth alive for
runs longer than a token's lifetime.

Each provider (:mod:`~hackbot_runtime.anthropic_wif`,
:mod:`~hackbot_runtime.openai_wif`, :mod:`~hackbot_runtime.wandb_wif`) declares a
:class:`WifSettings` subclass with its env prefix and policy, and exposes a
:class:`WifAuth` built from it.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

import google.auth.transport.requests
import google.oauth2.id_token
from google.auth.exceptions import GoogleAuthError
from pydantic import BaseModel, PositiveFloat, SecretStr

from hackbot_runtime.providers import ProviderError

# Google identity tokens expire after ~1h; refresh well inside that window so
# the file always carries plenty of remaining lifetime for the SDK to exchange.
DEFAULT_REFRESH_INTERVAL = 1800


class WifSettings(BaseModel):
    """Federation config for one provider, read from ``<env_prefix>*`` env vars.

    Subclasses set the class-level policy and provide ``from_env()`` via a private
    ``BaseSettings`` subclass, the same pattern as ``PhabricatorSettings``.
    """

    # Human-readable name for logs and errors, e.g. "Anthropic".
    provider_name: ClassVar[str]
    # Env prefix shared by every field, e.g. "ANTHROPIC_".
    env_prefix: ClassVar[str]
    # Field whose presence flips the runtime from API-key mode to WIF mode; the
    # deploy sets it only on federation-enabled workloads.
    enable_field: ClassVar[str] = "federation_rule_id"
    # Audience used when ``audience`` is not set; ``None`` makes it required.
    default_audience: ClassVar[str | None] = None
    # Whether a leftover ``<PREFIX>API_KEY`` takes precedence over federation in
    # the provider's SDK. If so, configuring WIF would be silently ignored, so we
    # refuse and log an error instead.
    api_key_shadows_wif: ClassVar[bool] = True

    federation_rule_id: str | None = None
    audience: str | None = None
    identity_token_file: Path | None = None
    identity_token_refresh_seconds: PositiveFloat = DEFAULT_REFRESH_INTERVAL
    api_key: SecretStr | None = None

    @classmethod
    def from_env(cls) -> WifSettings:
        raise NotImplementedError

    @classmethod
    def token_file_env(cls) -> str:
        """Env var the provider SDK reads the identity token path from."""
        return f"{cls.env_prefix}IDENTITY_TOKEN_FILE"

    @classmethod
    def api_key_env(cls) -> str:
        return f"{cls.env_prefix}API_KEY"

    @classmethod
    def slug(cls) -> str:
        """Short lowercase id for temp dirs and thread names, e.g. "anthropic"."""
        return cls.env_prefix.rstrip("_").lower()

    @property
    def enabled(self) -> bool:
        return bool(getattr(self, self.enable_field))

    @property
    def resolved_audience(self) -> str:
        audience = self.audience or self.default_audience
        if not audience:
            raise ProviderError(
                f"{self.provider_name} federation is enabled but no audience is set."
            )
        return audience


def fetch_gcp_identity_token(audience: str, provider_name: str = "provider") -> str:
    """Fetch a Google-signed OIDC identity token for ``audience``.

    Delegates to ``google.oauth2.id_token``, which sources the token from the
    GCE/Cloud Run/GKE metadata server (or a ``GOOGLE_APPLICATION_CREDENTIALS``
    service-account file for local testing). On the metadata path it requests
    ``format=full``, so the token carries the ``email`` claim federation rules
    match on; without it Anthropic's exchange fails with ``invalid_grant``.
    """
    request = google.auth.transport.requests.Request()
    try:
        token = google.oauth2.id_token.fetch_id_token(request, audience)
    except GoogleAuthError as exc:
        # Surface provider-credential failures as a single ProviderError type so
        # callers (and the refresh loop) handle them uniformly.
        raise ProviderError(
            "Failed to fetch a Google identity token for "
            f"{provider_name} federation: {exc}"
        ) from exc
    if not token:
        raise ProviderError(
            "Google returned an empty identity token; the workload has no usable "
            "service account."
        )
    return token


def _default_token_path(slug: str) -> Path:
    """A private, process-owned, absolute path for the identity token file.

    ``mkdtemp`` gives a 0700 directory so the bearer token isn't world-readable.
    """
    return Path(tempfile.mkdtemp(prefix=f"{slug}-wif-")) / "identity-token"


class _TokenFileRefresher:
    """Keeps ``token_file`` populated with a fresh Google identity token.

    The first write happens synchronously in :meth:`start` so a metadata-server
    failure surfaces immediately (fail fast) rather than as an opaque auth error
    once the agent is mid-run. Subsequent writes run on a daemon thread.
    """

    def __init__(
        self,
        token_file: Path,
        interval: float,
        audience: str,
        provider_name: str = "provider",
        slug: str = "provider",
        log: logging.Logger | None = None,
    ):
        self._token_file = token_file
        self._interval = interval
        self._audience = audience
        self._provider_name = provider_name
        self._log = log or logging.getLogger(__name__)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop,
            name=f"{slug}-wif-refresh",
            daemon=True,
        )

    def _write_token(self) -> None:
        """Atomically replace the token file so the SDK never reads a partial write."""
        token = fetch_gcp_identity_token(self._audience, self._provider_name)
        self._token_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._token_file.parent, prefix=".identity-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(token)
            os.replace(tmp, self._token_file)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def _loop(self) -> None:
        # wait() returns True only when stop() is set, so the loop exits cleanly
        # on shutdown and otherwise re-writes the token every interval.
        while not self._stop.wait(self._interval):
            try:
                self._write_token()
            except (ProviderError, OSError) as exc:
                # A transient metadata blip is survivable: the previous token is
                # still on disk and valid for a while, so log and keep the loop
                # alive to retry on the next tick rather than crashing the thread.
                self._log.warning(
                    "Failed to refresh %s WIF identity token; "
                    "serving the previously written token: %s",
                    self._provider_name,
                    exc,
                )

    def start(self) -> None:
        self._write_token()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


class WifAuth:
    """Wires up one provider's WIF auth from its :class:`WifSettings`."""

    def __init__(self, load_settings: Callable[[], WifSettings], log: logging.Logger):
        self._load_settings = load_settings
        self._log = log
        # Set once configure() succeeds; keeps the daemon refresher alive for the
        # process lifetime and makes a second configure() call a no-op.
        self._refresher: _TokenFileRefresher | None = None

    def is_enabled(self) -> bool:
        """True when the deploy provisioned federation for this provider."""
        return self._load_settings().enabled

    def configure(self) -> bool:
        """Start the identity token refresher when the deploy enables WIF.

        Returns ``True`` when WIF was configured, ``False`` in API-key mode.
        Idempotent: a second call while the refresher is running is a no-op.
        Settings are read at call time, so env changes before the call apply.
        """
        settings = self._load_settings()
        if not settings.enabled:
            return False
        if self._refresher is not None:
            return True

        name = settings.provider_name
        api_key_env = settings.api_key_env()
        if settings.api_key is not None:
            if settings.api_key_shadows_wif:
                self._log.error(
                    "%s is set while Workload Identity Federation is configured; "
                    "the API key takes precedence and shadows WIF. Unset it if you "
                    "intend to authenticate via federation.",
                    api_key_env,
                )
                return False
            self._log.warning(
                "%s is set while Workload Identity Federation is configured; "
                "%s auth will use federation instead. Unset %s to keep a "
                "long-lived key out of the container.",
                api_key_env,
                name,
                api_key_env,
            )

        token_file = settings.identity_token_file or _default_token_path(
            settings.slug()
        )
        interval = settings.identity_token_refresh_seconds
        audience = settings.resolved_audience
        refresher = _TokenFileRefresher(
            token_file, interval, audience, name, settings.slug(), self._log
        )
        refresher.start()
        os.environ[settings.token_file_env()] = str(token_file)
        self._refresher = refresher
        self._log.info(
            "%s auth: GCP Workload Identity Federation "
            "(audience %s, identity token file %s, refresh every %ss)",
            name,
            audience,
            token_file,
            interval,
        )
        return True

    def stop(self) -> None:
        """Stop the refresher and allow a later configure() to start over."""
        if self._refresher is not None:
            self._refresher.stop()
            self._refresher = None
