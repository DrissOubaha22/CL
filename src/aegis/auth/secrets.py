"""Secret storage (spec §11).

Spec §11: "scanner/cloud credentials and feed API keys in a vault;
rotated."  This is the seam a vault plugs into, plus the two backends a
deployment actually has on day one:

* ``env`` - the process environment, which is what a container orchestrator
  injects a vault-held secret as.
* ``file`` - a directory of one-file-per-secret, which is the shape a
  mounted Kubernetes secret or a Vault agent sidecar takes.

Both are *reads of something a vault put there*.  A direct HashiCorp Vault
or AWS Secrets Manager client implements :class:`SecretStore` and nothing
else changes; the protocol is the point.

Rotation is observable rather than automatic: :meth:`SecretStore.describe`
reports each secret's age, and a secret past ``secret_max_age_days`` is
reported stale.  Rotating on a schedule is the orchestrator's job; noticing
that nobody did is ours.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

import structlog

from aegis.config import Settings, get_settings

log = structlog.get_logger(__name__)

__all__ = [
    "EnvSecretStore",
    "FileSecretStore",
    "SecretInfo",
    "SecretNotFound",
    "SecretStore",
    "build_secret_store",
]


class SecretNotFound(KeyError):
    """The secret is not present in the configured store."""

    def __init__(self, name: str, where: str) -> None:
        super().__init__(f"secret {name!r} not found in {where}")
        self.name = name


@dataclass(frozen=True, slots=True)
class SecretInfo:
    """What is known about a stored secret, never including its value."""

    name: str
    present: bool
    #: When the secret was last written, where the backend can tell.
    updated_at: datetime | None = None
    source: str = ""

    def age(self, *, now: datetime | None = None) -> timedelta | None:
        if self.updated_at is None:
            return None
        return (now or datetime.now(UTC)) - self.updated_at

    def is_stale(self, max_age_days: int, *, now: datetime | None = None) -> bool:
        """Past its rotation window?

        An unknown age counts as *not* stale: reporting every secret stale
        because a backend cannot date them trains people to ignore the
        report.
        """
        age = self.age(now=now)
        return age is not None and age > timedelta(days=max_age_days)


class SecretStore(Protocol):
    """Anything that can supply a named secret."""

    def get(self, name: str) -> str:  # pragma: no cover - protocol
        """Return the secret, raising :class:`SecretNotFound` if absent."""

    def get_optional(self, name: str) -> str | None:  # pragma: no cover
        """Return the secret, or ``None`` if absent."""

    def describe(self, name: str) -> SecretInfo:  # pragma: no cover
        """Report on a secret without returning its value."""

    def names(self) -> list[str]:  # pragma: no cover
        """Every secret this store holds, by name."""


class EnvSecretStore:
    """Secrets from the process environment.

    Names are upper-cased and prefixed, so ``slack_webhook`` reads
    ``AEGIS_SECRET_SLACK_WEBHOOK``.  The environment carries no write time,
    so ages are unknown and nothing is ever reported stale.
    """

    def __init__(self, *, settings: Settings | None = None) -> None:
        self._prefix = (settings or get_settings()).secret_env_prefix

    def _key(self, name: str) -> str:
        return f"{self._prefix}{name.strip().upper().replace('-', '_')}"

    def get(self, name: str) -> str:
        value = self.get_optional(name)
        if value is None:
            raise SecretNotFound(name, f"environment ({self._key(name)})")
        return value

    def get_optional(self, name: str) -> str | None:
        value = os.environ.get(self._key(name))
        return value if value else None

    def describe(self, name: str) -> SecretInfo:
        return SecretInfo(
            name=name,
            present=self.get_optional(name) is not None,
            updated_at=None,
            source="env",
        )

    def names(self) -> list[str]:
        return sorted(
            key[len(self._prefix) :].lower() for key in os.environ if key.startswith(self._prefix)
        )


class FileSecretStore:
    """Secrets from a directory of files, one per secret.

    The shape a mounted Kubernetes secret or a Vault agent sidecar takes.
    The file's modification time is the rotation date, which makes staleness
    answerable.
    """

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)

    def _path(self, name: str) -> Path | None:
        """The file holding ``name``, or ``None`` if the name is unsafe.

        Returns rather than raises, because ``get_optional`` promises never
        to raise - a traversal attempt is simply a secret that is not there.
        """
        safe = name.strip().lower().replace("/", "_").replace("\\", "_")
        if not safe or safe.startswith("."):
            log.warning("secret.unsafe_name", name=str(name)[:60])
            return None
        return self._dir / safe

    def get(self, name: str) -> str:
        value = self.get_optional(name)
        if value is None:
            raise SecretNotFound(name, str(self._dir))
        return value

    def get_optional(self, name: str) -> str | None:
        path = self._path(name)
        if path is None or not path.is_file():
            return None
        try:
            # Trailing newlines are an artefact of how secrets get written.
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            log.error("secret.read_failed", name=name, error=str(exc))
            return None
        return value or None

    def describe(self, name: str) -> SecretInfo:
        path = self._path(name)
        if path is None or not path.is_file():
            return SecretInfo(name=name, present=False, source=str(self._dir))
        return SecretInfo(
            name=name,
            present=True,
            updated_at=datetime.fromtimestamp(path.stat().st_mtime, tz=UTC),
            source=str(self._dir),
        )

    def names(self) -> list[str]:
        if not self._dir.is_dir():
            return []
        return sorted(
            item.name
            for item in self._dir.iterdir()
            if item.is_file() and not item.name.startswith(".")
        )


def build_secret_store(*, settings: Settings | None = None) -> SecretStore:
    """Construct the configured store.

    Raises:
        ValueError: on an unknown backend, or a file backend with no
            directory.  Starting with a misconfigured vault and discovering
            it at the first credential read is worse than not starting.
    """
    config = settings or get_settings()
    backend = config.secret_backend.strip().lower()

    if backend == "env":
        return EnvSecretStore(settings=config)
    if backend == "file":
        if not config.secret_file_dir:
            raise ValueError("secret_backend is 'file' but secret_file_dir is unset")
        return FileSecretStore(config.secret_file_dir)

    raise ValueError(
        f"unknown secret backend {backend!r}; use 'env' or 'file', or "
        "implement SecretStore for your vault"
    )
