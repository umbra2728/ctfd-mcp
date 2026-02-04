from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv


DEFAULT_USER_AGENT = "ctfd-mcp/0.1 (+https://github.com/)"


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


@dataclass
class Config:
    base_url: str
    token: str | None = None
    session_cookie: str | None = None
    csrf_token: str | None = None
    total_timeout: float | None = None
    connect_timeout: float | None = None
    read_timeout: float | None = None
    username: str | None = None
    password: str | None = None
    user_agent: str | None = None

    @property
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.token}"} if self.token else {}


def _parse_timeout(env_key: str) -> float | None:
    raw = os.getenv(env_key)
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError as exc:  # noqa: B904 - more readable error
        raise ConfigError(f"{env_key} must be a number (seconds).") from exc


def load_config() -> Config:
    """Load config from environment or .env and validate values."""
    load_dotenv()

    base_url = os.getenv("CTFD_URL")
    token = os.getenv("CTFD_TOKEN")
    session_cookie = os.getenv("CTFD_SESSION")
    csrf_token = os.getenv("CTFD_CSRF_TOKEN")
    username = os.getenv("CTFD_USERNAME")
    password = os.getenv("CTFD_PASSWORD")
    total_timeout = _parse_timeout("CTFD_TIMEOUT")
    connect_timeout = _parse_timeout("CTFD_CONNECT_TIMEOUT")
    read_timeout = _parse_timeout("CTFD_READ_TIMEOUT")
    user_agent = os.getenv("CTFD_USER_AGENT")

    if not base_url:
        raise ConfigError(
            "CTFD_URL is not set. Provide full URL to your CTFd instance."
        )

    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ConfigError("CTFD_URL must be a full URL, e.g. https://ctfd.example.com")

    # Precedence: username/password > token > session cookie.
    if username and password:
        token = None
        session_cookie = None
        csrf_token = None
    elif token:
        session_cookie = None
        csrf_token = None

    if not token and not session_cookie and not (username and password):
        raise ConfigError(
            "Set CTFD_TOKEN, CTFD_SESSION or both CTFD_USERNAME/CTFD_PASSWORD."
        )

    user_agent = user_agent.strip() if user_agent else ""
    if not user_agent:
        user_agent = DEFAULT_USER_AGENT

    return Config(
        base_url.rstrip("/"),
        token.strip() if token else None,
        session_cookie.strip() if session_cookie else None,
        csrf_token.strip() if csrf_token else None,
        total_timeout=total_timeout,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        username=username.strip() if username else None,
        password=password.strip() if password else None,
        user_agent=user_agent,
    )
