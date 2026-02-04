import pytest

from ctfd_mcp.config import DEFAULT_USER_AGENT, ConfigError, _parse_timeout, load_config


def _load_with_env(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]):
    monkeypatch.setattr("ctfd_mcp.config.load_dotenv", lambda: None)
    for key in (
        "CTFD_URL",
        "CTFD_TOKEN",
        "CTFD_SESSION",
        "CTFD_CSRF_TOKEN",
        "CTFD_USERNAME",
        "CTFD_PASSWORD",
        "CTFD_TIMEOUT",
        "CTFD_CONNECT_TIMEOUT",
        "CTFD_READ_TIMEOUT",
        "CTFD_USER_AGENT",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return load_config()


def test_username_password_take_priority(monkeypatch: pytest.MonkeyPatch):
    cfg = _load_with_env(
        monkeypatch,
        {
            "CTFD_URL": "https://ctfd.example.com",
            "CTFD_USERNAME": "user1",
            "CTFD_PASSWORD": "pw1",
            "CTFD_TOKEN": "token-should-be-ignored",
            "CTFD_SESSION": "session-should-be-ignored",
            "CTFD_CSRF_TOKEN": "csrf-should-be-ignored",
        },
    )
    assert cfg.username == "user1"
    assert cfg.password == "pw1"
    assert cfg.token is None
    assert cfg.session_cookie is None
    assert cfg.csrf_token is None


def test_token_beats_session_cookie(monkeypatch: pytest.MonkeyPatch):
    cfg = _load_with_env(
        monkeypatch,
        {
            "CTFD_URL": "https://ctfd.example.com",
            "CTFD_TOKEN": "use-this-token",
            "CTFD_SESSION": "drop-this-session",
            "CTFD_CSRF_TOKEN": "csrf-should-be-ignored",
        },
    )
    assert cfg.token == "use-this-token"
    assert cfg.session_cookie is None
    assert cfg.csrf_token is None


def test_session_cookie_when_no_other_creds(monkeypatch: pytest.MonkeyPatch):
    cfg = _load_with_env(
        monkeypatch,
        {
            "CTFD_URL": "https://ctfd.example.com",
            "CTFD_SESSION": "session-only",
        },
    )
    assert cfg.session_cookie == "session-only"
    assert cfg.token is None
    assert cfg.username is None
    assert cfg.password is None


def test_missing_base_url(monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(ConfigError, match="CTFD_URL is not set"):
        _load_with_env(
            monkeypatch,
            {
                "CTFD_TOKEN": "token",
            },
        )


def test_missing_creds(monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(ConfigError, match="Set CTFD_TOKEN"):
        _load_with_env(
            monkeypatch,
            {
                "CTFD_URL": "https://ctfd.example.com",
            },
        )


def test_invalid_url(monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(ConfigError, match="CTFD_URL must be a full URL"):
        _load_with_env(
            monkeypatch,
            {
                "CTFD_URL": "ctfd.example.com",
                "CTFD_TOKEN": "token",
            },
        )


def test_parse_timeout_valid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CTFD_TIMEOUT", "12.5")
    assert _parse_timeout("CTFD_TIMEOUT") == 12.5


def test_parse_timeout_invalid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CTFD_TIMEOUT", "nope")
    with pytest.raises(ConfigError, match="CTFD_TIMEOUT must be a number"):
        _parse_timeout("CTFD_TIMEOUT")


def test_auth_header(monkeypatch: pytest.MonkeyPatch):
    cfg = _load_with_env(
        monkeypatch,
        {
            "CTFD_URL": "https://ctfd.example.com",
            "CTFD_TOKEN": "token",
        },
    )
    assert cfg.auth_header == {"Authorization": "Token token"}


def test_user_agent_default(monkeypatch: pytest.MonkeyPatch):
    cfg = _load_with_env(
        monkeypatch,
        {
            "CTFD_URL": "https://ctfd.example.com",
            "CTFD_TOKEN": "token",
        },
    )
    assert cfg.user_agent == DEFAULT_USER_AGENT


def test_user_agent_override(monkeypatch: pytest.MonkeyPatch):
    cfg = _load_with_env(
        monkeypatch,
        {
            "CTFD_URL": "https://ctfd.example.com",
            "CTFD_TOKEN": "token",
            "CTFD_USER_AGENT": " custom-agent/1.0 ",
        },
    )
    assert cfg.user_agent == "custom-agent/1.0"
