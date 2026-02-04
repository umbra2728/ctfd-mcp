import asyncio
import json
import httpx
import pytest

from ctfd_mcp.config import Config, ConfigError
from ctfd_mcp.ctfd_client import (
    AuthError,
    CTFdClient,
    CTFdClientError,
    NotFoundError,
    RateLimitError,
    _html_to_text,
)
from ctfd_mcp.server import (
    _challenge_markdown,
    _format_error,
    challenge_details,
    list_challenges,
    start_container,
    stop_container,
    submit_flag,
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def base_config():
    return Config(base_url="https://ctfd.example.com", token="test-token")


@pytest.fixture
def make_client(base_config):
    def _make(transport: httpx.MockTransport, config: Config | None = None):
        cfg = config or base_config
        client = CTFdClient(cfg, timeout=None)
        run(client._client.aclose())
        client._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            headers=client._client.headers,
            cookies=client._client.cookies,
            transport=transport,
            follow_redirects=True,
            http2=False,
        )
        return client

    return _make


def test_user_agent_header_custom(make_client):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.headers.get("User-Agent") == "custom-agent/1.0"
        if request.url.path == "/api/v1/challenges/123":
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "id": 123,
                        "name": "Example",
                        "category": "misc",
                        "value": 100,
                        "description": "<p>hi</p>",
                        "type": "standard",
                        "tags": [],
                        "files": [],
                    },
                },
            )
        return httpx.Response(404, json={"success": False, "message": "not found"})

    transport = httpx.MockTransport(handler)
    cfg = Config(
        base_url="https://ctfd.example.com",
        token="test-token",
        user_agent="custom-agent/1.0",
    )
    client = make_client(transport, config=cfg)
    try:
        detail = run(client.get_challenge(123))
        assert detail.get("id") == 123
    finally:
        run(client.aclose())

    assert calls == ["/api/v1/challenges/123"]


def test_token_auth_headers_and_no_csrf(make_client):
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        assert request.headers.get("Authorization") == "Token test-token"
        assert request.headers.get("CSRF-Token") is None

        if request.url.path == "/api/v1/challenges/123":
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "id": 123,
                        "name": "Example",
                        "category": "misc",
                        "value": 100,
                        "description": "<p>hi</p>",
                        "type": "standard",
                        "tags": [],
                        "files": [],
                    },
                },
            )

        if request.url.path == "/api/v1/challenges/attempt":
            body = json.loads(request.content.decode("utf-8"))
            assert body["challenge_id"] == 123
            assert body["submission"] == "flag{test}"
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {"status": "correct", "message": "ok"},
                },
            )

        return httpx.Response(404, json={"success": False, "message": "not found"})

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        detail = run(client.get_challenge(123))
        assert detail.get("id") == 123
        result = run(client.submit_flag(123, "flag{test}"))
        assert result.get("status") == "correct"
    finally:
        run(client.aclose())

    paths = [p for _, p in calls]
    assert paths == ["/api/v1/challenges/123", "/api/v1/challenges/attempt"]


def test_session_cookie_csrf_refresh_on_403(make_client):
    calls: list[tuple[str, str, str | None]] = []
    state = {"refreshed": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(
            (request.method, request.url.path, request.headers.get("CSRF-Token"))
        )
        if request.url.path == "/api/v1/csrf_token":
            state["refreshed"] += 1
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {"csrf_token": f"api-token-{state['refreshed']}"},
                },
            )
        if request.url.path == "/challenges":
            html = (
                '<input type="hidden" name="nonce" '
                f'value="page-nonce-{state["refreshed"]}">'  # noqa: E501
            )
            return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})
        if request.url.path == "/api/v1/challenges/attempt":
            if request.headers.get("CSRF-Token") != "page-nonce-1":
                return httpx.Response(403, json={"success": False, "message": "CSRF"})
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {"status": "correct", "message": "ok"},
                },
            )
        return httpx.Response(404, json={"success": False, "message": "not found"})

    transport = httpx.MockTransport(handler)
    cfg = Config(base_url="https://ctfd.example.com", session_cookie="session")
    client = make_client(transport, config=cfg)
    client._csrf_token = "stale"
    try:
        result = run(client.submit_flag(1, "flag{test}"))
        assert result.get("status") == "correct"
    finally:
        run(client.aclose())

    post_tokens = [t for m, p, t in calls if m == "POST" and p.endswith("/attempt")]
    assert post_tokens[0] == "stale"
    assert post_tokens[-1] == "page-nonce-1"


def test_session_cookie_fetches_csrf_token(make_client):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/v1/csrf_token":
            return httpx.Response(
                200,
                json={"success": True, "data": {"csrf_token": "api-token"}},
            )
        if request.url.path == "/challenges":
            html = '<input type="hidden" name="nonce" value="page-nonce">'
            return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})
        if request.url.path == "/api/v1/challenges/attempt":
            assert request.headers.get("CSRF-Token") == "page-nonce"
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {"status": "correct", "message": "ok"},
                },
            )
        return httpx.Response(404, json={"success": False, "message": "not found"})

    transport = httpx.MockTransport(handler)
    cfg = Config(base_url="https://ctfd.example.com", session_cookie="session")
    client = make_client(transport, config=cfg)
    try:
        result = run(client.submit_flag(1, "flag{test}"))
        assert result.get("status") == "correct"
    finally:
        run(client.aclose())

    assert "/api/v1/csrf_token" in calls
    assert "/challenges" in calls
    assert calls[-1] == "/api/v1/challenges/attempt"


def test_html_to_text_and_nonce_parsing(base_config):
    assert _html_to_text("<p>Hello</p><div>World</div>") == "Hello\nWorld"
    client = CTFdClient(base_config, timeout=None)
    try:
        assert client._extract_nonce('<input type="hidden" name="nonce" value="abc">') == "abc"
        assert client._extract_nonce("var config = {'csrfNonce': \"def\"};") == "def"
    finally:
        run(client.aclose())


def test_full_url(base_config):
    client = CTFdClient(base_config, timeout=None)
    try:
        assert client._full_url("https://example.com/x") == "https://example.com/x"
        assert client._full_url("/files/x") == "https://ctfd.example.com/files/x"
    finally:
        run(client.aclose())


def test_list_challenges_filters(make_client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/challenges":
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": [
                        {"id": 1, "name": "A", "category": "web", "solved": True},
                        {
                            "id": 2,
                            "name": "B",
                            "category": "pwn",
                            "solved_by_me": False,
                        },
                    ],
                },
            )
        return httpx.Response(404, json={"success": False})

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        results = run(client.list_challenges(category="pwn", only_unsolved=True))
        assert len(results) == 1
        assert results[0]["id"] == 2
    finally:
        run(client.aclose())


def test_error_status_mapping(make_client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/challenges/404":
            return httpx.Response(404, json={"success": False})
        if request.url.path == "/api/v1/challenges/401":
            return httpx.Response(401, json={"success": False})
        if request.url.path == "/api/v1/challenges/429":
            return httpx.Response(
                429,
                json={"success": False},
                headers={"Retry-After": "120"},
            )
        return httpx.Response(500, json={"success": False, "message": "boom"})

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        with pytest.raises(NotFoundError):
            run(client.get_challenge(404))
        with pytest.raises(AuthError):
            run(client.get_challenge(401))
        with pytest.raises(RateLimitError) as exc:
            run(client.get_challenge(429))
        assert exc.value.retry_after == "120"
        with pytest.raises(CTFdClientError, match="CTFd error 500"):
            run(client.get_challenge(500))
    finally:
        run(client.aclose())


def test_redirect_error(make_client):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302)

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        with pytest.raises(AuthError, match="Unexpected redirect"):
            run(client.get_challenge(1))
    finally:
        run(client.aclose())


def test_non_json_response(make_client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/challenges/123":
            return httpx.Response(200, text="<html>nope</html>", headers={"Content-Type": "text/html"})
        return httpx.Response(404, json={"success": False})

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        with pytest.raises(CTFdClientError, match="non-JSON response"):
            run(client.get_challenge(123))
    finally:
        run(client.aclose())


def test_dynamic_container_flow(make_client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/challenges/1":
            return httpx.Response(
                200,
                json={"success": True, "data": {"id": 1, "type": "dynamic_docker"}},
            )
        if request.url.path == "/api/v1/containers":
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {"id": 2, "challenge_id": 1, "host": "h", "port": 1337},
                },
            )
        if request.url.path == "/api/v1/containers/2":
            return httpx.Response(
                200,
                json={"success": True, "data": {"status": "stopped", "message": "ok"}},
            )
        return httpx.Response(404, json={"success": False})

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        result = run(client.start_container(1))
        assert result["connection_info"] == "h:1337"
        stopped = run(client.stop_container(container_id=2, challenge_id=1))
        assert stopped["message"] == "ok"
    finally:
        run(client.aclose())


def test_owl_container_flow(make_client):
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/api/v1/challenges/1":
            return httpx.Response(
                200,
                json={"success": True, "data": {"id": 1, "type": "dynamic_check_docker"}},
            )
        if request.url.path == "/plugins/ctfd-owl/container" and request.method == "POST":
            return httpx.Response(200, json={"success": True, "data": {"success": True}})
        if request.url.path == "/plugins/ctfd-owl/container" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "containers_data": [
                            {"host": "owl", "port": 9000, "container_id": "c1"}
                        ],
                        "ip": "1.2.3.4",
                    },
                },
            )
        if request.url.path == "/plugins/ctfd-owl/container" and request.method == "DELETE":
            return httpx.Response(
                200,
                json={"success": True, "data": {"status": "stopped", "message": "ok"}},
            )
        return httpx.Response(404, json={"success": False})

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        result = run(client.start_container(1))
        assert result["connection_info"] == "1.2.3.4:9000"
        stopped = run(client.stop_container(challenge_id=1))
        assert stopped["message"] == "ok"
    finally:
        run(client.aclose())

    assert ("POST", "/plugins/ctfd-owl/container") in calls
    assert ("GET", "/plugins/ctfd-owl/container") in calls
    assert ("DELETE", "/plugins/ctfd-owl/container") in calls


def test_k8s_container_flow(make_client):
    calls: list[tuple[str, str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/challenges/1":
            return httpx.Response(
                200,
                json={"success": True, "data": {"id": 1, "type": "k8s"}},
            )
        if request.url.path == "/api/v1/k8s/create":
            calls.append(
                (
                    request.method,
                    request.url.path,
                    {k.lower(): v for k, v in request.headers.items()},
                )
            )
            return httpx.Response(302, headers={"Location": "/challenges"})
        if request.url.path == "/api/v1/k8s/delete":
            calls.append(
                (
                    request.method,
                    request.url.path,
                    {k.lower(): v for k, v in request.headers.items()},
                )
            )
            return httpx.Response(302, headers={"Location": "/challenges"})
        if request.url.path == "/api/v1/k8s/get":
            return httpx.Response(
                200,
                json={
                    "ConnectionHost": "k8s",
                    "ConnectionPort": 31337,
                    "InstanceRunning": True,
                    "ThisChallengeInstance": True,
                },
            )
        return httpx.Response(404, json={"success": False})

    transport = httpx.MockTransport(handler)
    client = make_client(transport)
    try:
        client._csrf_token = "csrf-token"
        result = run(client.start_container(1))
        assert result["connection_info"] == "k8s:31337"
        stopped = run(client.stop_container(challenge_id=1))
        assert stopped["status"] in {"stopped", "running"}
    finally:
        run(client.aclose())

    for _, path, headers in calls:
        assert headers.get("origin") == "https://ctfd.example.com"
        assert headers.get("referer") == "https://ctfd.example.com/challenges"


def test_format_error_mapping():
    assert str(_format_error(ConfigError("bad"))) == "Configuration error: bad"
    assert str(_format_error(AuthError("no"))) == "Auth failed: no"
    assert str(_format_error(NotFoundError("no"))) == "Not found: no"
    err = _format_error(RateLimitError("no", retry_after="30"))
    assert str(err) == "Rate limited. Retry-After=30."
    assert str(_format_error(CTFdClientError("no"))) == "CTFd API error: no"
    assert str(_format_error(ValueError("nope"))) == "Unexpected error: nope"


def test_challenge_markdown_formatting():
    details = {
        "id": 1,
        "name": "Challenge",
        "category": "web",
        "value": 100,
        "solved": True,
        "description_text": "Hello",
        "connection_info": "host:1",
        "files": ["https://ctfd.example.com/files/a"],
    }
    md = _challenge_markdown(details)
    assert "# Challenge" in md
    assert "ID: 1 / Category: web / Points: 100 / Solved" in md
    assert "## Description" in md
    assert "Hello" in md
    assert "## Connection" in md
    assert "host:1" in md
    assert "## Files" in md
    assert "- https://ctfd.example.com/files/a" in md


def test_server_tools_map_errors(monkeypatch: pytest.MonkeyPatch):
    class StubClient:
        async def list_challenges(self, **_):
            raise AuthError("bad")

        async def get_challenge(self, *_):
            raise NotFoundError("missing")

        async def submit_flag(self, *_):
            raise CTFdClientError("boom")

        async def start_container(self, *_):
            raise RateLimitError("slow", retry_after="5")

        async def stop_container(self, *_, **__):
            raise CTFdClientError("stop")

    async def fake_get_client():
        return StubClient()

    monkeypatch.setattr("ctfd_mcp.server._get_client", fake_get_client)

    with pytest.raises(RuntimeError, match="Auth failed"):
        run(list_challenges())
    with pytest.raises(RuntimeError, match="Not found"):
        run(challenge_details(1))
    with pytest.raises(RuntimeError, match="CTFd API error: boom"):
        run(submit_flag(1, "flag"))
    with pytest.raises(RuntimeError, match="Rate limited"):
        run(start_container(1))
    with pytest.raises(RuntimeError, match="CTFd API error: stop"):
        run(stop_container(container_id=1))
    with pytest.raises(RuntimeError, match="CTFd API error: boom"):
        run(submit_flag(1, "flag"))
