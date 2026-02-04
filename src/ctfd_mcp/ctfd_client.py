from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser
from typing import Any

import httpx

from .config import DEFAULT_USER_AGENT, Config


class CTFdClientError(Exception):
    """Base error for CTFd client issues."""


class AuthError(CTFdClientError):
    """Authentication or authorization error."""


class NotFoundError(CTFdClientError):
    """Requested resource not found."""


class RateLimitError(CTFdClientError):
    """CTFd rate limit hit."""

    def __init__(self, message: str, retry_after: str | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class CTFdClient:
    """Thin async wrapper over the CTFd REST API for user-level actions."""

    def __init__(self, config: Config, timeout: float | httpx.Timeout | None = None):
        self.config = config
        if timeout is None:
            # generous defaults to avoid TLS stalls while still failing eventually
            timeout = httpx.Timeout(
                config.total_timeout if config.total_timeout is not None else 20.0,
                connect=config.connect_timeout
                if config.connect_timeout is not None
                else 10.0,
                read=config.read_timeout if config.read_timeout is not None else 15.0,
            )
        # Force h1 and send explicit Accept/UA to reduce chances of HTML/redirect responses.
        user_agent = (config.user_agent or "").strip() or DEFAULT_USER_AGENT
        headers = {
            "Accept": "application/json",
            "User-Agent": user_agent,
            "X-Requested-With": "XMLHttpRequest",
            **config.auth_header,
        }
        cookies = {}
        if config.session_cookie:
            cookies["session"] = config.session_cookie
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            headers=headers,
            timeout=timeout,
            http2=False,  # some CTFd deployments can stall on HTTP/2; force h1
            follow_redirects=True,
            cookies=cookies or None,
        )
        self._csrf_token = config.csrf_token
        self._username = config.username
        self._password = config.password
        self._has_logged_in = False

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _refresh_csrf_token(self) -> None:
        """Fetch a fresh CSRF token after login; many CTFd installs require it for attempts."""
        try:
            resp = await self._client.get("/api/v1/csrf_token")
            resp.raise_for_status()
            data = resp.json()
            token = data.get("data", {}).get("csrf_token") or data.get("csrf_token")
            if token:
                self._csrf_token = token
        except Exception:
            pass
        # parse nonce from challenges page (some deployers use this specific nonce)
        try:
            resp = await self._client.get("/challenges")
            resp.raise_for_status()
            token = self._extract_nonce(resp.text)
            if token:
                self._csrf_token = token
        except Exception:
            return

    def _extract_nonce(self, html: str) -> str:
        for pat in [r'name="nonce" value="([^"]+)"', r"'csrfNonce': \"([^\"]+)\""]:
            m = re.search(pat, html)
            if m:
                return m.group(1)
        return ""

    async def _login(self) -> None:
        if not (self._username and self._password):
            return
        try:
            # Fetch login page to grab nonce like a browser.
            page = await self._client.get("/login")
            nonce = self._extract_nonce(page.text)
            headers = {"Referer": f"{self.config.base_url}/login"}
            if nonce:
                headers["CSRF-Token"] = nonce
            resp = await self._client.post(
                "/login",
                data={
                    "name": self._username,
                    "password": self._password,
                    "nonce": nonce,
                },
                headers=headers,
                follow_redirects=True,
            )
            if resp.status_code not in (200, 302, 303, 403):
                raise AuthError(
                    f"Login failed with provided credentials (code {resp.status_code})."
                )
            if nonce:
                self._csrf_token = nonce
            await self._refresh_csrf_token()
            self._has_logged_in = True
        except AuthError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AuthError(f"Login failed: {exc}")

    async def _ensure_login(self) -> None:
        """
        Ensure username/password login is performed when no token/session is present.
        A no-op when token or session cookie is configured.
        """
        if (
            not self.config.token
            and not self.config.session_cookie
            and self._username
            and self._password
            and not self._has_logged_in
        ):
            await self._login()

    async def _ensure_csrf_token(self) -> None:
        """Refresh CSRF token if missing."""
        if not self._csrf_token:
            await self._refresh_csrf_token()

    def _csrf_required(self) -> bool:
        """
        CSRF is typically enforced for cookie-authenticated requests (session or browser login).
        API-token authenticated requests generally do not require CSRF.
        """
        return bool(self.config.session_cookie or self._has_logged_in)

    async def list_challenges(
        self, category: str | None = None, only_unsolved: bool = False
    ) -> list[dict[str, Any]]:
        """List challenges the user can see, optionally filtered by category and solve state."""
        payload = await self._request("GET", "/api/v1/challenges")
        challenges = payload.get("data") or []

        normalized = []
        for item in challenges:
            if category and (item.get("category") or "").lower() != category.lower():
                continue

            solved = item.get("solved")
            if solved is None:
                solved = item.get("solved_by_me")
            if only_unsolved and solved:
                continue

            normalized.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "category": item.get("category"),
                    "value": item.get("value"),
                    "solved": solved if solved is not None else item.get("solved"),
                    "type": item.get("type"),
                    "tags": item.get("tags") or [],
                }
            )
        return normalized

    async def get_challenge(self, challenge_id: int) -> dict[str, Any]:
        """Get challenge details including description and attachment URLs."""
        payload = await self._request("GET", f"/api/v1/challenges/{challenge_id}")
        data = payload.get("data") or {}

        description = data.get("description")

        return {
            "id": data.get("id"),
            "name": data.get("name"),
            "category": data.get("category"),
            "value": data.get("value"),
            "solved": data.get("solved")
            if data.get("solved") is not None
            else data.get("solved_by_me"),
            "solved_by_me": data.get("solved_by_me"),
            "description": description,
            "description_text": _html_to_text(description) if description else None,
            "connection_info": data.get("connection_info"),
            "state": data.get("state"),
            "type": data.get("type"),
            "tags": data.get("tags") or [],
            "files": [self._full_url(f) for f in data.get("files") or []],
            "requirements": data.get("requirements"),
        }

    async def submit_flag(self, challenge_id: int, flag: str) -> dict[str, Any]:
        """Attempt a flag submission for a challenge."""
        payload = await self._request(
            "POST",
            "/api/v1/challenges/attempt",
            json={"challenge_id": challenge_id, "submission": flag},
        )
        data = payload.get("data") or {}
        return {
            "status": data.get("status"),
            "message": data.get("message"),
        }

    async def start_dynamic_container(self, challenge_id: int) -> dict[str, Any]:
        """Start a dynamic_docker instance (ctfd-whale)."""
        payload = await self._request(
            "POST",
            "/api/v1/containers",
            json={"challenge_id": challenge_id},
        )
        # Some ctfd-whale deployments return connection details at the top level; prefer data if present.
        data = payload.get("data") or payload or {}
        host = data.get("host") or data.get("docker_server")
        port = data.get("port")
        connection_info = data.get("connection_info")
        if not connection_info and host and port:
            connection_info = f"{host}:{port}"
        return self._trim_none(
            {
                "id": data.get("id"),
                "challenge_id": data.get("challenge_id"),
                "state": data.get("state"),
                "connection_info": connection_info,
                "ip": data.get("ip"),
                "port": port,
                "host": host,
                "container_id": data.get("container_id"),
                "created": data.get("created"),
                "raw": data,
            }
        )

    async def stop_dynamic_container(self, container_id: int) -> dict[str, Any]:
        """Stop a dynamic_docker instance."""
        payload = await self._request(
            "DELETE",
            f"/api/v1/containers/{container_id}",
        )
        data = payload.get("data") or payload or {}
        message = data.get("message") or data or "stopped"
        if isinstance(message, dict):
            message = message.get("message") or str(message)
        return self._trim_none(
            {
                "status": data.get("status") or payload.get("success"),
                "message": message,
                "raw": data,
            }
        )

    async def start_k8s_container(self, challenge_id: int) -> dict[str, Any]:
        """
        Start a Kubernetes-backed instance exposed via /api/v1/k8s endpoints.
        Uses multipart form with nonce/CSRF token when available, then polls the GET endpoint
        for connection details.
        """
        files = {"challenge_id": (None, str(challenge_id))}
        if self._csrf_token:
            files["nonce"] = (None, self._csrf_token)

        await self._k8s_request(
            "POST", "/api/v1/k8s/create", files=files, action="start"
        )
        status = await self._get_k8s_container(challenge_id)
        return self._trim_none(status)

    async def stop_k8s_container(self, challenge_id: int) -> dict[str, Any]:
        """
        Stop a Kubernetes-backed instance exposed via /api/v1/k8s endpoints.
        """
        files = {"challenge_id": (None, str(challenge_id))}
        if self._csrf_token:
            files["nonce"] = (None, self._csrf_token)

        await self._k8s_request(
            "POST", "/api/v1/k8s/delete", files=files, action="stop"
        )
        status = await self._get_k8s_container(challenge_id)
        status["status"] = (
            "stopped" if not status.get("instance_running") else "running"
        )
        return self._trim_none(status)

    async def _get_k8s_container(self, challenge_id: int) -> dict[str, Any]:
        resp = await self._k8s_request(
            "GET",
            "/api/v1/k8s/get",
            params={"challenge_id": challenge_id},
            action="get",
        )
        try:
            payload = resp.json()
        except ValueError as exc:  # noqa: BLE001
            snippet = resp.text[:500] if resp.text else "<empty>"
            raise CTFdClientError(
                f"CTFd returned non-JSON response from k8s get (status {resp.status_code}): {snippet}"
            ) from exc
        if not isinstance(payload, dict):
            raise CTFdClientError("Unexpected response shape from k8s get endpoint.")
        return self._parse_k8s_payload(payload, challenge_id)

    def _parse_k8s_payload(
        self, data: dict[str, Any], challenge_id: int
    ) -> dict[str, Any]:
        connection_url = data.get("ConnectionURL")
        port = data.get("ConnectionPort")
        connection_info = connection_url
        if not connection_info and port:
            host = data.get("ConnectionHost") or data.get("host")
            if host:
                connection_info = f"{host}:{port}"

        expires_at = data.get("ExpireTime")
        state = "running" if data.get("InstanceRunning") else "stopped"

        return {
            "challenge_id": challenge_id,
            "connection_info": connection_info,
            "connection_url": connection_url,
            "connection_port": port,
            "expires_at": expires_at,
            "instance_running": data.get("InstanceRunning"),
            "is_current_instance": data.get("ThisChallengeInstance"),
            "extend_available": data.get("ExtendAvailable"),
            "state": state,
            "raw": data,
        }

    def _raise_for_k8s_response(self, response: httpx.Response, action: str) -> None:
        if response.status_code in (401, 403):
            raise AuthError(
                "Unauthorized for k8s API. Check session cookie and CSRF token."
            )
        if response.status_code == 404:
            raise NotFoundError("K8s API not found on this CTFd instance.")
        if response.status_code == 429:
            raise RateLimitError(
                "Rate limit reached on k8s API. Retry later.",
                retry_after=response.headers.get("Retry-After"),
            )
        if response.status_code >= 400:
            raise CTFdClientError(
                f"k8s {action} failed with status {response.status_code}: {response.text}"
            )

    async def _k8s_request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        files: dict[str, tuple[str | None, str]] | None = None,
        headers: dict[str, str] | None = None,
        action: str = "request",
        _retried: bool = False,
    ) -> httpx.Response:
        await self._ensure_login()
        # Refresh CSRF each time to align with per-page nonce used by some k8s deployers.
        await self._refresh_csrf_token()
        request_headers = self._k8s_headers()
        if headers:
            request_headers.update(headers)
        files_with_nonce = files.copy() if files else None
        if files_with_nonce is not None and self._csrf_token:
            files_with_nonce.setdefault("nonce", (None, self._csrf_token))
        # Ensure Referer/Origin headers include /challenges to match browser flows.
        request_headers.setdefault("Referer", f"{self.config.base_url}/challenges")
        request_headers.setdefault("Origin", self.config.base_url)
        response = await self._client.request(
            method,
            path,
            params=params,
            files=files_with_nonce,
            headers=request_headers,
            follow_redirects=False,
        )
        if response.status_code in (401, 403):
            if _retried:
                self._raise_for_k8s_response(response, action=action)
            # refresh CSRF token and retry once (also re-login if credentials exist)
            if self._username and self._password:
                await self._login()
            else:
                await self._refresh_csrf_token()
            if files_with_nonce is not None and self._csrf_token:
                files_with_nonce["nonce"] = (None, self._csrf_token)
            return await self._k8s_request(
                method,
                path,
                params=params,
                files=files_with_nonce,
                headers=headers,
                action=action,
                _retried=True,
            )
        # k8s create/delete endpoints respond with 302 back to /challenges; treat as success.
        if 300 <= response.status_code < 400:
            return response
        self._raise_for_k8s_response(response, action=action)
        return response

    def _k8s_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Origin": self.config.base_url,
            "Referer": f"{self.config.base_url}/challenges",
        }
        if self._csrf_token:
            headers["CSRF-Token"] = self._csrf_token
        return headers

    async def start_owl_container(self, challenge_id: int) -> dict[str, Any]:
        """
        Start a dynamic_check_docker (ctfd-owl) instance.
        Requires session cookie; may require CSRF token depending on server config.
        """
        headers = self._owl_headers()

        initial_payload = await self._request(
            "POST",
            "/plugins/ctfd-owl/container",
            params={"challenge_id": challenge_id},
            json={},
            headers=headers,
        )
        data = initial_payload.get("data") or initial_payload or {}

        parsed = self._parse_owl_container(data, challenge_id)

        # Some ctfd-owl versions return only {"success": true} on POST; fetch details with GET.
        if not self._has_owl_details(parsed) and data.get("success"):
            poll_payload = await self._request(
                "GET",
                "/plugins/ctfd-owl/container",
                params={"challenge_id": challenge_id},
                headers=headers,
            )
            poll_data = poll_payload.get("data") or poll_payload or {}
            polled = self._parse_owl_container(poll_data, challenge_id)
            if self._has_owl_details(polled):
                polled["raw"] = poll_data
                return self._trim_none(polled)

        return self._trim_none(parsed)

    def _parse_owl_container(
        self, data: dict[str, Any], challenge_id: int
    ) -> dict[str, Any]:
        # ctfd-owl returns connection details inside containers_data.
        containers = data.get("containers_data") or data.get("containers") or []
        container_info = containers[0] if containers else {}

        host = container_info.get("lan_domain") or container_info.get("host")
        ip = data.get("ip") or container_info.get("ip") or host
        port = container_info.get("port") or data.get("port")
        conntype = container_info.get("conntype") or data.get("conntype")
        connect_host = data.get("ip") or container_info.get("ip") or host
        # Prefer the externally reachable IP/host over LAN domain in connection_info.
        connection_info = data.get("connection_info") or (
            f"{connect_host}:{port}" if connect_host and port else None
        )
        if not connection_info and conntype and host and port:
            connection_info = f"{conntype}://{host}:{port}"

        return {
            "id": data.get("id") or container_info.get("id"),
            "challenge_id": data.get("challenge_id") or challenge_id,
            "state": data.get("state") or container_info.get("state"),
            "connection_info": connection_info,
            "ip": ip,
            "port": port,
            "host": host,
            "conntype": conntype,
            "remaining_time": container_info.get("remaining_time")
            or data.get("remaining_time"),
            "container_id": container_info.get("container_id")
            or data.get("container_id"),
            "created": data.get("created") or container_info.get("created"),
            "raw": data,
        }

    @staticmethod
    def _has_owl_details(parsed: dict[str, Any]) -> bool:
        return any(
            parsed.get(key)
            for key in (
                "connection_info",
                "host",
                "ip",
                "port",
                "container_id",
                "remaining_time",
            )
        )

    @staticmethod
    def _is_k8s_type(ctype: str | None) -> bool:
        if not ctype:
            return False
        lowered = ctype.lower()
        return "k8s" in lowered or "kube" in lowered

    @staticmethod
    def _trim_none(values: dict[str, Any]) -> dict[str, Any]:
        """Drop keys with None to keep responses compact."""
        return {k: v for k, v in values.items() if v is not None}

    async def stop_owl_container(self, challenge_id: int) -> dict[str, Any]:
        """
        Stop a dynamic_check_docker (ctfd-owl) instance.
        Uses the same endpoint with DELETE and challenge_id.
        """
        headers = self._owl_headers()
        payload = await self._request(
            "DELETE",
            "/plugins/ctfd-owl/container",
            params={"challenge_id": challenge_id},
            headers=headers,
        )
        data = payload.get("data") or payload
        message = data.get("message") or data or "stopped"
        if isinstance(message, dict):
            message = message.get("message") or str(message)
        return self._trim_none(
            {
                "status": data.get("status") or payload.get("success"),
                "message": message,
                "raw": data,
            }
        )

    async def start_container(self, challenge_id: int) -> dict[str, Any]:
        """
        Unified start: detects challenge type and calls the appropriate backend.
        - dynamic_docker -> ctfd-whale /api/v1/containers
        - dynamic_check_docker -> ctfd-owl /plugins/ctfd-owl/container
        - k8s-backed -> /api/v1/k8s (form-based)
        """
        details = await self.get_challenge(challenge_id)
        ctype = (details.get("type") or "").lower()
        if self._is_k8s_type(ctype):
            return await self.start_k8s_container(challenge_id)
        if ctype == "dynamic_docker":
            try:
                return await self.start_dynamic_container(challenge_id)
            except NotFoundError:
                # Some events expose dynamic challenges via /api/v1/k8s while keeping the same type.
                return await self.start_k8s_container(challenge_id)
        if ctype == "dynamic_check_docker":
            return await self.start_owl_container(challenge_id)
        raise CTFdClientError(
            f"Unsupported challenge type '{ctype}' for container start."
        )

    async def stop_container(
        self, *, container_id: int | None = None, challenge_id: int | None = None
    ) -> dict[str, Any]:
        """
        Unified stop:
        - dynamic_docker: requires container_id
        - dynamic_check_docker (owl): uses challenge_id
        - k8s-backed: uses challenge_id
        If no challenge_id is given, assumes dynamic_docker and stops by container_id.
        """
        if container_id is None and challenge_id is None:
            raise CTFdClientError(
                "Provide container_id or challenge_id to stop a container."
            )

        ctype: str | None = None
        if challenge_id is not None:
            details = await self.get_challenge(challenge_id)
            ctype = (details.get("type") or "").lower()

        if self._is_k8s_type(ctype):
            if challenge_id is None:
                raise CTFdClientError("k8s stop requires challenge_id.")
            return await self.stop_k8s_container(challenge_id)
        if ctype == "dynamic_docker":
            if container_id is None:
                raise CTFdClientError("dynamic_docker stop requires container_id.")
            try:
                return await self.stop_dynamic_container(container_id)
            except NotFoundError:
                if challenge_id is not None:
                    return await self.stop_k8s_container(challenge_id)
                raise
        if ctype == "dynamic_check_docker":
            if challenge_id is None:
                raise CTFdClientError("ctfd-owl stop requires challenge_id.")
            return await self.stop_owl_container(challenge_id)

        if ctype:
            raise CTFdClientError(
                f"Unsupported challenge type '{ctype}' for container stop."
            )

        # No challenge_id was provided; default to whale-style stop by container_id.
        if container_id is None:
            raise CTFdClientError("dynamic_docker stop requires container_id.")
        return await self.stop_dynamic_container(container_id)

    def _owl_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Origin": self.config.base_url,
            "Referer": f"{self.config.base_url}/challenges",
        }
        if self._csrf_token:
            headers["CSRF-Token"] = self._csrf_token
        return headers

    async def _request(
        self, method: str, path: str, _retried: bool = False, **kwargs: Any
    ) -> dict[str, Any]:
        # Lazy login if we only have username/password and no session/token.
        await self._ensure_login()

        method_upper = method.upper()
        if (
            method_upper in {"POST", "PUT", "PATCH", "DELETE"}
            and self._csrf_required()
        ):
            await self._ensure_csrf_token()

        # Attach CSRF token to all requests when available (some CTFd deployments require it even for API).
        headers = kwargs.setdefault("headers", {})
        if self._csrf_token and "CSRF-Token" not in headers:
            headers["CSRF-Token"] = self._csrf_token
        if self._csrf_token and "Referer" not in headers:
            headers["Referer"] = f"{self.config.base_url}/challenges"

        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            raise CTFdClientError(
                f"Network error talking to CTFd ({exc.__class__.__name__}): {exc}"
            ) from exc

        if (
            response.status_code == 403
            and self._csrf_required()
            and not _retried
            and method_upper in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            # Cookie-authenticated flows can require a per-session/per-page CSRF token/nonce.
            # Refresh once and retry to avoid hard failures on CSRF-enforced deployments.
            await self._refresh_csrf_token()
            headers = kwargs.setdefault("headers", {})
            if self._csrf_token:
                headers["CSRF-Token"] = self._csrf_token
                headers.setdefault("Referer", f"{self.config.base_url}/challenges")
            response = await self._client.request(method, path, **kwargs)

        if response.status_code == 401 and self._username and self._password:
            # For username/password flows, re-login and retry once to avoid infinite recursion.
            if _retried:
                raise AuthError("Unauthorized after re-login. Check credentials.")
            await self._login()
            return await self._request(method, path, _retried=True, **kwargs)

        if 300 <= response.status_code < 400:
            raise AuthError(
                f"Unexpected redirect ({response.status_code}) to {response.headers.get('Location')}. "
                "Check token and CTFD_URL."
            )
        if response.status_code in (401, 403):
            raise AuthError("Unauthorized. Check CTFD_TOKEN permissions or value.")
        if response.status_code == 404:
            raise NotFoundError("Resource not found.")
        if response.status_code == 429:
            raise RateLimitError(
                "Rate limit reached. Retry later.",
                retry_after=response.headers.get("Retry-After"),
            )
        if response.status_code >= 400:
            raise CTFdClientError(f"CTFd error {response.status_code}: {response.text}")

        try:
            payload = response.json()
        except ValueError as exc:
            snippet = response.text[:500] if response.text else "<empty>"
            ctype = response.headers.get("Content-Type")
            raise CTFdClientError(
                f"CTFd returned non-JSON response (status {response.status_code}, "
                f"content-type={ctype}): {snippet}"
            ) from exc

        if isinstance(payload, dict) and payload.get("success") is False:
            message = (
                payload.get("message")
                or payload.get("data")
                or "CTFd API reported failure"
            )
            raise CTFdClientError(str(message))

        if not isinstance(payload, dict):
            raise CTFdClientError("Unexpected response shape from CTFd.")

        return payload

    def _full_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.config.base_url}/{path.lstrip('/')}"


class _HTMLToTextParser(HTMLParser):
    """Lightweight HTML -> text converter to keep responses chat-friendly."""

    def __init__(self):
        super().__init__()
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str]]):
        if tag in {"p", "div", "br", "li"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str):
        if tag in {"p", "div", "li"}:
            self._parts.append("\n")

    def handle_data(self, data: str):
        self._parts.append(data)

    def get_text(self) -> str:
        text = unescape("".join(self._parts))
        # Collapse excessive blank lines but keep intentional spacing.
        lines = [line.strip() for line in text.splitlines()]
        return "\n".join([line for line in lines if line])


def _html_to_text(value: str) -> str:
    parser = _HTMLToTextParser()
    parser.feed(value)
    return parser.get_text().strip()
