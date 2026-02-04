# CTFd MCP server (user scope)

![](https://badge.mcpx.dev?type=server 'MCP Server')
[![GitHub Release](https://img.shields.io/github/v/release/umbra2728/ctfd-mcp?sort=semver)](https://github.com/umbra2728/ctfd-mcp/releases)
[![License](https://img.shields.io/github/license/umbra2728/ctfd-mcp)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.13%2B-blue)](https://www.python.org/downloads/)
[![Issues](https://img.shields.io/github/issues/umbra2728/ctfd-mcp)](https://github.com/umbra2728/ctfd-mcp/issues)

MCP server that lets a regular CTFd user list challenges, read details, start/stop dynamic docker instances, and submit flags.

## Requirements

- Python 3.13 (managed by `uv`).
- Environment variables (choose one auth method):
- `CTFD_URL` (e.g. <https://ctfd.example.com>)
- `CTFD_TOKEN` (user token, not admin) **or** `CTFD_SESSION` (session cookie if tokens are disabled).
  - `CTFD_CSRF_TOKEN` (optional, only if the server/plugin requires CSRF for ctfd-owl).

You can store them in a `.env` file in the repo root:

```bash
CTFD_URL=https://ctfd.example.com/
CTFD_USERNAME=your_username
CTFD_PASSWORD=your_password
# or, if you prefer to use a token:
# CTFD_TOKEN=your_ctfd_api_token_here
# or, if tokens are disabled:
# CTFD_SESSION=your_session_token_here
# and, if the owl plugin enforces CSRF:
# CTFD_CSRF_TOKEN=your_csrf_token_here
```

## Install

- From PyPI (recommended): `uvx ctfd-mcp --help`
- From source checkout (no install): `uvx --from . ctfd-mcp --help`

## Run MCP server (stdio)

```bash
# installed from PyPI
uvx ctfd-mcp
# from local checkout
uvx --from . ctfd-mcp
```

## Cursor and Claude MCP config example

```json
{
  "mcpServers": {
    "ctfd-mcp": {
      "command": "uvx",
      "args": ["ctfd-mcp"],
      "env": {
        "CTFD_URL": "https://ctfd.example.com",
        "CTFD_TOKEN": "your_user_token"
      }
    }
  }
}
```

## Codex MCP config example

```toml
[mcp_servers.ctfd-mcp]
command = "uvx"
args = ["ctfd-mcp"]

[mcp_servers.ctfd-mcp.env]
CTFD_URL = "https://ctfd.example.com"
CTFD_TOKEN = "your_user_token"
```

## Exposed tools

- `list_challenges(category?, only_unsolved?)` — list visible challenges, optional category/unsolved filter.
- `challenge_details(challenge_id)` — description (HTML + `description_text`), metadata, attachment URLs, solved status.
- `submit_flag(challenge_id, flag)` — attempt a flag; returns status/message.
- `start_container(challenge_id)` — unified start; auto-detects dynamic_docker, ctfd-owl or k8s `/api/v1/k8s`.
- `stop_container(container_id?, challenge_id?)` — unified stop; whale can be stopped with just `container_id`, owl/k8s need `challenge_id`.

Attachments are returned as absolute URLs in `files`; the client/host can fetch them directly.

## MCP resources

- `resource://ctfd/challenges/{challenge_id}` — markdown snapshot of a challenge (metadata, description, attachment URLs, connection info if present).

## Error handling

- Missing env/config -> clear MCP error.
- 401/403 -> auth failed, check token or session cookie.
- 404 -> not found (or dynamic container API missing).
- 429 -> rate limited (Retry-After if present).
- Other HTTP/API errors -> surfaced as MCP errors with CTFd message/status.

## Notes and troubleshooting

- Dynamic containers require the ctfd-whale (dynamic_docker) plugin on the target CTFd; otherwise `/api/v1/containers` returns 404.
- Owl challenges (`dynamic_check_docker`) use a different endpoint: `/plugins/ctfd-owl/container?challenge_id=<id>`. They usually require a session cookie, and some setups require a CSRF token; set `CTFD_CSRF_TOKEN` if needed.
- Some events expose Kubernetes-backed instances at `/api/v1/k8s/{get,create,delete}` with multipart form data; the client will try these when the challenge type includes `k8s` (or when a dynamic_docker endpoint is missing).
- If the server redirects you to `/login` (302) when using a token, switch to a browser session cookie: set `CTFD_SESSION` from the `session` cookie after logging in.
- The client now supports logging in with `CTFD_USERNAME` and `CTFD_PASSWORD`; these fields take precedence over stale tokens/sessions.
- Auth priority: username/password first, then token, then session cookie. Lower-priority credentials are ignored when a higher-priority option is present.

## Support / feedback

If something breaks or you have questions, reach out:
- Telegram: @ismailgaleev
- Jabber: ismailgaleev@chat.merlok.ru
- Email: umbra2728@gmail.com

## Testing

- Run `uv run pytest`.
- Timeouts are configurable via env: `CTFD_TIMEOUT` (total), `CTFD_CONNECT_TIMEOUT`, `CTFD_READ_TIMEOUT` (seconds). Defaults are 20s total / 10s connect / 15s read.

## Development

- Dev dependencies: `uv sync --group dev`
- Lint/format: `uv run ruff check .` and `uv run ruff format .`
- Tests: `uv run pytest`
- Pre-commit: `uv run pre-commit install` (see `CONTRIBUTING.md`)

## License

Apache-2.0. See `LICENSE`.
