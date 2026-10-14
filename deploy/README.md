# deploy/README.md — Blue-Green Router

## Default: Python FastAPI router (`router.py`)

The default router is a ~60-line Python FastAPI reverse proxy that reads
`deploy/state/state.json` on every request to determine the active slot.
In the container that file arrives as `/app/state/state.json` (`STATE_FILE`),
from `./deploy/state` bind-mounted read-only.

**Advantages:**
- Zero config reload on slot switch (reads the state file live)
- No external dependencies beyond Python
- Works locally without Docker

**Start the router locally:**
```bash
python deploy/router.py
# Listens on port 8080 (ROUTER_PORT)
```

Under compose it is reached on the host at `127.0.0.1:${ROUTER_HOST_PORT:-8081}`.

**Switch slots:**
```bash
python deploy/switch.py switch green --version v1.2.3 --variant hardened
python deploy/switch.py rollback
python deploy/switch.py status
```

## What a switch writes

`deploy/state/` holds all runtime deployment state (it is gitignored):

| File | Written by | Read by |
|------|-----------|---------|
| `state.json` | `switch.py` | `router.py`, on every request |
| `<slot>.env` | `switch.py` | docker-compose, as that slot's `env_file` |

`state.json` decides **which slot receives traffic**. `<slot>.env`
(`AGENT_VARIANT`, `AGENT_VERSION`) decides **which build that slot runs**, so
a slot must be recreated to pick up a new one:

```bash
docker compose up -d --force-recreate agent-green
```

Traffic moves the moment `state.json` changes; the slot itself only changes
on recreate. Roll back with `switch.py rollback` — traffic returns to the
previous slot immediately, with no rebuild.

Three guarantees hold the files honest:

- **Validated input.** `--version` must be a tag/SHA-like string and
  `--variant` the name of a file in `agent/variants/`. Both end up in
  `<slot>.env`, which Compose loads as the slot's environment, so a newline
  or `$` in either would otherwise inject variables into the agent container.
- **Atomic writes.** Both files are written to a temp file and renamed, so
  the router can never read half of a `state.json`.
- **Fail-closed routing.** A *missing* `state.json` means nothing has been
  deployed, and blue is served. A file that exists but cannot be parsed, or
  names an unknown slot, gets **503** — guessing "blue" there could route live
  traffic to the build a rollback just moved away from.

A slot staged with a variant its image cannot load refuses to start, so the
gate's `docker compose up --wait` fails and traffic never moves to it.

---

## Upgrade path: Nginx

For high-traffic production use, Nginx is a faster, more battle-tested
reverse proxy, with an `upstream` block per slot.

**Limitation:** Nginx requires a config reload (`nginx -s reload`) on every
slot switch, which adds latency and needs Nginx running as a service. The
Python router avoids this, which is why it is the default. (The one nginx
container here, `llm-proxy`, is the sandbox's egress gateway, not a router —
see `deploy/llm-proxy/default.conf.template`.)

---

## Known limitation: single-writer state

`state.json` is a single-writer file. Atomic writes stop a reader seeing a
torn file, but two concurrent gate runs can still overwrite each other's
switch. CI serialises gate runs (`concurrency:` in `gate.yml`); run them one at
a time locally too.

For concurrent use: replace it with a Redis key or a proper distributed lock
(e.g. Python `filelock` + atomic write).
