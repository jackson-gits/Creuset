# deploy/README.md — Blue-Green Router Options

## Default: Python FastAPI router (`router.py`)

The default router is a ~60-line Python FastAPI reverse proxy that reads
`deploy/state.json` on every request to determine the active slot.

**Advantages:**
- Zero config reload on slot switch (reads state.json live)
- No external dependencies beyond Python
- Works locally without Docker

**Start the router locally:**
```bash
python deploy/router.py
# Listens on port 8080
```

**Switch slots:**
```bash
python deploy/switch.py switch green --version v1.2.3
python deploy/switch.py rollback
python deploy/switch.py status
```

---

## Upgrade path: Nginx

For high-traffic production use, Nginx is a faster, more battle-tested
reverse proxy. The included `nginx.conf` uses an upstream block.

**Limitation:** Nginx requires a config reload (`nginx -s reload`) on every
slot switch, which adds ~100ms latency and requires Nginx to be running as a
service. The Python router avoids this.

**Switch Nginx upstream:**
```bash
# Edit nginx.conf to point to agent-blue or agent-green, then:
nginx -s reload
```

See `nginx.conf` for the upstream configuration.

---

## Known limitation: single-writer state.json

`state.json` is a single-writer file. Concurrent gate runs will race on writes.
This is acceptable for a single-demo POC with sequential deployments.

For concurrent use: replace `state.json` with a Redis key or a proper
distributed lock (e.g., Python `filelock` + atomic write).
