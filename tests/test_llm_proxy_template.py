"""
llm-proxy is the one process holding the real API key. Its config is rendered at
container start: deploy/llm-proxy/05-creuset-validate.envsh validates the
provider profile and fills in defaults, then the nginx image's envsubst renders
default.conf.template, substituting only the variables that are DEFINED.

Pinned here without Docker, so every CI leg runs it:

1. With only the variables the proxy took before provider profiles existed
   (LLM_API_KEY, LLM_UPSTREAM_HOST, LLM_PROXY_RESOLVER), the render is byte-for-
   byte tests/snapshots/llm_proxy_default.conf, the config every published
   result ran behind. That file was captured from nginx:1.31-alpine's own
   entrypoint rendering the template as of d0b66d6. Never regenerate it from
   the current template: the test would then pass whatever the template says.
2. In every profile, what closed the `..%2F` bypass still holds: an exact-path
   allowlist on nginx's normalised $uri, $uri forwarded (never the raw request
   line) with no query string, upstream TLS verified, everything else 403.
3. The envsh exports what the renders assume, and refuses what it must. Those
   tests source the real script, so they need a POSIX sh (skipped on Windows).

`nginx -t` for each profile runs in CI (tests.yml); the live bypass reproduction
against a fake upstream needs Docker and is not part of this suite.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import unquote

import pytest
import yaml

from conftest import ROOT

PROXY_DIR = ROOT / "deploy" / "llm-proxy"
TEMPLATE = PROXY_DIR / "default.conf.template"
ENVSH = PROXY_DIR / "05-creuset-validate.envsh"
SNAPSHOT = ROOT / "tests" / "snapshots" / "llm_proxy_default.conf"

# The envsubst the image runs is handed "${A} ${B} ..." for every variable in
# its environment and replaces both $NAME and ${NAME} forms of those, leaving
# any other $... (nginx's own $uri, $llm_upstream) and undefined names as text.
_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

KEY = "ci-placeholder"
TODAY = {"LLM_API_KEY": KEY, "LLM_UPSTREAM_HOST": "api.groq.com", "LLM_PROXY_RESOLVER": "127.0.0.11"}

# What the envsh exports when given TODAY alone: the defaults.
DEFAULTS = {
    **TODAY,
    "LLM_UPSTREAM_SCHEME": "https",
    "LLM_UPSTREAM_PORT": "",
    "LLM_UPSTREAM_PATH_PREFIX": "",
    "LLM_ALLOWED_ENDPOINTS": "chat/completions|models",
    "LLM_AUTH_HEADER": "Authorization",
    "LLM_AUTH_PREFIX": "Bearer ",
    "LLM_PROXY_EXTRA_CA_FILE": "",
    "CREUSET_PROXY_PORT_SUFFIX": "",
    "CREUSET_PROXY_TRUSTED_CA": "/etc/ssl/certs/ca-certificates.crt",
    "CREUSET_PROXY_AUTH_CLEAR": "",
}

# What docker-compose.yml passes when .env sets none of the profile variables.
COMPOSE_DEFAULTS = {
    **TODAY,
    "LLM_UPSTREAM_SCHEME": "https",
    "LLM_UPSTREAM_PORT": "",
    "LLM_UPSTREAM_PATH_PREFIX": "",
    "LLM_ALLOWED_ENDPOINTS": "chat/completions|models",
    "LLM_AUTH_HEADER": "Authorization",
    "LLM_AUTH_PREFIX": "",
    "LLM_PROXY_EXTRA_CA_FILE": "",
}

_CLEAR_AUTHORIZATION = ' proxy_set_header Authorization "";'

# name -> (what compose / `docker run -e` passes, what the envsh then exports)
PROFILES = {
    "default": (TODAY, DEFAULTS),
    "compose-defaults": (COMPOSE_DEFAULTS, DEFAULTS),
    "openai": (
        {**TODAY, "LLM_UPSTREAM_HOST": "api.openai.com",
         "LLM_ALLOWED_ENDPOINTS": "chat/completions|models|responses|embeddings"},
        {**DEFAULTS, "LLM_UPSTREAM_HOST": "api.openai.com",
         "LLM_ALLOWED_ENDPOINTS": "chat/completions|models|responses|embeddings"},
    ),
    "prefixed": (
        {**TODAY, "LLM_UPSTREAM_HOST": "openrouter.ai", "LLM_UPSTREAM_PATH_PREFIX": "/api"},
        {**DEFAULTS, "LLM_UPSTREAM_HOST": "openrouter.ai", "LLM_UPSTREAM_PATH_PREFIX": "/api"},
    ),
    "gateway": (  # another port, a nested prefix, an api-key header
        {**TODAY, "LLM_UPSTREAM_HOST": "llm.corp.example", "LLM_UPSTREAM_PORT": "8443",
         "LLM_UPSTREAM_PATH_PREFIX": "/inference/openai", "LLM_AUTH_HEADER": "api-key"},
        {**DEFAULTS, "LLM_UPSTREAM_HOST": "llm.corp.example", "LLM_UPSTREAM_PORT": "8443",
         "LLM_UPSTREAM_PATH_PREFIX": "/inference/openai", "LLM_AUTH_HEADER": "api-key",
         "LLM_AUTH_PREFIX": "", "CREUSET_PROXY_PORT_SUFFIX": ":8443",
         "CREUSET_PROXY_AUTH_CLEAR": _CLEAR_AUTHORIZATION},
    ),
    "explicit-scheme-port": (  # 443 under https renders as unset; the prefix gets one space
        {**TODAY, "LLM_UPSTREAM_PORT": "443", "LLM_AUTH_PREFIX": "Token  "},
        {**DEFAULTS, "LLM_UPSTREAM_PORT": "443", "LLM_AUTH_PREFIX": "Token "},
    ),
    "local-http": (  # a compose-internal gateway that takes no key
        {"LLM_API_KEY": "", "LLM_UPSTREAM_HOST": "ollama", "LLM_PROXY_RESOLVER": "127.0.0.11",
         "LLM_UPSTREAM_SCHEME": "http", "LLM_UPSTREAM_PORT": "11434"},
        {**DEFAULTS, "LLM_API_KEY": "", "LLM_UPSTREAM_HOST": "ollama", "LLM_UPSTREAM_SCHEME": "http",
         "LLM_UPSTREAM_PORT": "11434", "CREUSET_PROXY_PORT_SUFFIX": ":11434",
         "LLM_AUTH_PREFIX": ""},  # no key: `Authorization ""`, which nginx does not send
    ),
}

ENDPOINT_VOCABULARY = {"chat/completions", "completions", "embeddings", "models", "responses"}


def envsubst(template: str, env: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        return env[name] if name in env else m.group(0)

    return _REF.sub(sub, template)


def render(env: dict[str, str]) -> str:
    # newline="": compare the bytes nginx would read, not a platform translation.
    return envsubst(TEMPLATE.read_text(encoding="utf-8", newline=""), env)


# ── 1. The default render is the published config ───────────────────────────

def test_default_render_is_byte_identical_to_the_published_config():
    assert render(DEFAULTS).encode("utf-8") == SNAPSHOT.read_bytes(), (
        "the default llm-proxy config changed. Every published result ran behind "
        "tests/snapshots/llm_proxy_default.conf; a new knob must default to today's text."
    )


def test_snapshot_is_the_hardened_pre_profile_config():
    # Guards the guard: a snapshot regenerated from a broken template would let
    # the byte-identity test pass on exactly the regression it exists to catch.
    snap = SNAPSHOT.read_text(encoding="utf-8")
    assert "location ~ ^/(openai/)?v1/(chat/completions|models)\\z {" in snap
    assert "proxy_pass https://$llm_upstream$uri;" in snap
    assert f'proxy_set_header Authorization "Bearer {KEY}";' in snap
    assert "proxy_ssl_verify on;" in snap
    assert "proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;" in snap
    assert "${" not in snap


def test_compose_passes_the_defaults_the_snapshot_was_rendered_with():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    proxy = compose["services"]["llm-proxy"]
    passed = {}
    for name, value in proxy["environment"].items():
        m = re.fullmatch(r"\$\{(\w+):[-?](.*)\}", str(value))
        assert m and m.group(1) == name, f"{name}: expected ${{{name}:-default}}, got {value!r}"
        passed[name] = m.group(2)
    passed["LLM_API_KEY"] = KEY  # `:?` — required, no default
    assert passed == COMPOSE_DEFAULTS
    # Without this mount nginx refuses the config (see below), so a refactor
    # that drops it is caught here rather than as a proxy that will not start.
    assert any(str(v).endswith(":/docker-entrypoint.d/05-creuset-validate.envsh:ro")
               for v in proxy["volumes"])


def test_template_uses_only_variables_the_envsh_sets():
    used = {m.group(1) or m.group(2) for m in _REF.finditer(TEMPLATE.read_text(encoding="utf-8"))}
    nginx_vars = {"uri", "llm_upstream", "host"}  # $host only in a header comment
    assert used - nginx_vars <= set(DEFAULTS), used - nginx_vars - set(DEFAULTS)


def test_without_the_envsh_the_config_cannot_load():
    # If 05-creuset-validate.envsh is missing or not executable, its computed
    # variables are undefined and stay literal: nginx then rejects the config
    # ('unknown directive "${CREUSET_PROXY_AUTH_CLEAR}"'), so an unvalidated
    # profile can never serve. Checked live against nginx:1.31-alpine too.
    rendered = render(COMPOSE_DEFAULTS)
    for line in ("proxy_pass ", "proxy_set_header Host ", "proxy_ssl_trusted_certificate "):
        directive = next(x for x in rendered.splitlines() if x.strip().startswith(line))
        assert "${CREUSET_PROXY_" in directive
    assert '";${CREUSET_PROXY_AUTH_CLEAR}' in rendered


# ── 2. The bypass fix holds in every profile ────────────────────────────────

def _nginx_uri(target: str) -> str | None:
    """
    A model of how nginx derives $uri from a request target: drop the query,
    percent-decode (%2F included), merge slashes, resolve dot segments. None is
    nginx's 400 for climbing above the root. This is what the allowlist sees.
    """
    path = unquote(target.split("?", 1)[0])
    parts = path.split("/")[1:]
    out: list[str] = []
    for i, seg in enumerate(parts):
        last = i == len(parts) - 1
        if seg == "..":
            if not out:
                return None
            out.pop()
            if last:
                out.append("")
        elif seg == ".":
            if last:
                out.append("")
        elif seg or last:
            out.append(seg)
    return "/" + "/".join(out)


def _directives(rendered: str, name: str) -> list[str]:
    return [line.strip() for line in rendered.splitlines() if line.strip().startswith(name + " ")]


def _forwarded(rendered: str, final: dict[str, str], target: str) -> str | None:
    """Path the upstream receives for `target`, or None for the 403 location."""
    uri = _nginx_uri(target)
    regex = re.search(r"location ~ (\S+) \{", rendered).group(1)
    # PCRE's \z (absolute end) is spelled \Z in Python; Python's \Z is NOT
    # PCRE's \Z, which, like $, also matches before a final newline.
    regex = regex.replace("\\z", "\\Z")
    if uri is None or not re.search(regex, uri):
        return None
    return final["LLM_UPSTREAM_PATH_PREFIX"] + uri


BYPASS_PROBES = {
    # The request that reached the files API with the real key before d0b66d6.
    "/openai/v1/files/..%2F..%2Fv1/models": "/openai/v1/models",
    "/v1/files/..%2F..%2Fv1/models": "/v1/models",
    "/v1/models%2F..%2Ffiles": None,
    "/v1/models/../files": None,
    "/v1//models": "/v1/models",
    "/v1/files": None,
    "/v1/models/": None,
    "/V1/models": None,
    "/v1/chat/completions?api-version=x&url=https://evil": "/v1/chat/completions",
    "/admin": None,
    "/": None,
    "/healthz/../v1/models": "/v1/models",
}


@pytest.mark.parametrize("profile", PROFILES)
def test_bypass_fix_holds(profile):
    _, final = PROFILES[profile]
    rendered = render(final)
    assert "${" not in rendered

    # One regex location, the same shape as before, over known endpoints only.
    regexes = re.findall(r"location ~ (\S+) \{", rendered)
    assert regexes == [f"^/(openai/)?v1/({final['LLM_ALLOWED_ENDPOINTS']})\\z"]
    assert set(final["LLM_ALLOWED_ENDPOINTS"].split("|")) <= ENDPOINT_VOCABULARY

    # The normalised $uri is forwarded, after the fixed prefix, with no query.
    (proxy_pass,) = _directives(rendered, "proxy_pass")
    assert proxy_pass == (
        f"proxy_pass {final['LLM_UPSTREAM_SCHEME']}://$llm_upstream"
        f"{final['CREUSET_PROXY_PORT_SUFFIX']}{final['LLM_UPSTREAM_PATH_PREFIX']}$uri;"
    )
    for raw in ("$request_uri", "$args", "$is_args", "$query_string", "$request"):
        assert raw not in rendered

    # Upstream TLS verified against the system bundle (or a superset of it).
    assert _directives(rendered, "proxy_ssl_verify") == ["proxy_ssl_verify on;"]
    assert _directives(rendered, "proxy_ssl_trusted_certificate") == [
        f"proxy_ssl_trusted_certificate {final['CREUSET_PROXY_TRUSTED_CA']};"]

    # Everything else is refused.
    assert re.search(r'location / \{\s*default_type text/plain;\s*return 403 ', rendered)

    # The key is sent once, in the configured header; Authorization never carries
    # the agent's own value through.
    auth = f'proxy_set_header {final["LLM_AUTH_HEADER"]} "{final["LLM_AUTH_PREFIX"]}{final["LLM_API_KEY"]}";'
    assert auth in rendered
    if final["LLM_API_KEY"]:
        assert rendered.count(final["LLM_API_KEY"]) == 1
    if final["LLM_AUTH_HEADER"].lower() != "authorization":
        assert 'proxy_set_header Authorization "";' in rendered

    for target, expected in BYPASS_PROBES.items():
        upstream_path = _forwarded(rendered, final, target)
        assert upstream_path == (None if expected is None else final["LLM_UPSTREAM_PATH_PREFIX"] + expected), target


@pytest.mark.parametrize("target", ["/v1/models%0A", "/openai/v1/chat/completions%0A",
                                    "/v1/models%0D%0A", "/v1/models%0AX-Injected:%201"])
def test_allowlist_refuses_a_trailing_newline(target):
    # Anchored with \z: a decoded LF must never reach the upstream request line.
    assert _forwarded(render(DEFAULTS), DEFAULTS, target) is None


# ── 3. The envsh itself ─────────────────────────────────────────────────────

_SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(os.name == "nt" or _SH is None, reason="sources the envsh with a POSIX sh")


def _source_envsh(env: dict[str, str]) -> subprocess.CompletedProcess:
    """Source the envsh as the entrypoint does, then dump what it EXPORTED (all envsubst sees)."""
    dump = 'exec "$2" -c "import json, os; print(json.dumps(dict(os.environ)))"'
    return subprocess.run(
        [_SH, "-c", '. "$1" && ' + dump, "sh", str(ENVSH), sys.executable],
        # A clean environment: a developer's own LLM_* exports must not leak in.
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env},
        capture_output=True, text=True, timeout=30,
    )


@needs_sh
@pytest.mark.parametrize("profile", PROFILES)
def test_envsh_exports_what_the_render_assumes(profile):
    given, final = PROFILES[profile]
    result = _source_envsh(given)
    assert result.returncode == 0, result.stderr
    exported = json.loads(result.stdout.splitlines()[-1])
    assert {k: exported.get(k) for k in final} == final
    # The startup log names the upstream but never the key.
    if given.get("LLM_API_KEY"):
        assert given["LLM_API_KEY"] not in result.stderr + result.stdout.splitlines()[0]


@needs_sh
def test_envsh_derives_resolvers_from_resolv_conf_on_request():
    if not os.path.exists("/etc/resolv.conf"):
        pytest.skip("no /etc/resolv.conf")
    result = _source_envsh({**TODAY, "LLM_PROXY_RESOLVER": "local"})
    if result.returncode != 0:
        assert "lists no nameserver" in result.stderr
        return
    resolver = json.loads(result.stdout.splitlines()[-1])["LLM_PROXY_RESOLVER"]
    assert resolver and resolver != "local"
    assert re.fullmatch(r"[][A-Za-z0-9.:_ -]+", resolver)


REFUSED = {
    # Clear text only to a bare compose service, and never to Creuset itself.
    "http to a public host": ({"LLM_UPSTREAM_SCHEME": "http"}, "LLM_UPSTREAM_SCHEME"),
    "http to an IP": ({"LLM_UPSTREAM_SCHEME": "http", "LLM_UPSTREAM_HOST": "10.0.0.5"}, "LLM_UPSTREAM_SCHEME"),
    "http to the agent": ({"LLM_UPSTREAM_SCHEME": "http", "LLM_UPSTREAM_HOST": "agent-blue"}, "LLM_UPSTREAM_HOST"),
    "http to mock-services": ({"LLM_UPSTREAM_SCHEME": "http", "LLM_UPSTREAM_HOST": "mock-services"},
                              "LLM_UPSTREAM_HOST"),
    "http to itself": ({"LLM_UPSTREAM_SCHEME": "http", "LLM_UPSTREAM_HOST": "localhost"}, "LLM_UPSTREAM_HOST"),
    "unknown scheme": ({"LLM_UPSTREAM_SCHEME": "ftp"}, "LLM_UPSTREAM_SCHEME"),
    # The key.
    "empty key over https": ({"LLM_API_KEY": ""}, "LLM_API_KEY"),
    "key with a quote": ({"LLM_API_KEY": 'gsk_a";b'}, "LLM_API_KEY"),
    "key with a capture ref": ({"LLM_API_KEY": "gsk_a$1b"}, "LLM_API_KEY"),
    "key with a newline": ({"LLM_API_KEY": "gsk_a\nb"}, "LLM_API_KEY"),
    "key with a space": ({"LLM_API_KEY": "gsk_a b"}, "LLM_API_KEY"),
    # The host.
    "no host": ({"LLM_UPSTREAM_HOST": ""}, "LLM_UPSTREAM_HOST"),
    "host with a path": ({"LLM_UPSTREAM_HOST": "api.groq.com/evil"}, "LLM_UPSTREAM_HOST"),
    "host with a port": ({"LLM_UPSTREAM_HOST": "api.groq.com:443"}, "LLM_UPSTREAM_HOST"),
    "host injecting a directive": ({"LLM_UPSTREAM_HOST": "a.com; proxy_ssl_verify off"}, "LLM_UPSTREAM_HOST"),
    # The port.
    "port 0": ({"LLM_UPSTREAM_PORT": "0"}, "LLM_UPSTREAM_PORT"),
    "port too large": ({"LLM_UPSTREAM_PORT": "65536"}, "LLM_UPSTREAM_PORT"),
    "port not a number": ({"LLM_UPSTREAM_PORT": "443/x"}, "LLM_UPSTREAM_PORT"),
    # The path prefix.
    "prefix without a slash": ({"LLM_UPSTREAM_PATH_PREFIX": "api"}, "LLM_UPSTREAM_PATH_PREFIX"),
    "prefix with a trailing slash": ({"LLM_UPSTREAM_PATH_PREFIX": "/api/"}, "LLM_UPSTREAM_PATH_PREFIX"),
    "prefix with dot segments": ({"LLM_UPSTREAM_PATH_PREFIX": "/api/../files"}, "LLM_UPSTREAM_PATH_PREFIX"),
    "prefix that is a dot segment": ({"LLM_UPSTREAM_PATH_PREFIX": "/.."}, "LLM_UPSTREAM_PATH_PREFIX"),
    "prefix with a query": ({"LLM_UPSTREAM_PATH_PREFIX": "/api?x=1"}, "LLM_UPSTREAM_PATH_PREFIX"),
    "prefix percent-encoded": ({"LLM_UPSTREAM_PATH_PREFIX": "/%2e%2e"}, "LLM_UPSTREAM_PATH_PREFIX"),
    "prefix with a variable": ({"LLM_UPSTREAM_PATH_PREFIX": "/$request_uri"}, "LLM_UPSTREAM_PATH_PREFIX"),
    # The allowlist.
    "files endpoint": ({"LLM_ALLOWED_ENDPOINTS": "chat/completions|files"}, "LLM_ALLOWED_ENDPOINTS"),
    "empty alternative": ({"LLM_ALLOWED_ENDPOINTS": "chat/completions|"}, "LLM_ALLOWED_ENDPOINTS"),
    "doubled bar": ({"LLM_ALLOWED_ENDPOINTS": "models||responses"}, "LLM_ALLOWED_ENDPOINTS"),
    "regex wildcard": ({"LLM_ALLOWED_ENDPOINTS": "models|.*"}, "LLM_ALLOWED_ENDPOINTS"),
    "regex group": ({"LLM_ALLOWED_ENDPOINTS": "models)|(.*"}, "LLM_ALLOWED_ENDPOINTS"),
    "dot segment endpoint": ({"LLM_ALLOWED_ENDPOINTS": "models/../files"}, "LLM_ALLOWED_ENDPOINTS"),
    "nested files path": ({"LLM_ALLOWED_ENDPOINTS": "files/content"}, "LLM_ALLOWED_ENDPOINTS"),
    # The auth header and prefix.
    "header with a space": ({"LLM_AUTH_HEADER": "X Api-Key"}, "LLM_AUTH_HEADER"),
    "header with an underscore": ({"LLM_AUTH_HEADER": "api_key"}, "LLM_AUTH_HEADER"),
    "header that breaks the request": ({"LLM_AUTH_HEADER": "Host"}, "LLM_AUTH_HEADER"),
    "prefix of two words": ({"LLM_AUTH_PREFIX": "Bearer x"}, "LLM_AUTH_PREFIX"),
    "prefix with a quote": ({"LLM_AUTH_PREFIX": 'Bearer"'}, "LLM_AUTH_PREFIX"),
    # The resolver.
    "resolver injecting a directive": ({"LLM_PROXY_RESOLVER": "1.1.1.1; include /etc/passwd"},
                                       "LLM_PROXY_RESOLVER"),
    # The extra CA.
    "missing extra CA": ({"LLM_PROXY_EXTRA_CA_FILE": "/nonexistent/corp-ca.pem"}, "LLM_PROXY_EXTRA_CA_FILE"),
}


@needs_sh
@pytest.mark.parametrize("name", REFUSED)
def test_envsh_refuses(name):
    overrides, variable = REFUSED[name]
    result = _source_envsh({**TODAY, **overrides})
    assert result.returncode != 0, f"{name}: accepted"
    assert variable in result.stderr
    assert "refusing to start llm-proxy" in result.stderr
    assert result.stdout == ""  # nothing exported, nothing rendered
    key = {**TODAY, **overrides}["LLM_API_KEY"]
    if key:
        assert key not in result.stderr


@needs_sh
@pytest.mark.parametrize("content, reason", [
    ("just some text\n", "contains no PEM certificate"),
    ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
     "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n", "contains a private key"),
])
def test_envsh_refuses_an_unusable_extra_ca(tmp_path, content, reason):
    ca = tmp_path / "corp-ca.pem"
    ca.write_text(content, encoding="utf-8")
    result = _source_envsh({**TODAY, "LLM_PROXY_EXTRA_CA_FILE": str(ca)})
    assert result.returncode != 0
    assert reason in result.stderr
