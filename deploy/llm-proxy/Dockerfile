# llm-proxy: the stock nginx image with Creuset's config baked in.
#
# The config used to be bind-mounted from the host, which a remote Docker
# daemon (docker-in-docker CI, a remote DOCKER_HOST) resolves on ITS own
# filesystem: nginx then started without the allowlist. In the image, it
# travels with the container. Rebuild after editing either file:
#   docker compose build llm-proxy
FROM nginx:1.31-alpine

LABEL org.opencontainers.image.title="creuset-llm-proxy" \
      org.opencontainers.image.description="Creuset's LLM egress gateway: one upstream, an endpoint allowlist, the real key injected" \
      org.opencontainers.image.source="https://github.com/jackson-gits/Creuset" \
      org.opencontainers.image.licenses="Apache-2.0"

# Rendered by the image's entrypoint (envsubst) into /etc/nginx/conf.d.
COPY default.conf.template /etc/nginx/templates/default.conf.template
# Sourced by the entrypoint before rendering, which it does only for an
# executable file: without it the template's variables stay unset and nginx
# refuses the config rather than start unvalidated.
COPY --chmod=0755 05-creuset-validate.envsh /docker-entrypoint.d/05-creuset-validate.envsh
