# A box image with one agent installed, built FROM the box image:
#
#   docker build -t ovara-box box/
#   docker build --build-arg AGENT=codex -t ovara-box-codex box/agents
#   sudo ovara box -tier 2 -agent codex ./myrepo -- codex
#
# Releases publish ghcr.io/sidianlabs/ovara-box-<agent>:<tag> for claude,
# codex, opencode and aider. The agent is installed into the image (as root,
# at build time), never into a running box. Its own sandbox, update checks
# and telemetry are the box's business: Ovara is the sandbox.
ARG BASE=ovara-box
FROM ${BASE}
ARG AGENT
USER root
RUN set -eu; \
    case "${AGENT:-}" in \
      claude)   NPM_CONFIG_PREFIX=/usr/local npm install -g --no-fund --no-audit @anthropic-ai/claude-code && claude --version ;; \
      codex)    NPM_CONFIG_PREFIX=/usr/local npm install -g --no-fund --no-audit @openai/codex && codex --version ;; \
      opencode) NPM_CONFIG_PREFIX=/usr/local npm install -g --no-fund --no-audit opencode-ai && opencode --version ;; \
      aider)    python3 -m venv /opt/aider && /opt/aider/bin/pip install -q --no-cache-dir aider-chat \
                && ln -s /opt/aider/bin/aider /usr/local/bin/aider && aider --version ;; \
      *) echo "AGENT must be claude, codex, opencode or aider (got '${AGENT:-}')" >&2; exit 1 ;; \
    esac; \
    rm -rf /root/.npm /root/.cache
LABEL org.opencontainers.image.description="Ovara box image with ${AGENT} installed"
USER ovara-agent
