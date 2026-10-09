FROM golang:1.25 AS go
FROM node:24-bookworm
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=$PATH:/usr/local/go/bin
# Tools a real agent (or an attacker driving one) has: shells, curl, DNS and
# raw-TCP utilities, plus what the boundary scripts need.
RUN apt-get update -qq && apt-get install -y -qq python3-venv sudo iproute2 nftables iptables \
      procps dnsutils netcat-openbsd >/dev/null 2>&1
# The agents under test. A failed install must fail the build, not leave an
# image without the agent in it.
RUN npm install -g --no-fund --no-audit opencode-ai @anthropic-ai/claude-code @openai/codex && \
    opencode --version && claude --version && codex --version && git --version && node --version
