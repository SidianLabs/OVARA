# The box image the tests run agents in (tier 2): ovara-box plus the agents
# under test and the tools an attacker driving an agent would reach for.
# Built FROM the real box image, so the box's own properties are tested too.
#
#   docker build -t ovara-box box/ && docker build -t ovara-box-test tests/box
FROM ovara-box
USER root
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      sudo netcat-openbsd dnsutils iproute2 nftables iputils-ping util-linux \
 && rm -rf /var/lib/apt/lists/*
RUN NPM_CONFIG_PREFIX=/usr/local npm install -g --no-fund --no-audit opencode-ai @anthropic-ai/claude-code @openai/codex \
 && opencode --version && claude --version && codex --version
RUN python3 -m venv /opt/aider && /opt/aider/bin/pip install -q --no-cache-dir aider-chat==0.86.2 \
 && ln -s /opt/aider/bin/aider /usr/local/bin/aider && aider --version
USER ovara-agent
