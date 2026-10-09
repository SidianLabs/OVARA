# The box image for `ovara box -tier 2`: what an agent's box is made of.
#
#   docker build -t ovara-box box/
#   sudo ovara box -tier 2 ./myrepo -- bash
#
# Extend it with your agent (as root, into the image, never into a running
# box):
#
#   FROM ovara-box
#   USER root
#   RUN npm install -g @openai/codex
#   USER ovara-agent
#
# What `ovara box` adds at run time, and what it does not:
#   - /work        the workspace copy of your project (secrets left out)
#   - /home/agent  a fresh home for this run
#   - /tmp, /scratch  in-memory scratch space
#   - the Ovara binary (read-only), its PUBLIC certificate, and a root-only
#     directory with two sockets (the proxy and the command gate)
#   - no network interface but loopback; no capabilities for the agent; a
#     read-only root filesystem; no-new-privileges, so set-uid programs in
#     the image give the agent nothing
#
# Nothing secret belongs in this image: no keys, tokens, SSH configuration
# or registry credentials. Ovara injects keys at the proxy; the agent only
# ever holds placeholders.
FROM node:24-bookworm-slim

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      git python3 python3-venv ca-certificates curl procps less \
 && rm -rf /var/lib/apt/lists/* \
 # the node image's own user would share the agent's role; one agent user only
 && (userdel -r node 2>/dev/null || true) \
 && groupadd --gid 10001 ovara-agent \
 && useradd --uid 10001 --gid 10001 --home-dir /home/agent --no-create-home --shell /bin/bash ovara-agent \
 && mkdir -p /work /home/agent /scratch \
 && chown ovara-agent:ovara-agent /work /home/agent /scratch

# npm installs into the agent's own (per-run) home, never the image. Python
# packages go in a virtualenv (python3 -m venv), as Debian's system Python
# refuses pip installs; PIP_USER is deliberately not set: it breaks pip
# inside every virtualenv.
ENV HOME=/home/agent \
    NPM_CONFIG_PREFIX=/home/agent/.npm-global \
    PATH=/home/agent/.npm-global/bin:/home/agent/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

USER ovara-agent
WORKDIR /work
CMD ["bash"]
