# The image the docker-mode red team runs its probes in: an ordinary
# container on the boundary network with the tools an attacker would use.
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      bash curl ca-certificates iputils-ping iproute2 nftables util-linux python3 \
 && rm -rf /var/lib/apt/lists/*
