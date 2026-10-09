#!/usr/bin/env bash
# Docker Hub rate-limits anonymous pulls from shared runner addresses (HTTP
# 429), and a run of this repository builds many images at once. Pull
# docker.io images through Google's public mirror instead; an image the
# mirror lacks still comes from Docker Hub. Keeps the runner's own settings.
set -euo pipefail
f=/etc/docker/daemon.json
cur='{}'
if sudo test -s "$f"; then cur="$(sudo cat "$f")"; fi
printf '%s' "$cur" | python3 -c '
import json, sys
d = json.load(sys.stdin)
m = d.setdefault("registry-mirrors", [])
if "https://mirror.gcr.io" not in m:
    m.insert(0, "https://mirror.gcr.io")
print(json.dumps(d, indent=2))' | sudo tee "$f" >/dev/null
sudo systemctl restart docker
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
echo "registry mirrors: $(docker info --format '{{.RegistryConfig.Mirrors}}')"
