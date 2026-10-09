FROM golang:1.26 AS go
FROM node:24-bookworm
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=$PATH:/usr/local/go/bin
# A failed install must fail the build, not produce an image without it.
RUN apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null && \
    python3 -m venv /tmp/venv-check && rm -rf /tmp/venv-check && \
    git --version && node --version && python3 --version
