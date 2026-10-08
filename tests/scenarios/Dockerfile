FROM golang:1.25 AS go
FROM node:24-bookworm
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=$PATH:/usr/local/go/bin
RUN apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null 2>&1; git --version; node --version; python3 --version
