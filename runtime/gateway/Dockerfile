# Build context is the REPO ROOT: go.mod carries
# `replace ovara.identity => ../../identity`, which must resolve inside
# the image. Layout: /app/runtime/gateway + /app/identity.
#   docker build -f runtime/gateway/Dockerfile -t ovara/gateway .
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY identity/ identity/
COPY runtime/gateway/ runtime/gateway/

WORKDIR /app/runtime/gateway
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ovara-gateway ./cmd/server/

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

RUN mkdir -p /etc/ovara /var/data/ovara /var/log/ovara /tmp/ovara-exec

COPY --from=builder /ovara-gateway /usr/local/bin/ovara-gateway

ENV OVARA_ENVIRONMENT=production
ENV OVARA_CONFIG=/etc/ovara/config.json

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD wget -q -O - http://localhost:8080/v1/runtime/health || exit 1

ENTRYPOINT ["/usr/local/bin/ovara-gateway"]
