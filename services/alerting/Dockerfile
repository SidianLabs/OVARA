FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /alerting-service ./cmd/server/
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /alerting-service /usr/local/bin/alerting-service
EXPOSE 8083
ENTRYPOINT ["/usr/local/bin/alerting-service"]
