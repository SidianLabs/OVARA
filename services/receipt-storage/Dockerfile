FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /receipt-storage ./cmd/server/
FROM alpine:3.20
COPY --from=builder /receipt-storage /usr/local/bin/receipt-storage
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/receipt-storage"]
