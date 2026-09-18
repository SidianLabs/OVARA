# Build the unified Ovara binary (gateway + executor proxy).
# Build context is the REPO ROOT (the binary embeds the gateway module
# via a local replace):  docker build -f proxy/Dockerfile -t ovara .
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY . .
RUN cd proxy && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /ovara ./cmd/ovara

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ovara /ovara
# Mount your deployment dir at /data:  ovara init /data  &&  ovara run -dir /data
VOLUME /data
EXPOSE 8080 9443
ENTRYPOINT ["/ovara"]
CMD ["run", "-dir", "/data"]
