# Build stage
FROM golang:1.26@sha256:5f3787b7f902c07c7ec4f3aa91a301a3eda8133aa32661a3b3a3a86ab3a68a36 AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm gcc libbpf-dev && \
    rm -rf /var/lib/apt/lists/*

RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.21.0

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go generate ./... && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags='-s -w' -o /hotspot ./cmd/hotspot

# Runtime stage
FROM gcr.io/distroless/static-debian12:latest@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838

COPY --from=build /hotspot /hotspot
COPY thresholds.yaml /etc/hotspot-bpf/thresholds.yaml

ENTRYPOINT ["/hotspot"]
CMD ["-config", "/etc/hotspot-bpf/thresholds.yaml"]
