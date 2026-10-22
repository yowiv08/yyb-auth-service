# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.10

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/yyb-auth-service ./cmd/yyb-auth-service

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app \
    && adduser -S -G app app \
    && mkdir -p /data \
    && chown -R app:app /data

WORKDIR /app

COPY --from=builder /out/yyb-auth-service /app/yyb-auth-service

ENV YYB_LISTEN_ADDR=0.0.0.0:8080
ENV YYB_RUNTIME_DIR=/data
ENV YYB_LOG_LEVEL=info
ENV YYB_CORS_ORIGINS=*

EXPOSE 8080
VOLUME ["/data"]

USER app

ENTRYPOINT ["/app/yyb-auth-service"]
