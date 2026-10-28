# syntax=docker/dockerfile:1.7
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/siem-lite ./cmd/siem-lite && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/loggen ./cmd/loggen

FROM gcr.io/distroless/static-debian12:nonroot AS loggen
COPY --from=build /out/loggen /usr/local/bin/loggen
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/loggen"]

FROM gcr.io/distroless/static-debian12:nonroot AS siem-lite
WORKDIR /app
COPY --from=build /out/siem-lite /usr/local/bin/siem-lite
COPY rules /app/rules
COPY deploy/geo /app/geo
ENV SIEM_RULES_DIR=/app/rules
USER nonroot:nonroot
EXPOSE 8080 5514/udp 5514/tcp
ENTRYPOINT ["/usr/local/bin/siem-lite"]
