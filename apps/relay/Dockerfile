# Build from the repository root:
#   docker build -f apps/relay/Dockerfile -t quorum-relay .
#
# The root is the build context because the relay needs packages/protocol/schemas
# as well as its own source. Those schemas are not a nice-to-have asset: the
# relay refuses to start without them, deliberately, because a relay that
# silently stops validating still looks healthy.

FROM golang:1.25-alpine AS build

WORKDIR /src

COPY apps/relay/go.mod apps/relay/go.sum ./
RUN go mod download

COPY apps/relay/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/quorum-relay .

FROM alpine:3.21

RUN adduser -D -H -u 10001 quorum

COPY --from=build /out/quorum-relay /usr/local/bin/quorum-relay
COPY packages/protocol/schemas /srv/quorum/schemas

ENV QUORUM_ADDR=:3334 \
    QUORUM_DATA_DIR=/var/lib/quorum \
    QUORUM_SCHEMA_DIR=/srv/quorum/schemas

# The relay's key is generated here on first run and is its identity: it signs
# the group metadata clients trust and, from M7, the checkpoints that make
# withholding an event provable. Mount it, or the workspace gets a new identity
# every time the container is replaced.
VOLUME /var/lib/quorum
RUN mkdir -p /var/lib/quorum && chown quorum /var/lib/quorum

USER quorum
EXPOSE 3334

ENTRYPOINT ["quorum-relay"]
