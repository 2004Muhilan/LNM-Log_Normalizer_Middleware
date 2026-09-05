# ULPF runtime — single static binary, no network egress, no model, no inference.
# Build context: repository root (the tests read contracts/ and ocsf/pinned/).
#   docker build -f runtime/Dockerfile --target test  .   # runs the runtime test suite inside the image
#   docker build -f runtime/Dockerfile -t ulpf-runtime .   # produces the runtime image

FROM golang:1.24-alpine AS build
RUN apk add --no-cache e2fsprogs   # chattr, for the IMMUTABLE step (privilege boundary itself is P5)
WORKDIR /src
COPY runtime/go.mod runtime/go.sum ./runtime/
RUN cd runtime && go mod download
COPY contracts ./contracts
COPY ocsf/pinned ./ocsf/pinned
COPY drafts ./drafts
COPY runtime ./runtime
RUN cd runtime && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ulpf-runtime ./cmd/ulpf-runtime

FROM build AS test
# Corpus-backed tests skip when corpus/cache is absent; mount it read-only to include them:
#   docker run --rm -v "$PWD/corpus/cache:/src/corpus/cache:ro" <image-id> go test ./... -run Replay
RUN cd runtime && go vet ./... && go test ./...

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/ulpf-runtime /ulpf-runtime
COPY --from=build /src/contracts /contracts
COPY --from=build /src/ocsf/pinned /ocsf/pinned
USER nonroot
ENTRYPOINT ["/ulpf-runtime"]
