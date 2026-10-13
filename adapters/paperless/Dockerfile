# The Paperless adapter (interpose-adapter-paperless), built from source. Build from the repository root (one Go
# module):
#   docker build -f adapters/paperless/Dockerfile -t interpose-adapter-paperless:local .
# distroless/static: no shell, no package manager. The publish workflow pushes it to ghcr.io/vfilby/interpose-adapter-paperless.
# The build stage runs on the build machine and cross-compiles for the target, so a multi-arch build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY adapter ./adapter
COPY adapters/paperless ./adapters/paperless
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/interpose-adapter-paperless ./adapters/paperless/cmd/interpose-adapter-paperless

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/interpose-adapter-paperless /interpose-adapter-paperless
ENV GOMEMLIMIT=48MiB
EXPOSE 8750
ENTRYPOINT ["/interpose-adapter-paperless"]
