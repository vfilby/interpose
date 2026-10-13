.PHONY: check test ios-test e2e e2e-ui build dist-adapter dist-adapter-mailpit docker-hub docker-adapter-paperless clean

# What CI runs on every push and pull request (.github/workflows/ci.yml), minus Docker.
check: test e2e
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

test:
	go vet ./... && go test -race -count=1 ./...

ios-test:
	cd ios/ApproverKit && swift test

e2e:
	scripts/e2e-cli.sh

e2e-ui:
	scripts/e2e-ui.sh

# Every command, for this machine, into bin/.
build:
	go build -o bin/ ./broker/cmd/... ./adapter/cmd/... ./adapters/warpgate/cmd/... ./adapters/mailpit/cmd/... ./adapters/paperless/cmd/...

# The Warpgate adapter, for the Warpgate host (adapters/warpgate/README.md).
dist-adapter: test
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o adapters/warpgate/deploy/interpose-adapter ./adapters/warpgate/cmd/interpose-adapter
	@shasum -a 256 adapters/warpgate/deploy/interpose-adapter

# The mail adapter, for the Mailpit host (adapters/mailpit/README.md). MAILPIT_ARCH=arm64 for an ARM host.
MAILPIT_ARCH ?= amd64
dist-adapter-mailpit: test
	CGO_ENABLED=0 GOOS=linux GOARCH=$(MAILPIT_ARCH) go build -trimpath -ldflags='-s -w' -o adapters/mailpit/deploy/interpose-adapter-mailpit ./adapters/mailpit/cmd/interpose-adapter-mailpit
	@shasum -a 256 adapters/mailpit/deploy/interpose-adapter-mailpit

# The hub's container image (docs/docker.md).
docker-hub:
	docker build -f broker/Dockerfile -t interpose-hub:local .

# The Paperless adapter's container image (adapters/paperless/README.md).
docker-adapter-paperless:
	docker build -f adapters/paperless/Dockerfile -t interpose-adapter-paperless:local .

clean:
	rm -rf bin adapters/warpgate/deploy/interpose-adapter adapters/mailpit/deploy/interpose-adapter-mailpit
