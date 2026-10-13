# Interpose

Approve or deny agent requests from an iPhone, secured by a Secure Enclave key behind Face ID or an app PIN. A
**clearing house** for agent approvals: SSH tickets (Warpgate), held mail (Mailpit), and later scoped MCP leases.

Three parts:
- **Interpose Hub** (`interpose-hub`): a relay and management UI. It holds nothing that can act: requests are sealed for
  the user's phones, decisions are signed on them.
- **Adapters**, one beside each service it guards: they build the requests, verify every decision against their own
  trust list, and act.
- **The app** (Interpose, iOS): shows a request, asks for Face ID, signs the decision.

## Layout

```
ios/                  the app (SwiftUI, XcodeGen; ApproverKit Swift package)          ios/README.md
broker/               the hub (interpose-hub) and the software phone for tests         broker/README.md
                      (interpose-device)
adapter/              how adapters work, the shared adapter core and command line,     adapter/README.md
                      and the reference adapter (interpose-adapter-demo)
adapters/warpgate/    the Warpgate adapter (interpose-adapter) and its guided install  adapters/warpgate/README.md
adapters/mailpit/     the mail adapter (interpose-adapter-mailpit): held mail          adapters/mailpit/README.md
adapters/paperless/   the Paperless adapter (interpose-adapter-paperless): a gateway   adapters/paperless/README.md
                      where agents add documents freely and read within leases
internal/             Go shared by all of the above: protocol (+ Go/Swift interop fixtures), audit log, software device
docs/                 design, wire protocol, Docker setup, runbooks
scripts/              end-to-end tests (CLI device; real app in the simulator)
SECURITY.md           security model and how to report a vulnerability
```

All Go is one module (`go.mod` at the root), so `go test ./...` covers the hub and every adapter.

## Documentation

- Design and decisions: [docs/DESIGN.md](docs/DESIGN.md)
- Wire protocol (adapters, hub, app): [docs/PROTOCOL.md](docs/PROTOCOL.md)
- Writing an adapter: [adapter/README.md](adapter/README.md)
- Running the hub and adapters in Docker: [docs/docker.md](docs/docker.md)
- Deploying end to end (hub, then an adapter): [docs/runbooks/deploy-clearing-house.md](docs/runbooks/deploy-clearing-house.md)
- Hub sign-in with OIDC: [docs/runbooks/oidc.md](docs/runbooks/oidc.md)
- iOS app: [ios/README.md](ios/README.md); TestFlight: [docs/runbooks/testflight.md](docs/runbooks/testflight.md)
- Security model and reporting: [SECURITY.md](SECURITY.md)

## Develop

```
make check         # what CI runs: gofmt, vet, tests (race detector), CLI end to end
make test          # Go: vet + tests
make e2e           # real binaries over loopback with the software device
make ios-test      # ApproverKit: swift test
make e2e-ui        # real app in the iOS simulator against a live hub and the reference adapter
make build         # every Go command into bin/
make dist-adapter  # tests, then adapters/warpgate/deploy/interpose-adapter for linux/arm64
make dist-adapter-mailpit  # tests, then adapters/mailpit/deploy/interpose-adapter-mailpit (linux/amd64)
make docker-hub    # the hub's container image
make docker-adapter-paperless  # the Paperless adapter's container image (published to GHCR by CI)
```

### Pull requests and CI

`main` is protected: changes land through pull requests. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs
on every push and every pull request:

| Job | What |
|---|---|
| Go | gofmt, `go mod tidy`, vet, tests with the race detector, `scripts/e2e-cli.sh`, cross-builds for linux/arm64 and amd64 |
| Docker | builds the hub image and the Warpgate adapter image, checks the adapter's compose file and install script |
| ApproverKit | `swift test`, including the Go ↔ CryptoKit interop fixtures |
| govulncheck | known vulnerabilities in dependencies and the Go standard library (informational, not required) |
| **CI ok** | passes only if Go, Docker and ApproverKit passed: the one check branch protection requires |

Changes to `main` go through pull requests that merge automatically once **CI ok** passes. Repository settings and
the pull request workflow: [docs/runbooks/github.md](docs/runbooks/github.md).

## Notes

Host names in the docs are placeholders: `*.home.example` stands for your internal domain and `192.0.2.x` for LAN
addresses. Put real values in local configuration (`.env`, flags), never in the repository: it is public.

Trust is per **user**. Each user has a device list (roster) signed by their own phones, and a new phone is approved on
an existing one with Face ID. Each adapter trusts a user once:
`interpose-adapter trust add-user <user> <account fingerprint>`. The hub hands out enrollment codes but cannot add a
device to anyone.

Status:
- In use for Warpgate tickets, on LAN/VPN, with APNs wake-ups. Phase 1 (a single broker that sent Pushover links to
  Warpgate's own UI) is retired.
- Off-network transport is not chosen yet (see DESIGN.md, "Off-network transport").
