# Adapters: how they work, and how to write one

An adapter sits **beside one service** (Warpgate, a mail relay, a document store) and is the only part of the clearing
house that can act on it. It turns the service's pending items into requests a person approves on their phone, and
acts only on a decision it has verified itself. The hub in between is a relay that is assumed hostile.

This directory holds:

```
adapter/                    the adapter core (Go package adapter): records, sealing, trust, decisions, acks, state
adapter/cli/                the command line every adapter binary shares: key, trust, run
adapter/demo/               the demo Source: a fake service fed over loopback HTTP
adapter/cmd/interpose-adapter-demo/  the reference adapter: cli.Main + the demo Source
```

Real adapters live in [`../adapters/`](../adapters/), one directory each.

## What an adapter is responsible for

These hold for every adapter, in any language. The wire formats are in [docs/PROTOCOL.md](../docs/PROTOCOL.md).

1. **It describes the request from the service's own state.** `title` and `facts` come from what the service says is
   pending, never from the requester. What the requester claims goes in `reason`, which the app shows as a quote.
2. **It applies its own policy first.** Anything the service's policy would refuse is denied at the service without
   asking anyone (the Warpgate adapter refuses unknown requesters and over-long tickets this way).
3. **It signs every record** with its own Ed25519 key, and **seals it** (HPKE, P-256) separately to each device of each
   user it trusts. The hub sees only ciphertext and routing metadata.
4. **It trusts users, not the hub.** Its trust list pins user id + account fingerprint (the hash of the user's first
   roster), set by an operator with `trust add-user`, or read from the user's LDAP entry when the adapter is told to
   trust that user or a group they are in (`-trust`; [docs/runbooks/ldap.md](../docs/runbooks/ldap.md)). It fetches
   each user's roster chain through the hub and verifies it itself: every version signed by a device on the previous
   one, no rollback, no fork. A hub that lies can only withhold. An LDAP user is asked of the directory again, live,
   before any decision of theirs is acted on.
5. **It verifies every decision before acting**: a device on a trusted user's current roster, the right key (approve
   needs the approve key), this adapter's id, the hash of the exact record it sent, an unused nonce, a timestamp within
   300 s, an unexpired record.
6. **It re-reads the item just before acting.** If the service no longer shows it pending, or shows it changed since the
   record was made, it does not act; a changed item is sent again as a new record.
7. **It fails closed.** Unanswered requests are denied at the service when they expire. An unreadable trust list stops
   publishing. A decision that does not verify does nothing.
8. **It acknowledges** every outcome with a signed ack, so the phone can show what actually happened.
9. **It keeps an audit log** (append-only JSON lines) of records, publications, outcomes and every change in who it
   trusts (`trust-added` / `trust-removed`: user, account fingerprint, source), and **does not let the hub fill it**. Everything from the hub is bounded before it is written: at most 500 decisions are looked at per
   long-poll; a decision whose request id or envelope `kid` does not have the form the adapter and devices make is
   dropped unlogged; rejected decisions are logged (and, for a known request, acked) in a burst of 20 and then one
   per 6 s, separately for unknown requests and for ones that failed verification; whatever is dropped is summed up in
   one `decisions-not-logged` entry at most once a minute. A `decision-rejected` entry names the device the envelope
   claims, marked `"unverified": true`, never the hub's `device_id`. The Go adapter starts a new `audit.jsonl` past
   `-audit-max-mb` (64) and keeps `-audit-keep` (8) old ones as `audit.jsonl.1` (newest) to `audit.jsonl.8`.
10. **It only connects out**, to the hub and to its service, and holds only that service's credential, scoped as
    narrowly as the service allows (Warpgate: a user whose only right is to manage ticket requests).

## Writing one in Go

The core does items 3–9. An adapter supplies a `Source` (`adapter.go`):

```go
type Source interface {
	// Pending lists what needs a person now, after the source's own policy (which may deny by itself).
	Pending(ctx context.Context) ([]Item, error)
	// Current re-reads one item just before acting. ok false: no longer pending.
	Current(ctx context.Context, key string) (it Item, ok bool, err error)
	Approve(ctx context.Context, key string) error
	Deny(ctx context.Context, key, reason string) error
}
```

- `Item.Key` is the service's own id for the item, stable while it is pending. Every field of the item is hashed; if
  `Current` returns something different from what `Pending` returned, the adapter treats it as changed.
- `Approve` and `Deny` return `adapter.ErrGone` if the item is no longer pending at the service.
- `Kind` names the request type (`ssh.ticket`, `mail.release`); `Shape` is `once` or `lease`; `Risk` is `normal`,
  `elevated` or `high` (high makes the app ask for a second, deliberate gesture).
- Errors from `Pending` are logged and retried on the next poll. Never turn "could not read the service" into a deny
  or an empty list that closes open requests.

Then a `main` that hands the source to the shared command line, as the reference adapter does
([`cmd/interpose-adapter-demo/main.go`](cmd/interpose-adapter-demo/main.go)):

```go
func main() {
	cli.Main("interpose-adapter-mysvc", cli.Source{Name: "mysvc", Flags: func(fs *flag.FlagSet) func(context.Context, *slog.Logger) (adapter.Source, error) {
		url := fs.String("mysvc-url", "", "the service's API base URL")
		return func(ctx context.Context, log *slog.Logger) (adapter.Source, error) { return mysvc.New(*url) }
	}})
}
```

That gives the binary the same commands as every other adapter:

```
interpose-adapter-mysvc key                          # make the signing key; prints the public key to register at the hub
interpose-adapter-mysvc trust add-user USER ACCOUNT  # trust a user (account fingerprint read off their phone)
interpose-adapter-mysvc trust list | remove-user USER
interpose-adapter-mysvc run -id mysvc -hub https://hub.example [trust flags] [source flags]
```

Trust flags (`run` and `trust list`) choose where trusted users come from: `-trust local` (the default:
`trusted-users.json`), `-trust ldap-group:<group>`, `-trust ldap-user:<uid>`, or several comma-separated, with
`-ldap-url`, `-ldap-bind-dn`, `-ldap-bind-password-file`, `-ldap-user-base` and the rest. Each has an environment
variable (`INTERPOSE_TRUST`, `LDAP_URL`, …) so a compose project's `.env` can carry it; the table is in
[docs/runbooks/ldap.md](../docs/runbooks/ldap.md).

The adapter directory (`-dir`, default `adapter-data`) holds `signing.key`, `hub-token` (from the hub's management UI),
`trusted-users.json`, `trusted-heads.json`, `state.json` and `audit.jsonl`. Keep it private to the adapter.

### Layout of a new adapter

```
adapters/<service>/
  README.md        what it guards, the credential it needs and how to scope it, settings, deploy steps
  source.go        package <service>: the Source
  cmd/<binary>/    main: cli.Main with the Source
  deploy/          Dockerfile, compose.yaml, example env (no real host names: the repository is public)
```

Test the Source against a fake of the service's API (see `adapters/warpgate/wgapi` and `policy` tests), and the whole
flow with the core's end-to-end tests in [`broker/e2e`](../broker/e2e), which run a real hub, the core and software
phones in one process.

### Checklist before deploying a new adapter

- [ ] Facts come from the service, not the requester; nothing the requester controls can make a fact look different.
- [ ] `Current` re-reads the service, not a cache.
- [ ] `Approve` acts on exactly what was shown (same recipients, same scope, same duration), nothing more.
- [ ] Read errors never become denials or closures.
- [ ] The service credential cannot do more than approve and deny (or grant the lease).
- [ ] It runs as its own non-root user with a read-only filesystem, no capabilities, and a memory limit
      (see `adapters/warpgate/deploy/compose.yaml`).

## Writing one in another language

Implement [docs/PROTOCOL.md](../docs/PROTOCOL.md): the signed envelope, the sealed box, the request record, decision
verification, the ack, roster chain verification, and the adapter routes of the hub API. The Go and Swift interop
fixtures in [`internal/protocol/testdata/interop`](../internal/protocol/testdata/interop) are known-good inputs to
test against. Everything in "What an adapter is responsible for" still applies.

## Try the reference adapter

```
make e2e    # a hub, the reference adapter and software phones on loopback: enroll, approve, deny, join, remove
```

Or by hand: run `interpose-hub` locally (`broker/README.md`), then

```
go build -o bin/ ./broker/cmd/... ./adapter/cmd/...
bin/interpose-adapter-demo key                        # register the public key at http://127.0.0.1:8741/adapters, id demo
echo '<token from the hub>' > adapter-data/hub-token
bin/interpose-adapter-demo trust add-user vince '<account fingerprint from the phone>'
bin/interpose-adapter-demo run -id demo
curl localhost:8749/requests -d '{"requester":"claude","title":"claude wants RW on db-01","risk":"elevated","reason":"fix backups"}'
```
