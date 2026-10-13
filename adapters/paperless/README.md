# Paperless adapter (Paperless-ngx)

A gateway between agents and a [Paperless-ngx](https://docs.paperless-ngx.com) document store. Agents **add**
documents without asking anyone and get the document's link back. To **read**, an agent asks for a **lease** (a
scope, a duration and a document budget); a person grants it on the phone; the gateway enforces it on every call.
Agents hold a token for the gateway only; the Paperless token stays here. How adapters work in general:
[adapter/README.md](../../adapter/README.md).

```
lease.go                            package paperless: leases (scope, budget, expiry) and their store (leases.json)
source.go                           the Source: pending leases -> records; approve grants, deny refuses
gateway.go                          the HTTP API agents use (uploads, leases, reads within a lease)
agents.go                           agent names and token hashes (agents.json)
ppapi/                              the small part of Paperless's REST API it uses (API version 9, Paperless 2.x)
cmd/interpose-adapter-paperless/    the binary: adapter/cli with the Paperless source, plus `agent add|remove|list`
Dockerfile                          the image, built from source (ghcr.io/vfilby/interpose-adapter-paperless)
deploy/                             a reference compose.yaml and adapter.env.default
```

## Where it sits

```
agent ─HTTPS (bearer token)─> reverse proxy ─> this gateway ─Token─> Paperless API
                                                   │
                                   upload: straight through; the document's link comes back
                                   read:   needs a lease ──> record ──> phone
                                                                 │
                                           approve: the lease is granted for its duration
                                           deny / unanswered within REQUEST_TTL: refused
```

The gateway builds every Paperless request itself and forwards nothing from the agent's request. That matters when
Paperless trusts a remote-user header from its reverse proxy: the gateway reaches Paperless inside the stack's network,
with its token only, and the proxy's forward-auth never sees these calls.

What a lease allows, and what the gateway checks on every read:

| | |
|---|---|
| **scope** | a correspondent, a document type, tags (all of them), a full-text query, explicit document ids, in any combination; or nothing, which is every document the adapter's Paperless user can see (shown on the phone as a `danger` fact, risk `elevated`) |
| **duration** | from approval; `DEFAULT_LEASE` when the agent names none, at most `MAX_LEASE` |
| **budget** | how many distinct documents may be read (text or file); `MAX_DOCUMENTS` by default, 0 = unlimited (a `warn` fact) |
| **searches** | run inside the scope: the scope's filters are added server-side; the agent may narrow, never widen |
| **documents** | one is served only if Paperless lists it under the scope's own filter (`id__in` plus the scope), then it is charged to the budget, once |
| **agent** | a lease belongs to the agent that asked; another agent's token cannot use it |

Writes other than adding a document (edit, delete, tag) do not exist here, by design.

## What the phone shows

Title: `maggy wants to read Paperless: Correspondent: Insurance Co; Tags: 2026`. Facts come from the store, as the
scope was resolved when the agent asked (names are shown, ids are enforced): **Agent**, one line per scope limit (or
**Scope: every document**, `danger`), **Duration**, **Documents** (the budget; `unlimited` is `warn`). The agent's
`reason` is quoted as its own claim, bounded to 1 KiB. Shape `lease`, kind `paperless.read`.

## The gateway

All calls carry `Authorization: Bearer <agent token>`; answers are JSON unless noted. Reads carry the lease id in
`X-Lease: <id>` (or `?lease=`).

| Call | What |
|---|---|
| `GET /healthz` | `ok` (no token) |
| `GET /v1/tags`, `/v1/correspondents`, `/v1/document_types` | `[{id, name}]`, no lease: needed to file well and to ask for a well-scoped lease |
| `POST /v1/tags`, `/v1/correspondents` | `{name}`: add one, no lease. **201** `{id, name, existing: false}`; a name Paperless already has (any case) comes back **200** with `existing: true`, never duplicated. Document types are not creatable |
| `POST /v1/documents` | multipart: `file` (required), `title`, `created` (YYYY-MM-DD), `correspondent`, `document_type`, `tags` (names, repeated or comma-separated), `asn`. `?wait=` (default 90s) waits for consumption. **201** `{status: done, document: {id, title, url, …}}`; **202** `{status: pending, task, poll}` when still consuming; **409** `{status: duplicate, document: {id, url}}`; **422** `{status: failed, error}` |
| `GET /v1/uploads/{task}` | the same answer for an upload that was still consuming; `?wait=` |
| `POST /v1/leases` | `{scope: {correspondent, document_type, tags: [], query, documents: []}, duration: "2h", max_documents: 20, reason: "…"}` (`reason` required). **202** with the lease, `status: pending` |
| `GET /v1/leases/{id}` | the lease; `?wait=60s` returns as soon as it is approved or denied (at most `MaxWait`, 2 min) |
| `GET /v1/leases` | this agent's leases |
| `GET /v1/documents` | search within the lease: `q` (full text), `correspondent`, `document_type`, `tags`, `created_after`, `created_before`, `ordering`, `page`, `page_size` (≤100). Listings carry no content |
| `GET /v1/documents/{id}` | the document with its text (`content`) and `url`; charged to the lease |
| `GET /v1/documents/{id}/file` | its original file (binary, `Content-Disposition`); the same document, not charged again |

A lease's `status` is `pending`, `approved`, `denied` (with `deny_reason`) or `expired`. Refusals are 403 with a
one-line `error`: no lease, not approved, expired, budget spent, outside the scope.

## Settings

`deploy/adapter.env.default` lists them: `HUB_URL`, `ADAPTER_ID`, `PAPERLESS_URL` (inside the stack),
`PAPERLESS_PUBLIC_URL` (for links), `PAPERLESS_TOKEN_FILE`, `LISTEN`, `DEFAULT_LEASE`, `MAX_LEASE`, `MAX_DOCUMENTS`,
`MAX_UPLOAD_MB`, `REQUEST_TTL`. The adapter directory (`-dir`, `/data` in the container) holds the shared adapter
files (signing key, hub token, trust list, open records, `audit.jsonl`) plus `leases.json`, `agents.json` and
`access.jsonl` (every upload, lease, search, read, file and refusal, with the agent and the lease).

## The credential

A Paperless user of its own (for example `interpose-gateway`), **not** a superuser, with these permissions and no
others: `Document: add, view`; `Tag`, `Correspondent`: `add, view`; `Document type`, `Paperless task`: `view`. A
missing one shows in the log as a 403 naming the path. Its API token (`manage.py drf_create_token <user>`, or My
profile → API auth token) goes in `secrets/paperless-token`.

Paperless's object permissions apply: the user sees documents that have no owner, that it owns, or that are shared with
it. Documents it uploads are its own, so give the household a way to see them: a Paperless workflow (trigger: document
added; action: assign owner, or grant view to a group) does it on every upload.

## Deploying

The image is published by [`.github/workflows/docker-publish.yml`](../../.github/workflows/docker-publish.yml) as
`ghcr.io/vfilby/interpose-adapter-paperless:sha-<commit>` on every main commit that touches the adapter; pin a full
sha. `deploy/compose.yaml` is the reference: it joins Paperless's internal network and the reverse proxy's, publishes no
port, and expects the proxy to put TLS in front of `:8750` and to limit who may reach it (an IP allow-list for the
agents' host is a good start; the tokens are the second factor). Then, in the stack's directory:

```
cp adapter.env.default .env                        # fill in the host names
install -d -m 0700 -o 65534 -g 65534 data secrets
install -m 0400 -o 65534 -g 65534 paperless-token secrets/paperless-token
docker compose run --rm adapter-paperless key -dir=/data      # prints the public key: register the adapter at the hub
docker compose run --rm adapter-paperless trust add-user -dir=/data <user> <account fingerprint>
docker compose run --rm adapter-paperless agent add -dir=/data maggy   # prints the token once: into the agent's secrets
docker compose up -d
```

The hub token (from the hub's management UI, when the adapter is registered) goes in `data/hub-token`, mode 0400,
owner 65534. `agent list` and `agent remove NAME` manage the agents; a removed agent's leases stay in `leases.json`
until they age out.

## Developing

`go test -race ./adapters/paperless/...` runs the gateway against a fake Paperless over real HTTP (uploads, duplicates,
the lease flow through the Source, scope and budget refusals, expiry, persistence). `make docker-adapter-paperless`
builds the image locally.
