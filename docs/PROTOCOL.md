# Approval protocol v1

The wire formats shared by adapters (Go), the hub (Go) and the iOS app (Swift). Anything not written here is not
part of the protocol. Architecture and reasoning: [DESIGN.md](DESIGN.md), section "Clearing house".

## Roles

| Role | Holds | Trusted for |
|---|---|---|
| **Adapter** (one per service: Warpgate, Mailpit, Paperless, …) | the service credential; an Ed25519 signing key; pinned users (user id + account fingerprint) | building the request record, verifying decisions, acting |
| **Hub** | nothing that can act: bearer tokens for transport, ciphertexts, metadata | relaying and storing. It can drop or delay; it cannot approve, forge, or read a record |
| **Device** (iPhone) | Secure Enclave keys | showing the record, getting Face ID / PIN, signing the decision |

Every security property below holds with a hostile hub and hostile transports.

## Encodings

- **b64**: base64url without padding (RFC 4648 §5), everywhere.
- **Times**: integer Unix seconds (UTC).
- **JSON**: UTF-8. Readers ignore unknown fields. Nothing is canonicalized: signatures cover the exact payload bytes
  carried in the envelope, and hashes are over those same bytes.
- **Fingerprint** of a public key: the first 8 bytes of SHA-256 over the key's raw encoding, as 4 groups of 4 lower-case
  hex digits: `3f2a-91c0-77de-0b14`.

## Keys

| Key | Algorithm | Public encoding | Where |
|---|---|---|---|
| adapter signing | Ed25519 | 32 raw bytes | file on the adapter's host (0400) |
| device approve | ECDSA P-256 / SHA-256 | X9.63 uncompressed, 65 bytes | Secure Enclave, Face ID (current set) or app PIN |
| device deny | ECDSA P-256 / SHA-256 | X9.63 uncompressed, 65 bytes | Secure Enclave, device unlocked |
| device encryption | P-256 key agreement (HPKE) | X9.63 uncompressed, 65 bytes | Secure Enclave, after first unlock |

ECDSA signatures are the 64-byte raw `r || s` form (CryptoKit `rawRepresentation`). Ed25519 signatures are 64 bytes.

**Device id** = the fingerprint of the approve key without dashes (16 hex digits).

## Signed envelope

```json
{"alg": "ed25519" | "es256", "kid": "<signer id>", "payload": "<b64 bytes>", "sig": "<b64>"}
```

`sig` is over the decoded `payload` bytes. `kid` is the adapter id for `ed25519`, the device id for `es256`. A verifier
checks the signature with the key it has **pinned** for `kid` before parsing the payload, and then checks that the
payload names the same signer (`adapter` / `device_id`).

### Payload types

Every signed payload carries `"t"`, saying what it is, and every verifier refuses a payload whose `t` is not the
kind it expects (a missing `t` included). One key signs more than one kind: the adapter key signs records and acks,
and a device's approve key signs cards, rosters and approvals.

| `t` | Signed with | Section |
|---|---|---|
| `record` | adapter key | Request record |
| `ack` | adapter key | Acknowledgement |
| `decision` | device approve key, or deny key for a deny | Decision |
| `card` | device approve key | Device card |
| `roster` | device approve key | Users and rosters |

## Sealed box (adapter → device)

```json
{"suite": "hpke-p256-sha256-aes256gcm", "kid": "<device id>", "enc": "<b64 65 bytes>", "ct": "<b64>"}
```

RFC 9180 HPKE, mode base: DHKEM(P-256, HKDF-SHA256) `0x0010`, HKDF-SHA256 `0x0001`, AES-256-GCM `0x0002`
(CryptoKit `HPKE.Ciphersuite.P256_SHA256_AES_GCM_256`). `info` = the ASCII bytes `interpose/v1/record`, `aad` = empty,
one message per context. The plaintext is the JSON of a **signed envelope** whose payload is a request record: sign,
then encrypt, so the hub sees neither the record nor the adapter's signature over it.

## Request record (adapter → device)

```json
{
  "t": "record",
  "v": 1,
  "id": "<adapter-scoped request id>",
  "adapter": "warpgate",
  "kind": "ssh.ticket",
  "shape": "once" | "lease",
  "risk": "normal" | "elevated" | "high",
  "title": "helper wants RW on db-01",
  "requester": "helper",
  "on_behalf_of": {"principal": "slack:U0123", "display": "Kim", "attested_by": "chatbot@agent-host"},
  "facts": [
    {"label": "Host", "value": "db-01"},
    {"label": "Tier", "value": "RW", "level": "warn"},
    {"label": "Duration", "value": "2h"}
  ],
  "reason": "<requester's own words>",
  "lease": {"duration_s": 7200, "scope": "db-01-rw", "max_uses": 0},
  "created_at": 1790000000,
  "expires_at": 1790000900,
  "nonce": "<b64 16 random bytes>"
}
```

- `title` and `facts` are written by the adapter from the service's own state: they are the **authoritative**
  part and are shown first. `level` is `""`, `"warn"` or `"danger"`. The app renders any kind from these fields
  alone. It needs no kind-specific code.
- `reason` is the requester's claim. The app shows it after the facts, quoted and labelled as the requester's.
  Adapters bound it where it comes in: at most 1 KiB, without C0 or C1 control characters or U+2028/U+2029 (line
  breaks and tabs become spaces). The app still sanitizes everything it shows.
- `on_behalf_of` is optional: the human the requester says it acts for, and which component attested it. It is a
  claim by `attested_by`, not by the requester.
- `lease` is present only when `shape` = `lease`. `max_uses` 0 means unlimited within the duration.
- `risk` = `high` makes the app ask for a second deliberate gesture before signing an approval.
- `nonce` makes every record unique. It is echoed in the decision and is single-use at the adapter.

## Decision (device → adapter)

A signed envelope (`es256`, `kid` = device id) over:

```json
{
  "t": "decision",
  "v": 1,
  "user": "<user whose roster the device is on>",
  "request_id": "<record id>",
  "adapter": "warpgate",
  "decision": "approve" | "deny",
  "record_hash": "<b64 SHA-256 of the record payload bytes>",
  "nonce": "<record nonce>",
  "device_id": "<device id>",
  "ts": 1790000123
}
```

- `user` says which account the device decides for. A device can be on the rosters of two users an adapter trusts;
  the decision holds only against the roster of the user it names, and that user is the one the adapter records.
- `approve` must be signed with the device's **approve** key. `deny` may be signed with the deny key or the
  approve key.
- The adapter acts only if all of these hold:
  - the device is on the current roster of `user`, a user this adapter pins, and the key matches the decision;
  - `adapter` is this adapter;
  - `record_hash` equals the hash of the record it sent;
  - the nonce is unused;
  - `|now - ts|` ≤ 300 s;
  - the record has not expired;
  - the service still shows the request pending and unchanged.

  Otherwise it rejects the decision and does nothing.

## Acknowledgement (adapter → device)

A signed envelope (`ed25519`, `kid` = adapter id) over:

```json
{"t": "ack", "v": 1, "request_id": "…", "adapter": "warpgate", "outcome": "approved" | "denied" | "rejected" | "expired" | "failed",
 "detail": "…", "decision_hash": "<b64 SHA-256 of the decision payload bytes, or empty>", "ts": 1790000125}
```

The app shows the outcome only after verifying the adapter's signature. An unverified ack is shown as "unconfirmed".

`approved`, `denied` and `expired` are **final**: the hub stops offering the request. `rejected` (the decision did not
verify) and `failed` (the service call failed) are **notes**: the request stays pending, and the person may decide
again. That produces a fresh decision with a new `ts` and the same record nonce. A record's nonce is used up only when
the adapter acts on it.

## Device card

A signed envelope (`es256`, `kid` = device id, signed with the approve key: making it needs Face ID) over:

```json
{"t": "card", "v": 1, "device_id": "…", "name": "Vince's iPhone", "approve_key": "<b64>", "deny_key": "<b64>",
 "enc_key": "<b64>", "created_at": 1790000000}
```

`name` is at most 100 bytes of UTF-8 with no control, format (bidi overrides, zero-width), line separator or
paragraph separator characters (Unicode general categories Cc, Cf, Zl, Zp); a card with another name does not verify.
Devices clean the name before signing their card. It is shown when a join is approved and written into deny reasons
("denied by vince on Vince's iPhone").

A card says what a device's keys are. Which **user** a device belongs to is said only by that user's roster.

## Users and rosters

A user (`vince`, `kim`; 1–40 of `a-z 0-9 . _ -`) is the set of devices on the head of their **roster chain**. Each
roster is a signed envelope (`es256`, `kid` = id of the signing device) over:

```json
{
  "t": "roster",
  "v": 1,
  "user": "vince",
  "seq": 2,
  "prev": "<b64 SHA-256 of roster seq-1's payload bytes; empty for seq 1>",
  "members": [ {"kind": "device", "card": <device card envelope>}, … ],
  "ts": 1790000000
}
```

A chain `[r1, r2, …, rn]` is valid only if all of these hold:
- **r1 (genesis):** `seq` 1, empty `prev`. It is signed by the approve key of a device that is a member of r1.
  Verifiers check the signer's own card, then r1's signature, and only then the other member cards.
- **Each later rk:**
  - `seq` = k and `user` is unchanged;
  - `prev` = SHA-256 of r(k-1)'s payload bytes;
  - it is signed by the approve key of a device that is a member of **r(k-1)**, the previous roster. That device may
    be absent from rk: a device can remove itself.
- **Every roster:**
  - at least one member;
  - every card verifies (as in "Device card");
  - no device id appears twice.
- **Unknown member kinds** make the roster invalid. `recovery` (an offline key that may sign roster updates but never
  decisions) is reserved for a later version (see D16 in [DESIGN.md](DESIGN.md)).

The **account fingerprint** pins a user. It is the first 16 bytes of SHA-256 over r1's payload bytes, as 8 groups of
4 hex digits: `3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0`. The phone that made r1 shows it, and so does the hub. An adapter
pins `(user, account fingerprint)` and accepts a chain only if the hash of its r1 matches.

Adding a device:
1. The new device enrolls with a **join** code for the user. It is then pending: no adapter knows it, and the hub
   serves it only its user's roster (to learn when it is admitted) and a plain leave (to withdraw); every other device
   route answers 403.
2. An existing device of the user sees the join request: name and device fingerprint, which the person compares with
   the new phone.
3. On approval (Face ID), that device builds the next roster from **its own verified copy** of the chain, adds the
   new card, signs it, and posts it.
4. The new device sees a verified chain that includes it. It does not pin that chain's account fingerprint on sight:
   the hub holds the join card and could have built a chain of its own around it. The person compares the fingerprint
   with an existing device of the account; the new device pins it only once they confirm it matches, and acts as a
   member only then.

Removing a device is a next roster without it, signed on any current device.

The hub keeps chains bounded: it takes a roster (genesis included) only if it has at most 20 members and at most
48 KB of payload and signature, and it keeps at most 200 rosters per user. A user whose chain is full takes no more
rosters: an admin deletes the account and it is enrolled again, with a new account fingerprint (below).

Adapters re-fetch chains and verify them back to the pin. Compared with the head they last verified, a chain is
refused if any of these hold:
- its head has a lower `seq`;
- its head has the same `seq` but different bytes;
- its head has a higher `seq` but the chain does not contain that exact last-verified head. A device removed at vN
  still holds its key; it could sign an alternative vN' from v(N-1), where it was a member, and then vN+1'. Without
  this rule that would undo the removal.

Devices apply the same rules to their own user's chain. So the hub cannot add devices or roll back a removal an adapter has seen. It can still withhold a newer roster:
a removal takes effect at an adapter only once that adapter sees it.

An admin can also delete an account at the hub (management UI, break glass): for when none of its phones is left to
approve another. The next enrollment of that user starts a new account with a new fingerprint, which adapters do not
trust until `interpose-adapter trust add-user` is run again (or, for adapters that read the fingerprint from the user's
LDAP entry, until that entry is updated); the old account's trust does not carry over.

## Hub HTTP API (transport only)

Every route requires `Authorization: Bearer <token>`. Adapter tokens and device tokens are different kinds and
reach different routes. Tokens are transport credentials: they stop LAN noise and abuse, not forgery. A device whose
join is not approved yet (enroll `status` `pending`) gets 403 on every device route except `GET /v1/device/roster` and
`POST /v1/device/leave` without `roster` or `delete_account`.

| Route | Caller | Purpose |
|---|---|---|
| `POST /v1/adapter/requests` | adapter | `{id, kind, expires_at, boxes: {device_id: sealed}}`: publish a request. The hub drops boxes for devices it does not serve (unknown or revoked), so only the devices left are woken, and refuses the request (400) if none is left. It caps `expires_at` at 24 hours from now. |
| `GET /v1/adapter/decisions?wait=25` | adapter | long-poll: `[{request_id, device_id, decision: envelope}]` not yet taken |
| `POST /v1/adapter/acks` | adapter | `{request_id, ack: envelope}`: resolves the request at the hub |
| `GET /v1/adapter/rosters?user=<id>` | adapter | `{user, chain: [roster envelopes]}` |
| `POST /v1/enroll` | new device (one-time code instead of a token) | `{code, card, genesis?}` → `{device_id, token, user, status}`. `genesis` (r1, containing this card) is required for a `new` code and refused for a `join` code. `status` is `active` (in the head roster) or `pending` (join not approved yet). A device revoked at the hub is refused until an admin removes it from the hub's list. |
| `GET /v1/device/roster` | device (also pending) | `{user, chain}` for the device's user |
| `POST /v1/device/roster` | device (current member) | `{roster: envelope}`: the next roster. The hub checks it extends the chain, appends it, and stops serving devices it removes |
| `POST /v1/device/leave` | device (pending: plain leave only) | `{roster?, delete_account?}`: the device goes away and the hub deletes its record. `roster` is the next roster, without this device, signed by it: it takes itself off the account first. `delete_account` is only for the account's last device (its keys are going, so nothing could sign for the account again): the hub deletes the account. Neither: the roster is unchanged and the device may come back with a join code. |
| `POST /v1/device/push` | device | `{token, environment}`: the device's APNs token (hex) and `production` or `development`; an empty token stops pushes. The hub pushes a fixed text, never request content: "Approval request" to the devices a request is sealed for, "New device" to an account's devices when another asks to join. |
| `GET /v1/device/joins` | device | `[{device_id, name, card, requested_at}]`: pending join requests for the device's user |
| `GET /v1/device/adapters` | device | `[{id, key, fingerprint}]`: adapter keys, pinned once the person confirms each fingerprint |
| `GET /v1/device/requests` | device | `[{id, adapter, kind, created_at, expires_at, box}]`: pending requests that have a box for this device |
| `POST /v1/device/decisions` | device | `{adapter, request_id, decision: envelope}`. The hub checks the signature against the device's card and that the decision names this device, its user, adapter and request (it cannot check the record hash: it never sees the record); otherwise 400. Envelopes over 2 KB are refused. A device has at most one decision queued per request: a newer one replaces it. At most 500 decisions are queued per adapter; past that, 429 until the adapter takes them. |
| `GET /v1/device/acks?since=<unix>` | device | `[{adapter, request_id, ack: envelope}]`: acks and notes of the requests that were sealed for this device |

The enrollment link the management UI shows as a QR code (and as text):

```
interpose://enroll?hub=<url-encoded hub base URL>&code=<one-time code>&user=<user id>&mode=new|join
```

`mode=new` makes the first device of a new user, which creates and signs r1. `mode=join` adds a device to an existing
user, pending approval on one of that user's devices. The code expires after 10 minutes and works once. `user` and
`mode` in the link only tell the app what to do; the hub enforces the code's own user and mode.
