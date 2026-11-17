# Deploying the clearing house: a hub, and an adapter beside each service

Where things run, and why:
- **The hub** (`interpose-hub`) runs behind your reverse proxy, which terminates TLS, and signs people in with your OIDC
  provider (`oidc.md`). It holds nothing that can act, so it can sit apart from the services it serves.
- **Each adapter** runs **beside the service it guards**, e.g. the Warpgate adapter on the Warpgate host. It holds that
  service's credential and its own trust list. Owning that host already owns the service, so keeping them there adds
  no new place to steal approval from. An adapter only connects out: to the hub and to its service.

Host names below are placeholders (`hub.home.example`, `warpgate.home.example`, the "adapter host"); use your own.

## 1. The hub

Run `interpose-hub` (`broker/cmd/interpose-hub`, [broker/README.md](../../broker/README.md)) in a container
([docs/docker.md](../docker.md)) or as a binary. It needs:
- **a state directory** (`-state`), writable, private to the hub;
- **the reverse proxy** sending `/v1/*` and `/healthz` to the API listener (`-api`, default `127.0.0.1:8740`;
  `0.0.0.0:8740` in a container) and everything else to the management UI (`-admin`, default `127.0.0.1:8741`;
  `0.0.0.0:8741` with OIDC). `-url` is the public base URL, e.g. `https://hub.home.example` (the hub refuses an http
  `-url` with a non-loopback `-api`). Give the proxy's address as `-trusted-proxy` (e.g. `127.0.0.1` or the Docker
  network's CIDR) so failed enrollments are rate-limited per client rather than for everyone behind the proxy;
- **OIDC** for the management UI and phone sign-in (`oidc.md`): `-oidc-issuer`, `-oidc-client-id`,
  `-oidc-secret-file`, `-oidc-redirect`, `-oidc-admin-group`;
- **optionally APNs** for wake-up pushes (`testflight.md` step 5): `-apns-key-file`, `-apns-key-id`.

Check: `https://hub.home.example/healthz` says `ok`; signing in shows you as admin.

## 2. Phones

Enroll the first phone of each user from the management UI (or phone sign-in, `oidc.md`). Note each user's **account
fingerprint** on the phone (Device tab → **Account**): adapters need it.

## 3. An adapter per service

Each adapter has its own deploy steps:
- Warpgate: [adapters/warpgate/README.md](../../adapters/warpgate/README.md), "Deploying".

They all end the same way: register the adapter's public key at the hub (**Adapters**), give the adapter the token
the hub shows once, trust each user with `trust add-user <user> <account fingerprint>` (or point the adapter at LDAP
users and groups carrying that fingerprint: [ldap.md](ldap.md)), start it, and compare the adapter fingerprint on the
phone (Device → **Check hub for new adapters**).

## Updating

- **Hub:** rebuild from the new commit and restart it; its state directory carries over.
- **Adapters:** see each adapter's README; the Warpgate install is re-run and skips what is already set up.
