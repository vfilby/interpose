# Hub sign-in with OIDC (Authelia example)

The hub's management UI, and phone sign-in in the app, authenticate with OIDC. Any OIDC provider that can put a
username and groups in its tokens works; the examples below are for Authelia 4.39 at `https://sso.home.example`.
This page is everything needed on both sides.

What sign-in decides, and what it does not:
- **It decides** who may hand out enrollment codes and see what.
  - Members of `interpose_admins` see everything, register adapters and read the audit log.
  - Everyone else sees only their own account: they can create it (their first phone), add phones to it, and revoke
    their own phones at the hub.
- **It does not decide** which phones can approve. That is each user's roster, signed by their own phones
  (`docs/PROTOCOL.md`).
- **So a compromised OIDC account can start an enrollment, and little more.** The new phone still waits for
  approval on one of the user's existing phones, and adapters trust users by account fingerprint, not by what the hub
  or the OIDC provider says. Until it is admitted, the hub serves that phone the user's roster (device names, public
  keys) and nothing else: no adapters, requests, acks, other join requests or push registration.

## 1. Groups

In the provider's user directory (for Authelia, its LDAP backend or file users), create these groups, then add people
to them:
- `interpose_users`: may sign in to the hub;
- `interpose_admins`: may sign in and is a hub admin.

These groups reach the hub as OIDC claims and decide sign-in only. Adapters can also trust LDAP groups, but they read
the directory themselves, never the hub's claims: [ldap.md](ldap.md).

## 2. Authelia

In your Authelia configuration, under `identity_providers.oidc.authorization_policies`:

```yaml
      interpose:
        default_policy: deny
        rules:
          - policy: two_factor
            subject:
              - 'group:interpose_users'
              - 'group:interpose_admins'
```

Under `identity_providers.oidc.claims_policies`. This puts the username and groups in the ID token, which Authelia
4.39 otherwise leaves out. The hub falls back to the userinfo endpoint if this is missing, but one round trip fewer is
better:

```yaml
    claims_policies:
      interpose:
        id_token: ['preferred_username', 'groups', 'name']
```

Under `identity_providers.oidc.clients`:

```yaml
      - client_id: interpose
        client_name: Interpose Hub
        client_secret: '{{ env "AUTHELIA_OIDC_CLIENT_SECRET_INTERPOSE" }}'
        consent_mode: implicit
        require_pkce: true
        pkce_challenge_method: S256
        token_endpoint_auth_method: client_secret_basic
        claims_policy: interpose
        redirect_uris:
          - https://interpose-hub.home.example/oidc/callback
        scopes: ['openid', 'profile', 'email', 'groups']
        authorization_policy: interpose
```

Provide the client secret to Authelia as `AUTHELIA_OIDC_CLIENT_SECRET_INTERPOSE` (hashed or plain, in the same form as
your other clients' secrets), and give the hub the plain secret in a file. Restart Authelia.

## 3. The hub

The management UI needs a stable https name: `interpose-hub.home.example` is assumed above, routed by your reverse
proxy to the hub's `-admin` listener. Do **not** put forward-auth in front of it as well: the hub signs people in
itself, and `/oidc/callback` must reach it.

```
interpose-hub \
  -api 0.0.0.0:8740 -url https://<hub API name> \
  -admin 0.0.0.0:8741 \
  -oidc-issuer https://sso.home.example \
  -oidc-client-id interpose \
  -oidc-secret-file /run/secrets/oidc-client-secret \
  -oidc-redirect https://interpose-hub.home.example/oidc/callback \
  -oidc-admin-group interpose_admins
```

- **Session cookies** are signed with `<state>/session.key`, made on first start. Delete it to sign everyone out.
- **Sessions** last 12 hours.
- **Without `-oidc-issuer`** the hub has no sign-in and refuses to start unless `-admin` is a loopback address
  (development only).

## 4. Phones

- In the app's Enroll screen, under **Sign in**, enter `https://interpose-hub.home.example`, then tap *Sign in to get a
  code*. The OIDC provider's sign-in (two-factor) opens in a private browser session.
- The hub sends the app back a code for you: a **new account** the first time, otherwise **another device**. Approve
  that device on one of your existing phones.
- Nothing is remembered between sign-ins.
- An admin can still hand out codes from the management UI (QR code, link, simulator command).

## Usernames

- **The first sign-in names the user.** The first time someone signs in, their `preferred_username`, lower-cased,
  becomes their hub user id. It must be 1–40 of `a-z 0-9 . _ -`; a username outside that is refused at sign-in with a
  message saying why.
- **After that the hub knows them by their provider account, not their username.** The user id is bound to the
  token's issuer and subject (`iss`, `sub`). OIDC does not promise a username is unique or stable, and some providers
  let people edit their own.
  - Someone who renames themselves keeps their hub user id. The header shows their new username next to it.
  - Someone else who takes a username already bound to another account is refused at sign-in. They cannot become
    that hub user, issue codes for it, revoke its phones or see its devices.
- **When an existing hub is upgraded,** each user id is bound to whoever signs in with that username first. Accounts
  that existed before are unaffected otherwise.
- **To release a binding,** an admin opens *Sign-ins* on the overview. Releasing a user id unbinds it, so the next
  person to sign in with that username becomes that hub user, with its devices. Use this when:
  - a person's account at the provider was recreated, which gives it a new subject;
  - the hub moves to another issuer, where every subject is new. Release each user id, then have the owners sign in
    before anyone else can.
- **Deleting an account** (break glass) keeps its sign-in binding. The same person can start a new account under the
  same user id.
