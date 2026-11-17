# Adapter trust from LDAP (users and groups)

By default an adapter trusts the users its operator pinned by hand, one `trust add-user <user> <account fingerprint>`
per user per adapter. With a directory, the same pin can be kept **once, on the user's LDAP entry**, and each adapter
told which users or groups to trust. This page sets that up; the design and what it trades away are in
[DESIGN.md](../DESIGN.md), D17.

What changes, and what does not:
- **Who is asked and who may approve** at an adapter with LDAP sources is whoever the directory says: the named users,
  and every member of the named groups, each with the account fingerprint on their entry.
- **Rosters, signatures and the hub are unchanged.** The fingerprint from LDAP is checked against the user's roster
  chain exactly as a local pin is: a wrong fingerprint trusts nobody. The hub never reads LDAP and gets no credentials
  for it.
- **Every decision asks the directory live.** Leaving a group takes effect at the user's next decision. If the
  directory is unreachable, decisions by its users are refused (fail closed); local users are unaffected.
- **So whoever can write that attribute, or group memberships, decides who approves at those adapters.** That is the
  trade: the directory is trusted as much as the adapter's operator. Keep the attribute admin-only (below) and
  the bind account read-only. Without a directory, or where that trade is not wanted, keep `local`.

The fingerprint is not a secret (the hub shows it, and so does every phone of the account), so reading it is harmless.
Only writing it matters.

## 1. The directory

### The account attribute

Each user who may approve gets an attribute, by default **`interposeAccount`**, holding their account fingerprint
(`3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0`, as the phone's Device tab → **Account** shows it, or the hub's user list).
Read it off a phone of the account, never off a request or a chat.

If the hub knows the user under another id than their uid (they were renamed at the identity provider, and the hub
kept the id from their first sign-in; `oidc.md`, "Usernames"), the value is `<hub user id> <fingerprint>`:
`alice 3f2a-91c0-…`.

**The attribute must not be editable by the user.** A user who could set their own fingerprint could point it at an
account they control. Check this in the directory, not in Interpose.

- **LLDAP:** *Settings → Custom attributes → Add user attribute*: name `interposeAccount`, type `String`, not a list,
  **Editable by user: off**, Visible: on. Then set it on each user's page. The attribute is served over LDAP under
  that name (LLDAP lowercases it; the adapter does not mind).
- **OpenLDAP and others:** add an attribute type to the schema, or reuse an existing single-valued string attribute
  users cannot write (`employeeNumber`, say) and set `LDAP_ACCOUNT_ATTR` to it. Make sure the ACLs let the bind account
  read it and do not let users write it.

### Groups

Any static group works: `groupOfNames` / `groupOfUniqueNames` (`member`, `uniqueMember` DNs; LLDAP's groups) or
`posixGroup` (`memberUid`). Nested groups are not followed. A member without the account attribute, or with one that
does not parse, is **not trusted** and is named in the adapter's log and in `trust list` each time the group is read,
so an unfinished setup is visible, not silent.

### A read-only bind account

Make the adapter its own account that can read users, groups and the account attribute, and nothing else. For LLDAP,
create a user (`interpose-adapter`, say) and add it to the built-in group **`lldap_strict_readonly`**. Put its password
in `secrets/ldap-password` beside the adapter's compose file.

## 2. The adapter

Settings, as flags of `run` and `trust list` or as environment variables (the `.env` of each adapter's compose project
is the usual place; `deploy/adapter.env.default` has them commented out):

| Flag | Variable | Default | Meaning |
|---|---|---|---|
| `-trust` | `INTERPOSE_TRUST` | `local` | trust sources, comma-separated: `local`, `ldap-user:<uid>`, `ldap-group:<group>` |
| `-ldap-url` | `LDAP_URL` | | `ldaps://host[:636]`, or `ldap://host[:389]` with StartTLS |
| `-ldap-bind-dn` | `LDAP_BIND_DN` | | the read-only account, e.g. `uid=interpose-adapter,ou=people,dc=home,dc=example` |
| `-ldap-bind-password-file` | `LDAP_BIND_PASSWORD_FILE` | `/run/secrets/ldap-password` | its password |
| `-ldap-ca-file` | `LDAP_CA_FILE` | system roots | PEM to verify the directory's certificate |
| `-ldap-plain` | `LDAP_PLAIN=true` | off | allow `ldap://` **without** StartTLS. Only for a directory on the adapter's own Docker network; the bind password and every answer go in clear. The adapter says so at start |
| `-ldap-user-base` | `LDAP_USER_BASE` | | base DN of users, e.g. `ou=people,dc=home,dc=example` |
| `-ldap-group-base` | `LDAP_GROUP_BASE` | the user base | base DN of groups, e.g. `ou=groups,dc=home,dc=example` |
| `-ldap-user-attr` | `LDAP_USER_ATTR` | `uid` | the attribute that is a user's uid |
| `-ldap-account-attr` | `LDAP_ACCOUNT_ATTR` | `interposeAccount` | the attribute holding the account fingerprint |
| `-ldap-group-attr` | `LDAP_GROUP_ATTR` | `cn` | the attribute that names a group |
| `-ldap-refresh` | `LDAP_REFRESH` | `1m` | how often the sources are re-read to decide whose phones get a request. Decisions always ask live |

Sources combine: `INTERPOSE_TRUST=local,ldap-group:warpgate_approvers,ldap-user:bob` trusts the local pins, every
member of `warpgate_approvers` and bob. A user named by two sources with the same fingerprint is trusted once; named
with two **different** fingerprints, they are not trusted at all until the sources agree.

For a compose project, add the password to the service's volumes:

```yaml
      - ./secrets/ldap-password:/run/secrets/ldap-password:ro
```

Then, in `.env`:

```
INTERPOSE_TRUST=ldap-group:warpgate_approvers
LDAP_URL=ldaps://ldap.home.example:636
LDAP_BIND_DN=uid=interpose-adapter,ou=people,dc=home,dc=example
LDAP_USER_BASE=ou=people,dc=home,dc=example
LDAP_GROUP_BASE=ou=groups,dc=home,dc=example
```

## 3. Check it

```
docker compose run --rm adapter-warpgate trust list -dir=/data
```

lists the sources, then every trusted user with their fingerprint, source and last verified roster, and a warning
for every entry that could not be used (no account, bad account, no such user or group). The running adapter logs the
same warnings on each refresh, and writes to `audit.jsonl`:

- `trust-added` / `trust-removed`: user, `account <fingerprint> via <source>` — every change in who is trusted, local
  pins included, and the whole list at each start;
- `decision-rejected` with the reason when a decision fails the live check: `… is no longer a member`,
  `… now has account …`, `directory check failed: …`;
- the outcome of a decision names the source when it is not local: `approved by alice on phone (ldap-group:…)`.

Approvals go through the usual steps after the directory check: roster, signature, nonce, time window, and a re-read
of the service.

## When the directory is down

- Users from LDAP **keep being asked**, on the last pins read, for 15 minutes; after that they are set aside until the
  directory answers (the log says `set aside`), and pinned again on the next successful read.
- Their **decisions are refused** the whole time: each one asks the directory.
- Verified rosters are kept on disk through the outage, so a user pinned again takes up the roster last verified; the
  hub cannot slip in an older one meanwhile.
- Local pins are unaffected.

## Trying it against a directory in Docker

`adapter/ldapdir`'s `TestLive` runs against a real directory when `INTERPOSE_LDAP_TEST_URL` is set (with
`INTERPOSE_LDAP_TEST_BIND_DN`, `_PASSWORD`, `_USER_BASE`, `_GROUP_BASE`, `_UID`, `_ACCOUNT`, `_GROUP`; see the test).
LLDAP is quick to seed: run `ghcr.io/lldap/lldap:stable` with ports 3890 and 17170, sign in to the GraphQL API
(`POST /auth/simple/login`), then `addUserAttribute(name: "interposeAccount", attributeType: STRING, isEditable: false)`,
`createUser`, `updateUser(insertAttributes: …)`, `createGroup`, `addUserToGroup`, and add a read-only user to
`lldap_strict_readonly` with `/app/lldap_set_password` for its password. Then:

```
INTERPOSE_LDAP_TEST_URL=ldap://127.0.0.1:3890 INTERPOSE_LDAP_TEST_BIND_DN=uid=ro,ou=people,dc=example,dc=com \
INTERPOSE_LDAP_TEST_PASSWORD=… INTERPOSE_LDAP_TEST_USER_BASE=ou=people,dc=example,dc=com \
INTERPOSE_LDAP_TEST_GROUP_BASE=ou=groups,dc=example,dc=com INTERPOSE_LDAP_TEST_ACCOUNT=<fingerprint> \
go test -run TestLive -v ./adapter/ldapdir/
```
