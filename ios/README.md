# Approver (iOS)

Native SwiftUI app: the device half of [docs/PROTOCOL.md](../docs/PROTOCOL.md). No third-party dependencies, no
React Native / Expo.

```
ios/
  project.yml        XcodeGen spec (Approver.xcodeproj is generated, not committed)
  Approver/          the app: enrollment, inbox, request detail, device settings
  ApproverKit/       Swift package with everything testable: wire types, base64url, fingerprints, envelope
                     verification, HPKE open, decision/card signing, key stores, hub client
```

## Build and test

```
cd ios/ApproverKit && swift test          # protocol + interop with the Go side (internal/protocol/testdata/interop)
cd ios && xcodegen generate               # writes Approver.xcodeproj
xcodebuild -project Approver.xcodeproj -scheme Approver \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -derivedDataPath build \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual build
```

Sign to run locally (`CODE_SIGN_IDENTITY=-`) rather than `CODE_SIGNING_ALLOWED=NO`: an unsigned app builds, but at
run time every Keychain call fails with -34018 (missing entitlement), so it cannot enroll.

Or open `Approver.xcodeproj` in Xcode and run. A device build needs a signing team: `project.yml` takes it from
`APPLE_TEAM_ID` when `xcodegen` runs (`set -x APPLE_TEAM_ID <team id>` in fish, `export` elsewhere), so it is never
in the repository. Simulator builds do not need it.

## Connecting a device

The app opens on **Connect to Interpose**. There are three steps:

1. **Interpose server:** enter the address of your server, the page you manage it from (for example
   `interpose-hub.home.example`). The app checks it really is one (`/app/hello`) before going on.
2. **Continue on the server:** the app opens the server in a private browser session. You sign in there
   (Authelia, two-factor), and the server registers the device for you. The first time that is a new account;
   otherwise the device joins your account and waits for approval on a phone you already have.
3. **Connect this device:** name it, set the app PIN on a device with a Secure Enclave, and connect. The summary
   shows the device and account fingerprints.

The other way in is **I have an enrollment link or QR code**, using a code from the management page. Scan its QR code
with the in-app scanner, or with the Camera app, which opens the app straight at step 3.

Each step shows the server's full address (scheme, host and port), not just the host. The link the server sends back
in step 2 is used only if its hub has the same host as the server typed in step 1 (or as the device API that server
named at `/app/hello`): the `interpose://` scheme can be claimed by any app. Universal links would close that fully
once the hub has a public hostname (not done).

In the simulator against a local hub (no OIDC):
- The hub says it has no sign-in, so step 2 asks for a user id instead.
- Use `http://127.0.0.1:8741` as the server (the simulator shares the Mac's loopback). Plain http is accepted only
  in Debug builds and only to loopback (`localhost`, `127.0.0.0/8`, `::1`); the app shows the full address and marks
  it as unencrypted. Every other hub, and every hub in a Release build, must be https (`HubTransport`).
- Or run the `xcrun simctl openurl booted '…'` command the management page shows, then click Open.

Then tell each adapter to trust the account (`interpose-adapter trust add-user vince <account fingerprint>`), and
requests show up in the inbox.

## Accounts (rosters)

A user's devices are the head of a signed roster chain (docs/PROTOCOL.md, "Users and rosters"). Adapters trust the
account, not single devices.

- **First device** (`mode=new`): creates the account's first roster, signed by itself, and pins the account fingerprint.
- **Another device** (`mode=join`): asks to join and is *pending*. The inbox shows its fingerprint until it is approved.
  It can decide nothing meanwhile.
- **Approving a join** (inbox, "Devices asking to join"):
  - compare the fingerprint with the new phone's screen, then Approve (Face ID);
  - this phone builds the next roster from its own verified copy of the chain, adds the card, signs it, and posts it.
- **Removing a device** (Device tab → Devices on this account): signs a roster without it. The last device cannot be
  removed. A removed device shows that it was removed and hides Approve/Deny.
- **Checks on every refresh:** the chain verifies back to the pinned account fingerprint, and it must **build on the
  head already accepted**:
  - never shorter;
  - holding exactly that roster at its seq.

  That stops rollbacks, and forks signed by a device after it was removed (it keeps its key). The accepted head's
  seq and payload hash are persisted. A refused chain shows a red error and the last good head stays.
- **Pinning on join:** the hub holds the join card, so it could build a chain of its own (its own genesis, its own
  device) around it. A joining device therefore never pins on the hub's say-so:
  - before it is admitted, the hub's account fingerprint is shown only as unconfirmed, not to be given to an adapter;
  - once a verified chain includes it, the inbox asks **Confirm the account**: open Device → Account on a phone already
    on the account, and tap *It matches* only if both show the same fingerprint. Only then is it pinned and the device
    acts as a member (Settings shows the fingerprint for `trust add-user`; the approving phone shows it on the join
    screen too);
  - *It is different* remembers that fingerprint as rejected: the device never pins it. Leave the hub.

The simulator always uses **software keys** (orange INSECURE banner): it reports a Secure Enclave, but its Face ID
and app-password access control are not the real thing. A device uses the Secure Enclave; a device without one refuses
to enroll rather than fall back to software keys, which adapters could not tell apart:

| Key | Access control |
|---|---|
| approve | `.privateKeyUsage` + `.applicationPassword`, `WhenPasscodeSetThisDeviceOnly`. The password is 32 random bytes: Face ID reads a copy (`.biometryCurrentSet` keychain item), the app PIN unwraps another (PBKDF2-HMAC-SHA256, 600,000 iterations) |
| deny | `.privateKeyUsage`, `WhenUnlockedThisDeviceOnly` |
| encryption | `.privateKeyUsage`, `AfterFirstUnlockThisDeviceOnly` |

Each Face ID prompt says what the signature is for: connecting this device (its card), creating the account, adding
or removing a named device, or approving a request by its title.

The app PIN (8+ characters, letters allowed) is asked for when Face ID fails or is cancelled. Wrong PINs are counted:
after 3, each locks the PIN for longer (1 min, 4 min, 16 min, …), and the 10th in a row deletes the keys. Adding a
face or finger turns Face ID off for approvals until **Device → Use Face ID for approvals…** turns it on again with the
PIN. Devices connected before this change keep their keys (the app PIN is still the key's password, with the counter
on top); Reset device and connect again to get a random password. Details and limits: [DESIGN.md](../docs/DESIGN.md),
"iOS app".

The Keychain holds each key's `dataRepresentation` (a handle only this Secure Enclave can use), the PIN-wrapped
password, the PIN failure count and the hub token.
The pins (account fingerprint, adapter keys, the last accepted roster head) are in the Keychain too, this device only,
so a restored or edited backup cannot carry or change them. Older versions kept them in UserDefaults; they are moved on
first launch.
The "Decided here" list (the last 50 decisions this device sent: request title, approve or deny, and the verified final
ack once it arrived) is a JSON file in Application Support, readable only while the phone is unlocked and not backed up,
so it survives the app being killed and goes with the hub when you leave or reset.

**Adapter keys** the hub lists are not pinned on first sight either: the inbox shows each new adapter with its
fingerprint under "New adapters", and its requests wait until you compare that with what the adapter prints
(`interpose-adapter key`) and tap Trust.

## End-to-end UI test

`scripts/e2e-ui.sh` (repository root) runs a real hub and the demo adapter on loopback. It then runs
`ApproverUITests` in the simulator:
1. The app enrolls from the link (`mode=new`), through the `-interposeAutoEnroll` launch argument (simulator Debug
   builds only). The script does the admin step: it trusts the new account at the adapter (`interpose-adapter trust
   add-user`).
2. The test confirms the demo adapter's key (its requests wait until then), opens a normal-risk request, taps Approve, and waits for the adapter's verified ack.
3. It opens a high-risk request and checks that a tap does **not** approve it, then that a long press does.
4. A second test joins user ann, whose first device is the Go software device (the script admits every join for it).
   It checks that the app shows no account fingerprint as the account's until the person taps *It matches*, then pins
   it.

`testPrivacyCoverWhenNotActive` needs no hub: it pulls Notification Center over the app and checks the screen is
covered.

The script checks the demo service's outcome afterwards. `scripts/e2e-cli.sh` is the same flow with the Go software
device instead of the app.

## Hubs: switching, leaving, resetting (Device tab)

| Action | What it does | Adapters |
|---|---|---|
| **Enroll with another hub…** (or open an `interpose://enroll` link while enrolled) | Enrolls with the new hub first, and forgets the old hub (and the account, if the link is for another user or a new account) only once that succeeds. Works for the same hub too, e.g. after its state was reset. | Keys are kept |
| **Leave this hub** | Forgets the hub, its token, adapter pins, the account and requests. Keys are kept. | To stop the device, remove it from the account on another device |
| **Reset device** | Leave the hub, and delete the keys | New keys must join the account again; remove the old device from the account first |

A hub that no longer knows the device (revoked, or its state wiped) answers 401. The app then says so and points to
Enroll with another hub. A new code from the same hub re-enrolls the same keys.

## What the app enforces

- A record is shown only if all of these hold:
  - the box is addressed to this device and opens;
  - the record is signed by the **pinned** key of the adapter the hub listed;
  - its inner `adapter` and `id` match both the signer and the hub's listing.

  Anything else goes to "Refused (not shown)".
- Adapter keys are pinned on first sight. A different key for a pinned adapter is shown as a conflict and never used.
- The detail view shows the adapter-written fields first: title, requester, on-behalf-of with who attested it, facts
  coloured by level, lease, expiry. The requester's reason comes after them, quoted and labelled as their claim.
  All requester and adapter text is sanitized: control and format (bidi, zero-width) characters are removed and it
  is shown on one line.
- Text from the hub (error bodies, adapter and device ids in status and error rows) is sanitized the same way.
- Hub responses: redirects are not followed (they would carry the bearer token to another host) and answers over
  4 MiB are not read.
- The screen is covered while the app is not active, so the app-switcher snapshot shows no request. Not during the
  approve key's own Face ID prompt.
- `risk: high` needs a press-and-hold before the approve signature (and its Face ID prompt).
- Acks:
  - `approved`, `denied` and `expired` are final.
  - `rejected` and `failed` are notes: shown as a warning, with Approve/Deny still available. A new tap signs a fresh
    decision on the same record. A note counts only if its `decision_hash` is this device's latest decision.
  - An ack that does not verify shows as "unconfirmed".
  - `since` is the highest verified ack `ts` seen, minus 5 s.

## Not built yet (TODO)

- **APNs** and a **Notification Service Extension** to decrypt and verify pushes and show authoritative-first
  notifications, with a lock-screen Deny action (signed with the deny key).
- **App Attest** assertion at enrollment.
- **Off-network transport.** Only the direct path is implemented: the hub's HTTP API on LAN/VPN.
- **Untested on hardware:** Secure Enclave key creation with `.applicationPassword`, the random password with Face ID
  and the PIN path, the PIN prompt, lockout and wipe on a real key, and turning Face ID back on after a biometric
  change. The simulator only exercises software keys; `swift test` covers the PIN wrap and the attempt counter.
- Device-side revocation handling and key rotation; Apple Watch approve.
