# passkey.js — provenance

- **md5**: `ce5e3c02e233c3787231e89d03e87257` (patched; upstream was
  `f4685f75507e3658c8ec2ad7f9e48365`)
- **copied from**: `canisters/thebes-ide/examples-react/chat/public/passkey.js`
  on 2026-07-27 (branch `feat/new-project-command`) — the same client the
  live Memphis site (`canisters/memphis-frontend/dist/passkey.js`) and the
  thebes-ide React examples ship.
- **talks to**: Memphis canister **cid 921** on the production network via
  the boundary (`POST /api/call`, `GET /api/receipt`,
  `POST /api/v1/canister/921/query`).
- **surface**: `window.MemphisPasskey` — `register`, `signIn`,
  `signInOrRegister`, `whoami`, `lookupName`, `loadSession`,
  `saveSession`, `clearSession`, `signOut`.

## The RP_ID constraint (read before debugging sign-in)

`passkey.js` pins `RP_ID = "memphis.mercaturaforum.com"`. WebAuthn requires
the relying-party id to match the page's origin (or be a registrable
suffix of it). Consequences for a scaffolded app:

- ✅ **Served from the gateway** (`https://memphis.mercaturaforum.com/_/raw/<cid>/index.html`)
  — same origin, passkeys work.
- ❌ **`npm run dev` on `http://localhost:5173`** — origin mismatch, the
  browser refuses the credential. Local dev can exercise the backend
  (queries/updates proxy fine) but **not** passkey sign-in. Test auth on
  a deployed build.

To retarget a different deployment, change `RP_ID` **and** `BOUNDARY` at
the top of the vendored file to that host.

---

# Divergences from upstream

Four, added 2026-07-28/29 while getting sign-in working on the live
gateway. Keep them if you re-copy from upstream; each fixes a defect that
is **still present in production's own copy**.

## 1. Error decoding — upstream mislabels EVERY error

`extractErrorTag` is patched. Upstream passed the *outer* `Result` tag
(0=`Ok`, 1=`Err`) into a table whose index 1 happens to be
`"NotAuthenticated"`, so any `Err` — `ChallengeExpired`,
`InvalidArgument`, `InvariantViolation`, whatever — printed as
`NotAuthenticated`, and the actual variant (sitting at the offset upstream
ignored) was never read. This sent a real debugging session down the wrong
path for an hour.

The patch decodes the *inner* `MemphisError` index and surfaces payload
text for `InvalidArgument` / `InvariantViolation`. Candid orders variant
fields by **field-name hash**, not declaration order, so the table is
hash-sorted:

| idx | variant | idx | variant |
|---|---|---|---|
| 0 | InvariantViolation | 5 | NotAuthenticated |
| 1 | FactorNotFound | 6 | InvalidArgument |
| 2 | ChallengeExpired | 7 | InsufficientFactors |
| 3 | Unauthorized | 8 | SessionExpired |
| 4 | DuplicateCredential | 9 | AnchorNotFound |

Verified against the live canister: `whoami` with a bogus token returns
`variant { 3_456_837 = variant { 2_801_171_900 } }` — `3_456_837` =
hash("Err"), `2_801_171_900` = hash("NotAuthenticated") = index 5, exactly
as the table says.

## 2. Transient tolerance — but only for idempotent methods

`memphisCallAwait` and `memphisQuery` retry via `postJsonWithRetry`
(4 attempts, linear backoff), gated on a **non-delivery** predicate
(`validator unreachable` / `no healthy validator` / 502-503-504). The
boundary fans out to a validator set that flaps in and out; upstream threw
on the first such answer, so a healthy chain aborted sign-in/sign-out
(observed live: `call: validator unreachable … <validator>`).

**Retry is restricted to `begin_registration`, `begin_authentication`,
`end_session`.** The `begin_*` calls mint a fresh challenge per call, so a
duplicate is harmless; `end_session` is idempotent.

**`register` / `authenticate` / `claim_name` are NEVER re-sent.** The first
two consume a single-use challenge: if a submission actually landed and
only its *response* was lost, a re-send finds the challenge gone and fails
`ChallengeExpired` — converting a recoverable blip into a dead end. This
restriction was added after a live `register: ChallengeExpired` in which
the original broad retry could not be ruled out as the cause.

Also fixed: the receipt poll treated **any** `status:"error"` as a canister
rejection, so a gateway blip mid-poll reported a failure the canister never
issued. It now keeps polling on a transient, and **backs off 150→1200ms**
while the gateway is refusing — at a flat 150ms a flapping cluster emitted
~50 console 502s per call, burying the real error. Snaps back to 150ms on
the first clean answer.

## 4. Per-app session scope

`STORAGE_KEY` is `memphisSessionV1:<scope>` when the page sets
`window.MEMPHIS_SESSION_SCOPE` (the scaffolder emits the backend cid,
before the passkey.js tag). `localStorage` is keyed by ORIGIN, not path,
and every app deployed to the gateway shares one origin
(`/_/raw/<cid>/`) — so the upstream fixed key made a brand-new project
open **already signed in with another app's session**. Observed live.

Does NOT change on-chain identity: Memphis derives the per-app principal
from `location.origin`, so two apps on one gateway host still resolve to
the same identity. Per-app principals require per-app origins.

## 3. `ChallengeExpired` diagnosis

`register` records when the challenge was issued and, on
`ChallengeExpired`, reports elapsed seconds and interprets them. The
canister returns that one variant for **two different faults**:

- the 5-minute TTL genuinely elapsing, and
- the challenge not being *found* — already consumed, or lost because
  `CHALLENGES` is deliberately non-persisted heap state
  (`canisters/memphis/src/lib.rs:1476`: *"on upgrade, in-flight ceremonies
  abort and the client retries"*).

They need opposite responses and upstream gave no way to tell them apart.

## Upstream follow-up owed

Defects 1 and 2 affect `canisters/memphis-frontend/dist{,-v2-wow,-v3}/passkey.js`
and every `canisters/thebes-ide/examples-react/*/public/passkey.js`, so
**error reports from the live Memphis site are untrustworthy** until fixed
there too. If upstream fixes them differently, re-sync this file.

## Refreshing

Re-copy from the source above, then re-apply the three divergences and
update the md5 here.
