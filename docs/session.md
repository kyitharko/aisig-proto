# RQ5 slice — tester proof of possession bound to a provider session (DRAFT s1)

**Status:** DRAFT s1, 2026-10-15. Research working hypothesis. Every case label for this
slice is **proposed** until the research owner reviews it. Builds on spec r3.1
([spec.md](spec.md)); the chain decision `ValidChain_P` and its 93 chain and 15 lookup
labels are unchanged.

## 1. Question and scope

RQ5 asks how a grant G is bound to the party actually using it. A chain Accept says only
that G is a valid, non-amplifying, currently-active grant for tester key K_T. Anyone who
copies the bundle can present the same bytes. This slice adds a **separate** decision,
`SessionAuth`. A provider P accepts that a specific provider-held session may act under G
only when the holder of K_T's private key signs a fresh, one-time, P-issued challenge
bound to that session and to the exact signed G.

**Kept distinct from ValidChain.** `ChainVerifier::verify` still returns the chain
`Decision` (`Accept / Reject / Indeterminate`). A chain Accept is never a session
authorization. The session decision has its own type and spelling (`SessionAccept`,
`SessionReject`, `SessionIndeterminate`). The only way to obtain a `SessionAuthorization`
value is a successful redemption (§5).

**Not claimed.** This slice does not provide:
- TLS or other channel binding;
- phishing or relay resistance (§8);
- per-request proof of possession after redemption;
- tool or action enforcement (RQ6);
- bounded revocation freshness during a session (RQ7).

## 2. Trusted session context — who creates what

| Item | Created by | Trusted because |
| --- | --- | --- |
| `session_id` | P's own session layer, when the tester's agent session is opened (for example P's authenticated account session or agent-run identifier). P passes it to `issue` and `redeem` from **server-side state**. | It is P's own state. It is never read from the bundle, the challenge response, or any tester-supplied field. |
| audience | P's configuration (`urn:aisig:provider:p-synthetic`) | P's own identity. |
| challenge record | P, at issuance; stored in **P's own authoritative store** (a P-private namespace that only P writes) | P's own state. In s1 no other provider can insert a record into P's store; the tester receives a copy but redemption uses only the stored record. |
| nonce, challenge_id | P, from the OS CSPRNG (`getrandom`) | Unpredictable to the tester and others. |
| clock reading (now, ε) | P's trusted clock (the same injected clock as the chain verifier) | As in spec §6. |
| G identity | Derived by P from the G that P's chain verifier accepted: its exact `StatusKey` (spec §6) | Bound to the exact signed G bytes, including the digest. |
| tester_key K_T | Read from that accepted G (signed by K_authorizer) | Authenticated by the chain. |

What a `SessionAccept` establishes: at redemption time, a party holding K_T's private key
had signed the challenge that P issued for *this* `session_id`, *this* audience and *this*
exact G. The challenge had not expired, had not been redeemed before, and the chain was
re-verified as Accept at that moment. Nothing more.

## 3. Challenge

```
Challenge = {
  audience:     P's audience,
  challenge_id: lowercase hex of 16 CSPRNG bytes,
  expires_at:   Time,
  format:       "aisig-session/v0",
  grant:        { digest: hex(StatusKey.digest), id, object_type: "EngagementGrant", org_id, version },
  issued_at:    Time,
  nonce:        base64url(32 CSPRNG bytes),
  session_id:   P's session identifier
}
```

- Times are canonical UTC `Z` strings (spec §2.1). The record is encoded with the
  canonical JSON rules of spec §3.
- **Signed response bytes:** `"aisig-v0" ‖ 0x00 ‖ "SessionChallengeResponse" ‖ 0x00 ‖
  canonical(Challenge)`. The type tag is distinct from all four chain object tags, so a
  challenge signature cannot verify as a chain object and vice versa.
- **Response (proof) wire:** `{ "challenge_id": …, "format": "aisig-session/v0",
  "sig": base64url(64 bytes) }`.
  - Strictly parsed: duplicate keys, unknown fields, `null`, a wrong format or a bad
    length all give `MalformedProof`.
  - The proof carries no binding fields. The verifier rebuilds the signed bytes from its
    **stored** record, so a tester cannot change audience, session or grant by editing what
    it sends.

## 4. Issuance

`issue(bundle, session_id) → Issued(Challenge) | IssueRefused(chain Decision) | IssueUnavailable(reason)`

1. Run the chain verifier on the raw bundle. Anything other than chain Accept →
   `IssueRefused(decision)`; no challenge is created.
2. Read the clock. `issued_at = now`.
   TTL is **fixed at 120 s** (no override). With any RFC 3339 clock (maximum year 9999,
   ~2.5e11 s, far below `i64::MAX`), `issued_at + 120 s` never overflows, so
   `expires_at = min(issued_at + 120 s, G.window.end)` exactly — the fixed-120 guarantee
   always holds for every representable clock. The implementation still uses checked
   addition; the overflow branch (falling back to `G.window.end`) is an unreachable
   fail-closed guard, not a second behaviour, so it does not weaken the guarantee and adds
   no issuance outcome.
3. Draw the nonce (32 bytes) and challenge_id (16 bytes) from the OS CSPRNG. On failure →
   `IssueUnavailable(NonceUnavailable)`.
4. Validate the issuance reading against the grant window: if `issued_at ≥ G.window.end`
   or `expires_at ≤ issued_at` (possible when the clock returns a different, later reading
   at issuance than at the chain check, since `Ts` is publicly constructible), fail closed
   with `IssueUnavailable(InvalidClockReading)` — no record is stored.
5. Insert the record into the store in state `Pending`. If the store is unavailable →
   `IssueUnavailable(ChallengeStateUnavailable)`.

## 5. Redemption

`redeem(bundle, session_id, proof?) → SessionAccept(SessionAuthorization) |
SessionReject{stage, reason} | SessionIndeterminate{stage, reason}`

Stages in fixed order. Reject-dominates as in spec §7.1: the first Reject ends evaluation,
an Indeterminate is recorded and evaluation continues where possible, and SessionAccept
requires every stage positive.

1. **chain** — re-verify the raw bundle with `ChainVerifier` (stages F–X), now, at
   redemption.
   - Chain Reject → `SessionReject / chain / ChainRejected(<chain decision>)`.
   - Chain Indeterminate → record `ChainIndeterminate(<chain decision>)` and continue,
     only to look for contradictions.
   - Later stages use the decoded chain's G. Under a chain Indeterminate that G is not
     authenticated, so as in spec §7.2 it may only yield a Reject, never support Accept.
     This is consistent because SessionAccept requires chain Accept, and then the decoded
     G *is* the accepted G.
2. **proof**
   - No proof → `MissingProof`.
   - Unparseable or non-conforming → `MalformedProof`.
3. **challenge** — read the stored record by challenge_id.
   - Store unavailable → record `ChallengeStateUnavailable` and stop (the later stages
     need the record).
   - No record → `UnknownChallenge` (P's store is authoritative for P's challenges).
   - State `Consumed` → `ChallengeAlreadyConsumed`.
4. **binding**
   - `record.audience ≠ P` → `ChallengeAudienceMismatch`.
   - `record.session_id ≠ session_id` → `SessionMismatch`.
   - `record.grant ≠ StatusKey(G)` (any field, including the digest) → `GrantMismatch`.
5. **time** — clock `(now, ε)`.
   - Clock unavailable → record `ClockUnavailable`.
   - `now − ε ≥ expires_at` → `ChallengeExpired`.
   - `now + ε < expires_at` → ok.
   - Otherwise → record `ClockUncertainty` (half-open expiry; same rule as spec §6).
   - `issued_at` is recorded for audit but not used as a lower bound: P issued it.
6. **pop** — verify the proof signature over the response bytes of the stored record with
   K_T from G (Ed25519 `verify_strict`). Failure → `InvalidProofSignature`. This covers a
   wrong key, a signature over other content, and a wrong domain tag.
7. **consume** — reached only if nothing was recorded as Indeterminate. Atomically change
   the stored record from `Pending` to `Consumed`.
   - This call made the change → `SessionAccept`.
   - Already consumed (a concurrent redemption won) → `ChallengeAlreadyConsumed`.
   - Store unavailable → `SessionIndeterminate / consume / ChallengeStateUnavailable`.

**One-time use and concurrency.**
- Consumption is a compare-and-set under the store's lock. Of any number of concurrent
  redemptions of the same challenge, at most one returns SessionAccept. Every other one
  returns `ChallengeAlreadyConsumed`, at stage `challenge` if it read the record after the
  winner consumed it, or at stage `consume` if it lost the compare-and-set.
- **Failed and inconclusive attempts do not consume.** A Reject or Indeterminate
  redemption leaves the record `Pending`. So a party that only knows the challenge_id
  cannot burn a challenge without a valid proof, and a temporary evidence outage does not
  waste the challenge.
- The cost of this choice is that invalid attempts are not rate-limited; attempt limits
  are future work.

**SessionAuthorization** (returned only by SessionAccept): `session_id, challenge_id,
audience, grant (StatusKey fields), tester_key_id, authorized_at = now,
grant_window_end = G.window.end`. P must not treat the session as authorized beyond
`grant_window_end`. Whether P re-checks status during a long session is RQ7 and is not
modelled.

## 6. Reason spelling

`SessionAccept`, or `SessionReject / <stage> / <Reason>`, or
`SessionIndeterminate / <stage> / <Reason>`. Stages: `chain, proof, challenge, binding,
time, pop, consume`. Chain-derived reasons embed the chain decision, e.g.
`ChainRejected(Reject / S / InvalidSignature{G})`. Issuance outcomes: `Issued`,
`IssueRefused / <chain decision>`, `IssueUnavailable / <Reason>`.

## 7. Public API boundary

`SessionService::issue` and `SessionService::redeem` take raw bundle bytes and run the
chain verifier themselves. No public entry point accepts a decoded chain (spec §7.5). The
decoded chain used inside redemption comes from the same internal decoding that the chain
decision used.

## 8. Limitations specific to this slice

- **Relay and phishing.** Suppose an attacker opens their own session S at P and relays
  S's challenge to a victim tester, who signs it. S then becomes authorized. The challenge
  names P and S, but the tester has no way to verify that S is "their" session. Defending
  against this needs origin or channel binding (for example a TLS exporter, or WebAuthn
  origin checks), which this slice does not provide.
- **No continued possession.** After SessionAccept, P's session is a bearer state at P. No
  per-request proof (DPoP-like) is modelled.
- **Key compromise.** Anyone holding K_T's private key passes. There is no revocation of
  K_T other than revoking G (status, RQ7).
- **Store provenance vs audience.** The audience field says which provider a challenge is
  *for*, not who *wrote* it. Comparing audience (binding stage) does not authenticate the
  inserter. s1 assumes a P-private store that only P can write, so provenance is not in
  question. SS08 fault-injects a foreign (audience-Q) record directly into the store to
  show that even if a writable shared store were used, such a record is rejected at the
  binding stage — but authenticating *who inserted* a record into a shared store is future
  work, not something the audience check provides.
- **Synthetic store.** The store is in memory, has one lock, and does no garbage
  collection. A distributed store needs the same atomic compare-and-set guarantee; that is
  assumed, not shown.
- **Sessions from authorized parties.** Nothing checks that P's session belongs to an
  account entitled to use G; P's account model is out of scope.
