# @kindred/kya

Know Your Agent. Two credentials that let a software agent act for a person in
their dealings with government, in a form the government can verify and the
person can withdraw.

**Given away.** Specification under CC BY 4.0, this implementation under
Apache-2.0, with an irrevocable patent non-assertion covenant in
[PATENTS.md](PATENTS.md). Implement it, fork it, ship it. Nobody needs to ask
us, and we would rather DIACC and the Digital Governance Council stewarded it
than we did.

```bash
npm install
npm test              # 129 tests, each named after the promise it defends
npm run demo          # end to end, no network
npm run verify:alberta   # talks to Alberta's live trust anchor
```

## Why this exists

Alberta runs a live OpenID Federation trust anchor at `https://account.alberta.ca/dts`,
and its published constraints permit third-party leaf entities of type
`openid_credential_issuer` and `openid_verifier`. That is the door Kindred needs
to walk through to present an Agent Identity Card that Alberta can verify.

This package does the two things a leaf entity has to do, and nothing else:

1. validate a trust chain from some entity up to a trust anchor, and
2. publish a signed Entity Configuration describing itself.

Trust anchors and intermediates also publish statements about subordinates,
evaluate metadata policy, and serve `/resolve`. Kindred is a leaf, so none of
that is implemented here.

## Prove interoperability

```bash
npm install
npm run verify:alberta
```

This talks to Alberta's production federation. It fetches their trust anchor,
verifies its signature, lists its members, fetches and cryptographically verifies
the subordinate statement for each one, and reports where their credential
profile departs from the current specifications. Exit code 0 means Kindred can
verify Government of Alberta credentials today.

## What we found implementing against them

Verified 6 August 2026. None of this is a criticism. Their wallet shipped in
August 2025, before several of these specifications were final, and finding this
sort of thing is what happens when somebody actually builds against a deployment
rather than reading the announcement.

**1. The trust anchor's signing key cannot be used by a strict library.**
The JWK at `https://account.alberta.ca/dts/.well-known/openid-federation` carries
`"key_ops": []`. An empty `key_ops` reads as "this key may be used for no
operation", which contradicts the `"use": "sig"` on the same key and causes
verification to fail outright in `jose`, the most widely used JOSE library in the
Node ecosystem. The same key also carries `"oth": []`, an RSA-only parameter
(RFC 7518 §6.3.2.7) that has no meaning on a P-256 key, and an empty `"x5c": []`.

We work around it in `sanitiseJwk()` by dropping empty members rather than
refusing the key. Removing the three empty members would let every conformant
verifier work without a workaround.

**2. Two of four advertised federation endpoints do not serve.**
The anchor advertises `federation_fetch_endpoint`, `federation_list_endpoint`,
`federation_resolve_endpoint` and `federation_status_endpoint`. `/fetch` and
`/list` work. `/resolve` returns a static 404 page, as does the `policy_uri`.
Consequence for integrators: a leaf cannot delegate chain resolution to the
anchor and must implement it locally, which this package does.

**3. The one federation member declares entity types the anchor does not permit.**
`healthcard.alberta.ca` declares `alberta_credential_issuer` and `holder_binding`.
Neither appears in the anchor's own `constraints.allowed_leaf_entity_types`. This
may be intentional, since the constraint list may not be enforced, but the two
published documents disagree.

**4. The credential profile is not conformant with SD-JWT VC or Token Status List.**
Enumerated in `src/alberta.js` and printed by the verifier: legacy `typ` values,
a flat status claim that is not wire-compatible with the IETF shape, `secure-qr-jwt`
and `ckapp` holder proofs instead of a Key Binding JWT, and a bespoke `"sd"` JSON
Schema annotation. Their base schema is titled "SD-JWT Schema (RFC-9901)", so they
are tracking the ratified RFC and will likely converge. Everything Alberta-specific
is behind `src/alberta.js` so it can be deleted when they do.

## The properties this enforces in code

These are the reason the package exists. Each is a rule the specification states
and this implementation refuses to break, rather than a guideline an operator is
trusted to follow.

**An agent cannot be configured to deny being an agent.** `conduct.discloses_ai`
is `always`. A card carrying anything else does not issue and does not verify.

**Accountability cannot be hidden.** `accountable`, `conduct`, `capabilities`,
`agent` and `status` are never selectively disclosable. Asking to hide one throws
at issue time. A verifier must never have to ask who is answerable for this
thing.

**A delegation belongs to one card and one key.** `delegate.aic_thumbprint` and
`delegate.cnf_thumbprint` are recomputed at verification from the card and the
key actually presented, and compared. A delegation carried alongside a different
agent's Agent Identity Card is refused, and so is a verifier that was given no
card to compare against, because an unchecked binding is not a passed one. Until
v0.3 both fields were required and neither was ever compared to anything.

**Preparing is not filing.** `draft`/`submit` and `draft-appeal`/`appeal` are
four actions, not two. A card carrying only `draft:appeal` can prepare an appeal
and cannot lodge one. Filing is irreversible, and for an appeal it starts or
forfeits a clock.

**Authority narrows and never widens.** A delegation may not grant an action the
Agent Identity Card does not hold, and where the human-authored `purpose`
sentence promises less than `authorization_details` grants, the narrower governs
and the credential is rejected. Rejected, not trimmed: silently clamping hides a
bug in whoever built the chain.

**The sensitive noun never reaches a field a clerk can read.** A delegation
carries a `capability` from a closed, subject-free vocabulary ("submit a form and
track its status"), and the person's own sentence is committed to and withheld by
default. Every publicly readable field is screened against eight categories of
sensitive term, and a hit is an error rather than a warning. `adc.present()`
withholds the purpose unless the person explicitly chooses to show it, because a
privacy property that depends on the caller remembering an argument is not a
property.

**An inference cannot wear the clothes of a decision.** Every determination
carries a `rule_basis` naming its tier. A tier 3 determination, meaning an answer
where no authoritative rule is published, is a malformed credential. See
[the Authoritative Rules Commitment](spec/authoritative-rules-commitment.md).

And one that is a service obligation rather than a data structure: **a verifier
that cannot reach a fresh status list treats the credential as not in force.**
Not "probably fine", not "warn and proceed". `inForce()` is one function so the
rule cannot drift between callers.

## Layout

| Path | What it is |
|---|---|
| `src/sdjwt.js` | SD-JWT VC: disclosures, digests, key binding. The subset these credentials need; the gaps are listed at the bottom of the file |
| `src/aic.js` | Agent Identity Card. What the agent is, and who is accountable |
| `src/adc.js` | Agent Delegation Credential. What the person authorised, and for how long |
| `src/capability.js` | Capability scoping. The public vocabulary, the sensitive-term screen, and purpose commitments |
| `src/status.js` | Token Status List, the fail-closed rule, and the revocation receipt |
| `src/determination.js` | `rule_basis`. Call the rule, cite the provision, or navigate only |
| `src/federation.js` | OpenID Federation 1.0, leaf subset. Anchor fetch, statement verification, chain validation |
| `src/alberta.js` | Alberta profile, quarantined so it can be deleted when they converge |
| `bin/make-keys.js` | Three key pairs: issuer, wallet, agent |
| `bin/make-entity-config.js` | The signed Entity Configuration to publish at `/.well-known/openid-federation` |
| `bin/demo-delegation.js` | Issue, delegate, present, revoke. No network |
| `bin/verify-alberta.js` | The interoperability proof |

## Status

The credentials, the status list, the rule basis, the federation half, the
revocation service and **chained delegation** are built and tested.

Chaining and chain-aware revocation landed 14 August 2026, with the design note
at [spec/revocation-and-chains.md](spec/revocation-and-chains.md). It answers two
criticisms directly: that a credential proves authority and not conduct, and that
nothing here governed agents crossing an organisational boundary. The answers are
smaller than the criticisms and the note says how, at "What this still does not
solve", which is written for a hostile reviewer rather than for us.

The short version. A chain carries its own key path — link *n+1* is signed by the
key link *n* committed to — so a relying party with no prior relationship to the
person can verify the whole thing from a single federation anchor. Scope narrows
on six axes and a widening link is rejected rather than clamped. Depth is capped
at three hops. Revoking a link stops everything below it and nothing above it;
revoking a card stops every delegation held by its key. And a relying party that
sees an agent misbehaving inside its grant can now **suspend** it — stopping it at
that party, reversibly, with only the person able to reinstate — because a
mechanism that lets one office permanently end a person's authority to be helped
would be an abandonment vector wearing a safety mechanism's clothes.

What is still not built: a running deployment of any of it. This is a library
with tests, not a service with an availability target.

One known unsolved problem, written down rather than deferred:
[the privacy gap](../knowledge-base/kya/PRIVACY-GAP.md). A stable agent
identifier correlates its principal across every service they touch, which is
close to the opposite of what sector-specific identifiers exist to prevent. We
would rather raise it first than be found holding it.
