# @kindred/kya

Know Your Agent. The OpenID Federation leaf-entity subset plus a Government of
Alberta credential adapter.

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

## Layout

| Path | What it is |
|---|---|
| `src/federation.js` | OpenID Federation 1.0, leaf subset. Anchor fetch, statement verification, one-hop chain validation |
| `src/alberta.js` | Alberta profile: entity types, accepted `typ` values, status-claim normalisation, deviation list |
| `bin/verify-alberta.js` | The interoperability proof |

## Status

Working proof of chain validation. Not yet built: the Agent Identity Card
credential itself, the delegation credential, and the revocation service. See
`../knowledge-base/kya/BUILD-PLAN.md`.
