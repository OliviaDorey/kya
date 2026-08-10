# The Agent Identity Card and the Delegation Credential
**Version 0.1, draft for review. 6 August 2026.**

Editor: Olivia Dorey, The Kindred Agency, Bridgewater, Nova Scotia.
Status: **draft, not implemented.** Circulated for technical review before code is written.

---

## 1. What this is for

When an AI agent acts for a person in their dealings with government, the
government needs to answer four questions before it acts on anything the agent
says, and the person needs to be able to answer a fifth.

1. **What is this agent?** Who built it, who operates it, what is it.
2. **Who authorised it?** Which person, proven, not asserted.
3. **What may it do?** Bounded, specific, and legible to a human.
4. **How do I verify all of that?** Cryptographically, offline where possible.
5. **How do I stop it?** Immediately, by the person, without asking anyone.

Two credentials answer these. The **Agent Identity Card** describes the agent as
a thing and is issued to the agent. The **Delegation Credential** describes one
person's grant to one agent and is issued by the person's wallet. They are
deliberately separate: an agent has one identity and many delegations, and a
delegation must be revocable without revoking the agent.

### What it is not

Not an eligibility engine. Where a jurisdiction publishes rules as code, an agent
carrying these credentials calls those rules and does not infer around them. This
specification carries authority, not answers.

---

## 2. Design constraints

**Interoperate with what governments have already deployed.** Alberta operates a
live OpenID Federation 1.0 trust anchor at `account.alberta.ca/dts` whose
published constraints admit `openid_credential_issuer` and `openid_verifier` as
leaf entity types. This specification targets that, not a greenfield.

**Build only on ratified standards where they exist.** SD-JWT is RFC 9901.
Token exchange with the nesting `act` claim is RFC 8693 and has been stable since
2020. Rich Authorization Requests is RFC 9396. OpenID4VCI, OpenID4VP and OpenID
Federation are all Final. SD-JWT VC is at draft-18 and submitted to the IESG.

**Where nothing is ratified, be explicit and loosely coupled.** No standard
covers person-to-agent delegation. The nearest work is
`draft-gco-oauth-delegate-sd-jwt-00`, a Google individual submission from April
2026 that expires in October 2026, and DIF's KYA-OS, which is heading to a vote.
Nothing here pins to either. §6 is written so the chaining mechanism can be
replaced without touching the claim set.

**Selective disclosure is the default, not a feature.** A verifier confirming
that an agent may submit a benefit application does not need the person's name.

**Plain language is normative.** Every delegation carries a `purpose` written for
the person granting it. A credential a person cannot read is not consent.

---

## 3. Credential format

| | |
|---|---|
| Format | SD-JWT VC |
| `typ` emitted | `dc+sd-jwt` |
| `typ` accepted | `dc+sd-jwt`, `vc+sd-jwt`, `sd-jwt` |
| Signature | ES256 minimum. Ed25519 permitted. ML-DSA-65 where the verifier supports it |
| Holder binding | Key Binding JWT, `cnf.jwk` |
| Status | IETF Token Status List |
| Transport | OpenID4VCI to issue, OpenID4VP to present |

`vc+sd-jwt` and `sd-jwt` are accepted on ingest only, because deployed government
credentials use them. They are never emitted.

---

## 4. Namespace

Credential types are **not** namespaced to Kindred:

```
https://agentcredential.ca/aic/v1     Agent Identity Card
https://agentcredential.ca/adc/v1     Agent Delegation Credential
```

A credential type under a vendor's domain is a credential type that vendor
controls. Given §9, that would be incoherent.

---

## 5. The Agent Identity Card

Issued to an agent by an issuer registered in a federation. Long-lived relative
to a delegation. Answers question 1.

```jsonc
{
  "vct": "https://agentcredential.ca/aic/v1",
  "iss": "https://issuer.example.ca",
  "iat": 1785902742,
  "exp": 1817438725,

  "agent": {
    "id": "urn:agent:kindred:steward:7f3a…",   // stable, opaque, non-correlating
    "name": "Steward",                          // shown to the person
    "version": "1.4.2"
  },

  "builder": {                                  // who wrote it
    "legal_name": "The Kindred Agency Inc.",
    "jurisdiction": "CA-NS",
    "registry_id": "…",                         // corporate number
    "uri": "https://thekindredagency.com"
  },

  "operator": {                                 // who runs it, if different
    "legal_name": "The Kindred Agency Inc.",
    "jurisdiction": "CA-NS"
  },

  "accountable": {                              // question 5's human end
    "role": "Chief Technology Officer",
    "contact": "trust@thekindredagency.com",
    "redress_uri": "https://thekindredagency.com/redress"
  },

  "model": {                                    // "undisclosed" is permitted, silence is not
    "disclosed": true,
    "family": "claude-opus",
    "version": "5",
    "hosted_in": "CA"
  },

  "capabilities": [                             // the outer bound; a delegation narrows it
    "read:program-information",
    "draft:application",
    "submit:application",
    "draft:appeal",
    "monitor:status"
  ],

  "conduct": {
    "discloses_ai": "always",                   // never false, by policy
    "acts_without_approval": false,
    "retains_after_revocation": "audit-record-only"
  },

  "assurance": {
    "framework": "PCTF",                        // once a component exists, see §9
    "level": "…",
    "assessed_by": "…",
    "assessed_at": "…"
  },

  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "status": { "status_list": { "uri": "https://…/aic", "idx": 4213 } }
}
```

**Selectively disclosable:** `model`, `builder.registry_id`, `assurance`.
**Always disclosed:** `agent.id`, `agent.name`, `accountable`, `conduct`,
`capabilities`, `cnf`, `status`. A verifier must never have to ask who is
accountable.

`conduct.discloses_ai` is `always` and is not configurable. An agent that can be
configured to deny being an agent is a different product.

---

## 6. The Agent Delegation Credential

Issued **by the person's wallet** to a specific agent. Short-lived. Answers
questions 2 and 3.

```jsonc
{
  "vct": "https://agentcredential.ca/adc/v1",
  "iss": "https://wallet.example.ca/u/…",       // the person's wallet, not Kindred
  "iat": 1785902742,
  "exp": 1786507542,                            // hours or days, not months

  "delegator": {
    "sub": "…",                                 // pairwise per verifier; never a raw identifier
    "verified_by": "https://account.alberta.ca/dts",
    "assurance": "…"
  },

  "delegate": {
    "agent_id": "urn:agent:kindred:steward:7f3a…",
    "aic_thumbprint": "…",                      // binds to a specific Agent Identity Card
    "cnf_thumbprint": "…"                       // and to the key that will present it
  },

  "purpose": "Apply for the Alberta Disability Assistance Program on my behalf, and appeal if I am refused.",

  "authorization_details": [                    // RFC 9396 shape
    {
      "type": "gc_benefit_application",
      "programs": ["urn:ab:program:adap"],
      "actions": ["read", "draft", "submit", "appeal"],
      "constraints": {
        "max_submissions": 1,
        "requires_human_approval": ["submit", "appeal"],
        "valid_until": "2026-09-30"
      }
    }
  ],

  "consent": {                                  // ISO/IEC TS 27560 consent record
    "record_uri": "https://…/consent/…",
    "captured_at": "…",
    "language": "en-CA",
    "method": "in-app-explicit"
  },

  "revocation": {
    "revoke_uri": "https://revoke.agentcredential.ca/…",   // §7
    "citizen_facing": true
  },

  "cnf": { "jwk": { … } },
  "status": { "status_list": { "uri": "https://…/adc", "idx": 88117 } }
}
```

**Notes on three deliberate choices.**

`delegator.sub` is pairwise. A person delegating to one agent across three
programs must not be correlatable across those three verifiers by the identifier
alone.

`purpose` is normative and human-authored. It is what the person is shown at the
moment of granting and what a caseworker is shown at the moment of receiving. If
it and `authorization_details` disagree, the narrower governs and the verifier
should reject.

`requires_human_approval` lists the actions the agent may prepare but not
complete. This is where Kindred's approval architecture becomes cryptographic
rather than a promise in an interface.

**Chaining.** Where a delegation must pass through an intermediary, for example a
navigator acting with a client, chain per Delegate SD-JWT and mirror the chain in
the RFC 8693 `act` claim at runtime so downstream services see the full path.
Until that draft stabilises, use an explicit `delegation_chain` array of
thumbprints. Both approaches are transitional and the claim set does not depend
on which wins.

---

## 7. Revocation, and the part nobody has solved

Machine path: IETF Token Status List, one list per credential type, short cache
lifetimes.

That is the easy half. The Delegate SD-JWT draft names the hard half plainly: an
individual holder cannot distribute revocation information to verifiers. Its only
proposed mitigations are short expiry and embedded constraints.

**This specification treats revocation as a service obligation, not a data
structure.** A conforming deployment must provide:

- a **citizen-facing revocation endpoint** reachable without signing in to any
  government system, requiring only proof of control of the delegating key
- **immediate status-list update**, propagated within a stated maximum, published
- **notification to known verifiers** that have presented the credential within
  its lifetime, on a best-effort basis, logged
- **a receipt to the person**, stating what was revoked, when, and who was told
- **fail-closed on doubt**: a verifier that cannot reach the status list within
  the freshness window treats the delegation as not in force

Short expiry does most of the work. The service exists for the case where short
is not short enough, which is the case that matters to someone who has just
realised they should not have granted something.

**Availability commitment.** Revocation infrastructure must not have a cliff. See
§9.2, because this is where the sunset commitment and the safety obligation meet
and one of them has to give.

---

## 8. Trust and federation

An issuer of these credentials registers as an `openid_credential_issuer` leaf
under a government trust anchor and publishes a signed Entity Configuration at
`/.well-known/openid-federation`. Verifiers validate the chain to the anchor.

Alberta's deployed profile departs from the specifications in four places, all
enumerated in `../src/alberta.js` and handled behind that boundary: legacy `typ`
values, a flat status claim that is not wire-compatible, `secure-qr-jwt` and
`ckapp` in place of a Key Binding JWT, and a bespoke `"sd"` schema annotation.
Their anchor also publishes a signing key carrying `"key_ops": []`, which strict
libraries refuse. All of it is adapted to, none of it is adopted.

---

## 9. Licence, governance, and the gift

### 9.1 The gift

This specification and its reference implementation are **given away, not held.**
A trust framework owned by one vendor is not a trust framework. Decided by
Olivia Dorey, 6 August 2026.

| What | How | Status |
|---|---|---|
| Specification | **CC BY 4.0** | In force. `spec/LICENSE` |
| Reference implementation | **Apache-2.0**, chosen over MIT for its express patent grant | In force. `LICENSE` |
| Patents | **Irrevocable non-assertion covenant**, binding on successors and acquirers | In force. `PATENTS.md` |
| Stewardship | Contributed to **DIACC** as a Pan-Canadian Trust Framework component, and to the **Digital Governance Council** while `CAN/DGSI 103-3` and `103-4` are open | To be initiated |

Once a standards body holds the specification, it is nobody's to withdraw,
including Kindred's. That is the point.

**Scope: given to everyone, not to Alberta.** An open licence gifts this to the
whole country, Alberta included. Gifting it to Alberta alone would have stopped
Nova Scotia and New Brunswick using it, which cuts against a Canada-by-2028
objective. Alberta is named as the **first implementation partner**, which is
both the more useful arrangement and the better account of it.

**Corporate condition, outstanding.** Kindred is mid-incorporation. If this IP
vests in the company, giving it away is a board decision and must be minuted
rather than assumed, and John Spicer's assignment terms need confirming before
publication. The licences in this repository record the intent; the board
resolution is what makes them safe.

**What Kindred keeps, and why this is commercially coherent.** The standard is
free. The Loom, the Trustmark, the assurance assessment and the Friends and
Family roster are the business. Giving away the specification makes the
certification more valuable, not less, because a standard nobody can implement
certifies nothing. Red Hat, not Oracle.

### 9.2 Time-bounding operated services

Kindred creates **no permanent dependency**. Decided by Olivia Dorey, 6 August
2026, in the following construction.

| Commitment | Mechanism |
|---|---|
| No permanent dependency | The **co-development term** ends **31 December 2026** unless both parties renew. The date binds the engagement, not the infrastructure. |
| No lock-in | Alberta may take any operated service in-house **at any time, for any reason, at no cost**, with a committed handover package: source, runbooks, keys, data, and the agent skills. |
| No cliff on safety-critical services | Revocation continues under a **wind-down obligation**: it runs until every delegation it covers has expired or been transferred, with a minimum of **ninety days' written notice**. Availability is not conditional on a commercial relationship continuing. |
| No hostage-taking | **Automatic release**: if Kindred ceases to operate a service, becomes insolvent, or is acquired, the handover package transfers to Alberta automatically, under the open licences in §9.1. |

Why the date binds the term rather than the service. A hard expiry on revocation
infrastructure is a safety problem, not a commercial one: if people have
delegated authority to agents and the service stops on a date, either those
delegations become unrevocable or everything fails closed at once and people
lose access to things they depend on. The second contradicts Failing Well
directly. The construction above delivers everything a fixed service expiry was
reaching for, and binds Kindred in the cases a date does not cover, including
acquisition.

**Outstanding for Fasken:** whether 31 December binds the term, the exclusivity,
or both; and whether the automatic release is drafted as a contractual right or
as source escrow.

---

## 10. Open questions for review

1. Is `capabilities` in the Agent Identity Card meaningful, or does everything
   real live in the delegation? Argument for keeping it: it lets a verifier
   reject a whole class of agent before parsing any delegation.
2. Should `model.disclosed` ever be false? Kindred's position is that the
   *field* is mandatory and the *value* may be withheld with a stated reason.
3. Pairwise `delegator.sub` per verifier prevents correlation but complicates
   the person's own view of what they have granted. Where does that reconcile?
4. Is `purpose` genuinely enforceable, or is it advisory in practice because no
   verifier will parse prose? If advisory, say so rather than implying more.
5. What does a delegation mean when the delegator loses capacity? Guardianship
   and power of attorney are the hardest case and are deliberately out of scope
   for v0.1. They cannot stay out of scope for v1.
6. Does DIF KYA-OS, once voted, subsume §5? If it does, the right response is to
   adopt it and contribute §6 and §7, which it does not appear to cover.

---

## 11. Review

Sought from, in order: **Tim Bouma** (Pan-Canadian Trust Framework architect,
Digital Governance Council) on the trust and assurance model; **John Spicer**
(CTO, Kindred) on key management and the wallet issuance path; **Erin Hardy**
(Service New Brunswick, DIACC board) on how this should present to the trust
framework; and the DIF Trusted AI Agents working group on overlap with KYA-OS.

Comments to `trust@thekindredagency.com`.
