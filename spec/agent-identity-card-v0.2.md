# The Agent Identity Card and the Delegation Credential

**Version 0.4 — 14 August 2026.** Supersedes v0.3 of 13 August 2026, which
superseded v0.2 of 10 August 2026 and v0.1 of 6 August 2026.

The filename still says v0.2. It is left alone deliberately: this file is the
living specification and several documents outside this repository link to it by
name. The version above governs.

Editor: Olivia Dorey, The Kindred Agency, Bridgewater, Nova Scotia.
Status: **draft, implemented and tested.** Every *must* in this document is
enforced by `../src/` and defended by a named test in `../test/`, 108 of them.
The status line read "not implemented" for four days after that stopped being
true, which is the same class of defect as a document claiming a feature that
does not exist, and it is now checked in CI rather than remembered.

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
    "id": "urn:agent:kindred:steward:7f3a…",   // stable, opaque, and a lifetime
                                                // correlator for the person. See
                                                // the note below §5
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
    "draft:appeal",                             // prepare an appeal
    "submit:appeal",                            // and file it. Two grants, §6
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

**The card capability vocabulary.** Closed, and it is the outer bound a delegation
narrows. An unknown value is a typo, not a feature, and does not verify.

| Capability | What the agent may do | Delegation action it permits |
|---|---|---|
| `read:program-information` | Look things up | `read` |
| `draft:application` | Prepare an application | `draft` |
| `submit:application` | File one | `submit` |
| `draft:appeal` | Prepare an appeal | `draft-appeal` |
| `submit:appeal` | File one | `appeal` |
| `monitor:status` | Watch a file's progress | `monitor` |
| `correspond:on-behalf` | Exchange routine correspondence | `correspond` |

Preparing and filing are separate capabilities in both directions, applications
and appeals alike. See §6.

**On `agent.id` and correlation.** The identifier is stable and opaque. It is
**not** non-correlating, and v0.2 of this document said it was. An agent that
carries one identifier to every service it touches is a lifetime correlator for
the person it acts for: two departments holding presentations from the same
`agent.id` can join their records on that person exactly, without either doing
anything wrong and without sharing any personal data. That is close to the
opposite of what sector-specific identifiers exist to prevent.

This is an open problem, not a solved one. It is written up in full in
`knowledge-base/kya/PRIVACY-GAP.md` and in §9.1 of the threat model, with the
candidate directions — chiefly per-relying-party pairwise agent identifiers, and
what they cost in revocation and audit. Anyone implementing this specification
should read that before deciding the identifier is safe to log.

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

  "purpose_commitment": "K7dM…",                // SHA-256 over salt:purpose, §6.1
  "purpose": "Apply for Assured Income for the Severely Handicapped on my
              behalf, and appeal if I am refused.",
                                                // SELECTIVELY DISCLOSABLE and
                                                // WITHHELD BY DEFAULT. Hers.

  "authorization_details": [                    // RFC 9396 shape
    {
      "type": "ca_public_service_request",
      "capability": "submit:form",              // §6.1. Public, subject-free
      "actions": ["draft", "submit"],
      "constraints": {
        "max_submissions": 1,
        "requires_human_approval": ["submit"],
        "valid_until": "2026-09-30"
      }
    },
    {
      "type": "ca_public_service_request",
      "capability": "request:review",
      "actions": ["draft-appeal", "appeal"],    // prepare, and file. Two grants
      "constraints": { "requires_human_approval": ["appeal"] }
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

**Actions.** `read`, `draft`, `submit`, `draft-appeal`, `appeal`, `monitor`,
`correspond`. Each requires the corresponding card capability in §5, and a
delegation naming an action the card does not carry is rejected.

**Preparing is not filing.** `draft` and `submit` are two actions because
preparing an application is reversible and private and filing it is neither.
`draft-appeal` and `appeal` are two actions for exactly the same reason, and for
one more: filing an appeal starts or forfeits a clock. A person who authorises an
agent to draft an appeal has not authorised it to lodge one, and a conforming
implementation must not let a card carrying only `draft:appeal` file anything.
This was wrong until v0.3; see the changelog.

**Notes on five deliberate choices.**

`delegate.aic_thumbprint` and `delegate.cnf_thumbprint` are the binding, and a
verifier must **recompute both from what was actually presented** and compare,
rather than checking that the fields are there. A delegation carried alongside a
different agent's Agent Identity Card, or presented by a key other than the one
it was granted to, is rejected. Where a verifier has no card to compare against,
it has not checked the binding and must reject on that basis rather than proceed.
The two credentials are separable; the authority between them is not.

`delegator.sub` is pairwise. A person delegating to one agent across three
programs must not be correlatable across those three verifiers by the identifier
alone.

`capability` is what the verifier reads, and it comes from a closed vocabulary
that describes the *shape* of an interaction and never its subject. `purpose` is
the person's own sentence, and it is withheld by default. See §6.1, which is the
part of this specification that changed most between v0.1 and v0.2.

`purpose` and `capability` must agree, and where they disagree **the narrower
governs and the verifier rejects**. Rejects, not trims: silently clamping hides a
bug in whoever built the chain.

`requires_human_approval` lists the actions the agent may prepare but not
complete. This is where an approval architecture becomes cryptographic rather
than a promise in an interface.

**Chaining.** Built as of v0.4 and specified in full in
[revocation-and-chains.md](revocation-and-chains.md) §C, which this section now
defers to rather than restating.

The short form. A chain is an ordered set of delegations, each a credential in
its own right, each carrying a `chain` claim of `{ depth, parent_thumbprint,
root_thumbprint }`. Scope narrows on six axes and never widens, and a widening
link is **rejected, not clamped**. Depth is capped at **three hops**. The
property that makes it work across an organisational boundary is that a chain
carries its own key path:

> link *n+1* must be signed by the key committed to in link *n*'s
> `delegate.cnf_thumbprint`.

So a verifier trusts exactly one key from outside the chain — the issuer of link
0, the person's wallet, whose standing comes from the federation anchor — and
authenticates every later hop with material it has already verified. It needs no
prior relationship with the principal or with any intermediary.

Mirroring the chain in the RFC 8693 `act` claim at runtime remains the right
thing to do so downstream services see the full path, and is unchanged. The
Delegate SD-JWT draft is no longer on the critical path: nothing in the claim set
depends on it, and if it or DIF's KYA-OS wins, the chain claim is the only thing
that has to change.

---

### 6.1 Capability scoping, and why the programme is not named

**A verifier already knows who it is.** When an agent presents to the office that
administers a programme, naming that programme in the credential tells that
office nothing it did not already know. What it does is tell every other party
that handles the credential — intermediaries, logs, status infrastructure, anyone
who later obtains a copy — something about the person that they had no need for.

So a delegation carries two things where v0.1 carried one.

**`capability`** is public and comes from a closed vocabulary. Every entry
describes the shape of an interaction. None describes a subject, a programme, a
condition, or a circumstance.

| Capability | What the verifier is shown | Actions it permits |
|---|---|---|
| `read:public-information` | Look up publicly published information | `read` |
| `submit:form` | Submit a form and track its status | `draft`, `submit` |
| `provide:documents` | Provide documents that were asked for | `draft`, `submit` |
| `track:status` | Check where something has got to | `monitor` |
| `request:review` | Ask for a decision to be looked at again | `draft-appeal`, `appeal` |
| `correspond:administrative` | Exchange routine correspondence about a file | `correspond` |

**`purpose`** is the person's own sentence, in their own language. It is what
they read at the moment of granting. It is selectively disclosable and **withheld
by default**, and `purpose_commitment` — a salted SHA-256 over `salt:purpose` —
travels in the clear so that a verifier who is shown the sentence can prove it is
the one that was consented to.

The person loses nothing: the sentence lives in their wallet and they hold the
salt. The verifier loses nothing it needs.

**Conforming implementations must:**

- reject a delegation whose `authorization_details` name a programme in the clear
- reject a delegation carrying a `capability` outside the vocabulary
- reject actions beyond what the stated capability permits
- **withhold `purpose` by default** when presenting, requiring an explicit
  decision by the person to disclose it
- screen every publicly readable field for terms disclosing health,
  reproductive, immigration, housing, income, safety, family or justice
  circumstances, and treat a hit as an error

That last requirement is deliberately blunt and deliberately over-broad. A false
positive costs an implementer a rewrite. A false negative costs somebody their
privacy at a counter.

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

**Built as of v0.4**, along with four things this section did not previously
reach. All four are specified in [revocation-and-chains.md](revocation-and-chains.md),
which enumerates the five failure cases revocation must cover and is honest about
the ones it cannot.

- **Who else may pull the switch.** "Only the person can revoke" is useless in
  the case that matters most: the agent behaving inside its scope against the
  person's interest, seen by a relying party while the person knows nothing about
  it. A relying party may now **suspend** — scoped to itself, reversible, and
  **only the person may reinstate**. A relying party may never revoke, because
  one office permanently ending a person's authority to be helped is an
  abandonment vector wearing a safety mechanism's clothes.
- **Cascade.** Revoking a link stops every delegation below it and none above it.
  Revoking an Agent Identity Card stops every delegation held by its key, because
  when the holder key is compromised the unit of harm is the agent, not the grant.
- **The issuer's own compromise, which a status list structurally cannot report.**
  A status list is signed by the issuer, so a compromised issuer publishes one
  saying everything is fine. The switch has to be held by a party who is not the
  subject. That is a trust register, it is out of band, and §7 could not have
  been completed without admitting it.
- **A continuation on every stop.** Revocation that strands somebody mid-application
  is a failure of this specification, not a success of it. Every stop returns what
  stopped, what is unaffected, who did it, and what the person can do next.

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
6. Does DIF KYA-OS, once voted, subsume §5? **The v0.1–v0.3 wording of this
   question was wrong and is corrected here rather than quietly edited.** It said
   KYA-OS "does not appear to cover" §6 and §7. It covers both: delegation is
   central to it, chains are DAGs, each hop narrows its parent's scopes, they are
   rooted at an accountable Responsible Party, and revocation is specified via
   StatusList2021. That is the same shape as §6 and
   [revocation-and-chains.md](revocation-and-chains.md) §C, reached
   independently, and the agreement is worth more than the novelty would have
   been. The real divergence is format — W3C VC 1.1 and `Ed25519Signature2020`
   against SD-JWT VC and Key Binding JWT — and the real gap is a **trust
   register**: KYA-OS publishes conformance levels and names no party who decides
   a deployment meets them, and no way to withdraw an issuer whose own signature
   is in doubt. The right response is an SD-JWT VC binding of KYA-OS rather than
   a rival specification. Two things would need work and both are additive:
   StatusList2021 publishes no `ttl`, which the fail-closed rule needs something
   to fail closed against, and a two-state list cannot express a scoped
   suspension.

---

## 11. Review

Sought from, in order: **Tim Bouma** (Pan-Canadian Trust Framework architect,
Digital Governance Council) on the trust and assurance model; **John Spicer**
(CTO, Kindred) on key management and the wallet issuance path; **Erin Hardy**
(Service New Brunswick, DIACC board) on how this should present to the trust
framework; and the DIF Trusted AI Agents working group on overlap with KYA-OS.

Comments to `trust@thekindredagency.com`.

---

## Changelog

### v0.4 — 14 August 2026

**Chaining and revocation stop being the two things this document specified and
nobody had built.** Written against two criticisms rather than against review
comments, which is the second time that has been the more productive order.

- **§6 chaining is built**, and this section now defers to
  [revocation-and-chains.md](revocation-and-chains.md) §C rather than restating
  it. Six narrowing axes, three-hop cap, and a chain that carries its own key
  path so a relying party with no prior relationship to the person can verify the
  whole thing from one federation anchor. The Delegate SD-JWT draft expiring in
  October is no longer on the critical path.
- **§7 revocation gains the four things it did not reach**: who other than the
  principal may pull the switch, cascade down a chain and across a card's
  delegations, the issuer's own compromise, and a continuation on every stop.
- **A relying party may suspend and may never revoke.** This is the answer to
  "the credential proves authority, not conduct", and it is deliberately smaller
  than the criticism. It does not make an agent behave. It lets the party who can
  see the misbehaviour stop it without the person present, and stops that party
  being able to take the person's authority away.
- **The status line was wrong for four days** and said "not implemented" against
  52 passing tests. Corrected, and now checked in CI, because the lesson from
  10–13 August was that no document claiming product behaviour had a test that
  would fail when the claim went stale.
- **§10 question 6 was factually wrong about DIF KYA-OS** and is corrected in
  place with the correction visible rather than edited away. KYA-OS does cover
  delegation and does specify revocation. The gap it leaves is a trust register.

- **Threat model priorities 2, 3 and 4 are closed.** Issuer keys now resolve
  through the federation from the statement the anchor signs about the issuer,
  never from the issuer's own claims about itself, and **anchor pinning is the
  default** rather than an option. Status lists carry a published availability
  target and a two-mirror minimum. `delegator.sub` is **computed** by the
  library rather than asserted by a boolean.
- **A known status-list outage buys no grace period.** A verifier that cannot
  confirm a delegation is in force refuses it, announced outage or not: a
  relaxation would hand an attacker exactly the window they wanted and would
  break the promise made to whoever has just revoked. What is specified instead
  is that the **relying party falls back to its pre-agent process and serves the
  person directly**. Failing closed on the credential must never mean failing
  closed on the person.

**Migration from v0.3.** One breaking change, and the rest is additive.

**Breaking:** where a delegation asserts `delegator.pairwise: true` and the
verifier identifies itself with an audience, `delegator.sub_audience` must name
the verifier the subject was derived for. A subject that claims to be
per-verifier and cannot say which verifier is an assertion nobody can check.
The consequence is real and is stated rather than buried: **a pairwise
delegation is bound to one verifier**, so a person dealing with three programmes
holds three delegations. That is the cost of the identifier not being a lifetime
correlator, and it is the correct trade, but it is a cost.

*This paragraph read "None required. Everything in v0.4 is additive" for several
hours on 14 August, until the pairwise work later the same day made it false.
Corrected here rather than quietly. The CI check added in this version catches a
spec that calls a built thing unbuilt; it does not catch a migration note that
has gone stale, and nothing yet does.*

Additive: a delegation with no `chain` claim is a single-hop chain and verifies
exactly as it did. A deployment that wants suspension must publish a **two-bit**
status list, because a one-bit list can say revoked or not revoked and nothing
in between.

### v0.3 — 13 August 2026

**What changed in 0.3, and why.**

Everything here was found by building the appeal path, not by reading this
document. The specification had been read several times, including while writing
the threat model, and none of these came out of a reading. They came out of
sitting down to write the code that lets a person appeal a refusal and finding
that the code the document described did the wrong thing.

- **Appealing is now two actions, not one.** `draft-appeal` requires
  `draft:appeal` and `appeal` requires `submit:appeal`, mirroring `draft` and
  `submit` for applications. Until now, `appeal` needed only `draft:appeal`,
  which meant a person who authorised an agent to *prepare* an appeal had
  silently authorised it to *file* one. Filing an appeal cannot be taken back and
  it starts or forfeits a clock. Applications had this right from v0.1; appeals
  did not, and nobody noticed until the path was built.
- **`submit:appeal` is in the specification.** It was already in the reference
  implementation's capability list and appeared nowhere in this document. §5 now
  carries the full card capability vocabulary as a table, so code and
  specification can be checked against each other rather than assumed to agree.
- **The binding is now enforced, and this document says so.** §6 requires a
  verifier to recompute `aic_thumbprint` and `cnf_thumbprint` from the card and
  key actually presented and compare them. They were required fields that nothing
  compared to anything, which meant a delegation could be presented alongside a
  different agent's card and pass. This is T3.3 in the threat model, and it is
  closed.
- **`agent.id` is not "non-correlating", and §5 no longer says it is.** It is
  stable and opaque, and it is a lifetime correlator for the person the agent
  acts for. The correction points at `knowledge-base/kya/PRIVACY-GAP.md` rather
  than restating half of it.

**Migration from v0.2.** A v0.2 delegation granting `appeal` is not conforming
under v0.3 unless the card carries `submit:appeal`. This is the intended
direction of failure: an implementation that is refused finds out that its cards
were granting more than the person agreed to.

### v0.2 — 10 August 2026

Everything here came out of writing the threat model rather than out of review
comments, which is the intended order.

- **§6.1 is new: capability scoping.** A delegation now carries a public
  `capability` from a closed, subject-free vocabulary, and the person's own
  `purpose` is withheld by default with a salted commitment in the clear.
  Naming a programme in `authorization_details` is now non-conforming.
- **§7 gained the service half.** Revocation was specified as an obligation and
  is now also implemented: proof of control of the delegating key and nothing
  else, status list updated before any notification, best-effort notice that
  does not stop at the first failure, a receipt, and a freshness window capped
  at 24 hours.
- **Conformance is now testable.** The reference implementation refuses rather
  than warns on every rule marked *must* in this document.

**Migration from v0.1.** A v0.1 delegation is not conforming under v0.2, because
it names a programme in the clear and presents `purpose` to the verifier. There
is no compatibility shim on purpose: v0.1 was published four days ago, has no
deployments, and a shim would preserve the exact behaviour §6.1 exists to
prevent.

### v0.1 — 6 August 2026

First publication.
