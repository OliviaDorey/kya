# Changelog

The public record of Know Your Agent, so that anyone can follow how it grew and what changed
their mind. Newest first. Dates are the date the work landed, not the date it was written about.

The specification is CC BY 4.0. The implementation is Apache-2.0 with an irrevocable patent
non-assertion covenant in [PATENTS.md](PATENTS.md). Nobody needs to ask us.

---

## 0.8.0 — 23 August 2026

### The counter-claim

*"Identity is about who claims you, and who you claim back."* Suite went 184 to **203**.
Specification: [spec/the-counter-claim-v0.1.md](spec/the-counter-claim-v0.1.md).

Everything here recorded who claims an agent. Nothing recorded that a person had made a claim
back — a grant expires by design, a relationship lapses if it is not renewed, and the two are
not the same event.

- **`src/claim.js`** — the person's half, wallet-side by construction. Made, live, due, lapsed,
  ended. Quarterly renewal by default, matching Keep in Touch.
- **Renewal is always explicit.** No operation moves the renewal date without recording that
  somebody said so, and a test asserts the absence. Silent extension is a subscription wearing a
  relationship's clothes.
- **A lapse narrows; it does not end.** `read` and `monitor` survive so the agent can still tell
  a person what is happening to their file; everything that acts on their behalf stops. The
  mid-appeal hazard is written down rather than pretended away.
- **Only the principal may end a claim.** Others may stop the agent. Ending is free and needs no
  reason; no implementation may take a payment for it.
- **The purpose sentence never reaches a verifier.**
- **`counter_claim` on transfer, guardian and death** — the registrar records the obligation and
  never the claimant. Closed field set, refused at the door: the register says how many claims are
  outstanding and by when, never whose. A `reconsent` event records discharge.
- **An outstanding obligation does not change the status.** `adc.transferOutcome()` already
  refuses an unrecorded transfer; two verifiers reaching the same verdict by different routes is
  how they drift apart.

An earlier draft put CLAIM and UNCLAIM in the registrar as event kinds. It would have broken the
register's no-personal-data rule on the day it shipped.

---

## 0.7.0 — 20 August 2026

### The registrar

Packages 4 to 7 of the specification scope. Suite went 157 to **174**.

A trust anchor answers one question: may this agent act, right now. A registrar answers three: did
it exist, what changed about it, and when did it end. The second contains the first, and
`Registry.lookup()` computes it.

- **`src/events.js`** — an append-only, signed, chained record. Nine event kinds: birth, version,
  transfer, guardian, suspension, reinstatement, revocation, death, correction. Malformed events
  are refused at the door rather than stored and flagged.
- **A death must name a successor or explicitly name none.** A record that an agent ended, with
  nothing said about the people relying on it, is an accountability sink with a certificate
  attached.
- **A transfer must carry notice.** Not as a courtesy: `transfer.notice.given_at` is a condition
  of validity on both the card and the event.
- **`Registry.lookup()`** — current operator, accountable human, version, successor, transfer
  count, and a status derived from the events and then handed to the same `inForce()` every other
  verifier uses. That is how "a verifier holding only the register decides as one holding the
  credentials" is made true rather than asserted; there is a test that compares the two directly.
- **Corrections amend without deleting.** The corrected entry stays in the history and the
  amendment is itself part of the record, as a civil registry does it.
- **Revocation outranks retirement** in the derived state, because a person asking why is owed the
  first answer rather than the tidier second one.
- **`aic.TRANSFER_POLICY`** and **`adc.transferOutcome()`** — notify, re-consent and void as three
  settings on one mechanism, which is only possible because the binding report separates "different
  document" from "different terms". VOID is the default. An **unrecorded** transfer is refused
  under every policy, including notify.
- **`conformance.probeRegistrar()`** — four probes: the chain is intact, the reported state is the
  state the events replay to, malformed events are refused, and nothing is recorded after an end.

### Two limits, stated rather than buried

**A chain does not detect entries removed from the end.** A shorter chain is still a valid chain.
Removing an entry from the *middle* is caught, because the entry after it no longer follows.
Closing the tail case needs the head published somewhere the registrar does not control — a
transparency log, a witness, or simply publishing the current hash and count on a schedule. Until
then a registrar can drop its most recent entries and pass every check here. There is a test named
`LIMITATION:` that asserts exactly this, so nobody mistakes it for tamper-evidence it does not have.

**A registrar that lies passes.** Nothing here detects a record that was never written. What these
probes detect is a record that contradicts itself, which is the failure that happens by accident
rather than by intent, and it is worth catching on its own terms.

---

## 0.6.0 — 20 August 2026

### Transfer, succession, and what a delegation is bound to

Packages 1 to 3 of the specification scope. Suite went 144 to **157**.

**The defect this began with.** A delegation bound to an Agent Identity Card by hashing the issued
credential, so reissuing the card broke every delegation held against it — including a reissue
with **identical claims**, because the signature and the disclosure salts differ. The binding was
to a document, not to an agent. It was invisible only because cards live a year and delegations
cap at thirty days, so no reissue happened in between; every vital event in an agent's life
reissues the card mid-life.

- **`aic.termsDigest(card)`** — a stable digest over the material terms a person was agreeing to:
  who built and runs the agent, who answers for it, what it may ever do, how it behaves, and
  whether it is being retired. Unchanged by a reissue, unchanged by bookkeeping, unchanged by an
  agent *gaining* a certification. Moves when the operator changes or the ceiling widens.
- **`adc.bindingReport()`** — five bindings reported separately (agent, key, holder, document,
  terms) with a `continuity` verdict: `same-document`, `reissued-same-terms`,
  `reissued-terms-changed`, `different-agent`, `unchecked`.
- **`delegate.agent_id` is now compared.** It was a required field that nothing checked, which is
  the defect this file's own comments warn about.
- **`delegate.terms_digest`** is computed at issue from the card rather than accepted from the
  caller, on the same principle as the pairwise subject.
- **`allowReissue` on `adc.verify()`, off by default.** The default is therefore the strictest
  transfer policy — a reissued card voids the delegation — which is what the library already did.
  Making it explicit rather than emergent is the point. Continuity has to be asked for, and is
  granted only when the terms are unchanged.
- **`STATUS.RETIRED`.** Until now a verifier could not tell a retired agent from a revoked one.
  Revoked, retired and *gone* (an unreachable list) are now three distinguishable states, all
  failing closed. Needs `bits: 2`; `bitsFor()` says so and `set()` explains itself.
- **`succession` on the card.** Optional, so cards predating it stay valid, and strictly checked
  the moment it is present. A retirement must name a successor **or explicitly name none** —
  absence is refused. A retirement with no recorded notice is refused: *a retirement nobody was
  told about is an abandonment.* Never selectively disclosable.

### A limit, stated rather than buried

The terms digest covers only always-disclosed claims. A verifier cannot detect a change in a claim
it was never shown, so **a change to the model family or its hosting country does not move the
digest**. The first version covered `model` and every real presentation failed, because the demo
withholds it. A relying party that cares about model residency must require it disclosed and check
it itself. That is a property of selective disclosure rather than of this design.

---

## 0.5.0 — 20 August 2026

### The Gaia-X profile

- `spec/gaia-x-participant-profile-v0.1.md`, expressing an AI agent as a Gaia-X-compatible
  resource. An agent is **not** a Gaia-X Participant: it is not a legal person, so it maps to
  `gx:SoftwareResource` co-typed `kya:AutonomousAgent`, made and maintained by `gx:LegalPerson`
  builder and operator.
- `src/gaiax.js`, a deterministic two-way mapping. The capability ceiling becomes a `gx:policy`
  as an ODRL permission set, flagged `kya:closedVocabulary` so a Gaia-X reader takes the list as
  a ceiling rather than as examples.
- `test/gaiax.test.js`, fifteen tests. Suite went 129 to **144**.
- `npm run gaiax` emits a sample self-description and runs the conformance probe.
- **The delegation credential has no Gaia-X equivalent.** Gaia-X has no concept of a person
  mandating software to act for them against a third party. `gx:consent` was available and was
  rejected: consent to process data about me is not authority to act as me. Declared as
  `kya:Delegation` and held out of scope for v0.1.
- **The mapping refuses to invent.** `gx:VirtualResource` makes `license` mandatory and the Agent
  Identity Card does not carry one, so `toGaiaX()` throws unless the caller supplies it.
- Found by the round-trip test rather than by review: Gaia-X `gx:countryCode` is country-level, so
  `CA-NS` silently became `CA` and back, downgrading which registry a builder is incorporated in.
  Fixed by carrying the full value in `kya:jurisdiction`.

### Stated limits

Semantic equivalence, not cryptographic — nothing in the mapping signs anything. One direction
only: Card to Gaia-X is a widening. And Kindred does not mark its own homework; the profile is
offered to Gaia-X Hub Canada to publish and to run on their test bench.

## 0.4.x — 14 August 2026

- A residency claim must say how it is known. `model.residency_basis` is now required and ordered
  `asserted`, `contractual`, `attested`. An honest weak claim is worth more than a missing one.
- A pairwise subject on its own was decorative. The unlinkability probe proves it, and the
  limitation that a lying wallet passes is recorded in the test suite rather than in a footnote.
- Threat model remediation, priorities 2 to 4.
- Spec v0.4, plus a CI check for the class of defect that produced it.
- **Chained delegation**, and revocation that is not the principal's private button. A chain
  carries its own key path so a relying party with no prior relationship can verify from a single
  federation anchor. Scope narrows on six axes; a widening link is rejected rather than clamped.
  Depth capped at three hops. A relying party seeing misbehaviour can **suspend** at that party,
  reversibly, with only the person able to reinstate.

## 0.3.x — 13 August 2026

- The appeal is a second delegation, not a wider first one. Until this release, authorising an
  agent to *draft* an appeal had silently authorised it to *file* one.
- Spec v0.3: split the appeal action, and enforce the delegation binding.
- Two of three bindings is not a binding, and neither is a skipped invariant.

## 0.2.x — 10 and 11 August 2026

- Implement the Agent Identity Card and the Delegation Credential.
- **Capability scoping**: keep the sensitive noun out of the credential. A delegation says
  *submit a form and track its status*, never the name of the programme.
- The revocation service, the caseworker screen, and the honest slide.
- Spec v0.2, security policy, headers.
- Audit the audit: a scheduled CI check for drift between the specification and the code.
- README states the four properties enforced in code, and what is still unbuilt.

## 0.1.x — 7 and 9 August 2026

- **The gift put in force**: Apache-2.0, CC BY 4.0, and the patent non-assertion covenant.
- The Authoritative Rules Commitment v1.0.
- Agent Identity Card spec v0.1, draft and not yet implemented.
- Interoperability proved against Alberta's live federation.

---

## How to follow along

- Releases and tags mark each version above.
- The specification lives in `spec/`. Where the spec and the code disagree, that is a bug in one
  of them and CI is supposed to catch it.
- `npm test` is the honest measure. It currently passes 144 checks, and several of them exist to
  record limitations rather than capabilities — those are named `LIMITATION` on purpose.
