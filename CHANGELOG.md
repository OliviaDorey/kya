# Changelog

The public record of Know Your Agent, so that anyone can follow how it grew and what changed
their mind. Newest first. Dates are the date the work landed, not the date it was written about.

The specification is CC BY 4.0. The implementation is Apache-2.0 with an irrevocable patent
non-assertion covenant in [PATENTS.md](PATENTS.md). Nobody needs to ask us.

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
