# The Gaia-X profile of the Agent Identity Card

**Version 0.1.0 · 20 August 2026 · CC BY 4.0**

*A profile of `agent-identity-card-v0.2.md` expressing an AI agent as a Gaia-X-compatible
resource, so that Canadian agent-trust infrastructure is legible to the European dataspace
ecosystem from the day it exists rather than after a translation project.*

---

## Status of this document

This is a **draft profile written by the author of the specification it profiles**, and that is
a conflict worth naming in the first paragraph. Kindred wrote the Agent Identity Card, wrote
this mapping, and wrote the conformance test in `test/gaiax.test.js`. **Kindred does not mark
its own homework.** The intended arrangement is that Gaia-X Hub Canada publishes this profile
and runs its conformance test on the Digital Trust Test Bench. Until that happens, this
document is a proposal and nothing has been certified by anyone.

Two things in it are known to be unstable and are flagged rather than smoothed:

- **The Gaia-X core JSON-LD context URL.** The Trust Framework text read on 20 August 2026 says
  the context "will be published together with the machine-executable implementation of the
  Trust Framework at `https://w3id.org/gaia-x/core/` with the release of this specification."
  Deployments in the field currently point at the trusted shape registry instead. Both are
  recorded in `src/gaiax.js` as `CONTEXT.GX_CORE` and `CONTEXT.GX_SHAPES`, neither is hardcoded
  into the mapping, and **an ecosystem states which one it uses**.
- **Class names.** The Trust Framework's participant section describes `LegalPerson` and
  `NaturalPerson` under an abstract `Participant`; deployed credentials in the wild use
  `gx:LegalParticipant`. This profile emits `gx:LegalPerson` and treats the difference as a
  context-resolution question for the Hub to settle, not for us.

---

## 1. Why a profile is needed at all, and why it is small

Gaia-X self-descriptions and Agent Identity Cards are **the same W3C Verifiable Credentials
data model in two serialisations**. Gaia-X expresses claims as JSON-LD over an RDF ontology.
This specification expresses them as SD-JWT, as does the Government of Alberta's credential
stack, because selective disclosure matters more to a citizen presenting a credential than
graph-native semantics do.

That difference is a serialisation and a signature envelope. It is not a semantic gap. So the
profile is a mapping, a set of extension terms for the concepts Gaia-X has no word for, and a
test — roughly three hundred lines in total. Anyone who tells you this is a research problem is
selling a research project.

## 2. The modelling decision

**An AI agent is not a legal person, so it is not a Gaia-X Participant.** It is a thing a legal
person made and operates. In the Gaia-X ontology that is a Virtual Resource, and specifically a
`gx:SoftwareResource`, defined there as recorded information "such as, and not limited to, a
dataset, a software, a configuration file, an AI model."

| Agent Identity Card | Gaia-X | Why |
|---|---|---|
| `builder`, `operator` | `gx:LegalPerson` | These are legal persons and Gaia-X already models them |
| the agent itself | `gx:SoftwareResource` + `kya:AutonomousAgent` | Software made and maintained by a participant |
| `capabilities` | `gx:policy` as an ODRL permission set | A capability ceiling *is* a usage policy |
| the delegation credential | `kya:Delegation` — **an extension** | See §4 |

### The three mandatory Gaia-X fields, and what happens to them

`gx:VirtualResource` makes `copyrightOwnedBy`, `license` and `policy` mandatory.

| Field | Source | Behaviour |
|---|---|---|
| `gx:copyrightOwnedBy` | `builder.uri`, or a URN derived from `builder.legal_name` | Derived. Throws if `builder.legal_name` is absent |
| `gx:policy` | the capability ceiling, as an ODRL `Set` with `kya:closedVocabulary: true` | Derived. The flag is required, because without it a Gaia-X reader takes the list as examples rather than as a ceiling |
| `gx:license` | **not carried by the Agent Identity Card** | **Supplied by the caller on every crossing. The mapping throws without it** |

That last row is the profile's one opinionated refusal and it is deliberate. A mapping that
quietly fills a mandatory field with a plausible default puts an invented claim inside a signed
document. That is the exact failure this specification exists to prevent, and it is why
`toGaiaX()` stops rather than guesses.

## 3. Extension terms

Namespace `kya:` = `https://agentcredential.ca/gaia-x/v1#`.

| Term | Carries |
|---|---|
| `kya:AutonomousAgent` | class, co-typed with `gx:SoftwareResource` |
| `kya:agentId`, `kya:agentVersion` | the `urn:agent:` identifier and version |
| `kya:builder`, `kya:operator` | the legal persons, as `gx:LegalPerson` nodes |
| `kya:jurisdiction` | the **full** KYA jurisdiction, e.g. `CA-NS` |
| `kya:accountablePerson` | role, contact, redress URI. Never optional |
| `kya:conduct` | `disclosesAi`, `actsWithoutApproval`, `retainsAfterRevocation` |
| `kya:model` | family, version, hosting country, residency basis |
| `kya:assurance`, `kya:status`, `kya:confirmationKey` | framework and level, status list pointer, holder key |
| `kya:unmapped` | anything the card carries that this profile version does not cover |
| `kya:closedVocabulary` | on a policy set: this list is exhaustive, not illustrative |

### Why `kya:jurisdiction` exists

Gaia-X addresses are country-level: `gx:countryCode` is ISO 3166-2 alpha2. A KYA jurisdiction is
subdivision-level — `CA-NS`, not `CA` — and the subdivision is load-bearing, because it is
which registry the builder is incorporated in. Mapping `CA-NS` to `CA` and back returns `CA`,
which is a silent downgrade of an identity claim.

**This was found by the round-trip test, not by review.** It is recorded here because it is the
clearest evidence available that the conformance test does real work.

## 4. What has no Gaia-X equivalent, and is not forced to have one

Gaia-X has **no concept of a natural person mandating a piece of software to act for them
against a third party**. That is the entire subject of the delegation credential.

`gx:consent` was available and would have been wrong. Consent to process data about me is not
authority to act as me. Bending one onto the other would have produced a profile that validated
and lied.

So the delegation is declared as extension class `kya:Delegation` and is **out of scope for
profile v0.1**. It is proposed as v0.2 work, jointly with Gaia-X Hub Canada, and it is the more
interesting of the two contributions because it is a gap in Gaia-X rather than a translation
into it.

## 5. Conformance

The claim this profile makes is: **a credential issued in one form verifies in the other.**
That claim is defined as four testable properties, in `test/gaiax.test.js`:

1. **Totality.** Every field the profile claims to cover appears in the self-description.
2. **Determinism.** The same card produces byte-identical output, and key insertion order in
   the source does not change the bytes.
3. **Round-trip fidelity.** A card survives Card → Gaia-X → Card with every always-disclosed
   field intact, and the result still passes `aic.validate()`. Unmapped claims are carried, not
   dropped.
4. **Refusal.** The mapping throws rather than inventing a licence or a copyright owner, and an
   absent registry identifier stays absent rather than becoming `null`.

Run it with `npm test`. Emit a sample self-description with `npm run gaiax`.

### Two limits, stated by us

- **This is semantic equivalence, not cryptographic equivalence.** The two ecosystems sign
  differently. Nothing in `src/gaiax.js` signs anything, and a re-signed credential is a new
  credential with a new issuer and a new revocation story. Any ecosystem accepting a bridged
  credential is making a trust decision about the bridging party, and should say so.
- **Only one direction round-trips.** Card → Gaia-X is a widening: it adds `gx:license` and
  `gx:copyrightOwnedBy`, which have nowhere to live in an Agent Identity Card. So the licence
  must be supplied on every crossing rather than carried, and Gaia-X → Card → Gaia-X is not
  claimed and is not tested.

## 6. Licence

This profile is CC BY 4.0. The implementation in `src/gaiax.js` and the conformance test are
Apache-2.0 with the patent non-assertion covenant in `PATENTS.md`, on the same terms as the rest
of this repository. Implement it, fork it, ship it. Nobody needs to ask us.

## 7. References

- Gaia-X Trust Framework, *Resource & Subclasses* and *Participant*, main version, read 20 August 2026.
- Gaia-X Trust Framework, *Technical Prelude*, read 20 August 2026, for the context URL status.
- W3C Verifiable Credentials Data Model.
- `spec/agent-identity-card-v0.2.md`, this repository.
- ODRL Information Model, for the policy serialisation.
