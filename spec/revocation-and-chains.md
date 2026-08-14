# Revocation and chained delegation

**Design note, 14 August 2026.** Editor: Olivia Dorey, The Kindred Agency.
Companion to `agent-identity-card-v0.2.md` (v0.3) §6 chaining and §7 revocation,
which specify both of these and implement neither.

Licensed CC BY 4.0 with the rest of the specification. The implementation it
describes is Apache-2.0 under the patent covenant in `PATENTS.md`.

---

## Why this exists

Two criticisms, and they are the same criticism seen from two ends.

**A credential proves authority, not conduct.** Anthropic's agentic-misalignment
work found models from several providers choosing blackmail, corporate espionage
and harmful strategic action when those became instrumentally useful, without
being instructed to. Nothing in a credential inspects reasoning. The properly
credentialed agent doing the wrong thing is not an edge case, it is the expected
case at volume, and until now this specification's only answer was to bound the
grant and hope.

**Nick Ris, at Identiverse:** the hardest problems are governing agents you do
not control and agents that cross organisational boundaries; the moment an agent
leaves your perimeter or enters it, many of today's assumptions break. Chained
delegation *is* the cross-boundary case, and §6 deferred it to a Google
individual draft that expires in October.

The connection: both are asking who can stop a thing they do not own. That is
one question, and it is answered by revocation that is not the principal's
private button.

---

## A. Threat model

Five failure cases. For each: who detects it, who can pull the switch, how fast
it propagates, and what a relying party that checked one second earlier is
entitled to.

The last column is the one that matters and it is the one usually left out.
"Revoked" is not a fact about the past. A relying party that checked at *t* and
acted at *t* acted correctly, and no revocation at *t+1* makes that action
wrongful. What revocation controls is what happens next. Conflating those two is
how you get systems that either strand people retroactively or fail to stop
anything at all.

### R1 — The principal revokes deliberately

| | |
|---|---|
| **Detects** | The person. This is the only case where detection is free. |
| **Pulls** | The person, proving control of the delegating key. No account, no government login. Already built. |
| **Propagation** | Status list written before any notification. Verifiers that have presented are told best-effort; everyone else finds out when their cached list goes stale, bounded by the published freshness window (default 300s, hard cap 24h). |
| **RP that checked one second earlier** | Entitled to keep the completed act. **Not** entitled to take a further act on the same authority. A submitted form stays submitted; a second submission is not authorised. |

Covered. `revoke()` in `revocation.js`.

### R2 — The agent is compromised

| | |
|---|---|
| **Detects** | The operator, from telemetry; a relying party, from anomaly; the person, from a receipt for something they did not ask for. Frequently nobody, for a while. |
| **Pulls** | The **accountable party** named in the Agent Identity Card — this is what `accountable.contact` is for and it had no mechanism until now — and independently the person, for their own delegation. |
| **Propagation** | Same window, but the unit is different. Compromise of the agent's holder key compromises **every delegation bound to that key**, not one. Revoking the card must therefore cascade to every delegation carrying its thumbprint. |
| **RP that checked one second earlier** | Entitled to the completed act. Should treat everything that agent did within the compromise window as suspect, and the receipt states the window so it can. |

Newly covered. `revokeCard()` cascades by `delegate.aic_thumbprint`. This is the
first thing in the system where revoking one credential invalidates others, and
it is why the register tracks bindings rather than just indices.

### R3 — The agent behaves within scope, against the principal's interest

The misalignment case. The credential verifies perfectly, because from the
verifier's position nothing is wrong: the right agent, holding the right key,
doing a thing the person authorised.

| | |
|---|---|
| **Detects** | The relying party, usually — it is the one watching the behaviour. Sometimes the person, late. **The credential detects nothing and never will.** |
| **Pulls** | This is the change. Previously only the principal could stop anything, which is useless precisely when the principal is absent or does not yet know. A relying party may now **suspend** — stop the agent acting *at that relying party* — without owning the grant. The accountable party and the issuer may suspend globally. |
| **Propagation** | Suspension writes status 2 and propagates on the same window as revocation. |
| **RP that checked one second earlier** | Nothing changes for it, and this is the honest part: the credential was valid the entire time. A verifier cannot have been warned, because there was nothing to warn it about. Revocation is a **stop**, not a **detect**. |

**Why suspension rather than revocation, and why a relying party cannot revoke.**
If a relying party could revoke, a caseworker who disliked an agent could
permanently destroy a person's authority to be helped, and the person's remedy
would be to notice and re-grant. That is an abandonment vector wearing a safety
mechanism's clothes. So the asymmetry is deliberate and it runs in the direction
of the person:

- a relying party may **stop** (scoped to itself), and may not **destroy**
- a suspension is reversible, and only the **principal** may reinstate
- every suspension names who imposed it and why, and reaches the person as a
  sentence, not a status code

This is the whole of the answer to criticism 1, and it is smaller than the
criticism. It does not make the agent behave. It makes stopping the agent
possible for the party who can actually see the misbehaviour, without making the
person a hostage to that party's judgement.

### R4 — The issuer itself is wrong or compromised

| | |
|---|---|
| **Detects** | The trust anchor, another participant, a researcher. Not the issuer. |
| **Pulls** | **Not the status list.** A status list is signed by the issuer, so a compromised issuer publishes a list saying everything is fine, and every conformant verifier believes it. Self-revocation is structurally impossible. The switch has to be held by somebody who is not the subject: a trust register, out of band. |
| **Propagation** | Human timescale. Hours to days. There is no honest way to claim otherwise — it requires a person to decide an issuer is untrustworthy. |
| **RP that checked one second earlier** | **Entitled to nothing.** It checked a lying oracle and got the answer the liar chose. This is the one case where prior verification bought no protection at all, and no amount of protocol fixes it. |

This is the case that decides section B, so it is written before section B rather
than after.

### R5 — An agent three hops down misbehaves

| | |
|---|---|
| **Detects** | Whoever is at that hop, or the relying party at the end of it. The principal is three parties away and generally has no visibility. |
| **Pulls** | Any **ancestor** in the chain, plus the principal at the root. Nobody below. Authority flows down, so the switch flows down. |
| **Propagation** | Same window per link, but a verifier must reach a status list **for every link**, so the availability cost compounds. See "what this still does not solve". |
| **RP that checked one second earlier** | Same as R1 for the completed act. New acts on any descendant of the revoked link are unauthorised. |

Newly covered. `revokeLink()` with descendant cascade.

### What no revocation mechanism covers, stated here rather than discovered later

- **Detection.** Every case above assumes somebody noticed. R3 and R4 are the
  cases where nobody reliably does, and they are the two most serious.
- **The window between act and stop.** Whatever the freshness window is, the
  agent had it. Short expiry does most of the work; the service exists for when
  short was not short enough.
- **Anything already done.** Revocation stops the next act. It does not unfile a
  filing or unsend a letter, and an appeal deadline forfeited by a hijacked agent
  stays forfeited. The remedy for that is `accountable.redress_uri` and a human,
  which is why that field can never be withheld.

---

## B. The gift boundary

The specification is given away. Trustmark v0 — conformance suite, public
register, revocation switch — is deliberately retained. Revocation straddles the
line, so the line has to be drawn explicitly rather than defaulted into.

### The line

> **Anything a participant can do for itself is protocol, and is given away.
> Anything that requires a party who is not the subject to say it is service,
> and is retained.**

That is not a commercial convenience. It is R4. An issuer cannot revoke itself,
because its own signature is the thing in doubt. The moment you need somebody who
is not the subject to make the assertion, you need an institution — a roster, a
governance process, a named human who decides and can be held to it. That is not
a protocol feature that could be specified and freely implemented; there is no
code that makes a stranger's assertion trustworthy. It is exactly and only a
service.

So the split falls out of the threat model rather than being imposed on it.

### Given away — protocol

Everything here is in this repository under CC BY 4.0 and Apache-2.0, and a third
party can stand up a complete, conformant revocation service against nothing but
this repository, with no Kindred involvement, no key from us, and no permission.
That is the test of whether it is a gift, and it is the acceptance criterion for
the implementation.

- the status list format, the fail-closed rule, and the freshness semantics
- the **revocation request format**: what a signed request contains, what proves
  authority to make it, the replay window
- the **authority model**: who may revoke, who may suspend, who may reinstate,
  and the asymmetry in R3 that keeps a relying party from destroying a grant
- the **receipt format**, and the obligation to produce one
- the **chain format** and every narrowing rule in section C
- the **cascade semantics**: what a revoked link does to its descendants and to
  its ancestors, and what a revoked card does to its delegations
- the **register interface** — `check()`, `attest()`, `withdraw()` — and a
  working reference implementation, so a jurisdiction can operate its own register
  rather than depending on anybody's
- the **conformance tests**, because closing them would be both futile and bad
  faith: DIF's KYA-OS already publishes its conformance levels and documentation
  openly, and a conformance suite nobody can read certifies nothing

### Retained — service

Not mechanism. Roster, attestation and standing.

- **The Kindred-operated register instance and who is on it.** The interface is
  open and anyone may run one. What is retained is the operated instance: which
  issuers and operators have been assessed, by whom, against what, and on what
  date — and the authority to withdraw an issuer from it. R4's switch.
- **Attested conformance runs.** The tests are open. The signed statement that a
  named deployment passed them on a named date, by an assessor who can be sued if
  it did not, is retained. The distinction is the same one that separates a
  scale you can buy from a weights-and-measures certificate.
- **Cross-issuer propagation.** The thing no single participant can do for
  itself, by definition.

### Why this is commercially coherent and not a hostage situation

A revocation protocol nobody can implement without Kindred is not a gift. A
revocation service with no retained value is not a business. The line above
gives away everything that makes the protocol work and retains only the thing
that cannot be given away without ceasing to exist — an institution's word.

The safety obligations in §9.2 apply in full and are not conditional on a
commercial relationship: the wind-down obligation, the ninety days' notice, the
automatic release on insolvency or acquisition, and the right to take any
operated service in-house at any time at no cost. A retained register that could
be switched off over a person's head would be worse than no register.

### Where this sits against KYA-OS

**Correcting a premise this note was written against.** KYA-OS v1.0.0 (29 July
2026) is not silent on revocation — it specifies StatusList2021 — and its
delegation model already has chains as DAGs, each hop narrowing its parent's
scopes, rooted at an accountable Responsible Party. That is the same shape as
section C below, arrived at independently, and the agreement is worth more than
the novelty would have been.

The genuine gap is the **trust register**, and it is the gap the retained asset
occupies. KYA-OS publishes conformance levels; it names no party who decides that
a given deployment meets them, and no mechanism for withdrawing an issuer whose
own signature is in doubt. That is R4, and it is unaddressed there.

The divergence remains format: W3C VC 1.1 and `Ed25519Signature2020` against
SD-JWT VC and Key Binding JWT; StatusList2021 against IETF Token Status List.
**Nothing in this note forecloses alignment.** The authority model, the cascade
semantics, the narrowing rules and the register interface are all format-neutral
and could be re-expressed over KYA-OS's credential format without change of
meaning. Two things would need work in an alignment, and are flagged now rather
than found later:

1. **StatusList2021 has no `ttl`.** The fail-closed rule in `status.js` depends on
   a published freshness window to fail closed *against*. Aligning means either
   carrying freshness out of band or accepting a weaker rule, and the second is
   not acceptable.
2. **The relying-party suspension in R3 has no counterpart** in a two-state
   revoked/not-revoked list. It needs a third state and an imposer field.

Both are additive. Neither is a fork.

---

## C. Chained delegation semantics

Principal → agent → sub-agent → third-party service.

### How scope narrows, and never widens

Each link is a delegation credential in its own right, and is checked against its
parent, not merely against the Agent Identity Card. A link that widens anything
is **rejected, not clamped** — silently trimming hides a bug in whoever built the
chain, and the party who built it is the one who needs to know.

Narrowing is checked on six axes:

| Axis | Rule |
|---|---|
| Capabilities | child ⊆ parent |
| Actions | child ⊆ parent, per capability |
| Expiry | child `exp` ≤ parent `exp` |
| Numeric constraints | `max_submissions` and friends: child ≤ parent |
| Date constraints | `valid_until`: child ≤ parent |
| Human approval | `requires_human_approval` may only be **added**. A child may not drop an approval requirement its parent carried. |

The last one runs opposite to the others and it is the one an implementer gets
wrong. Every other axis narrows by shrinking. This one narrows by growing: more
actions requiring approval is a *tighter* grant, and a sub-agent that quietly
drops its parent's approval requirement has widened authority while every set it
carries got smaller.

### Crossing an organisational boundary

**Yes, and this is the useful property.** A chain is verifiable by a party with
no prior relationship to the original principal, because a chain carries its own
key path:

> **link *n+1* must be signed by the key committed to in link *n*'s
> `delegate.cnf_thumbprint`.**

The verifier trusts exactly one thing from outside: the issuer of link 0, the
person's wallet, whose standing comes from the federation trust anchor. Every
subsequent signing key is named in advance by its parent, so the verifier
authenticates hop *n+1* using only material it has already verified. It never
needs a relationship with the principal, with the intermediary, or with anyone in
between. It needs a path to an anchor and the chain itself.

This is what makes a navigator at a settlement agency able to act for a client at
a provincial office that has never heard of either the navigator or the client,
without either of them holding an account there.

The cost is stated plainly in the last section: it multiplies the fail-closed
surface.

### What a revoked link does to the chain

- **Everything below it stops.** Every descendant is revoked with the reason
  `ancestor revoked`, immediately and in the same operation, because a
  sub-delegation of an authority that no longer exists is not a smaller authority,
  it is no authority.
- **Everything above it survives.** Revoking a sub-agent does not touch the agent
  that delegated to it, and certainly does not touch the person's own grant.
- **Revoking the root revokes everything.** That is the person's stop button and
  it reaches the whole tree, however far it has travelled.
- **Suspension cascades and uncascades the same way**, and reinstating an
  ancestor reinstates descendants that were suspended *only* by that cascade —
  never one suspended on its own account, which stays suspended until whoever
  suspended it deals with it.

### Depth limit: three hops, and why

`MAX_HOPS = 3`. Principal → agent → sub-agent → service. Four reasons, in the
order they should be weighed:

1. **Availability compounds.** Verification fails closed on any unreachable link.
   At a generous 99.9% per status list, three hops is 99.7% and the failure is
   denial of service to a person mid-application. Depth is paid for in outages
   and the person pays.
2. **Each hop is another party who can misbehave inside scope.** R3 does not get
   easier with distance; it gets harder to detect, and the person is further from
   the thing acting in their name.
3. **Comprehensibility is a consent property.** A person consenting to a
   four-party chain is consenting to something they cannot hold in their head.
   Plain language is normative in this specification and it has to survive
   contact with chaining.
4. **Verification cost is linear in depth and the verifier pays it.** Unbounded
   depth is a denial-of-service surface pointed at relying parties.

Three is not derived from anything; it is the smallest number that covers the
real case — a person, their agent, a navigator's agent, and the office — and
every additional hop after that has been someone's convenience rather than
someone's need. It is a constant in one place and a deployment that needs four
should have to change it deliberately and say why.

### Non-abandonment, which is the part that is not a data structure

A broken chain must never leave a person at a dead end. Revocation that strands
somebody mid-application is a failure of this design, not a success of it.

So every stop in this implementation returns a **continuation** alongside the
receipt: what stopped, what is unaffected, what is still in flight, who to
contact, and what the person can do next. Verification failure returns the same
shape rather than a boolean, because `false` tells a person nothing and tells the
service building the interface nothing either.

The rule that follows from it, and that shaped the authority model above: **the
party who stops something is never the party who decides whether the person gets
help.** A relying party may suspend and may not revoke. Only the principal
reinstates. Re-granting is deliberately cheap. Failing Well applies throughout:
where the system cannot do something, it says so in a sentence, and there is no
silent degradation anywhere in this path.

---

## What this still does not solve

Written for a hostile reviewer.

1. **Detection, which is the actual problem in R3.** Everything here is a
   mechanism for stopping an agent once somebody has decided it should be
   stopped. Nothing here decides that. The misalignment criticism is answered
   only in the narrow sense that the party who can see the misbehaviour can now
   act on it without the principal present. If nobody is watching, nothing in
   this repository notices, and at production volume nobody is watching most of
   the time.

2. **The window is still the window.** Default 300 seconds. An agent that decides
   to do something harmful has those seconds, and the freshness window is a floor
   on the harm, not a ceiling. Shortening it trades directly against availability
   and against every relying party's ability to operate offline.

3. **Chained verification multiplies the fail-closed surface.** A three-hop chain
   requires three reachable status lists and three verified issuer keys. Every one
   is a single point of denial of service for a person mid-application, and the
   correct behaviour on each is to refuse. There is no availability target, no
   mirroring requirement and no specified degraded mode anywhere in this
   repository, and this note makes that worse rather than better by adding links.

4. **The register is an institution, and institutions can be wrong or captured.**
   R4's switch is held by a party who decides which issuers are trustworthy. That
   party can be mistaken, coerced, acquired, or simply slow. Moving the trust
   from a signature to a roster does not remove it, it relocates it somewhere a
   protocol cannot check. The mitigations are governance — published criteria, a
   named accountable human, an appeal path, automatic release on acquisition —
   and governance is not cryptography.

5. **Relying-party suspension is a new denial vector.** A relying party can now
   stop an agent acting at it. A hostile or malfunctioning one can stop every
   agent acting at it, and the person's remedy is to notice and complain. Scoping
   the suspension to the imposing party and forbidding revocation bounds the
   damage; it does not prevent it. This is a deliberate trade against R3 and a
   reviewer is entitled to think it is the wrong one.

6. **Nothing here verifies that a relying party honours any of it.**
   `requires_human_approval`, scoped suspension, the obligation to stop acting on
   a revoked credential — all of them are claims a conformant party reads and
   acts on. A relying party that ignores them is not detected by anything in this
   repository. The conformance suite is a test of software, not of an operator.

7. **Cascade is only as good as the register's knowledge of the chain.** A
   descendant the register never saw does not get cascaded. A chain built
   entirely off-register still verifies correctly by signature and narrowing —
   which is the correct behaviour, since the whole point is that it works without
   Kindred — but revoking its root will not proactively stop it. It will fail on
   its next verification when the root's status is checked, which is the
   protocol's answer and is slower than a cascade.

8. **`delegator.pairwise` is still self-asserted**, the stable `agent.id` is
   still a lifetime correlator, and a chain makes the correlation worse: every
   link carries thumbprints that are stable per party, so a three-hop chain hands
   a relying party a small social graph. `PRIVACY-GAP.md` covers the first two.
   The third is new here and unmitigated.

9. **Guardianship and capacity are still out of scope,** and chaining makes the
   omission louder, because a navigator acting for a client is exactly the
   population where capacity questions arise most often.

10. **None of this is deployed.** It is a library with tests. A running register,
    an availability target, a real notification transport, and an operator who
    answers `trust@thekindredagency.com` at three in the morning are all
    prerequisites to any of it mattering, and none of them exist yet.

---

*Findings against this note to `trust@thekindredagency.com`. Findings against the
specification are more useful than findings against the code.*
