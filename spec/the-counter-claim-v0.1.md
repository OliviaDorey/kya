# The Counter-Claim

**v0.1 — 26 August 2026. Implemented in `src/claim.js` and `src/events.js`.**
CC BY 4.0, with the rest of the specification.

> *"Identity is about who claims you, and who you claim back."*

## 1. The gap this closes

The Agent Identity Card records who claims an agent: builder, operator, accountable human.
The Delegation Credential records what a person granted and until when. **Neither records that
the person made a claim.**

That is not a bookkeeping omission. A grant is a permission, and it expires by design — thirty
days maximum, present tense, the letter of employment. A claim is a relationship, and it does
not expire; it **lapses if it is not renewed**, which is a different event with a different
consequence. Every system built to date conflates them, which is why "your session has ended"
and "you are no longer my agent" are indistinguishable to the person on the receiving end.

Identity here is bilateral. An agent that is claimed but claims nothing back is a token with
better paperwork.

## 2. Where each half lives, and why the line is not negotiable

| | Where | Contains |
|---|---|---|
| The claim | the person's wallet | the agent, the card, **the person's own sentence**, when it was made, when it was last affirmed |
| The obligation | the registrar | policy, deadline, and a **count** |

The registrar records **how many claims are outstanding and by when, never whose.** A count is
an obligation. A list is a surveillance system with a civic name. `counter_claim` therefore
carries a closed set of fields — `policy`, `window_days`, `outstanding` — and any other key is
refused at the door, including ones that look aggregate (`claimant_count_by_region`) and ones
that look administrative (`contact`).

An earlier draft of this specification put CLAIM and UNCLAIM in the registrar as event kinds.
It would have broken the register's one governing rule on the day it shipped. Recorded here
because the mistake is more instructive than the fix.

## 3. Lifecycle

```
made ──▶ live ──▶ due ──▶ lapsed ──▶ (renewed) ──▶ live
  └────────────────────────────────▶ ended  [terminal]
```

- **live** — in force.
- **due** — inside the warning window (14 days). Still live. The warning is not a penalty.
- **lapsed** — not renewed. **Narrowed, not ended, and renewable.**
- **ended** — the person unclaimed. Terminal. A new claim is a new claim.

**Renewal is always an explicit act.** There is no operation in the reference implementation
that moves the renewal date without recording that somebody said so, and a test asserts the
absence. Silent extension turns a relationship into a subscription that renews while nobody is
looking, which is the pattern this specification exists to displace.

Default renewal interval: **90 days**, matching the Keep in Touch cadence.

## 4. Lapse degrades, it does not collapse

On lapse, `read` and `monitor` survive. `draft`, `submit`, `draft-appeal`, `appeal` and
`correspond` do not. The test is whether the office would experience the action as the person
acting.

The agent therefore keeps watching the file and keeps being able to tell the person what is
happening to it, and can send nothing on their behalf. Failing an agent closed at the moment
its person stopped answering emails is abandonment implemented as a safety feature.

**Known hazard, stated rather than solved.** A claim that lapses while an appeal clock is
running is a real abandonment risk. Keeping `monitor` alive is mitigation, not a solution.
Nothing in this specification stops a person losing a deadline they were told about and did not
act on; the product layer owes the harder answer.

## 5. Only the person ends a claim

`revocation.js` already holds the asymmetry: every party may suspend, only the principal may
reinstate. Everyone can stop the agent; only the person decides whether the person gets help.

The same asymmetry governs a claim. An operator, an issuer or an ancestor may end the *agent*.
Only `AUTHORITY.PRINCIPAL` may end the *claim*, because a claim somebody else can end on your
behalf was never yours.

**Ending is free and needs no reason.** A fee on switching something off prices the exit, and a
register nobody closes an entry in is a register of fiction. No implementation of this section
may take a payment, and none may require a reason.

## 6. What a verifier sees

`forVerifier()` returns the agent, the card thumbprint, the claim state, when it was first made,
when it was last affirmed, and when it is due. **It never returns the purpose sentence.** Same
rule as capability scoping: the person's own words are theirs, they are allowed to name what the
person is going through, and a verifier already knows which office it is.

## 7. Registrar obligations

Three events change who claims an agent from the agent's side — `transfer`, `guardian`, `death`
— and each **must** carry a `counter_claim` stating what is asked of the people on the other
side of the relationship:

- `reconsent` — the claim must be made again, actively. Requires `window_days`; a re-consent with
  no deadline is a notification with a longer word.
- `notify` — the person must be told; silence stands as assent.

Kindred's position, generalised from transfer to all three: **re-consent for high assurance,
notify for the rest.**

Discharge is recorded as a `reconsent` event naming the `seq` it discharges, the method, and a
count still outstanding.

**An outstanding obligation does not change the agent's status.** This is deliberate.
`adc.transferOutcome()` already refuses an unrecorded transfer on the credential path, and a
registrar reaching the same verdict by a different route is how two verifiers drift apart while
both look correct. One rule, one place: the register surfaces the fact, the policy layer acts.

## 8. Conformance

Implemented and tested in `test/claim.test.js` (19 tests). Three sentences from this
specification are in the claims register with checks attached: the ending asymmetry, the lapse
narrowing, and the count-never-a-list rule.
