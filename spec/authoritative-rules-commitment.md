# The Authoritative Rules Commitment

**Version 1.0 — 10 August 2026**
Licensed CC BY 4.0. Copy it, adapt it, hold anyone to it.

---

## The commitment, in one paragraph

**Where an authoritative machine-readable rule exists, a Kindred agent calls it. Where one does not,
the agent says so out loud before it answers.** An agent never produces an inferred determination in
the presence of an authoritative rule that could have produced a correct one. Where no rule is
published, the agent's output is a navigation aid, is labelled as such to the person reading it, and
never presents itself as a decision.

That is the whole thing. Everything below is how we make it checkable rather than sincere.

---

## Why this commitment exists

The strongest objection to citizen-side AI agents comes from inside the digital government movement,
not outside it. Pia Andrews has made the argument for two decades: if the rule is in legislation, the
legislation can be encoded, and an encoded rule is testable, auditable, versioned, and correct. An
inferential model that guesses at the same rule is slower, more expensive, wrong some fraction of the
time, and — worst of it — **launders an unaccountable guess into something that looks like an
answer**.

The objection is right. The correct response is not to argue with it. It is to accept it as a
constraint on the product and then publish the constraint so that it binds us.

Zoë Rose put the positive case more sharply than we could: rules as code is not AI, and that is the
point of it.[^1]

There is a live, well-documented failure mode on the other side of this line. Alberta's Ombudsman
found in *Programs Adrift* that 7,394 assured-income files were closed by an automated process that
nobody had asked to make a decision.[^2] The system was not malicious and was not, in the ordinary
sense, wrong. It did a thing it was never authorised to decide. This commitment is written against
that.

---

## The three-tier rule

Every question a Kindred agent handles falls into one of three tiers. The tier determines what the
agent is permitted to emit.

### Tier 1 — An authoritative rule exists and is callable

The agent **must** call it. It may not answer from its own weights, from cached text, or from a
paraphrase of the legislation.

The answer is returned with the rule's identifier, its version, and the time of the call. If the
authoritative service is unreachable, the agent **fails to Tier 3** and says the service is down. It
does not fall back to inference and quietly keep the confident tone.

*Examples as of writing:* determinations exposed by a rules-as-code service; published eligibility
calculators with an API; an authoritative registry lookup.

### Tier 2 — An authoritative rule exists but is not callable

The rule is published as text — legislation, regulation, a policy manual, a gazetted schedule — but
there is no machine interface.

The agent may reason over it, and **must cite the specific provision** it reasoned from, at the
section level, with a link. The output is labelled an interpretation. The agent states the date of
the version it read.

This is the tier where most Canadian benefits work actually lives, and being honest that it is an
interpretation is the entire difference between a useful assistant and an accountability sink.

### Tier 3 — No authoritative rule is published

The agent produces **navigation only**: what to gather, who to contact, what order to do it in, what
the deadlines are, what happens next. It does not produce a determination, an eligibility statement,
or a probability of success.

It says, in plain words the person will actually read: *nobody publishes a rule for this, so I can
help you get to the right desk but I can't tell you the answer.*

---

## What we will not do

- **We will not build a shadow rulebook.** If we find ourselves encoding a government's rules to
  work around the absence of a service, that encoding is published openly under CC BY 4.0 and offered
  to the responsible department. It does not become an asset.
- **We will not present Tier 2 or Tier 3 output in the visual language of a decision.** No approval
  colours, no percentage-likely, no green checkmark, on anything that is not a Tier 1 call.
- **We will not degrade silently.** A Tier 1 service going dark changes what the person sees on the
  screen, every time, without exception.
- **We will not treat a rules-as-code service as competition.** Every tier a government moves from 3
  to 1 makes our product better and cheaper to run. We will say so publicly, including when it is a
  government that has not bought anything from us.

---

## How to check that we meant it

A commitment nobody can audit is a marketing line. Four mechanisms, all inspectable:

**1. The tier is in the credential.** The Agent Delegation Credential carries a `rule_basis` claim on
every determination the agent emits:

```json
"rule_basis": {
  "tier": 1,
  "authority": "https://rules.example.ca/aish/eligibility",
  "rule_id": "AISH-ELIG-2026.2",
  "version": "2026-04-01",
  "retrieved": "2026-08-10T14:22:03Z"
}
```

At Tier 2, `authority` is the citation URL and `rule_id` is the provision. At Tier 3, `tier` is `3`
and the other members are absent — **a determination claim with `tier: 3` is a malformed credential**
and a conforming verifier rejects it. The rule is enforced by the schema, not by our good intentions.

**2. The registry is public.** We publish, and keep current, the list of Tier 1 services our agents
call and the questions we currently answer at Tier 2 and Tier 3. Anyone can see what we are guessing
at.

**3. Downgrades are logged and surfaced.** Every fall from Tier 1 to Tier 3 is recorded with a
timestamp and the reason, and the count is published. If an authoritative service is unreliable, that
becomes a public number rather than our private problem.

**4. Sunset by design.** Where we operate a service that exists only because a government has not
published a rule, that service carries an expiry. The KYA services gifted to Alberta expire
31 December 2026 for exactly this reason.

---

## The claim this lets us make

Not *"our agent is accurate."* Every vendor says that and none of them can be held to it.

**"Our agent tells you where its answer came from, and it is structurally incapable of pretending an
inference was a rule."**

That one is falsifiable. Break it and you can show us the credential.

---

## Publishable short forms

**One line, for a slide:**
> Where the rule exists, we call it. Where it doesn't, we say so.

**Three lines, for a website:**
> Kindred agents call authoritative rules wherever governments publish them. Where the rule is
> written but not callable, we cite the provision and label the output an interpretation. Where no
> rule is published, we help you navigate and we tell you plainly that we cannot tell you the answer.

**A paragraph, for a submission or a standards contribution:**
> The Authoritative Rules Commitment binds an agent operator to a three-tier discipline: call the
> rule where a machine-readable authority exists, cite the provision and label the interpretation
> where the rule is published as text only, and emit navigation rather than determination where no
> rule is published at all. The tier is carried as a signed claim on every determination the agent
> emits, so conformance is verifiable by any relying party rather than asserted by the operator. The
> commitment's purpose is to make it structurally impossible for an inferential system to present an
> unaccountable guess in the visual and semantic language of an authoritative decision.

---

[^1]: Zoë Rose, "Rules as code is not AI. It's better than that," *The Mandarin*. The line is Rose's;
Pia Andrews shared it, and it is frequently misattributed to her.

[^2]: Alberta Ombudsman, *Programs Adrift*, systemic investigation into Assured Income for the
Severely Handicapped. 7,394 files were closed by automated process; approximately 101,000 recipients
were affected by the underlying administration.

---

*Part of the KYA specification set. Given away under CC BY 4.0 — see [PATENTS.md](../PATENTS.md).*
