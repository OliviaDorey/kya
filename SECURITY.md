# Reporting a security problem

**Email `trust@thekindredagency.com`.** Include what you found, how to reproduce
it, and how you would like to be credited. You will get a human reply within
five business days.

If you would rather not use email, the same address is on every Agent Identity
Card we issue, under `accountable.contact`, which is deliberate: an agent that
cannot tell you who to complain to is the thing this specification exists to
prevent.

## What we consider a vulnerability

Anything that lets one of these become false:

- a credential is accepted that the issuer did not sign
- an agent presents authority beyond what the person granted
- a person's `purpose` reaches a verifier without their decision to disclose it
- a revoked or suspended credential verifies as in force
- a status list that is unreachable or stale is treated as valid
- a determination is emitted with a `rule_basis` tier that does not permit it
- an Agent Identity Card issues or verifies with `conduct.discloses_ai` other
  than `always`
- anything publicly readable in a delegation discloses the subject of the matter

The last three are policy properties enforced in code rather than conventional
security boundaries. We treat a break in any of them as a vulnerability because
the whole point of writing them as refusals was that they hold.

## What we will do

Acknowledge within five business days. Agree a disclosure date with you, ninety
days by default and sooner if there is an active harm. Publish the fix and the
advisory together, and name you unless you ask us not to.

We will not ask you to sign anything, we will not threaten you, and we do not
require you to withhold publication indefinitely as a condition of us fixing it.

## Scope

In scope: everything in `src/`, the conformance behaviour described in
`spec/`, and `bin/`.

Out of scope: the `demo/` directory. It is a demonstration harness with
generated keys and no persistence, it is not intended for deployment, and it
says so in its own README. Findings there are welcome as bug reports rather than
as security reports.

## A standing invitation

If you operate a trust framework and something here would not survive contact
with it, that is worth more to us than a vulnerability report. Tell us and we
will fix the specification, not just the code.
