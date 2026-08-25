/**
 * The counter-claim. The person's half of an identity, which nothing else here
 * records.
 *
 * ── Where this came from ───────────────────────────────────────────────────
 *
 * Olivia, 23 August 2026: *"identity is about who claims you, and who you claim
 * back."* Everything else in this library records the first half. The Agent
 * Identity Card says who claims the agent — builder, operator, accountable
 * human. The Delegation Credential says what the person granted and until when.
 * Neither records that the person **made a claim**, which is the durable,
 * bilateral thing the other two are downstream of.
 *
 * The difference is not philosophical. A grant is a permission and it expires by
 * design — `adc.js` caps it at thirty days, present tense, letter of employment.
 * A claim is a relationship and it does not expire; it **lapses if it is not
 * renewed**, which is a different event with a different consequence. Conflating
 * them is why "your session has ended" and "you are no longer my agent" look the
 * same in every system built to date.
 *
 * ── Why this is not in the registrar, and must never be ────────────────────
 *
 * `events.js` states its own governing rule: no personal data, ever, because a
 * register that accumulated a list of the people relying on agents would be a
 * surveillance system with a civic name. A claim names a person's relationship
 * to an agent. It is therefore **wallet-side by construction**, and the registrar
 * records only the *obligation* a change of claiming party creates — see
 * `EVENT.TRANSFER`, `EVENT.GUARDIAN`, `EVENT.DEATH` and `EVENT.RECONSENT`, which
 * carry counts and deadlines and never identities.
 *
 * The first design of this file put CLAIM and UNCLAIM in the registrar. It would
 * have broken the register's one rule on the day it shipped. Recorded here
 * because the mistake is more instructive than the fix.
 *
 * ── The asymmetry this file inherits ───────────────────────────────────────
 *
 * `revocation.js`: every party may suspend, only the person may reinstate.
 * Everyone can stop the agent; only the person decides whether the person gets
 * help. The same asymmetry governs a claim. An operator, an issuer or an
 * ancestor can end the *agent*. Only the principal can end the *claim*, because
 * a claim somebody else can end on your behalf was never yours.
 *
 * ── Known hazard, stated rather than solved ────────────────────────────────
 *
 * A claim that lapses while an appeal clock is running is a real abandonment
 * risk. `narrow()` deliberately keeps `read` and `monitor` alive through a lapse
 * so the agent can still tell the person what is happening to their file, and
 * `state()` reports a warning window before the due date. That is mitigation,
 * not a solution: nothing in this file can stop a person losing a deadline they
 * were told about and did not act on. The product layer owes the harder answer.
 */

import { AUTHORITY } from './revocation.js';

/** Quarterly. The Keep in Touch default, and the reason it is the default. */
export const DEFAULT_RENEWAL_DAYS = 90;

/** How long before the renewal date a claim starts saying so. */
export const WARNING_DAYS = 14;

export const CLAIM_STATE = {
  LIVE: 'live',
  DUE: 'due',          // live, but inside the warning window
  LAPSED: 'lapsed',    // not renewed. Narrowed, not ended, and renewable
  ENDED: 'ended',      // the person unclaimed. Terminal
};

/**
 * Actions that survive a lapse.
 *
 * Failing Well rule 4 — degrade, don't collapse — applied to identity itself.
 * A lapsed claim must not strand somebody mid-file, so the agent keeps watching
 * and keeps reading. Everything that touches the outside world on the person's
 * behalf stops: drafting, submitting, appealing, corresponding. The test is
 * whether the office would experience the action as the person acting.
 */
export const SURVIVES_LAPSE = ['read', 'monitor'];

const DAY = 24 * 60 * 60 * 1000;
const dayOf = (t) => new Date(t).toISOString().slice(0, 10);

function problemsWith(claim) {
  const out = [];
  if (!claim.agent_id) out.push('agent_id is required: which agent is being claimed');
  if (!claim.aic_thumbprint) {
    out.push(
      'aic_thumbprint is required. A claim on "the agent" rather than on a specific card is a '
      + 'claim that survives the agent being replaced underneath it.',
    );
  }
  if (!claim.purpose) {
    out.push(
      'purpose is required, in the person\'s own words. A claim recorded as a capability list is '
      + 'the system\'s account of the relationship, not the person\'s.',
    );
  }
  if (!claim.made_at) out.push('made_at is required');
  if (!(claim.renews_every_days > 0)) out.push('renews_every_days must be a positive number of days');
  return out;
}

export function validate(claim) {
  const problems = problemsWith(claim);
  return { ok: problems.length === 0, problems };
}

/**
 * Make a claim.
 *
 * `purpose` is the person's own sentence and it is allowed to name what they are
 * going through — it lives in their wallet and never travels. `forVerifier()`
 * below is the only supported way to show a claim to anybody else, and it does
 * not carry the sentence.
 */
export function make({
  agent_id,
  aic_thumbprint,
  purpose,
  made_at = dayOf(Date.now()),
  renews_every_days = DEFAULT_RENEWAL_DAYS,
}) {
  const claim = {
    agent_id,
    aic_thumbprint,
    purpose,
    made_at,
    renews_every_days,
    renewals: [],
    ended_at: null,
    ended_by: null,
    ended_reason: null,
  };
  const { ok, problems } = validate(claim);
  if (!ok) throw new Error(`refusing to make a malformed claim:\n  - ${problems.join('\n  - ')}`);
  return claim;
}

/** When the claim was last affirmed by the person: the making, or the last renewal. */
export function lastAffirmed(claim) {
  return claim.renewals.length ? claim.renewals[claim.renewals.length - 1].at : claim.made_at;
}

/** The date by which the person has to say so again. */
export function renewBy(claim) {
  return dayOf(Date.parse(lastAffirmed(claim)) + claim.renews_every_days * DAY);
}

/**
 * Renew it. An explicit act, always.
 *
 * There is deliberately no function anywhere in this file that extends a claim
 * without recording that somebody said so. Silent extension is the whole failure
 * mode: it turns a relationship into a subscription that renews while nobody is
 * looking, which is the shape of the pattern this project exists to displace.
 * `test/claim.test.js` asserts the absence.
 */
export function renew(claim, { at = dayOf(Date.now()), purpose = null, note = null } = {}) {
  if (claim.ended_at) {
    throw new Error(
      'this claim was ended by the person. A new claim is a new claim; reviving an ended one '
      + 'would let a lapse be undone without the person making the decision again.',
    );
  }
  return {
    ...claim,
    // A renewal may restate the purpose. If it does, the person's current words win.
    purpose: purpose ?? claim.purpose,
    renewals: [...claim.renewals, { at, purpose, note }],
  };
}

/**
 * End it. Only the principal, for the reason in the header.
 *
 * This is the unclaim primitive. It is free — vital-events pricing doctrine: a
 * fee on switching something off prices the exit, and a register nobody closes
 * an entry in is a register of fiction. Nothing in this file may take a payment
 * argument, and nothing about the reason may be required.
 */
export function end(claim, { at = dayOf(Date.now()), by, reason = null } = {}) {
  if (by !== AUTHORITY.PRINCIPAL) {
    throw new Error(
      `only ${AUTHORITY.PRINCIPAL} may end a claim; "${by}" may stop the agent instead. `
      + 'Everyone can stop the agent. Only the person decides whether the person gets help.',
    );
  }
  return { ...claim, ended_at: at, ended_by: by, ended_reason: reason };
}

/** Where the claim stands, and what the person should be told. */
export function state(claim, { now = Date.now() } = {}) {
  if (claim.ended_at) {
    return { state: CLAIM_STATE.ENDED, renew_by: null, days_left: null, live: false };
  }
  const by = renewBy(claim);
  const daysLeft = Math.floor((Date.parse(by) - now) / DAY);
  const s = daysLeft < 0 ? CLAIM_STATE.LAPSED
    : daysLeft <= WARNING_DAYS ? CLAIM_STATE.DUE
      : CLAIM_STATE.LIVE;
  return { state: s, renew_by: by, days_left: daysLeft, live: s !== CLAIM_STATE.LAPSED };
}

/**
 * Narrow a set of actions to what the claim currently supports.
 *
 * A live or due claim changes nothing. A lapsed claim keeps `read` and `monitor`
 * and drops the rest. An ended claim keeps nothing — the person said stop.
 */
export function narrow(actions, claimState) {
  if (claimState === CLAIM_STATE.ENDED) return [];
  if (claimState === CLAIM_STATE.LAPSED) return actions.filter((a) => SURVIVES_LAPSE.includes(a));
  return [...actions];
}

/** Convenience: does this action need a live claim? */
export function needsLiveClaim(action) {
  return !SURVIVES_LAPSE.includes(action);
}

/**
 * What a verifier may be shown.
 *
 * Not the purpose sentence, ever. Same rule as `capability.js`: the person's own
 * words are theirs, and a verifier already knows which office it is.
 */
export function forVerifier(claim, { now = Date.now() } = {}) {
  const s = state(claim, { now });
  return {
    agent_id: claim.agent_id,
    aic_thumbprint: claim.aic_thumbprint,
    claim_state: s.state,
    claimed_since: claim.made_at,
    last_affirmed: lastAffirmed(claim),
    renew_by: s.renew_by,
  };
}

/**
 * The sentence a person should see, in the mirror screen that sits beside
 * "what this knows about me".
 */
export function explainToPerson(claim, { agentName = 'this agent', now = Date.now() } = {}) {
  const s = state(claim, { now });
  const since = `You claimed ${agentName} on ${claim.made_at}, for: "${claim.purpose}"`;
  switch (s.state) {
    case CLAIM_STATE.ENDED:
      return `${since}\nYou ended that on ${claim.ended_at}. It is not acting for you.`;
    case CLAIM_STATE.LAPSED:
      return `${since}\nYou last said so on ${lastAffirmed(claim)}, and that was due to be renewed by `
        + `${s.renew_by}. Until you do, it can keep watching your file and tell you what happens, and `
        + 'it cannot send anything on your behalf.';
    case CLAIM_STATE.DUE:
      return `${since}\nWorth saying again by ${s.renew_by} — ${s.days_left} days. Nothing changes if you do nothing today.`;
    default:
      return `${since}\nStill in force. Next check-in ${s.renew_by}.`;
  }
}
