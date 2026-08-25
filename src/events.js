/**
 * The registrar: an append-only, signed record of what happened to an agent.
 *
 * ── What this is, and why it is not the trust anchor ───────────────────────
 *
 * A trust anchor answers one question: may this agent act, right now. A
 * registrar answers three: did it exist, what changed about it, and when did it
 * end. The second contains the first, because "may it act" is the current state
 * of a series of recorded events, which is what `state()` below computes.
 *
 * Everything else in this library describes an agent at a moment. This file is
 * the only part that describes an agent over time, and it is the part that lets
 * somebody ask a question afterwards — an auditor, an ombudsman, a court, or
 * the person themselves. Alberta's own Ombudsman found 7,394 files closed by an
 * automated process nobody had asked to make a decision. The question that
 * matters afterwards is not whether the process was permitted at the time; it
 * is what the process was, who ran it, who answered for it, and what changed
 * about it during the period in question. No credential can answer that. This
 * can.
 *
 * ── The two rules that make it a record rather than a log ──────────────────
 *
 * Append only. Nothing here mutates or deletes. A correction is a new event
 * that refers to the one it corrects, exactly as a civil registry amends rather
 * than overwrites, and the amendment is itself part of the record.
 *
 * Chained. Every entry names the hash of the entry before it, so removing or
 * altering one breaks every entry after it. The chain is per-registrar rather
 * than per-agent, so an agent's history cannot be quietly rewritten in
 * isolation.
 *
 * **The limit of that, stated plainly:** a chain detects an entry that was
 * altered or removed from the *middle*, because the entry after it no longer
 * follows. It cannot detect entries removed from the *end*, because a shorter
 * chain is still a valid chain. Closing that needs the head published somewhere
 * the registrar does not control — a transparency log, a witness, or simply
 * publishing the current hash and count on a schedule. Until one of those
 * exists, a registrar can drop its most recent entries and pass every check in
 * this file. That is recorded here rather than left for somebody to discover.
 *
 * ── What is deliberately not here ──────────────────────────────────────────
 *
 * No personal data of any kind. The registrar records facts about agents and
 * the organisations that run them. Who delegated to an agent, and what they
 * delegated, is the person's business and stays in their wallet. A register of
 * agents that accumulated a list of the people relying on them would be a
 * surveillance system with a civic name.
 */

import { SignJWT, compactVerify } from 'jose';
import { STATUS, inForce } from './status.js';

/**
 * The registrable life of an agent.
 *
 * Seven events. Two of them, SUSPENSION and REVOCATION, are the only two built
 * anywhere in this field today, and they are the two an operator needs in order
 * to switch something off. The other five are the ones a person needs in order
 * to know who they are now dealing with.
 */
export const EVENT = {
  BIRTH: 'birth',
  VERSION: 'version',
  TRANSFER: 'transfer',
  GUARDIAN: 'guardian',
  RECONSENT: 'reconsent',
  SUSPENSION: 'suspension',
  REINSTATEMENT: 'reinstatement',
  REVOCATION: 'revocation',
  DEATH: 'death',
  CORRECTION: 'correction',
};

/** Events after which an agent may not act, whatever else the record says. */
const TERMINAL = new Set([EVENT.REVOCATION, EVENT.DEATH]);

/**
 * What is being asked of the people who claimed this agent.
 *
 * Identity is bilateral: an agent is claimed by its operator and claimed back by
 * the person relying on it. Three events change who is doing the claiming from
 * the agent's side — transfer, guardian, death — and each therefore creates an
 * obligation on the other side of the relationship. Today that obligation is
 * discharged in silence or not at all: on an acquisition every agent changes
 * accountable party, the delegation stays in force, and nobody is told.
 *
 * `TRANSFER_POLICY` in `aic.js` already states Kindred's position — re-consent
 * for high assurance, notify for the rest. This generalises it from one event to
 * all three, so it is a rule rather than a special case.
 *
 * **The counter-claim itself is not here and must never be.** This register
 * records how many claims are outstanding and by when, never whose. A count is
 * an obligation; a list is a surveillance system with a civic name. The claim
 * lives in the person's wallet — see `claim.js`.
 */
export const COUNTER_CLAIM = {
  RECONSENT: 'reconsent',   // the claim must be made again, actively
  NOTIFY: 'notify',         // the person must be told; silence stands as assent
};

/**
 * The only fields a counter-claim obligation may carry.
 *
 * A closed list, enforced, because the pressure on this object will always be to
 * add one more helpful field — a claimant reference, a contact, a segment — and
 * any of them turns a count into a list. If a field is needed that is not here,
 * that is a conversation and not a commit.
 */
const COUNTER_CLAIM_FIELDS = new Set(['policy', 'window_days', 'outstanding']);

/** What each event must carry beyond the common fields. */
const REQUIRED = {
  [EVENT.BIRTH]: ['builder', 'operator', 'accountable', 'capabilities'],
  [EVENT.VERSION]: ['version'],
  [EVENT.TRANSFER]: ['from', 'to', 'notice', 'counter_claim'],
  [EVENT.GUARDIAN]: ['from', 'to', 'counter_claim'],
  [EVENT.RECONSENT]: ['discharges', 'method', 'outstanding'],
  [EVENT.SUSPENSION]: ['by', 'reason'],
  [EVENT.REINSTATEMENT]: ['by'],
  [EVENT.REVOCATION]: ['by', 'reason'],
  // successor may be null, but it must be stated. Same discipline as the card.
  [EVENT.DEATH]: ['effective', 'notice', 'counter_claim'],
  [EVENT.CORRECTION]: ['corrects', 'reason'],
};

function problemsWith(event) {
  const out = [];
  if (!event.agent_id) out.push('agent_id is required');
  if (!Object.values(EVENT).includes(event.kind)) {
    out.push(`kind must be one of: ${Object.values(EVENT).join(', ')}`);
  }
  if (!event.at) out.push('at is required: when this happened, not when it was recorded');

  for (const field of REQUIRED[event.kind] ?? []) {
    if (event[field] === undefined) out.push(`${event.kind} requires "${field}"`);
  }

  // The two events that carry an obligation to somebody outside the operator.
  if (event.kind === EVENT.TRANSFER && event.notice !== undefined && !event.notice?.given_at) {
    out.push(
      'transfer.notice.given_at is required. A transfer nobody was told about is not a lighter '
      + 'kind of transfer, it is an unrecorded one.',
    );
  }
  // The counter-claim, on the three events that change who claims the agent.
  if (REQUIRED[event.kind]?.includes('counter_claim') && event.counter_claim !== undefined) {
    const cc = event.counter_claim;
    if (cc === null || typeof cc !== 'object') {
      out.push('counter_claim must be an object stating what is asked of the people who claimed this agent');
    } else {
      if (!Object.values(COUNTER_CLAIM).includes(cc.policy)) {
        out.push(`counter_claim.policy must be one of: ${Object.values(COUNTER_CLAIM).join(', ')}`);
      }
      if (cc.policy === COUNTER_CLAIM.RECONSENT && !(cc.window_days > 0)) {
        out.push(
          'counter_claim.window_days is required for reconsent: a re-consent with no deadline is a '
          + 'notification with a longer word.',
        );
      }
      if (cc.outstanding !== undefined && typeof cc.outstanding !== 'number') {
        out.push('counter_claim.outstanding must be a count. This register records how many, never whose.');
      }
      for (const key of Object.keys(cc)) {
        if (!COUNTER_CLAIM_FIELDS.has(key)) {
          out.push(
            `counter_claim."${key}" is not a permitted field. Permitted: ${[...COUNTER_CLAIM_FIELDS].join(', ')}. `
            + 'Anything identifying a person turns this register into a list of who relies on which agent.',
          );
        }
      }
    }
  }

  if (event.kind === EVENT.RECONSENT) {
    if (typeof event.discharges !== 'number') {
      out.push('reconsent.discharges must be the seq of the event whose obligation this discharges');
    }
    if (typeof event.outstanding !== 'number') {
      out.push('reconsent.outstanding must be a count of claims still outstanding, never a list of them');
    }
  }

  if (event.kind === EVENT.DEATH) {
    if (!('successor' in event)) {
      out.push(
        'death requires "successor". Name the agent taking this on, or state null to say plainly '
        + 'that there is none. A record that an agent ended, with nothing said about the people '
        + 'relying on it, is an accountability sink with a certificate attached.',
      );
    }
    if (event.notice !== undefined && !event.notice?.given_at) {
      out.push('death.notice.given_at is required: when the people relying on this agent were told');
    }
  }
  return out;
}

export function validate(event) {
  const problems = problemsWith(event);
  return { ok: problems.length === 0, problems };
}

/** SHA-256 over a string, base64url. Matches the shape used elsewhere here. */
async function digest(text) {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(text, 'utf8').digest('base64url');
}

/** Stable serialisation, so a chain computed twice is the same chain. */
function stable(v) {
  if (Array.isArray(v)) return v.map(stable);
  if (v && typeof v === 'object') {
    return Object.keys(v).sort().reduce((a, k) => {
      if (v[k] !== undefined) a[k] = stable(v[k]);
      return a;
    }, {});
  }
  return v;
}

export const GENESIS = 'genesis';

/** One counter-claim obligation, as read back out of the record. */
function obligation(e) {
  const cc = e.counter_claim ?? {};
  return {
    seq: e.seq,
    kind: e.kind,
    at: e.at,
    policy: cc.policy ?? null,
    window_days: cc.window_days ?? null,
    outstanding: cc.outstanding ?? null,
    discharged: false,
    discharged_at: null,
  };
}

/**
 * A registrar's record.
 *
 * Deliberately a plain in-memory structure with an explicit `entries` array.
 * Whoever operates a registrar will put this behind a database, and the point
 * of keeping the reference implementation this small is that the rules live in
 * the code above rather than in somebody's schema.
 */
export class Registry {
  constructor({ id }) {
    if (!id) throw new Error('a registrar needs an id: who is keeping this record');
    this.id = id;
    this.entries = [];
  }

  /** Append one event, signed. Throws rather than recording something malformed. */
  async append(event, { privateKey, kid }) {
    const { ok, problems } = validate(event);
    if (!ok) {
      throw new Error(`refusing to record a malformed event:\n  - ${problems.join('\n  - ')}`);
    }

    const seq = this.entries.length + 1;
    const prev = seq === 1 ? GENESIS : this.entries[seq - 2].hash;
    // stable() is applied to the WHOLE payload, not just the event, because
    // verify() recomputes over the whole payload. Hashing two different key
    // orders on the write and the read path made every chain fail to verify,
    // which is the sort of thing that looks like tamper-evidence working.
    const payload = stable({ ...event, seq, prev, registrar: this.id });
    const hash = await digest(JSON.stringify(payload));

    const jwt = await new SignJWT({ ...payload, hash })
      .setProtectedHeader({ alg: 'ES256', kid: kid ?? `${this.id}#1` })
      .sign(privateKey);

    const entry = { ...payload, hash, jwt };
    this.entries.push(entry);
    return entry;
  }

  /** Every entry for one agent, oldest first. */
  history(agentId) {
    return this.entries.filter((e) => e.agent_id === agentId);
  }

  /**
   * The registrar lookup: what is true about this agent now, and how we know.
   *
   * ── The property this is written to have ───────────────────────────────
   *
   * A verifier holding only this lookup must reach the same decision as one
   * holding the credentials. The way to make that true rather than to assert it
   * is to derive a status value from the events and then hand it to the same
   * `inForce()` every other verifier uses, so the two cannot drift apart
   * without the shared function changing underneath both.
   *
   * Corrections are applied as they are encountered, in order, because a
   * correction is a later statement about an earlier event rather than a
   * deletion of it. The corrected event stays in `history`.
   */
  lookup(agentId) {
    const history = this.history(agentId);
    if (!history.length) {
      return {
        exists: false,
        state: 'unknown',
        history: [],
        // An agent nobody registered is not an agent in good standing that
        // happens to be missing. Fail closed and say which it is.
        inForce: { ok: false, state: 'unregistered', reason: 'no agent by that identifier is on this register' },
      };
    }

    const corrected = new Set(
      history.filter((e) => e.kind === EVENT.CORRECTION).map((e) => e.corrects),
    );
    const live = history.filter((e) => !corrected.has(e.seq));

    const current = {
      exists: true,
      agent_id: agentId,
      born: null,
      operator: null,
      accountable: null,
      version: null,
      successor: undefined,
      transfers: 0,
      counter_claims: [],
      suspended: false,
      revoked: false,
      retired: false,
      corrections: history.length - live.length,
      history,
    };

    for (const e of live) {
      switch (e.kind) {
        case EVENT.BIRTH:
          current.born = e.at;
          current.operator = e.operator;
          current.accountable = e.accountable;
          current.version = e.version ?? null;
          break;
        case EVENT.VERSION: current.version = e.version; break;
        case EVENT.TRANSFER:
          current.operator = e.to; current.transfers += 1;
          current.counter_claims.push(obligation(e));
          break;
        case EVENT.GUARDIAN:
          current.accountable = e.to;
          current.counter_claims.push(obligation(e));
          break;
        case EVENT.RECONSENT: {
          const o = current.counter_claims.find((c) => c.seq === e.discharges);
          if (o) { o.discharged = true; o.outstanding = e.outstanding; o.discharged_at = e.at; }
          break;
        }
        case EVENT.SUSPENSION: current.suspended = true; break;
        case EVENT.REINSTATEMENT: current.suspended = false; break;
        case EVENT.REVOCATION: current.revoked = true; break;
        case EVENT.DEATH:
          current.retired = true;
          current.successor = e.successor;
          current.counter_claims.push(obligation(e));
          break;
        default: break;
      }
    }

    // Obligations to the other side of the relationship. Reported, and
    // deliberately NOT folded into the status.
    //
    // The temptation is to make an overdue re-consent invalidate the agent here.
    // It is refused for one reason: `adc.transferOutcome()` already refuses an
    // unrecorded transfer on the credential path, and a registrar that reached
    // the same verdict by a different route is exactly how two verifiers drift
    // apart while both look correct. One rule, one place. This surfaces the fact;
    // the policy layer acts on it.
    current.counter_claim_outstanding = current.counter_claims.some((c) => !c.discharged);

    // Terminal states first, and revocation before retirement: an agent revoked
    // for cause and then decommissioned was still revoked, and a person asking
    // why is owed the first answer rather than the tidier second one.
    const derived = current.revoked ? STATUS.INVALID
      : current.retired ? STATUS.RETIRED
        : current.suspended ? STATUS.SUSPENDED
          : STATUS.VALID;

    current.status = derived;
    current.state = current.revoked ? 'revoked'
      : current.retired ? 'retired'
        : current.suspended ? 'suspended' : 'valid';
    current.inForce = inForce({ status: derived });
    return current;
  }

  /** Whether anything terminal has been recorded for this agent. */
  ended(agentId) {
    return this.history(agentId).some((e) => TERMINAL.has(e.kind));
  }

  /**
   * Verify the chain, and every signature in it.
   *
   * Returns per-entry results rather than a single boolean, because "the record
   * is broken" is not an answer anybody can act on. Which entry, and how.
   */
  async verify({ publicKey }) {
    const results = [];
    let expectedPrev = GENESIS;
    for (const e of this.entries) {
      let sigOk = false;
      try {
        await compactVerify(e.jwt, publicKey);
        sigOk = true;
      } catch { sigOk = false; }

      const { jwt, hash, ...payload } = e;
      const recomputed = await digest(JSON.stringify(stable(payload)));
      results.push({
        seq: e.seq,
        agent_id: e.agent_id,
        kind: e.kind,
        sigOk,
        hashOk: recomputed === hash,
        chainOk: e.prev === expectedPrev,
      });
      expectedPrev = e.hash;
    }
    return { ok: results.every((r) => r.sigOk && r.hashOk && r.chainOk), results };
  }
}
