/**
 * The revocation service. Section 7's obligations, as code.
 *
 * The specification says revocation is a service obligation and not a data
 * structure, and then lists five things a conforming deployment must provide.
 * `status.js` holds the data structure. This holds the obligations.
 *
 *   a citizen-facing endpoint reachable without signing in to any government
 *     system, requiring only proof of control of the delegating key
 *   immediate status-list update, propagated within a stated maximum
 *   notification to known verifiers, best effort, logged
 *   a receipt to the person
 *   fail closed on doubt
 *
 * ── A design decision that deserves to be argued with ──────────────────────
 *
 * The threat model ranks the person who shares the house as the most severe
 * adversary, and notes that an endpoint reachable without a government login is
 * reachable by whoever is holding the phone. That is true and it is not fixed
 * here.
 *
 * Revocation stays easy anyway, because the two failure modes are not
 * symmetrical. Someone revoking who should not have costs the person a
 * re-grant, which is a minute of annoyance. Someone unable to revoke costs them
 * an agent still acting in their name, which is the harm the whole
 * specification exists to prevent. So this fails toward stopping.
 *
 * What we do about the asymmetry: every revocation produces a receipt, the
 * receipt says which key authorised it, and re-granting is deliberately cheap.
 * The real answer is product design for shared devices and it is an open work
 * item, not something a library can close.
 */

import { compactVerify, importJWK } from 'jose';
import { STATUS, receipt as makeReceipt } from './status.js';

/** The stated maximum, published, so a verifier has something to fail closed against. */
export const DEFAULT_FRESHNESS_SECONDS = 300;

/** Never longer than this, whatever an operator would prefer. */
export const MAX_FRESHNESS_SECONDS = 24 * 60 * 60;

export const REASONS = {
  PERSON_REVOKED: 'the person withdrew it',
  EXPIRED: 'it reached its end date',
  SUPERSEDED: 'a newer delegation replaced it',
  OPERATOR_WITHDREW: 'the operator withdrew it',
};

/**
 * An in-memory register of live delegations and who has seen them.
 *
 * A real deployment puts this in a database. The interface is the part that
 * matters and it is deliberately small, because everything here has to survive
 * an operator implementing it differently.
 */
export class RevocationRegister {
  constructor({ list, listUri, freshnessSeconds = DEFAULT_FRESHNESS_SECONDS }) {
    if (freshnessSeconds > MAX_FRESHNESS_SECONDS) {
      throw new Error(
        `a freshness window of ${freshnessSeconds}s exceeds the 24 hour maximum. ` +
          'A window nobody can rely on is not a window.',
      );
    }
    this.list = list;
    this.listUri = listUri;
    this.freshnessSeconds = freshnessSeconds;
    this.records = new Map();   // credentialId -> record
  }

  /** Called when a delegation is issued. */
  register({ credentialId, idx, delegatorJwk, purposeCommitment, expiresAt }) {
    this.records.set(credentialId, {
      credentialId,
      idx,
      delegatorJwk,
      purposeCommitment,
      expiresAt,
      revoked: false,
      revokedAt: null,
      reason: null,
      presentedTo: new Map(),   // verifier -> last seen
    });
    return this.records.get(credentialId);
  }

  /** Called every time a verifier checks it. This is how we know who to tell. */
  notePresentation(credentialId, verifier, at) {
    const r = this.records.get(credentialId);
    if (!r) return;
    r.presentedTo.set(verifier, at);
  }

  get(credentialId) {
    return this.records.get(credentialId) ?? null;
  }
}

/**
 * Proof of control of the delegating key, and nothing else.
 *
 * No account, no government login, no email round trip. The person signs a
 * short statement with the same key their wallet used to issue the delegation.
 * That is the whole authentication story and it is deliberately the whole
 * story: anything more becomes a thing that can be unavailable at the moment
 * somebody most needs it.
 */
export async function verifyRevocationRequest(jws, { delegatorJwk, credentialId, now = Date.now() }) {
  let payload;
  try {
    const key = await importJWK(delegatorJwk, delegatorJwk.alg ?? 'ES256');
    const result = await compactVerify(jws, key);
    payload = JSON.parse(Buffer.from(result.payload).toString('utf8'));
  } catch (cause) {
    return { ok: false, reason: 'the request was not signed by the key that granted this delegation' };
  }

  if (payload.action !== 'revoke') return { ok: false, reason: 'not a revocation request' };
  if (payload.credential !== credentialId) return { ok: false, reason: 'this request is for a different delegation' };

  // A signed request that is replayable forever is a signed request somebody
  // else can use later. Five minutes is generous for a button press.
  const age = Math.floor(now / 1000) - (payload.iat ?? 0);
  if (!Number.isFinite(age) || age < -60) return { ok: false, reason: 'the request is dated in the future' };
  if (age > 300) return { ok: false, reason: 'the request is more than five minutes old' };

  return { ok: true, payload };
}

/**
 * Revoke, tell everyone who needs telling, and hand back a receipt.
 *
 * `notify` is injected so an operator can use whatever they use. It is called
 * once per verifier that has seen this credential, and a failure against one
 * verifier never stops the others: a best-effort obligation that gives up on
 * the first refusal is not best effort.
 */
export async function revoke(register, { credentialId, reason = REASONS.PERSON_REVOKED, notify, now = Date.now() }) {
  const record = register.get(credentialId);
  if (!record) {
    return { ok: false, reason: 'no such delegation' };
  }
  if (record.revoked) {
    // Idempotent on purpose. Someone pressing the button twice because they are
    // frightened should not see an error.
    return { ok: true, alreadyRevoked: true, receipt: record.receipt };
  }

  // Status list first. Everything else is notification, and notification that
  // races ahead of the authoritative answer is worse than no notification.
  register.list.set(record.idx, STATUS.INVALID);
  record.revoked = true;
  record.revokedAt = new Date(now).toISOString();
  record.reason = reason;

  const notified = [];
  const failed = [];
  for (const [verifier, lastSeen] of record.presentedTo) {
    if (typeof notify !== 'function') {
      failed.push({ verifier, error: 'no notifier configured' });
      continue;
    }
    try {
      await notify({ verifier, credentialId, revokedAt: record.revokedAt, lastSeen, reason });
      notified.push(verifier);
    } catch (err) {
      failed.push({ verifier, error: String(err?.message ?? err) });
    }
  }

  record.receipt = {
    ...makeReceipt({
      credentialId,
      purpose: null,   // the sentence is hers and is not ours to put in a receipt
      revokedAt: record.revokedAt,
      notified,
      listUri: register.listUri,
    }),
    reason,
    purpose_commitment: record.purposeCommitment,
    in_force_everywhere_within: `${register.freshnessSeconds} seconds`,
    could_not_reach: failed,
  };

  if (failed.length) {
    // Logged and surfaced rather than swallowed. A verifier we could not reach
    // still fails closed when its cached status goes stale, which is why this
    // is a note on the receipt and not an error.
    record.receipt.note +=
      ` ${failed.length} could not be reached and will find out when their copy of the status list goes stale,` +
      ` which is within ${register.freshnessSeconds} seconds.`;
  }

  return { ok: true, receipt: record.receipt, notified, failed };
}

/**
 * What the person is shown afterwards. Plain sentences, no identifiers, no
 * jargon, and it answers the question they actually have, which is "is it
 * stopped, and who knows."
 */
export function explainReceipt(r) {
  const lines = [
    'Done. That agent can no longer act for you.',
    `Withdrawn on ${new Date(r.revoked_at).toLocaleString('en-CA')}`,
  ];
  if (r.notified_count > 0) {
    lines.push(`We told ${r.notified_count} office${r.notified_count === 1 ? '' : 's'} that had used it.`);
  } else {
    lines.push('No office had used it yet, so there was nobody to tell.');
  }
  if (r.could_not_reach?.length) {
    lines.push(
      `We could not reach ${r.could_not_reach.length}. They will see it is withdrawn within ` +
        `${r.in_force_everywhere_within}, and until then they are required to treat it as not in force.`,
    );
  }
  lines.push('If you want that help again, you can grant it again at any time.');
  return lines.join('\n');
}
