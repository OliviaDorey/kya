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

  // Added with chaining and the conduct cases. See spec/revocation-and-chains.md.
  ANCESTOR_REVOKED: 'the delegation it came from was withdrawn',
  CARD_REVOKED: 'the agent it was granted to was withdrawn',
  AGENT_COMPROMISED: 'the agent is believed compromised',
  CONDUCT: 'the agent did something it should not have',
  ISSUER_WITHDRAWN: 'the organisation that issued it is no longer trusted',
};

/**
 * Who is pulling the switch. R1 to R5 in spec/revocation-and-chains.md.
 *
 * This exists because "only the principal can stop it" is useless in exactly the
 * case that matters most: the agent behaving within scope against the person's
 * interest, seen by a relying party while the person is asleep and knows
 * nothing about it.
 */
export const AUTHORITY = {
  PRINCIPAL: 'principal',           // the person, proving control of the delegating key
  ACCOUNTABLE: 'accountable',       // the human named in the card's accountable.contact
  ISSUER: 'issuer',                 // whoever signed the card
  ANCESTOR: 'ancestor',             // a party further up a delegation chain
  RELYING_PARTY: 'relying-party',   // the office the agent is acting at
};

/**
 * The asymmetry, and it is the whole design.
 *
 * A relying party may **stop** and may not **destroy**. If a caseworker could
 * revoke, a caseworker who disliked an agent could permanently end a person's
 * authority to be helped, and the person's remedy would be to notice and
 * re-grant. That is an abandonment vector wearing a safety mechanism's clothes,
 * and non-abandonment is the spine of this product.
 *
 * So: everyone above can stop the agent. Only the person can decide whether the
 * person gets help.
 */
export function mayRevoke(authority) {
  return [AUTHORITY.PRINCIPAL, AUTHORITY.ACCOUNTABLE, AUTHORITY.ISSUER, AUTHORITY.ANCESTOR].includes(authority);
}

export function maySuspend(authority) {
  return Object.values(AUTHORITY).includes(authority);
}

/** Reinstatement is the person's alone, for the reason above. */
export function mayReinstate(authority) {
  return authority === AUTHORITY.PRINCIPAL;
}

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

  /**
   * Called when a delegation is issued.
   *
   * `chain` and `aicThumbprint` are optional and are what make cascade possible.
   * A delegation registered without them still revokes correctly on its own;
   * what it does not do is stop its descendants, because the register cannot
   * cascade down a tree it was never told about. That limitation is real, it is
   * in the design note, and it has a test.
   */
  register({ credentialId, idx, delegatorJwk, purposeCommitment, expiresAt, chain = null, aicThumbprint = null }) {
    this.records.set(credentialId, {
      credentialId,
      idx,
      delegatorJwk,
      purposeCommitment,
      expiresAt,
      chain,                    // { depth, parentId, rootId }
      aicThumbprint,            // which Agent Identity Card this was granted to
      revoked: false,
      revokedAt: null,
      reason: null,
      suspensions: [],          // { by, authority, scope, reason, at, cascadedFrom }
      presentedTo: new Map(),   // verifier -> last seen
    });
    return this.records.get(credentialId);
  }

  /**
   * Every delegation below this one in its chain.
   *
   * Walks parent links rather than trusting `rootId`, because a spliced or
   * mis-stated root should not be able to widen or narrow a cascade.
   */
  descendantsOf(credentialId) {
    const out = [];
    const frontier = [credentialId];
    while (frontier.length) {
      const parent = frontier.pop();
      for (const r of this.records.values()) {
        if (r.chain?.parentId === parent && !out.includes(r.credentialId)) {
          out.push(r.credentialId);
          frontier.push(r.credentialId);
        }
      }
    }
    return out;
  }

  /** Every delegation granted to a given Agent Identity Card. R2's unit of harm. */
  boundTo(aicThumbprint) {
    return [...this.records.values()].filter((r) => r.aicThumbprint === aicThumbprint).map((r) => r.credentialId);
  }

  /**
   * Is this delegation stopped, from the position of a given relying party.
   *
   * Scope matters: a suspension imposed by one office stops the agent at that
   * office and nowhere else. A verifier asking without naming itself is asking
   * the global question and gets the global answer.
   */
  stopped(credentialId, { atVerifier = null } = {}) {
    const r = this.records.get(credentialId);
    if (!r) return { stopped: true, why: 'no such delegation' };
    if (r.revoked) return { stopped: true, why: r.reason ?? REASONS.PERSON_REVOKED, permanent: true };

    const live = r.suspensions.filter((s) => !s.scope || s.scope === atVerifier);
    if (live.length) {
      return { stopped: true, why: live[0].reason, permanent: false, suspendedBy: live.map((s) => s.by) };
    }
    return { stopped: false };
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
export async function revoke(register, {
  credentialId,
  reason = REASONS.PERSON_REVOKED,
  notify,
  authority = AUTHORITY.PRINCIPAL,
  now = Date.now(),
}) {
  if (!mayRevoke(authority)) {
    // The relying party case, and the refusal is the point rather than a
    // limitation. It may stop the agent at its own door with suspend(); it may
    // not end the person's authority to be helped.
    return {
      ok: false,
      refused: true,
      reason:
        `a ${authority} may not revoke a delegation. It can suspend it, which stops the agent ` +
        'at that party and is reversible by the person. Revocation would let one office ' +
        'permanently destroy a grant it does not hold, and the person would find out by noticing.',
    };
  }

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

  // Everything below this link stops with it. A sub-delegation of an authority
  // that no longer exists is not a smaller authority, it is no authority.
  // Everything *above* is untouched: revoking a sub-agent does not touch the
  // person's own grant.
  const cascaded = [];
  for (const childId of register.descendantsOf(credentialId)) {
    const child = register.get(childId);
    if (!child || child.revoked) continue;
    register.list.set(child.idx, STATUS.INVALID);
    child.revoked = true;
    child.revokedAt = record.revokedAt;
    child.reason = REASONS.ANCESTOR_REVOKED;
    child.cascadedFrom = credentialId;
    cascaded.push(childId);
    for (const [verifier, lastSeen] of child.presentedTo) {
      if (typeof notify !== 'function') continue;
      try {
        await notify({ verifier, credentialId: childId, revokedAt: child.revokedAt, lastSeen, reason: REASONS.ANCESTOR_REVOKED });
        if (!notified.includes(verifier)) notified.push(verifier);
      } catch (err) {
        failed.push({ verifier, error: String(err?.message ?? err) });
      }
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
    revoked_by: authority,
    purpose_commitment: record.purposeCommitment,
    in_force_everywhere_within: `${register.freshnessSeconds} seconds`,
    could_not_reach: failed,
    also_stopped: cascaded,
  };

  if (cascaded.length) {
    record.receipt.note +=
      ` ${cascaded.length} onward step${cascaded.length === 1 ? '' : 's'} that this authority had been passed to ` +
      'stopped at the same moment.';
  }

  if (failed.length) {
    // Logged and surfaced rather than swallowed. A verifier we could not reach
    // still fails closed when its cached status goes stale, which is why this
    // is a note on the receipt and not an error.
    record.receipt.note +=
      ` ${failed.length} could not be reached and will find out when their copy of the status list goes stale,` +
      ` which is within ${register.freshnessSeconds} seconds.`;
  }

  return { ok: true, receipt: record.receipt, notified, failed, cascaded };
}

/**
 * Suspend. The answer to the agent that behaved inside its scope and against
 * the person's interest.
 *
 * This is the mechanism criticism 1 was missing, and it is deliberately smaller
 * than the criticism. It does not make the agent behave and nothing ever will.
 * It makes stopping the agent possible for the party who can actually see the
 * misbehaviour — usually the relying party, not the person — without the
 * person having to be present, and without that party being able to take the
 * person's authority away.
 *
 * `scope` is a verifier identifier. A relying party may only suspend at itself;
 * anyone with revocation authority may suspend globally. A global suspension
 * writes status 2 and propagates on the same window as revocation. A scoped one
 * cannot and does not: a status list has no room for "suspended at one office",
 * so a scoped suspension is enforced by the party that imposed it, at its own
 * door. That is an honest limitation of the data structure and it has a test.
 */
export function suspend(register, {
  credentialId,
  authority,
  by,
  reason = REASONS.CONDUCT,
  scope = null,
  now = Date.now(),
}) {
  if (!maySuspend(authority)) return { ok: false, reason: `a ${authority} may not suspend a delegation` };
  if (!by) return { ok: false, reason: 'a suspension must name who imposed it; an anonymous stop has no appeal path' };

  if (authority === AUTHORITY.RELYING_PARTY && !scope) {
    return {
      ok: false,
      reason:
        'a relying party may only suspend at itself. Pass scope with your own verifier identifier. ' +
        'A global suspension by one office would stop the person being helped everywhere else too.',
    };
  }

  const record = register.get(credentialId);
  if (!record) return { ok: false, reason: 'no such delegation' };
  if (record.revoked) return { ok: false, reason: 'that delegation is already withdrawn; there is nothing to suspend' };

  // A one-bit status list has room for revoked and not-revoked and nothing else,
  // so an operator who wants suspension has to publish a two-bit list. Caught
  // here with a sentence, because the alternative is the list throwing
  // "status 2 does not fit in 1 bits" at the moment somebody is trying to stop
  // an agent, and a cryptic failure at that moment is the silent degradation
  // Failing Well exists to forbid. Found by the test suite, 14 August 2026.
  if (!scope && register.list.bits < 2) {
    return {
      ok: false,
      reason:
        'this deployment publishes a one-bit status list, which can say revoked or not revoked and ' +
        'nothing in between, so a suspension cannot be published. Either publish a two-bit list, or ' +
        'revoke instead and accept that the person must grant again rather than reinstate.',
    };
  }

  const at = new Date(now).toISOString();
  record.suspensions.push({ by, authority, scope, reason, at, cascadedFrom: null });

  // Only a global suspension can be expressed in a status list.
  if (!scope) register.list.set(record.idx, STATUS.SUSPENDED);

  const cascaded = [];
  for (const childId of register.descendantsOf(credentialId)) {
    const child = register.get(childId);
    if (!child || child.revoked) continue;
    child.suspensions.push({ by, authority, scope, reason: REASONS.ANCESTOR_REVOKED, at, cascadedFrom: credentialId });
    if (!scope) register.list.set(child.idx, STATUS.SUSPENDED);
    cascaded.push(childId);
  }

  return {
    ok: true,
    suspended: credentialId,
    scope,
    cascaded,
    reversible_by: 'the person who granted it, and nobody else',
    continuation: continuation(register, { credentialId, stoppedBy: by, reason, scope, permanent: false }),
  };
}

/**
 * Reinstate. The person's alone.
 *
 * Lifts suspensions that came down a cascade from this credential, and lifts
 * this credential's own. It does **not** lift a suspension somebody imposed on a
 * descendant on that descendant's own account: an office that stopped a
 * sub-agent for its own reasons has not been overruled by the person
 * reinstating something above it, and pretending otherwise would make the
 * relying party's stop meaningless.
 */
export function reinstate(register, { credentialId, authority, now = Date.now() }) {
  if (!mayReinstate(authority)) {
    return {
      ok: false,
      refused: true,
      reason:
        `a ${authority} may not reinstate a delegation. Only the person who granted it can decide ` +
        'they still want the help. Anyone else deciding that for them is the failure this asymmetry prevents.',
    };
  }

  const record = register.get(credentialId);
  if (!record) return { ok: false, reason: 'no such delegation' };
  if (record.revoked) {
    return {
      ok: false,
      reason: 'that delegation was withdrawn, not suspended, and withdrawal is final. Grant it again instead.',
      how_to_continue: 'Granting again takes about a minute and is deliberately cheap.',
    };
  }

  const lifted = record.suspensions.length;
  record.suspensions = [];
  register.list.set(record.idx, STATUS.VALID);

  const stillStopped = [];
  for (const childId of register.descendantsOf(credentialId)) {
    const child = register.get(childId);
    if (!child || child.revoked) continue;
    child.suspensions = child.suspensions.filter((s) => s.cascadedFrom !== credentialId);
    if (child.suspensions.length === 0) {
      register.list.set(child.idx, STATUS.VALID);
    } else {
      stillStopped.push({ credentialId: childId, by: child.suspensions.map((s) => s.by) });
    }
  }

  return { ok: true, lifted, still_stopped: stillStopped, at: new Date(now).toISOString() };
}

/**
 * R2. The agent is compromised, so every delegation granted to it is
 * compromised, not one.
 *
 * This is the first place where revoking one credential invalidates others, and
 * it is why the register tracks bindings rather than only indices. The unit of
 * harm is the agent's holder key, so the unit of revocation has to be too.
 *
 * `cardList` is the Agent Identity Card status list, which is a different list
 * from the delegation list. Passing it is optional so that an operator who runs
 * only the delegation half still gets the cascade.
 */
export async function revokeCard(register, {
  aicThumbprint,
  cardIdx = null,
  cardList = null,
  reason = REASONS.AGENT_COMPROMISED,
  authority = AUTHORITY.ACCOUNTABLE,
  notify,
  now = Date.now(),
}) {
  if (!mayRevoke(authority)) {
    return { ok: false, refused: true, reason: `a ${authority} may not revoke an Agent Identity Card` };
  }

  if (cardList && cardIdx !== null) cardList.set(cardIdx, STATUS.INVALID);

  const affected = register.boundTo(aicThumbprint);
  const receipts = [];
  for (const credentialId of affected) {
    const result = await revoke(register, { credentialId, reason: REASONS.CARD_REVOKED, notify, authority, now });
    if (result.ok && result.receipt) receipts.push(result.receipt);
  }

  return {
    ok: true,
    card: aicThumbprint,
    reason,
    revoked_by: authority,
    delegations_stopped: affected,
    receipts,
    note:
      affected.length === 0
        ? 'No delegation had been granted to that agent, so nothing else stopped.'
        : `Every one of the ${affected.length} delegation(s) granted to that agent stopped at the same moment, ` +
          'because they were all held by the same compromised key.',
  };
}

/**
 * Non-abandonment, as a return value rather than a doctrine.
 *
 * A stop that leaves somebody mid-application with a status code is a failure of
 * this design, not a success of it. So every stop hands back what stopped, what
 * did not, who did it, and what the person can do now. `false` tells a person
 * nothing, and it tells the service building the interface nothing either.
 */
export function continuation(register, { credentialId, stoppedBy, reason, scope = null, permanent = true, redressUri = null }) {
  const record = register.get(credentialId);
  const alsoStopped = record ? register.descendantsOf(credentialId) : [];

  const lines = [];
  if (permanent) {
    lines.push('That agent can no longer act for you.');
  } else if (scope) {
    lines.push(`That agent has been stopped at one office (${scope}). It can still act everywhere else.`);
  } else {
    lines.push('That agent has been paused. It has not been taken away.');
  }

  if (stoppedBy) lines.push(`This was done by ${stoppedBy}, because ${reason}.`);
  lines.push('Nothing you have already submitted has been withdrawn, and no deadline has been given up.');

  if (alsoStopped.length) {
    lines.push(`${alsoStopped.length} onward step${alsoStopped.length === 1 ? '' : 's'} stopped at the same time.`);
  }

  lines.push(
    permanent
      ? 'If you still want that help, you can grant it again at any time. It takes about a minute.'
      : 'You are the only one who can start it again. Nobody else can decide that for you.',
  );
  lines.push(`If this has held something up, tell us and a person will sort it out: ${redressUri ?? 'trust@thekindredagency.com'}`);

  return {
    stopped: credentialId,
    also_stopped: alsoStopped,
    permanent,
    scope,
    reversible_by: permanent ? null : 'the person who granted it',
    what_is_unaffected: 'anything already submitted, and every deadline already met',
    next_step: permanent ? 'grant it again' : 'reinstate it, or leave it paused',
    contact: redressUri ?? 'trust@thekindredagency.com',
    tell_the_person: lines.join('\n'),
  };
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
