/**
 * IETF Token Status List, and the fail-closed rule that goes with it.
 *
 * The data structure is the easy half. Section 7 of the specification says the
 * hard half plainly: a person cannot distribute revocation information to
 * verifiers. So the obligations that make revocation real live here too, as
 * code that refuses rather than as prose that asks nicely.
 */

import { deflateSync, inflateSync } from 'node:zlib';
import { SignJWT, compactVerify } from 'jose';

/**
 * What a status list can say about a credential.
 *
 * RETIRED was added 20 August 2026. Until then a verifier could not tell a
 * retired agent from a revoked one, because there was no value for it — both
 * came back as "not in force" and the person on the other end was told the same
 * thing in both cases. Those are very different events. Revoked means somebody
 * withdrew authority, usually for cause. Retired means the agent reached the end
 * of its working life and, if it was retired properly, handed over.
 *
 * A third case needs no value of its own: an operator that has simply vanished
 * shows up as an unreachable status list, which inForce() already fails closed
 * on and names. Revoked, retired, and gone are therefore all distinguishable.
 *
 * RETIRED is 3, so a list carrying it must be built with `bits: 2` or wider.
 */
export const STATUS = { VALID: 0, INVALID: 1, SUSPENDED: 2, RETIRED: 3 };

/** The smallest `bits` a list needs in order to express a given status. */
export function bitsFor(status) {
  return status <= 1 ? 1 : status <= 3 ? 2 : status <= 15 ? 4 : 8;
}

/** A packed bit array. `bits` is 1, 2, 4, or 8 per entry. */
export class StatusList {
  constructor({ size, bits = 1 }) {
    if (![1, 2, 4, 8].includes(bits)) throw new Error('bits must be 1, 2, 4, or 8');
    this.bits = bits;
    this.size = size;
    this.perByte = 8 / bits;
    this.bytes = new Uint8Array(Math.ceil(size / this.perByte));
  }

  set(idx, value) {
    this.#bounds(idx);
    const max = (1 << this.bits) - 1;
    if (value < 0 || value > max) {
      throw new Error(
        `status ${value} does not fit in ${this.bits} bits. A list that needs to express `
        + `RETIRED must be built with bits: 2 or wider.`,
      );
    }
    const byte = Math.floor(idx / this.perByte);
    const shift = (idx % this.perByte) * this.bits;
    this.bytes[byte] = (this.bytes[byte] & ~(max << shift)) | (value << shift);
    return this;
  }

  get(idx) {
    this.#bounds(idx);
    const max = (1 << this.bits) - 1;
    const byte = Math.floor(idx / this.perByte);
    const shift = (idx % this.perByte) * this.bits;
    return (this.bytes[byte] >> shift) & max;
  }

  #bounds(idx) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= this.size) {
      throw new Error(`index ${idx} is outside a list of ${this.size}`);
    }
  }

  encode() {
    return { bits: this.bits, lst: Buffer.from(deflateSync(Buffer.from(this.bytes))).toString('base64url') };
  }

  static decode({ bits, lst }, size) {
    const bytes = inflateSync(Buffer.from(lst, 'base64url'));
    const list = new StatusList({ size: size ?? bytes.length * (8 / bits), bits });
    list.bytes = new Uint8Array(bytes);
    return list;
  }

  /**
   * Herd size, from the privacy work item. A status list small enough to
   * identify one person by arithmetic protects nobody, so this is worth
   * checking before publishing rather than after.
   */
  populated() {
    let n = 0;
    for (let i = 0; i < this.size; i += 1) if (this.get(i) !== STATUS.VALID) n += 1;
    return n;
  }
}

/**
 * `ttl` is the freshness window in seconds and is not optional. A published
 * list with no stated freshness gives a verifier nothing to fail closed
 * against, which is the whole mechanism.
 */
export async function publish({ list, uri, issuer, privateKey, alg = 'ES256', ttl, now = Date.now() }) {
  if (!Number.isInteger(ttl) || ttl <= 0) throw new Error('a status list must publish a positive ttl');
  const iat = Math.floor(now / 1000);
  return new SignJWT({ status_list: list.encode(), ttl })
    .setProtectedHeader({ alg, typ: 'statuslist+jwt' })
    .setIssuer(issuer)
    .setSubject(uri)
    .setIssuedAt(iat)
    .sign(privateKey);
}

export async function fetchStatus(token, { issuerKey, idx, now = Date.now() }) {
  const { payload, protectedHeader } = await compactVerify(token, issuerKey)
    .then(({ payload, protectedHeader }) => ({
      payload: JSON.parse(Buffer.from(payload).toString('utf8')),   // Uint8Array, not Buffer
      protectedHeader,
    }));
  if (protectedHeader.typ !== 'statuslist+jwt') throw new Error(`wrong typ "${protectedHeader.typ}" for a status list`);

  const age = Math.floor(now / 1000) - payload.iat;
  const stale = age > payload.ttl;
  const list = StatusList.decode(payload.status_list);
  return { status: list.get(idx), stale, age, ttl: payload.ttl, uri: payload.sub };
}

/**
 * The availability commitment. Threat model priority 3.
 *
 * The fail-closed rule denies service to every holder at once when status
 * infrastructure goes down, and until now this repository stated that trade and
 * published no target, no mirroring requirement, and no specified behaviour
 * during a known outage. A safety rule whose cost is unbounded and unmeasured is
 * not a commitment, it is a hope.
 *
 * The numbers are deliberately modest and are a floor to be argued up, not a
 * boast. 99.9% monthly is about 43 minutes down; at that rate somebody is
 * mid-application during an outage most months.
 */
export const AVAILABILITY = {
  /** Monthly uptime target for published status lists. */
  TARGET: 0.999,
  /** Measured from outside, because a service measuring itself measures nothing. */
  MEASURED: 'external probes against every published mirror, one minute apart',
  /**
   * Two independent origins minimum. Mirroring is the only mitigation that
   * lowers the outage rate without weakening the rule, which is why it is the
   * requirement and a grace period is not.
   */
  MIN_MIRRORS: 2,
};

/**
 * Read a status list from several mirrors, and only fail closed once they have
 * all failed.
 *
 * `sources` are thunks so a caller can pass whatever transport it uses. Order is
 * preserved and the first success wins; the failures are still reported, because
 * a mirror that is quietly down for a month is how two mirrors become one.
 */
export async function fetchStatusMirrored(sources, options) {
  if (!Array.isArray(sources) || sources.length === 0) {
    throw new Error('fetchStatusMirrored needs at least one source');
  }
  if (sources.length < AVAILABILITY.MIN_MIRRORS) {
    // A warning rather than a refusal: a single-mirror deployment is
    // non-conforming and refusing to read it would strand the very people the
    // rule protects. Surfaced so it cannot be true silently.
    options = { ...options, underMirrored: true };
  }

  const failures = [];
  for (const source of sources) {
    try {
      const token = typeof source === 'function' ? await source() : source;
      const result = await fetchStatus(token, options);
      return { ...result, reachable: true, mirrorsTried: failures.length + 1, failures, underMirrored: options.underMirrored === true };
    } catch (err) {
      failures.push(String(err?.message ?? err));
    }
  }
  return { reachable: false, stale: true, failures, mirrorsTried: sources.length, underMirrored: options?.underMirrored === true };
}

/**
 * What happens during a **known** outage, which is the question the threat model
 * said was unspecified.
 *
 * The answer is that nothing changes about the authority: a verifier that cannot
 * confirm a credential is in force still refuses to act on it, declared outage
 * or not. There is no grace period and no signed "trust us for an hour" token,
 * because an attacker who can take down the status list would then have bought
 * exactly the window they wanted, and the person who revoked in a panic is
 * relying on the rule being unconditional.
 *
 * What changes is what happens to the **person**, and that is the whole point of
 * specifying it. An outage must not turn into a refusal at a counter. The
 * relying party falls back to its own non-agent process — the one it had before
 * any of this existed — and the person is served by a human. Failing closed on
 * the credential must never mean failing closed on the person.
 */
export function outageGuidance({ listUri, since = null, expectedBy = null, redressUri = null }) {
  return {
    authority: 'refused',
    grace_period: null,
    why:
      'A verifier that cannot confirm a delegation is in force must treat it as not in force, ' +
      'whether or not the outage is known. An announced outage that relaxed the rule would hand ' +
      'an attacker the window, and would break the promise made to whoever has just revoked.',
    relying_party_must:
      'Fall back to the process used before agents existed and serve the person directly. ' +
      'Do not turn anyone away, do not require them to come back later, and do not treat a ' +
      'failed credential check as a failed applicant.',
    tell_the_person: [
      'Something on our side is not working, and it is nothing you did.',
      'Your agent cannot act for you until it is back.',
      since ? `It has been down since ${since}.` : null,
      expectedBy ? `We expect it back by ${expectedBy}.` : 'We do not have a time yet, and we will not guess.',
      'You can still do this yourself, and the office is required to help you directly in the meantime.',
      `If this has held something up or a deadline is close, tell us now: ${redressUri ?? 'trust@thekindredagency.com'}`,
    ].filter(Boolean).join('\n'),
    status_list: listUri,
    availability_target: AVAILABILITY.TARGET,
  };
}

/**
 * The fail-closed rule, in one place so it cannot drift between callers.
 *
 * A verifier that cannot reach the status list, or reaches a stale one, treats
 * the credential as not in force. Not "probably fine". Not "warn and proceed".
 * The person who has just realised they should not have granted something is
 * relying on this being the boring, unconditional answer.
 */
export function inForce({ status, stale, reachable = true }) {
  // The operator that vanished. Distinguishable from both revoked and retired,
  // and the only one of the three that is an abandonment.
  if (!reachable) return { ok: false, reason: 'status list unreachable, failing closed', state: 'unreachable' };
  if (stale) return { ok: false, reason: 'status list older than its stated freshness window, failing closed', state: 'stale' };
  if (status === STATUS.INVALID) return { ok: false, reason: 'credential revoked', state: 'revoked' };
  if (status === STATUS.SUSPENDED) return { ok: false, reason: 'credential suspended', state: 'suspended' };
  // Retired is not revoked, and a verifier that conflates them tells the person
  // the wrong thing about why their agent stopped working.
  if (status === STATUS.RETIRED) {
    return {
      ok: false,
      state: 'retired',
      reason: 'the agent has been retired. This is the end of its working life rather than a '
        + 'withdrawal of authority. Check its card for a successor before telling anyone there is '
        + 'nothing further they can do.',
    };
  }
  if (status !== STATUS.VALID) return { ok: false, reason: `unrecognised status ${status}, failing closed`, state: 'unknown' };
  return { ok: true, reason: 'valid', state: 'valid' };
}

/**
 * A revocation receipt. Section 7 requires the person be told what was revoked,
 * when, and who was notified, so the receipt is part of the library rather than
 * something an operator is trusted to build later.
 */
export function receipt({ credentialId, purpose, revokedAt, notified = [], listUri }) {
  return {
    revoked: { id: credentialId, purpose },
    revoked_at: revokedAt,
    status_list: listUri,
    verifiers_notified: notified,
    notified_count: notified.length,
    note:
      notified.length === 0
        ? 'No verifier had presented this credential, so there was nobody to tell.'
        : `${notified.length} verifier(s) that had used this credential were told it is no longer in force.`,
  };
}
