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

export const STATUS = { VALID: 0, INVALID: 1, SUSPENDED: 2 };

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
    if (value < 0 || value > max) throw new Error(`status ${value} does not fit in ${this.bits} bits`);
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
 * The fail-closed rule, in one place so it cannot drift between callers.
 *
 * A verifier that cannot reach the status list, or reaches a stale one, treats
 * the credential as not in force. Not "probably fine". Not "warn and proceed".
 * The person who has just realised they should not have granted something is
 * relying on this being the boring, unconditional answer.
 */
export function inForce({ status, stale, reachable = true }) {
  if (!reachable) return { ok: false, reason: 'status list unreachable, failing closed' };
  if (stale) return { ok: false, reason: 'status list older than its stated freshness window, failing closed' };
  if (status === STATUS.INVALID) return { ok: false, reason: 'credential revoked' };
  if (status === STATUS.SUSPENDED) return { ok: false, reason: 'credential suspended' };
  if (status !== STATUS.VALID) return { ok: false, reason: `unrecognised status ${status}, failing closed` };
  return { ok: true, reason: 'valid' };
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
