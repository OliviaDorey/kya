/**
 * Pairwise subject identifiers, computed rather than asserted.
 *
 * Threat model priority 4. `delegator.pairwise` was a boolean the wallet set
 * about its own behaviour, nothing computed anything, and a wallet that simply
 * turned the flag on while reusing one identifier everywhere passed validation.
 * That is not a check, it is a field.
 *
 * ── What this fixes, and what it cannot ────────────────────────────────────
 *
 * **Fixed: the wallet no longer has to get it right by hand.** `derive()` is the
 * specified derivation and `adc.issue` will compute the subject with it, so the
 * common failure — a wallet author who means well and reuses a subject because
 * deriving one is fiddly — stops happening.
 *
 * **Fixed: the claim is now specific instead of a bare boolean.** A delegation
 * says which verifier its subject was derived for. A verifier can check the
 * subject in front of it was derived for *it* and refuse one minted for
 * somebody else, which is a real check it could not previously make.
 *
 * **Not fixed, and not fixable here: a wallet that lies.** The derivation input
 * is the wallet's secret and never travels, so no verifier can recompute the
 * subject and confirm it. A wallet that reuses one value across every verifier
 * while stamping each with the right audience passes everything in this file.
 * Closing that needs either a zero-knowledge proof of correct derivation or an
 * attested wallet, and both are out of scope for v0.4. This file narrows the gap
 * from "nothing is computed" to "the honest path is the easy one and the
 * dishonest one is at least specific", and says so rather than implying more.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * The derivation. HMAC-SHA256 over the verifier's identifier, keyed by a secret
 * the wallet holds and never discloses.
 *
 * HMAC rather than a plain hash because the verifier identifier is public and
 * low-entropy: a bare `sha256(verifier_id)` would be identical for every person
 * at that verifier, and `sha256(salt || verifier_id)` with a disclosed salt is
 * reversible by anybody holding the salt. The secret has to stay in the wallet
 * for the property to mean anything.
 */
export function derive({ walletSecret, verifierId }) {
  if (!walletSecret) throw new Error('a pairwise subject needs the wallet secret; without it there is nothing to key on');
  if (!verifierId) throw new Error('a pairwise subject is derived for one named verifier; none was given');
  const mac = createHmac('sha256', walletSecret).update(String(verifierId), 'utf8').digest('base64url');
  return `pw:${mac}`;
}

/**
 * Confirm a subject was derived for this verifier, by a wallet that will hand
 * over the secret. Only a wallet auditing itself, or a test, can call this.
 *
 * Deliberately not something a verifier can do: if a verifier could recompute
 * subjects it would be able to compute the person's subject at every *other*
 * verifier too, which is precisely the correlation this exists to prevent. The
 * check that protects the person and the check that would satisfy the verifier
 * are the same computation, and it can only safely be run by one of them.
 */
export function selfCheck({ walletSecret, verifierId, sub }) {
  const expected = Buffer.from(derive({ walletSecret, verifierId }));
  const actual = Buffer.from(String(sub));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/**
 * What a verifier can check without the secret: that this subject was minted
 * for it, and not handed on from somewhere else.
 *
 * Catches the reuse that is visible from where a verifier stands — one subject
 * presented at two verifiers, where the second sees an audience that is not its
 * own. It does not catch a wallet that mints a fresh audience stamp on a stale
 * subject. Stated in the return value rather than left for a caller to assume.
 */
export function boundToVerifier(delegator, verifierId) {
  const problems = [];
  if (delegator?.pairwise !== true) {
    problems.push('delegator.pairwise is not asserted, so this subject may be reused across verifiers');
  }
  if (!delegator?.sub_audience) {
    problems.push(
      'delegator.sub_audience is absent, so there is no way to tell whether this subject was ' +
        'derived for this verifier or forwarded from another one',
    );
  } else if (verifierId && delegator.sub_audience !== verifierId) {
    problems.push(
      `delegator.sub_audience is "${delegator.sub_audience}" and this verifier is "${verifierId}". ` +
        'This subject was derived for somebody else, which means either a misconfiguration or a ' +
        'credential being forwarded between verifiers.',
    );
  }
  return {
    ok: problems.length === 0,
    problems,
    // The honest ceiling on what a positive answer here means.
    proves:
      'that this subject is stamped for this verifier. Not that the wallet derived it correctly, ' +
      'which no verifier can establish without the wallet secret.',
  };
}
