/**
 * The trust register. The one switch a status list structurally cannot be.
 *
 * ── Why this file exists ────────────────────────────────────────────────────
 *
 * A status list is signed by the issuer. So a compromised or dishonest issuer
 * publishes a list saying everything is fine, and every conformant verifier
 * believes it. An issuer cannot revoke itself: its own signature is the thing in
 * doubt. That is R4 in spec/revocation-and-chains.md, and it is the only failure
 * case in the whole model that no amount of protocol can close, because the
 * assertion has to come from a party who is not the subject.
 *
 * ── The gift boundary, which this file straddles and therefore states ───────
 *
 *   Anything a participant can do for itself is protocol, and is given away.
 *   Anything that requires a party who is not the subject to say it is service,
 *   and is retained.
 *
 * **This file is the protocol half and it is given away.** The interface, the
 * semantics, the fail-closed rule, and a working reference implementation are
 * all here under Apache-2.0 with the patent covenant. A province, a department,
 * DIACC, or a competitor can operate its own register against this file alone,
 * with no key from Kindred, no permission, and no relationship. If that were not
 * true this would not be a gift, and the test for it is a test in the suite.
 *
 * **What Kindred retains is not in this file and cannot be**: the operated
 * instance and who is on it — which issuers have been assessed, by whom,
 * against what, on what date, and the authority to withdraw one. There is no
 * code that makes a stranger's assertion trustworthy. That part is an
 * institution, and an institution is the one thing that cannot be given away
 * without ceasing to exist.
 *
 * DIF's KYA-OS publishes conformance levels openly and specifies StatusList2021
 * for revocation. What it does not name is any party who decides that a given
 * deployment meets those levels, or any way to withdraw an issuer whose own
 * signature is in doubt. That gap is this file's subject.
 */

/** What a register says about an issuer. */
export const STANDING = {
  ATTESTED: 'attested',       // assessed, and currently in good standing
  WITHDRAWN: 'withdrawn',     // was attested; is not any more, and why
  UNKNOWN: 'unknown',         // never assessed. Not the same as withdrawn
};

/** Why an issuer was withdrawn. Stated, because "withdrawn" alone tells a verifier nothing. */
export const WITHDRAWAL = {
  KEY_COMPROMISE: 'the issuer signing key is believed compromised',
  NON_CONFORMANT: 'the issuer failed conformance and did not remedy it',
  CEASED: 'the issuer no longer operates',
  AT_REQUEST: 'the issuer asked to be withdrawn',
};

/**
 * A register entry. Deliberately small: everything here has to survive an
 * operator implementing it differently, and a rich schema is a thing to diverge
 * on.
 */
function entry({ issuer, standing, assessedBy, assessedAt, conformanceLevel, reason = null, withdrawnAt = null }) {
  return { issuer, standing, assessed_by: assessedBy, assessed_at: assessedAt, conformance_level: conformanceLevel, reason, withdrawn_at: withdrawnAt };
}

/**
 * A reference register. In memory, because the interface is the part that
 * matters and a database is an operator's business.
 *
 * `ttl` is the freshness window, and it is not optional here for the same reason
 * it is not optional on a status list: a published answer with no stated
 * freshness gives a verifier nothing to fail closed against.
 */
export class TrustRegister {
  constructor({ operator, ttl = 3600 }) {
    if (!operator) throw new Error('a register must name its operator; an anonymous register asserts nothing');
    if (!Number.isInteger(ttl) || ttl <= 0) throw new Error('a register must publish a positive ttl');
    this.operator = operator;
    this.ttl = ttl;
    this.entries = new Map();
  }

  /** Record that an issuer was assessed and is in good standing. */
  attest({ issuer, assessedBy, assessedAt, conformanceLevel }) {
    if (!assessedBy) {
      throw new Error(
        'an attestation must name who assessed it. An attestation nobody signed is a rumour, ' +
          'and the point of a register is that somebody can be held to it.',
      );
    }
    this.entries.set(issuer, entry({ issuer, standing: STANDING.ATTESTED, assessedBy, assessedAt, conformanceLevel }));
    return this.entries.get(issuer);
  }

  /**
   * Withdraw an issuer. This is R4's switch and it is the reason the register
   * exists at all.
   */
  withdraw({ issuer, reason, at = new Date().toISOString() }) {
    const existing = this.entries.get(issuer);
    if (!existing) {
      // Withdrawing something never attested still records the assertion, because
      // "we have looked at this and it should not be trusted" is a different and
      // more useful statement than silence.
      this.entries.set(issuer, entry({ issuer, standing: STANDING.WITHDRAWN, assessedBy: this.operator, assessedAt: at, conformanceLevel: null, reason, withdrawnAt: at }));
      return this.entries.get(issuer);
    }
    this.entries.set(issuer, { ...existing, standing: STANDING.WITHDRAWN, reason, withdrawn_at: at });
    return this.entries.get(issuer);
  }

  /**
   * What this register says about an issuer, right now.
   *
   * `UNKNOWN` is returned rather than thrown, and it is not the same as
   * `WITHDRAWN`. A verifier deciding what to do about an unassessed issuer is
   * making a policy decision; a verifier deciding what to do about a withdrawn
   * one is being told an answer. Collapsing them removes the distinction the
   * register exists to draw.
   */
  check(issuer) {
    const found = this.entries.get(issuer);
    if (!found) return entry({ issuer, standing: STANDING.UNKNOWN, assessedBy: null, assessedAt: null, conformanceLevel: null });
    return found;
  }
}

/**
 * The fail-closed rule for issuer standing, in one place so it cannot drift
 * between callers. The same shape as `status.inForce`, on purpose.
 *
 * `requireAttestation` is the policy knob, and it is the caller's decision
 * rather than this library's: a jurisdiction bootstrapping a register has
 * nobody attested yet, and a rule that refused every unknown issuer on day one
 * would mean no deployment could ever start. What is not a knob is
 * `WITHDRAWN`, which always refuses.
 */
export function issuerTrusted({ standing, reason, stale = false, reachable = true, requireAttestation = false }) {
  if (!reachable) {
    return { ok: false, reason: 'the trust register could not be reached, failing closed' };
  }
  if (stale) {
    return { ok: false, reason: 'the trust register answer is older than its stated freshness window, failing closed' };
  }
  if (standing === STANDING.WITHDRAWN) {
    return { ok: false, reason: `this issuer has been withdrawn from the register: ${reason ?? 'no reason given'}` };
  }
  if (standing === STANDING.UNKNOWN) {
    return requireAttestation
      ? { ok: false, reason: 'this issuer has never been assessed, and this verifier requires attestation' }
      : { ok: true, reason: 'this issuer has never been assessed; accepted under this verifier\'s policy', unattested: true };
  }
  if (standing === STANDING.ATTESTED) return { ok: true, reason: 'attested and in good standing' };
  return { ok: false, reason: `unrecognised standing "${standing}", failing closed` };
}

/**
 * What a person is told when an issuer they relied on is withdrawn.
 *
 * This is the non-abandonment case that is easiest to get wrong, because the
 * person did nothing and nothing they hold is at fault. Their credential stopped
 * working because of a decision made about somebody else, and a status code
 * would leave them with no idea what happened or what to do.
 */
export function explainWithdrawal({ issuer, reason, redressUri, alternatives = [] }) {
  const lines = [
    'Something on our side stopped working, and it is not anything you did.',
    `The organisation that issued your agent's identity (${issuer}) is no longer trusted, because ${reason}`,
    'While that is the case, your agent cannot act for you.',
    'Nothing you have already submitted is affected, and nothing has been withdrawn on your behalf.',
  ];
  if (alternatives.length) {
    lines.push(`You can carry on here instead: ${alternatives.join(', ')}`);
  }
  lines.push(
    'If something of yours is part-way through and this has held it up, tell us and a person will sort it out: ' +
      (redressUri ?? 'trust@thekindredagency.com'),
  );
  return lines.join('\n');
}
