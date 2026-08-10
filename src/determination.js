/**
 * rule_basis, from the Authoritative Rules Commitment.
 *
 * The commitment says an agent is structurally incapable of presenting an
 * inference as a rule. This file is where "structurally" earns the word: a
 * determination carrying tier 3 is a malformed credential and a conforming
 * verifier rejects it, so the discipline is enforced by the schema rather than
 * by the operator's good intentions.
 *
 * See spec/authoritative-rules-commitment.md.
 */

export const TIER = {
  CALLABLE: 1,     // a machine-readable authority exists and was called
  PUBLISHED: 2,    // the rule is published as text; this is an interpretation
  UNPUBLISHED: 3,  // nothing authoritative exists; navigation only
};

export const KIND = {
  DETERMINATION: 'determination',   // an answer
  INTERPRETATION: 'interpretation', // a reading of a published rule
  NAVIGATION: 'navigation',         // what to do next, and nothing about the outcome
};

/** What each tier is permitted to emit. */
const PERMITTED = {
  [TIER.CALLABLE]: [KIND.DETERMINATION, KIND.INTERPRETATION, KIND.NAVIGATION],
  [TIER.PUBLISHED]: [KIND.INTERPRETATION, KIND.NAVIGATION],
  [TIER.UNPUBLISHED]: [KIND.NAVIGATION],
};

export function validate(basis, { kind }) {
  const problems = [];

  if (!Object.values(TIER).includes(basis?.tier)) {
    problems.push('rule_basis.tier must be 1, 2, or 3');
    return { ok: false, problems };
  }
  if (!Object.values(KIND).includes(kind)) {
    problems.push(`unknown output kind "${kind}"`);
    return { ok: false, problems };
  }

  if (!PERMITTED[basis.tier].includes(kind)) {
    problems.push(
      `a tier ${basis.tier} basis may not carry a ${kind}. ` +
        (basis.tier === TIER.UNPUBLISHED
          ? 'Nothing authoritative is published, so the agent navigates and says so.'
          : 'The rule is published as text only, so this is an interpretation, not an answer.'),
    );
  }

  if (basis.tier === TIER.CALLABLE) {
    if (!basis.authority) problems.push('tier 1 requires authority, the endpoint that was called');
    if (!basis.rule_id) problems.push('tier 1 requires rule_id');
    if (!basis.version) problems.push('tier 1 requires version');
    if (!basis.retrieved) problems.push('tier 1 requires retrieved, the time of the call');
  }

  if (basis.tier === TIER.PUBLISHED) {
    if (!basis.authority) problems.push('tier 2 requires authority, the citation URL');
    if (!basis.rule_id) problems.push('tier 2 requires rule_id, the specific provision');
    if (!basis.version) problems.push('tier 2 requires version, the date of the text that was read');
  }

  if (basis.tier === TIER.UNPUBLISHED) {
    for (const member of ['authority', 'rule_id', 'version', 'retrieved']) {
      if (basis[member] !== undefined) {
        problems.push(`tier 3 must not carry ${member}; there is no authority to name`);
      }
    }
  }

  return { ok: problems.length === 0, problems };
}

/**
 * Attach a basis to an output. Throws rather than returning an invalid object,
 * because the failure mode this guards against is an inference travelling
 * onward wearing the clothes of an answer.
 */
export function stamp(output, { kind, basis }) {
  const { ok, problems } = validate(basis, { kind });
  if (!ok) throw new Error(`rule_basis is not conforming:\n  - ${problems.join('\n  - ')}`);
  return { ...output, kind, rule_basis: basis };
}

/**
 * Falling from tier 1 to tier 3 when an authoritative service is unreachable.
 *
 * The commitment forbids silent degradation, so this returns the honest sentence
 * alongside the downgraded basis. A caller that drops the sentence has broken
 * the commitment, and there is no way to make that harder from here.
 */
export function downgrade(basis, reason) {
  return {
    basis: { tier: TIER.UNPUBLISHED },
    kind: KIND.NAVIGATION,
    tell_the_person:
      `I could not reach the service that decides this (${reason}), so I cannot tell you the answer. ` +
      'I can still help you get to the right place.',
    logged: { from: basis.tier, to: TIER.UNPUBLISHED, authority: basis.authority ?? null, reason },
  };
}

/** What a person is shown, per tier. Never a green checkmark on anything but tier 1. */
export function presentation(tier) {
  switch (tier) {
    case TIER.CALLABLE:
      return { label: 'Decision', may_use_decision_styling: true, must_say: null };
    case TIER.PUBLISHED:
      return {
        label: 'Our reading of the rule',
        may_use_decision_styling: false,
        must_say: 'This is our interpretation of the published rule, not a decision.',
      };
    default:
      return {
        label: 'What to do next',
        may_use_decision_styling: false,
        must_say: 'Nobody publishes a rule for this, so I can help you get to the right desk but I cannot tell you the answer.',
      };
  }
}
