/**
 * Capability scoping, and the screen that enforces it.
 *
 * The commitment: we will not put the sensitive noun in a credential a clerk
 * can read. This file is where that stops being a promise.
 *
 * The observation it rests on is small and load-bearing. **A verifier already
 * knows who it is.** When Steward presents to the AISH office, the AISH office
 * does not learn anything from a credential that says "AISH" — it learns only
 * that everyone else who ever handles this credential now knows too. The
 * programme name is redundant where it is safe and dangerous everywhere else.
 *
 * So a delegation carries two things instead of one:
 *
 *   capability   what shape of interaction is authorised. Public. Closed
 *                vocabulary. Says nothing about the subject
 *   purpose      the sentence the person actually read and consented to.
 *                Selectively disclosable and withheld by default, with a
 *                commitment in the clear so it can be proven unchanged
 *
 * The person loses nothing: they see the full sentence, because it lives in
 * their wallet. The verifier loses nothing it needs: it knows what the agent
 * may do, and it already knew which office it was.
 */

import { createHash, randomBytes } from 'node:crypto';

/**
 * The public vocabulary. Closed on purpose.
 *
 * Every entry describes the *shape* of an interaction. None describes a
 * subject, a programme, a condition, or a circumstance. Adding an entry that
 * does is the failure mode this file exists to prevent, so new entries go
 * through the same sensitive-term screen as everything else.
 */
export const CAPABILITIES = {
  'read:public-information': 'Look up publicly published information',
  'submit:form': 'Submit a form and track its status',
  'provide:documents': 'Provide documents that were asked for',
  'track:status': 'Check where something has got to',
  'request:review': 'Ask for a decision to be looked at again',
  'correspond:administrative': 'Exchange routine correspondence about a file',
};

/** Which delegation action each capability permits. */
export const CAPABILITY_ACTIONS = {
  'read:public-information': ['read'],
  'submit:form': ['draft', 'submit'],
  'provide:documents': ['draft', 'submit'],
  'track:status': ['monitor'],
  // Drafting an appeal and filing one are separate actions, exactly as they are
  // for a form. Filing is the irreversible half and needs its own grant.
  'request:review': ['draft-appeal', 'appeal'],
  'correspond:administrative': ['correspond'],
};

/**
 * Terms that must not appear in any field a verifier can read without the
 * person choosing to disclose it.
 *
 * This list is a judgement and it is written down so the judgement can be
 * argued with rather than buried. It is deliberately over-broad: a false
 * positive costs somebody a rewrite, a false negative costs somebody their
 * privacy at a counter. Grouped so that a reviewer can take issue with a
 * category rather than a word.
 */
export const SENSITIVE_TERMS = {
  health: [
    'disab', 'handicap', 'aish', 'assured income', 'medical', 'health', 'illness',
    'diagnos', 'psychiatric', 'mental health', 'addiction', 'substance', 'hiv',
    'cancer', 'palliative', 'prescription', 'pharmacare', 'therapy', 'treatment',
  ],
  reproductive: ['pregnan', 'prenatal', 'maternity', 'abortion', 'fertility'],
  status: [
    'refugee', 'asylum', 'immigration', 'deportation', 'permanent resident',
    'work permit', 'citizenship application', 'undocumented',
  ],
  housing: ['eviction', 'homeless', 'shelter', 'tenancy', 'rent arrears', 'housing support'],
  income: [
    'welfare', 'income support', 'social assistance', 'benefit', 'food bank',
    'bankrupt', 'insolven', 'garnish', 'debt',
  ],
  safety: [
    'domestic violence', 'abuse', 'assault', 'protection order', 'restraining',
    'victim', 'stalking',
  ],
  family: ['custody', 'child protection', 'apprehension', 'access order', 'guardianship'],
  justice: ['criminal', 'parole', 'probation', 'conviction', 'charges', 'incarcerat'],
};

const ALL_SENSITIVE = Object.entries(SENSITIVE_TERMS).flatMap(([category, terms]) =>
  terms.map((term) => ({ term, category })),
);

/**
 * Screen a string for terms that must not travel in the clear.
 *
 * Returns every hit rather than the first, because a caller fixing one word at
 * a time will give up before the string is safe.
 */
export function screen(text) {
  if (typeof text !== 'string' || !text) return [];
  const haystack = text.toLowerCase();
  return ALL_SENSITIVE.filter(({ term }) => haystack.includes(term));
}

/** Every publicly visible field of a delegation, flattened for screening. */
export function publicSurface(adc) {
  const parts = [];
  for (const d of adc.authorization_details ?? []) {
    parts.push(d.type, d.capability, ...(d.actions ?? []), ...(d.programs ?? []));
    for (const [k, v] of Object.entries(d.constraints ?? {})) {
      parts.push(k, ...(Array.isArray(v) ? v.map(String) : [String(v)]));
    }
  }
  // purpose is deliberately absent. It is withheld by default and is the
  // person's own sentence, so it is allowed to name what they are going through.
  return parts.filter((p) => typeof p === 'string');
}

/**
 * The enforceable half of the commitment.
 *
 * Anything a clerk could read without the person disclosing it gets screened.
 * A hit is an error, not a warning, and the message says which category so the
 * author knows what they tripped rather than only that they tripped.
 */
export function screenDelegation(adc) {
  const problems = [];
  for (const field of publicSurface(adc)) {
    for (const { term, category } of screen(field)) {
      problems.push(
        `"${field}" contains "${term}", which is ${category} information. ` +
          'It is publicly readable by every party handling this credential. ' +
          'Use a capability from CAPABILITIES and keep the subject in the withheld purpose.',
      );
    }
  }
  return [...new Set(problems)];
}

/**
 * A commitment to the purpose sentence.
 *
 * The verifier holds the hash. If the person chooses to disclose the sentence,
 * the verifier can prove it is the one that was consented to and not a
 * substitute. Salted so that the hash of a common sentence is not itself a
 * lookup table entry, which it certainly would be otherwise.
 */
export function commitPurpose(purpose, salt = randomBytes(16).toString('base64url')) {
  const digest = createHash('sha256').update(`${salt}:${purpose}`, 'utf8').digest('base64url');
  return { commitment: digest, salt };
}

export function verifyPurpose(purpose, salt, commitment) {
  return commitPurpose(purpose, salt).commitment === commitment;
}

/** Actions a capability set permits. Used to check the two halves agree. */
export function actionsFor(capabilities) {
  return [...new Set(capabilities.flatMap((c) => CAPABILITY_ACTIONS[c] ?? []))];
}

/**
 * What a caseworker is shown. No subject, and no pretending there is not one.
 *
 * The last line matters more than it looks: a verifier that does not know a
 * purpose exists may assume none was given, which is worse than knowing one is
 * withheld.
 */
export function explainToVerifier(adc) {
  const caps = [...new Set((adc.authorization_details ?? []).map((d) => d.capability).filter(Boolean))];
  const lines = caps.map((c) => `  ${CAPABILITIES[c] ?? c}`);
  const approval = [
    ...new Set((adc.authorization_details ?? []).flatMap((d) => d.constraints?.requires_human_approval ?? [])),
  ];

  const out = ['This agent has been authorised to:', ...lines];
  if (approval.length) out.push(`It must return to the person for approval before it can: ${approval.join(', ')}.`);
  out.push(`This authority ends ${new Date(adc.exp * 1000).toISOString().slice(0, 10)}.`);
  out.push(
    adc.purpose_commitment
      ? 'The person wrote a purpose in their own words. It is withheld from you by design. They can choose to show it.'
      : 'No purpose commitment is present, which is a defect in this credential.',
  );
  return out.join('\n');
}
