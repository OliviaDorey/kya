/**
 * The Agent Identity Card.
 *
 * Section 5 of the specification. Issued to an agent by an issuer registered in
 * a federation, long-lived relative to a delegation, and it answers one
 * question: what is this thing and who is accountable for it.
 *
 * Two rules in here are structural rather than advisory, and both are enforced
 * at issue time so that a non-conforming card cannot be produced by accident:
 *
 *   conduct.discloses_ai is always "always". An agent that can be configured to
 *   deny being an agent is a different product.
 *
 *   accountable, conduct, capabilities, agent.id, agent.name, cnf and status can
 *   never be selectively disclosed. A verifier must never have to ask who is
 *   accountable.
 */

import { issue as sdIssue, verify as sdVerify, thumbprint } from './sdjwt.js';

export const AIC_VCT = 'https://agentcredential.ca/aic/v1';

export const SELECTIVELY_DISCLOSABLE = ['model', 'assurance'];
export const ALWAYS_DISCLOSED = ['agent', 'accountable', 'conduct', 'capabilities', 'cnf', 'status', 'builder'];

/** Capabilities a delegation may draw from. An unknown one is a typo, not a feature. */
export const KNOWN_CAPABILITIES = [
  'read:program-information',
  'draft:application',
  'submit:application',
  'draft:appeal',
  'submit:appeal',
  'monitor:status',
  'correspond:on-behalf',
];

export function validate(card) {
  const problems = [];

  if (card.vct !== AIC_VCT) problems.push(`vct must be ${AIC_VCT}`);
  if (!card.iss) problems.push('iss is required');
  if (!card.exp) problems.push('exp is required; a card with no expiry cannot be aged out');

  if (!card.agent?.id) problems.push('agent.id is required');
  if (!card.agent?.name) problems.push('agent.name is required; it is what the person is shown');
  if (card.agent?.id && !/^urn:agent:/.test(card.agent.id)) {
    problems.push('agent.id should be a urn:agent: identifier');
  }

  if (!card.builder?.legal_name) problems.push('builder.legal_name is required');
  if (!card.builder?.jurisdiction) problems.push('builder.jurisdiction is required');

  // Section 5, question 5. A card with no human at the end of it is the
  // accountability sink the whole specification exists to avoid.
  if (!card.accountable?.contact) problems.push('accountable.contact is required');
  if (!card.accountable?.role) problems.push('accountable.role is required');
  if (!card.accountable?.redress_uri) problems.push('accountable.redress_uri is required');

  if (card.conduct?.discloses_ai !== 'always') {
    problems.push('conduct.discloses_ai must be "always" and is not configurable');
  }
  if (typeof card.conduct?.acts_without_approval !== 'boolean') {
    problems.push('conduct.acts_without_approval must be stated as a boolean');
  }

  // "undisclosed" is permitted. Silence is not.
  if (card.model === undefined) {
    problems.push('model is required; state disclosed:false rather than omitting it');
  } else if (card.model.disclosed !== false && !card.model.family) {
    problems.push('model.family is required when model.disclosed is not false');
  }

  if (!Array.isArray(card.capabilities) || card.capabilities.length === 0) {
    problems.push('capabilities must be a non-empty array; it is the outer bound a delegation narrows');
  } else {
    const unknown = card.capabilities.filter((c) => !KNOWN_CAPABILITIES.includes(c));
    if (unknown.length) problems.push(`unknown capabilities: ${unknown.join(', ')}`);
  }

  if (!card.status?.status_list?.uri) problems.push('status.status_list.uri is required');

  return { ok: problems.length === 0, problems };
}

export async function issue({ card, privateKey, holderJwk, kid, alg = 'ES256', selective = ['model', 'assurance'] }) {
  const overreach = selective.filter((c) => ALWAYS_DISCLOSED.includes(c));
  if (overreach.length) {
    throw new Error(
      `these can never be selectively disclosed: ${overreach.join(', ')}. ` +
        'A verifier must never have to ask who is accountable.',
    );
  }

  const { ok, problems } = validate(card);
  if (!ok) throw new Error(`Agent Identity Card is not conforming:\n  - ${problems.join('\n  - ')}`);

  return sdIssue({
    payload: card,
    selective: selective.filter((c) => c in card),
    privateKey,
    holderJwk,
    kid,
    alg,
  });
}

export async function verify(presented, { issuerKey, audience, nonce, requireKeyBinding = true, now }) {
  const result = await sdVerify(presented, { issuerKey, audience, nonce, requireKeyBinding, now });
  const card = result.claims;

  if (card.vct !== AIC_VCT) throw new Error(`not an Agent Identity Card: vct is ${card.vct}`);

  // Re-check the invariants on receipt. A card issued by somebody else's
  // implementation gets held to the same rules as one we issued.
  for (const c of ALWAYS_DISCLOSED) {
    if (c === 'builder') continue;   // builder.registry_id may be withheld; the object may not
    if (card[c] === undefined) throw new Error(`Agent Identity Card is missing "${c}", which may never be withheld`);
  }
  if (card.conduct?.discloses_ai !== 'always') {
    throw new Error('Agent Identity Card claims it does not always disclose that it is an agent. Rejected.');
  }

  return { ...result, card, thumbprint: await cardThumbprint(presented) };
}

/** Binds a delegation to one specific card. Over the issuer JWT, not the disclosures. */
export async function cardThumbprint(presented) {
  const { createHash } = await import('node:crypto');
  const jwt = presented.split('~')[0];
  return createHash('sha256').update(jwt, 'ascii').digest('base64url');
}

export { thumbprint as jwkThumbprint };
