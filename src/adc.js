/**
 * The Agent Delegation Credential.
 *
 * Section 6. Issued by the person's wallet to one specific agent, short-lived,
 * and it answers the two questions a caseworker actually has: did this person
 * authorise it, and what exactly did they authorise.
 *
 * Four properties are enforced here rather than described:
 *
 *   Bound to one card and one key. A delegation names the Agent Identity Card
 *   and the holder key it was granted to, and both are recomputed from what was
 *   actually presented and compared. See bindingBreaches(). A field that is
 *   required but never compared is a comment, not a binding.
 *
 *   Attenuation only. A delegation may never grant an action the Agent Identity
 *   Card does not already carry. Authority narrows going down a chain and never
 *   widens, and a chain link that widens is rejected rather than clamped,
 *   because silently clamping hides a bug in whoever built the chain.
 *
 *   The narrower of purpose and authorization_details governs. Where they
 *   disagree, the verifier rejects. A human-authored purpose that promises less
 *   than the machine-readable grant is the more dangerous direction, and it is
 *   the one people actually read.
 *
 *   Short expiry is mandatory. Section 7 leans on it, because short expiry is
 *   the only revocation mechanism that works when the status list cannot be
 *   reached.
 */

import { issue as sdIssue, verify as sdVerify, present as sdPresent, thumbprint } from './sdjwt.js';
import { cardThumbprint } from './aic.js';
import {
  CAPABILITIES,
  actionsFor,
  commitPurpose,
  screenDelegation,
} from './capability.js';

export const ADC_VCT = 'https://agentcredential.ca/adc/v1';

/** Hours or days, not months. Section 6. */
export const MAX_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

export const ACTIONS = ['read', 'draft', 'submit', 'draft-appeal', 'appeal', 'monitor', 'correspond'];

/**
 * Which Agent Identity Card capability each action requires.
 *
 * Drafting and filing are two actions, not one, and they are two for appeals for
 * exactly the reason they are two for applications. Preparing a document is
 * reversible and private. Filing it is neither: it is irreversible, it is visible
 * to the office, and for an appeal it starts or forfeits a clock. Until v0.3 the
 * appeal action required only "draft:appeal", so a person who authorised an agent
 * to draft an appeal had, without being told, authorised it to file one.
 */
const ACTION_REQUIRES = {
  read: 'read:program-information',
  draft: 'draft:application',
  submit: 'submit:application',
  'draft-appeal': 'draft:appeal',
  appeal: 'submit:appeal',
  monitor: 'monitor:status',
  correspond: 'correspond:on-behalf',
};

/**
 * Actions a purpose sentence has to actually mention. The check is deliberately
 * crude: it catches a grant that reaches further than the sentence the person
 * read, and it does not pretend to understand the sentence.
 *
 * Only runs when the purpose is present, which is on the person's own copy. A
 * verifier holding a withheld purpose cannot run this and does not need to: the
 * capability, which it can read, is the narrower of the two by construction.
 */
const PURPOSE_HINTS = {
  submit: /\b(submit|apply|application|file|lodge)\b/i,
  // Both appeal actions mention an appeal, so a shared pattern let a purpose
  // reading "draft an appeal for me to look at" satisfy the hint for the action
  // that actually files one. That is the exact confusion v0.3 split the actions
  // to prevent, and the purpose guard could not see it. Review finding,
  // 13 August 2026.
  //
  // Filing is therefore defined by what the sentence does NOT say. Testing for a
  // filing verb fails in both directions: "Appeal it on my behalf" names no verb
  // and plainly means file, while "for me to look at before anything is filed"
  // contains one and plainly means do not. So the filing hint asks for an appeal
  // and refuses any sentence that scopes itself to preparation.
  'draft-appeal': /\b(appeal|reconsider|reconsideration|review|challenge)\b/i,
  appeal:
    /^(?!.*\b(?:draft|drafts|drafted|drafting|prepare|prepares|prepared|preparing)\b)(?=.*\b(?:appeal|reconsider|reconsideration|review|challenge)\b)/is,
  correspond: /\b(correspond|write|contact|communicate|speak|reply)\b/i,
};

export function validate(adc, { aic, now = Date.now() } = {}) {
  const problems = [];

  if (adc.vct !== ADC_VCT) problems.push(`vct must be ${ADC_VCT}`);
  if (!adc.iss) problems.push('iss is required and must be the person\'s wallet, not the agent operator');
  if (!adc.exp) problems.push('exp is required');
  if (!adc.iat) problems.push('iat is required');

  if (adc.iat && adc.exp) {
    const life = adc.exp - adc.iat;
    if (life <= 0) problems.push('exp must be after iat');
    if (life > MAX_LIFETIME_SECONDS) {
      problems.push(
        `lifetime of ${Math.round(life / 86400)} days exceeds the ${MAX_LIFETIME_SECONDS / 86400}-day maximum; ` +
          'section 6 says hours or days, not months',
      );
    }
  }

  if (!adc.delegator?.sub) problems.push('delegator.sub is required');
  if (adc.delegator?.sub && !adc.delegator.pairwise) {
    // Section 6, and the privacy work item. A raw identifier reused across
    // verifiers correlates the person across every service they touch.
    //
    // **This flag is self-asserted and nothing here verifies it.** `pairwise`
    // is a boolean the wallet sets about its own behaviour. Nothing in this
    // library computes the derivation or can tell a genuinely per-verifier
    // subject identifier from one value reused everywhere with the flag turned
    // on, because the derivation input is the wallet's secret and never
    // travels. A wallet that lies here passes validation. Recorded in the
    // threat model at §9.1 and in its priority list as item 4, and left visibly
    // unenforced rather than dressed up as a check.
    problems.push('delegator.sub must be pairwise per verifier; set delegator.pairwise true to assert it');
  }
  if (!adc.delegator?.verified_by) problems.push('delegator.verified_by is required');

  // Presence only. Whether these two thumbprints describe the card and key
  // actually presented is decided in bindingBreaches(), which recomputes both;
  // a required field is not a binding until something compares it.
  if (!adc.delegate?.agent_id) problems.push('delegate.agent_id is required');
  if (!adc.delegate?.aic_thumbprint) problems.push('delegate.aic_thumbprint is required; a delegation binds to one card');
  if (!adc.delegate?.cnf_thumbprint) problems.push('delegate.cnf_thumbprint is required; and to one key');

  // The person's own sentence, and the commitment that proves it unchanged.
  // On the wallet's copy both are present. On a presentation the sentence is
  // withheld by default and only the commitment travels.
  if (adc.purpose !== undefined && adc.purpose.trim().length < 10) {
    problems.push('purpose, when present, is human-authored and must be a real sentence');
  }
  if (!adc.purpose_commitment) {
    problems.push(
      'purpose_commitment is required. It lets the person prove what they consented to ' +
        'without the sentence itself having to travel.',
    );
  }
  if (adc.purpose === undefined && adc.purpose_commitment === undefined) {
    problems.push('a delegation with neither a purpose nor a commitment records no consent at all');
  }

  if (!Array.isArray(adc.authorization_details) || adc.authorization_details.length === 0) {
    problems.push('authorization_details must be a non-empty array');
  } else {
    adc.authorization_details.forEach((d, i) => {
      if (!d.type) problems.push(`authorization_details[${i}].type is required`);
      if (!Array.isArray(d.actions) || d.actions.length === 0) {
        problems.push(`authorization_details[${i}].actions must be a non-empty array`);
      } else {
        const unknown = d.actions.filter((a) => !ACTIONS.includes(a));
        if (unknown.length) problems.push(`authorization_details[${i}] has unknown actions: ${unknown.join(', ')}`);
      }
      if (!d.capability) {
        problems.push(
          `authorization_details[${i}].capability is required. It is the public, ` +
            'subject-free description of what the agent may do.',
        );
      } else if (!(d.capability in CAPABILITIES)) {
        problems.push(
          `authorization_details[${i}].capability "${d.capability}" is not in the vocabulary. ` +
            `Known: ${Object.keys(CAPABILITIES).join(', ')}`,
        );
      } else {
        const permitted = actionsFor([d.capability]);
        const beyond = (d.actions ?? []).filter((a) => !permitted.includes(a));
        if (beyond.length) {
          problems.push(
            `authorization_details[${i}] grants ${beyond.join(', ')} but the capability ` +
              `"${d.capability}" only permits ${permitted.join(', ')}`,
          );
        }
      }

      // Naming the programme tells the verifier what it already knew and tells
      // everyone else something they should not have. See capability.js.
      if (Array.isArray(d.programs) && d.programs.length) {
        problems.push(
          `authorization_details[${i}].programs names a programme in the clear. ` +
            'The verifier already knows which office it is. Remove it.',
        );
      }
    });
  }

  if (!adc.consent?.record_uri) problems.push('consent.record_uri is required');
  if (!adc.consent?.captured_at) problems.push('consent.captured_at is required');
  if (!adc.consent?.language) problems.push('consent.language is required; it records what language they consented in');

  if (!adc.revocation?.revoke_uri) problems.push('revocation.revoke_uri is required');
  if (adc.revocation?.citizen_facing !== true) {
    problems.push(
      'revocation.citizen_facing must be true. Section 7 requires an endpoint reachable ' +
        'without signing in to any government system.',
    );
  }

  if (!adc.status?.status_list?.uri) problems.push('status.status_list.uri is required');

  if (adc.purpose !== undefined) problems.push(...purposeDisagreements(adc));
  problems.push(...screenDelegation(adc));
  if (aic) problems.push(...attenuationBreaches(adc, aic));

  return { ok: problems.length === 0, problems };
}

/** The narrower governs. A grant that outruns the sentence the person read is rejected. */
export function purposeDisagreements(adc) {
  const out = [];
  const purpose = adc.purpose ?? '';
  const granted = new Set((adc.authorization_details ?? []).flatMap((d) => d.actions ?? []));

  for (const [action, hint] of Object.entries(PURPOSE_HINTS)) {
    if (granted.has(action) && !hint.test(purpose)) {
      out.push(
        `authorization_details grants "${action}" but the purpose sentence never mentions it. ` +
          'The narrower governs, so this is rejected rather than trimmed.',
      );
    }
  }
  return out;
}

/**
 * Does this delegation authorise this action, yes or no.
 *
 * The question worth asking out loud is the appeal. A delegation scoped to
 * submitting an application does not carry an appeal, because an appeal is a
 * different capability and not a later step of the same one. So the answer here
 * is no, and the remedy is a second delegation the person grants after the
 * refusal rather than a wider one granted before it, when she had no reason to.
 */
export function permits(adc, action) {
  return (adc.authorization_details ?? []).some((d) => (d.actions ?? []).includes(action));
}

/** Authority narrows going down. Anything else is a bug in whoever built the chain. */
export function attenuationBreaches(adc, aic) {
  const out = [];
  const held = new Set(aic.capabilities ?? []);

  for (const d of adc.authorization_details ?? []) {
    for (const action of d.actions ?? []) {
      const needed = ACTION_REQUIRES[action];
      if (needed && !held.has(needed)) {
        out.push(
          `delegation grants "${action}" but the Agent Identity Card does not carry "${needed}". ` +
            'A delegation may only narrow what the card already holds.',
        );
      }
    }
  }

  if (adc.delegate?.agent_id && aic.agent?.id && adc.delegate.agent_id !== aic.agent.id) {
    out.push(`delegation names agent ${adc.delegate.agent_id} but the card is for ${aic.agent.id}`);
  }

  // A card that says it never acts without approval must be delegated the same way.
  if (aic.conduct?.acts_without_approval === false) {
    for (const d of adc.authorization_details ?? []) {
      const needs = new Set(d.constraints?.requires_human_approval ?? []);
      for (const action of d.actions ?? []) {
        if (['submit', 'appeal'].includes(action) && !needs.has(action)) {
          out.push(
            `the card states it never acts without approval, so "${action}" must appear in ` +
              'constraints.requires_human_approval',
          );
        }
      }
    }
  }

  return out;
}

/**
 * The binding. Recomputed, never merely read.
 *
 * `delegate.aic_thumbprint` and `delegate.cnf_thumbprint` are the whole point of
 * having two credentials instead of one: a delegation is granted to *that* agent,
 * carrying *that* card, holding *that* key. Until v0.3 both fields were checked
 * for presence and never compared to anything, which meant a delegation could be
 * handed to a verifier alongside a completely different agent's identity card and
 * nothing in this library noticed. That is the finding recorded as T3.3 in the
 * threat model, and it is closed here.
 *
 * Three comparisons, all against what actually arrived:
 *
 *   1  the thumbprint of the Agent Identity Card presented in this exchange
 *   2  the thumbprint of the key that signed this presentation, which is the
 *      key in the delegation's own `cnf` and is the one the Key Binding JWT was
 *      just verified against
 *   3  that the card and the delegation name the same holder key, so a valid
 *      card and a valid delegation belonging to two different agents cannot be
 *      stapled together
 *
 * Absent evidence is a failure, not a pass. A verifier that was handed no card
 * to compare against cannot claim it checked the binding, so it says so and
 * rejects.
 */
export async function bindingBreaches(adc, { aic, presentedCard, aicThumbprint } = {}) {
  const out = [];

  const claimedCard = adc.delegate?.aic_thumbprint;
  const actualCard = aicThumbprint ?? (presentedCard ? await cardThumbprint(presentedCard) : undefined);

  if (actualCard === undefined) {
    out.push(
      'the card binding could not be checked: no Agent Identity Card was presented with this ' +
        'delegation. Pass the presented card as "presentedCard", or its thumbprint as ' +
        '"aicThumbprint" from aic.verify(). An unchecked binding is a failed binding.',
    );
  } else if (claimedCard !== actualCard) {
    out.push(
      `aic_thumbprint binding failed: this delegation was granted to the card ${claimedCard} ` +
        `and the card presented with it is ${actualCard}. A delegation is not transferable between agents.`,
    );
  }

  const presentedKey = adc.cnf?.jwk;
  if (!presentedKey) {
    out.push(
      'the key binding could not be checked: the delegation carries no cnf.jwk, so there is ' +
        'nothing to compare delegate.cnf_thumbprint against.',
    );
  } else {
    const actualKey = await thumbprint(presentedKey);
    if (adc.delegate?.cnf_thumbprint !== actualKey) {
      out.push(
        `cnf_thumbprint binding failed: this delegation was granted to the key ` +
          `${adc.delegate?.cnf_thumbprint} and the key that signed this presentation is ${actualKey}.`,
      );
    }
  }

  // The card and the delegation must be held by the same key. Without this, two
  // separately valid credentials belonging to two different agents could be
  // presented together.
  //
  // This was gated on `aic?.cnf?.jwk` until the review of 13 August 2026, which
  // meant a caller following the documented `aicThumbprint` route got checks 1
  // and 2 and skipped this one in silence. Checking two of three bindings and
  // reporting no breach is the failure this whole function was written to end.
  const cardKeyJwk = aic?.cnf?.jwk;
  if (!cardKeyJwk) {
    out.push(
      'the holder binding could not be checked: no Agent Identity Card claims were supplied, ' +
        'or the card carries no cnf.jwk, so there is nothing to compare the delegation holder ' +
        'against. Pass the verified card as "aic". An unchecked binding is a failed binding.',
    );
  } else if (presentedKey) {
    const cardKey = await thumbprint(cardKeyJwk);
    const delegationKey = await thumbprint(presentedKey);
    if (cardKey !== delegationKey) {
      out.push(
        `holder binding failed: the Agent Identity Card is held by key ${cardKey} and the ` +
          `delegation by key ${delegationKey}. They are not the same agent.`,
      );
    }
  }

  return out;
}

/**
 * Issue a delegation.
 *
 * The purpose is committed to and then hidden by default. `selective` defaults
 * to hiding it rather than requiring every caller to remember, because a
 * default that has to be remembered is not a default. Passing an explicit
 * `selective` that omits "purpose" puts the person's sentence in the clear and
 * is refused.
 *
 * Returns the credential and the salt. **The salt belongs to the person**, and
 * without it they cannot later prove which sentence they consented to.
 */
export async function issue({ adc, aic, walletKey, holderJwk, kid, alg = 'ES256', selective = ['purpose'], pairwise }) {
  // Compute the pairwise subject rather than trusting the caller to have got it
  // right. Threat model priority 4: the flag was self-asserted and nothing
  // computed anything, so a wallet author who reused a subject because deriving
  // one is fiddly passed validation. Making the library do it removes the
  // fiddliness, which is the actual cause.
  if (pairwise) {
    const { derive } = await import('./pairwise.js');
    adc = {
      ...adc,
      delegator: {
        ...adc.delegator,
        sub: derive(pairwise),
        pairwise: true,
        sub_audience: pairwise.verifierId,
      },
    };
  }

  if (adc.purpose !== undefined && !selective.includes('purpose')) {
    throw new Error(
      'refusing to issue a delegation with the purpose in the clear. ' +
        'The sentence names what the person is going through; the capability is what the verifier reads.',
    );
  }

  let payload = adc;
  let salt = null;
  if (adc.purpose !== undefined && !adc.purpose_commitment) {
    const committed = commitPurpose(adc.purpose);
    salt = committed.salt;
    payload = { ...adc, purpose_commitment: committed.commitment };
  }

  const { ok, problems } = validate(payload, { aic });
  if (!ok) throw new Error(`Agent Delegation Credential is not conforming:\n  - ${problems.join('\n  - ')}`);

  const credential = await sdIssue({
    payload,
    selective: selective.filter((c) => c in payload),
    privateKey: walletKey,
    holderJwk,
    kid,
    alg,
  });
  return { credential, salt, purpose_commitment: payload.purpose_commitment };
}

/**
 * Present a delegation to a verifier.
 *
 * Withholds the purpose unless the person explicitly chooses to show it. This
 * exists as its own function rather than leaving callers to use the general
 * SD-JWT `present()`, whose default is to reveal every disclosure. That default
 * is correct for a general library and wrong here: it would mean the person's
 * sentence travels whenever somebody forgets an argument, and a privacy
 * property that depends on remembering is not a property.
 *
 * `disclosePurpose` is the person's decision and nobody else's. There is no
 * verifier-side option to require it, on purpose.
 */
export async function present(credential, { audience, nonce, holderKey, disclosePurpose = false, alg = 'ES256' }) {
  return sdPresent(credential, {
    reveal: disclosePurpose ? ['purpose'] : [],
    audience,
    nonce,
    holderKey,
    alg,
  });
}

/**
 * Verify a presented delegation.
 *
 * `presentedCard` is the Agent Identity Card as it arrived in this same exchange,
 * or `aicThumbprint` is the value `aic.verify()` returned for it. One of the two
 * is required whenever a card is supplied, because the binding is checked against
 * the card that was presented and not against a card object a caller assembled.
 */
export async function verify(presented, {
  walletKey,
  aic,
  presentedCard,
  aicThumbprint,
  audience,
  nonce,
  now = Date.now(),
}) {
  // The card is not optional here. validate() skips attenuation when it has no
  // card to narrow against, and bindingBreaches() cannot compare holders without
  // one, so a verify() call with no `aic` was quietly checking neither the
  // headline invariant of the specification nor the third of three bindings, and
  // returning success. Review finding, 13 August 2026.
  if (!aic) {
    throw new Error(
      'verify requires the Agent Identity Card as "aic". Without it, attenuation is not ' +
        'checked and the card-to-delegation holder binding is not checked. Verifying a ' +
        'delegation against no card is not a weaker check, it is a different and much ' +
        'smaller one, and it must not report success.',
    );
  }

  // The issuer of a delegation is the person's wallet, so the "issuer key" here
  // is the wallet's key. Naming it walletKey at the boundary keeps callers from
  // reaching for the agent operator's key by habit.
  const result = await sdVerify(presented, { issuerKey: walletKey, audience, nonce, requireKeyBinding: true, now });
  const adc = result.claims;

  if (adc.vct !== ADC_VCT) throw new Error(`not an Agent Delegation Credential: vct is ${adc.vct}`);

  const { ok, problems } = validate(adc, { aic, now });
  if (!ok) throw new Error(`presented delegation is not conforming:\n  - ${problems.join('\n  - ')}`);

  // Where the verifier tells us who it is, check the subject was minted for it.
  // Optional because a verifier that does not know its own federation entity id
  // cannot do this, and refusing to verify at all would be worse.
  if (audience) {
    const { boundToVerifier } = await import('./pairwise.js');
    const bound = boundToVerifier(adc.delegator, audience);
    if (!bound.ok) {
      throw new Error(`the delegator subject is not bound to this verifier:\n  - ${bound.problems.join('\n  - ')}`);
    }
  }

  const breaches = await bindingBreaches(adc, { aic, presentedCard, aicThumbprint });
  if (breaches.length) {
    throw new Error(`presented delegation is not bound to what was presented with it:\n  - ${breaches.join('\n  - ')}`);
  }

  return { ...result, adc };
}

/**
 * What the **person** is shown, at the moment of granting and afterwards.
 *
 * This is their own copy, so it names what they are actually doing. For what a
 * caseworker sees, which is the subject-free version, use
 * `capability.explainToVerifier()`. Keeping these as two functions is the whole
 * point: one audience gets the sentence, the other gets the shape.
 */
export function explain(adc) {
  const actions = [...new Set((adc.authorization_details ?? []).flatMap((d) => d.actions ?? []))];
  const approval = [
    ...new Set((adc.authorization_details ?? []).flatMap((d) => d.constraints?.requires_human_approval ?? [])),
  ];
  const lines = [
    `Purpose, in their words: ${adc.purpose}`,
    `The agent may: ${actions.join(', ')}`,
  ];
  if (approval.length) lines.push(`It must come back for approval before it can: ${approval.join(', ')}`);
  lines.push(`This authority ends: ${new Date(adc.exp * 1000).toISOString()}`);
  lines.push(`They can withdraw it at any time here: ${adc.revocation?.revoke_uri}`);
  return lines.join('\n');
}
