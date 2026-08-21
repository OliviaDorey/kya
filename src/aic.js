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

/**
 * How a residency claim is known. Ordered weakest to strongest, and a verifier
 * is entitled to treat them differently.
 *
 *   asserted     the operator says so, and nothing backs it
 *   contractual  the model provider is contractually bound to the region
 *   attested     a third party has assessed it and can be held to the finding
 *
 * "asserted" is permitted rather than banned, for the same reason
 * model.disclosed may be false: an honest weak claim is worth more than a
 * missing one, and banning it only produces stronger words for the same fact.
 */
export const RESIDENCY_BASIS = ['asserted', 'contractual', 'attested'];

/**
 * Succession states. Added 20 August 2026.
 *
 * An agent that stops working is one of the most consequential things that can
 * happen to the person relying on it, and until now the specification had
 * nothing to say about it. Revocation covers authority being withdrawn. This
 * covers the working life ending.
 *
 * `retiring` exists so the notice period is a state rather than an intention:
 * an agent that will be gone in thirty days is a different thing to a verifier,
 * and to a person, than one that is gone.
 */
export const SUCCESSION = { ACTIVE: 'active', RETIRING: 'retiring', RETIRED: 'retired' };

/**
 * What happens to a delegation when the operator changes. Added 20 August 2026.
 *
 * VOID is the default everywhere in this library, and it is what the code
 * already did before anyone chose it: a reissued card no longer matches, so the
 * delegation fails. The other two are deliberate softenings and each requires
 * the terms to be otherwise unchanged.
 *
 * The threshold between them belongs to the registrar rather than to any
 * implementer, or the standard is read as one vendor's preference.
 */
export const TRANSFER_POLICY = { NOTIFY: 'notify', RE_CONSENT: 're-consent', VOID: 'void' };

export const SELECTIVELY_DISCLOSABLE = ['model', 'assurance'];
export const ALWAYS_DISCLOSED = ['agent', 'accountable', 'conduct', 'capabilities', 'cnf', 'status', 'builder'];

/**
 * Claims that may be absent but may never be *hidden*.
 *
 * Succession is optional in v0.5 so that cards issued before it existed remain
 * valid. But a card that says it is retiring and then withholds that fact from
 * a particular verifier would be worse than one that never said it, so the
 * moment it is present it is not selectively disclosable. Absence is a state;
 * concealment is not.
 */
export const NEVER_WITHHELD = ['succession', 'transfer'];

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

  // Section 5A, succession. Optional in v0.5 so existing cards remain valid, and
  // strictly checked the moment it is present. A card that says it is retiring
  // and will not say what happens next is the accountability sink this whole
  // specification exists to prevent, so it is refused at issue time rather than
  // flagged for somebody to notice later.
  if (card.succession !== undefined) {
    const su = card.succession;
    if (!Object.values(SUCCESSION).includes(su.state)) {
      problems.push(`succession.state must be one of: ${Object.values(SUCCESSION).join(', ')}`);
    }
    if (su.state === SUCCESSION.RETIRING || su.state === SUCCESSION.RETIRED) {
      if (!su.effective) {
        problems.push('succession.effective is required once an agent is retiring or retired');
      }
      // Absent is refused; an explicit null is accepted. "Nobody takes this on"
      // is a legitimate answer and a silence is not, on the same principle as
      // model.disclosed and rule_basis.
      if (!('successor' in su)) {
        problems.push(
          'succession.successor is required when retiring or retired. State the successor agent '
          + 'id, or state null to say plainly that there is none. Omitting it leaves the person '
          + 'relying on this agent with no answer at all.',
        );
      } else if (su.successor !== null && !/^urn:agent:/.test(String(su.successor))) {
        problems.push('succession.successor should be a urn:agent: identifier, or null');
      }
      if (!('notice' in su)) {
        problems.push(
          'succession.notice is required when retiring or retired: an object recording when the '
          + 'people relying on this agent were told, and where they can read it. A retirement '
          + 'nobody was told about is an abandonment.',
        );
      } else if (su.notice !== null && !su.notice?.given_at) {
        problems.push('succession.notice.given_at is required; it is the date the people relying on this agent were told');
      }
      if (su.notice === null) {
        problems.push('succession.notice may not be null. Somebody has to have been told.');
      }
    }
  }

  // Section 5B, transfer. A change of operator is the one vital event with no
  // mechanism anywhere, and the person who granted authority to an agent run by
  // a company they chose did not grant it to whoever bought that company.
  //
  // Notice is a condition of validity rather than a courtesy. A transfer nobody
  // was told about is indistinguishable, from where the person stands, from an
  // agent quietly changing hands.
  if (card.transfer !== undefined) {
    const t = card.transfer;
    if (!t.from?.legal_name) {
      problems.push('transfer.from.legal_name is required: who operated this agent before');
    }
    if (!t.effective) problems.push('transfer.effective is required: the date control changed');
    if (t.notice === null || t.notice === undefined) {
      problems.push(
        'transfer.notice is required and may not be null. Record when the people who delegated to '
        + 'this agent were told, and where they can read it. A transfer nobody was told about is '
        + 'not a lighter kind of transfer, it is an unrecorded one.',
      );
    } else if (!t.notice.given_at) {
      problems.push('transfer.notice.given_at is required; it is the date the delegators were told');
    }
    if (t.policy !== undefined && !Object.values(TRANSFER_POLICY).includes(t.policy)) {
      problems.push(`transfer.policy must be one of: ${Object.values(TRANSFER_POLICY).join(', ')}`);
    }
    if (t.from?.legal_name && card.operator?.legal_name
        && t.from.legal_name === card.operator.legal_name
        && t.from.jurisdiction === card.operator.jurisdiction) {
      problems.push(
        'transfer.from names the same operator as operator: a transfer that transfers nothing is '
        + 'either a mistake or a way to make a real transfer look routine.',
      );
    }
  }

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

  // `model.hosted_in` must say how it is known, on the same principle as
  // rule_basis: a claim may not wear the clothes of a verified fact.
  //
  // This is the field a procurement reviewer tests first, because it is the one
  // that decides whether a jurisdiction can use the thing at all. A card
  // presented to a caseworker reading "hosted in CA" asserts something specific
  // about where the person's words were sent, and until v0.5 nothing in this
  // library checked it, nothing recorded how it was established, and a verifier
  // had no way to tell a contractual commitment from a hopeful string. Audit
  // finding, 14 August 2026, prompted by finding a sibling product asserting
  // Canadian handling while calling an American inference endpoint.
  if (card.model?.hosted_in !== undefined) {
    if (!/^[A-Z]{2}$/.test(card.model.hosted_in)) {
      problems.push('model.hosted_in must be an ISO 3166-1 alpha-2 country code, e.g. "CA"');
    }
    if (!RESIDENCY_BASIS.includes(card.model.residency_basis)) {
      problems.push(
        `model.hosted_in is claimed without a model.residency_basis saying how it is known. ` +
          `One of: ${RESIDENCY_BASIS.join(', ')}. A residency claim nobody can weigh is the ` +
          'field a procurement reviewer tests first, and "we say so" and "our provider is ' +
          'contractually bound" are not the same assurance.',
      );
    }
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
  const hidden = (selective ?? []).filter((k) => NEVER_WITHHELD.includes(k));
  if (hidden.length) {
    throw new Error(
      `these claims may never be selectively withheld: ${hidden.join(', ')}. A card that says it `
      + 'is retiring and then hides that from one verifier is worse than one that never said it.',
    );
  }
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

/**
 * Verify an Agent Identity Card.
 *
 * Supply **either** `issuerKey`, a key the caller has already established by
 * some means it can defend, **or** `trust: { anchor }`, in which case the
 * issuer's key is resolved from the federation: the card's own `iss` is looked
 * up, its chain to the anchor is validated, and the key comes from the
 * statement the anchor signs about it rather than from anything the issuer says
 * about itself.
 *
 * Threat model priority 2. Until 14 August 2026 this function verified against
 * whatever key it was handed and the federation code sat unconnected in the
 * same repository, which meant a correct-looking signature check that answered
 * a question nobody had asked.
 */
export async function verify(presented, { issuerKey, trust, audience, nonce, requireKeyBinding = true, now }) {
  if (!issuerKey && !trust?.anchor) {
    throw new Error(
      'verify needs either issuerKey, or trust: { anchor } to resolve the issuer key from the ' +
        'federation. Verifying a credential against no established key is not a weaker check, ' +
        'it is a different and much smaller one.',
    );
  }

  let resolved = null;
  let key = issuerKey;

  if (!key) {
    // The card has to be read before it can be verified, so that its `iss` can
    // be looked up. Nothing from this read is trusted: it selects which key to
    // check the signature against, and a lie here produces a key that fails.
    const { decodeJwt } = await import('jose');
    const claimedIssuer = decodeJwt(presented.split('~')[0])?.iss;
    if (!claimedIssuer) throw new Error('card carries no iss, so no issuer key can be resolved for it');

    const federation = await import('./federation.js');
    resolved = await federation.resolveIssuerKeys(trust.anchor, claimedIssuer);

    if (!resolved.pinnedAnchor && trust.requirePinnedAnchor !== false) {
      throw new Error(
        `the trust anchor ${trust.anchor.entityId} was fetched without a pin, so resolving a key ` +
          'through it establishes nothing. Pin the anchor, or pass trust.requirePinnedAnchor: false ' +
          'and accept that this verification rests on an unauthenticated anchor.',
      );
    }

    // Try each key the federation names for this issuer. More than one is
    // normal during a rotation, and refusing to try the second is how a routine
    // key rotation becomes an outage.
    let lastError;
    for (const candidate of resolved.keys) {
      try {
        await sdVerify(presented, { issuerKey: candidate.key, audience, nonce, requireKeyBinding, now });
        key = candidate.key;
        break;
      } catch (err) {
        lastError = err;
      }
    }
    if (!key) {
      throw new Error(
        `card claims to be issued by ${claimedIssuer}, and it does not verify against any of the ` +
          `${resolved.keys.length} key(s) the federation names for that issuer: ${lastError?.message}`,
      );
    }
  }

  const result = await sdVerify(presented, { issuerKey: key, audience, nonce, requireKeyBinding, now });
  const card = result.claims;

  if (resolved && card.iss !== resolved.issuer) {
    throw new Error(`card iss "${card.iss}" is not the issuer whose key was resolved (${resolved.issuer})`);
  }

  if (card.vct !== AIC_VCT) throw new Error(`not an Agent Identity Card: vct is ${card.vct}`);

  // Re-check the invariants on receipt. A card issued by somebody else's
  // implementation gets held to the same rules as one we issued.
  for (const c of ALWAYS_DISCLOSED) {
    if (c === 'builder') continue;   // builder.registry_id may be withheld; the object may not
    if (card[c] === undefined) throw new Error(`Agent Identity Card is missing "${c}", which may never be withheld`);
  }
  // Section 5A, succession. Optional in v0.5 so existing cards remain valid, and
  // strictly checked the moment it is present. A card that says it is retiring
  // and will not say what happens next is the accountability sink this whole
  // specification exists to prevent, so it is refused at issue time rather than
  // flagged for somebody to notice later.
  if (card.succession !== undefined) {
    const su = card.succession;
    if (!Object.values(SUCCESSION).includes(su.state)) {
      problems.push(`succession.state must be one of: ${Object.values(SUCCESSION).join(', ')}`);
    }
    if (su.state === SUCCESSION.RETIRING || su.state === SUCCESSION.RETIRED) {
      if (!su.effective) {
        problems.push('succession.effective is required once an agent is retiring or retired');
      }
      // Absent is refused; an explicit null is accepted. "Nobody takes this on"
      // is a legitimate answer and a silence is not, on the same principle as
      // model.disclosed and rule_basis.
      if (!('successor' in su)) {
        problems.push(
          'succession.successor is required when retiring or retired. State the successor agent '
          + 'id, or state null to say plainly that there is none. Omitting it leaves the person '
          + 'relying on this agent with no answer at all.',
        );
      } else if (su.successor !== null && !/^urn:agent:/.test(String(su.successor))) {
        problems.push('succession.successor should be a urn:agent: identifier, or null');
      }
      if (!('notice' in su)) {
        problems.push(
          'succession.notice is required when retiring or retired: an object recording when the '
          + 'people relying on this agent were told, and where they can read it. A retirement '
          + 'nobody was told about is an abandonment.',
        );
      } else if (su.notice !== null && !su.notice?.given_at) {
        problems.push('succession.notice.given_at is required; it is the date the people relying on this agent were told');
      }
      if (su.notice === null) {
        problems.push('succession.notice may not be null. Somebody has to have been told.');
      }
    }
  }

  // Section 5B, transfer. A change of operator is the one vital event with no
  // mechanism anywhere, and the person who granted authority to an agent run by
  // a company they chose did not grant it to whoever bought that company.
  //
  // Notice is a condition of validity rather than a courtesy. A transfer nobody
  // was told about is indistinguishable, from where the person stands, from an
  // agent quietly changing hands.
  if (card.transfer !== undefined) {
    const t = card.transfer;
    if (!t.from?.legal_name) {
      problems.push('transfer.from.legal_name is required: who operated this agent before');
    }
    if (!t.effective) problems.push('transfer.effective is required: the date control changed');
    if (t.notice === null || t.notice === undefined) {
      problems.push(
        'transfer.notice is required and may not be null. Record when the people who delegated to '
        + 'this agent were told, and where they can read it. A transfer nobody was told about is '
        + 'not a lighter kind of transfer, it is an unrecorded one.',
      );
    } else if (!t.notice.given_at) {
      problems.push('transfer.notice.given_at is required; it is the date the delegators were told');
    }
    if (t.policy !== undefined && !Object.values(TRANSFER_POLICY).includes(t.policy)) {
      problems.push(`transfer.policy must be one of: ${Object.values(TRANSFER_POLICY).join(', ')}`);
    }
    if (t.from?.legal_name && card.operator?.legal_name
        && t.from.legal_name === card.operator.legal_name
        && t.from.jurisdiction === card.operator.jurisdiction) {
      problems.push(
        'transfer.from names the same operator as operator: a transfer that transfers nothing is '
        + 'either a mistake or a way to make a real transfer look routine.',
      );
    }
  }

  if (card.conduct?.discloses_ai !== 'always') {
    throw new Error('Agent Identity Card claims it does not always disclose that it is an agent. Rejected.');
  }

  return {
    ...result,
    card,
    thumbprint: await cardThumbprint(presented),
    // How this card's issuer key was established, so a caller can log the
    // difference between "the federation vouches for this issuer" and "somebody
    // handed us a key". Those are not the same fact and a verifier that records
    // them identically cannot audit its own trust decisions later.
    issuerTrust: resolved
      ? { via: 'federation', anchor: resolved.anchor, issuer: resolved.issuer, pinnedAnchor: resolved.pinnedAnchor }
      : { via: 'caller-supplied-key', anchor: null, issuer: null, pinnedAnchor: false },
  };
}

/** Binds a delegation to one specific card. Over the issuer JWT, not the disclosures. */
/**
 * The material terms of a card, as a stable digest.
 *
 * ── Why this exists ────────────────────────────────────────────────────────
 *
 * `cardThumbprint()` hashes the issued credential, so it changes whenever the
 * card is reissued — including a reissue with identical claims, because the
 * signature and the disclosure salts differ. That makes it a binding to a
 * *document*. It is the right check for "is this the exact card I was shown",
 * and the wrong one for "is this the agent I authorised", and until 20 August
 * 2026 it was being used for both.
 *
 * This digest covers only the claims a person was actually agreeing to when
 * they granted a delegation: who built and runs the agent, who answers for it,
 * what it may ever do, how it behaves, where its model sits and on what basis
 * that is known, and whether it is being retired. Reissue the card with those
 * unchanged and the digest is unchanged. Change any of them and it moves.
 *
 * ── What it can and cannot cover, which is a real limit ────────────────────
 *
 * Only claims in ALWAYS_DISCLOSED. A verifier cannot detect a change in a claim
 * it was never shown, so including selectively disclosable ones would make the
 * digest fail whenever disclosure varied rather than whenever terms changed —
 * which is worse than useless, because it would fire constantly and be switched
 * off. Found the hard way on 20 August 2026: the first version covered `model`
 * and every real presentation failed, because the demo withholds it.
 *
 * The consequence is stated rather than hidden: **a change to the model family
 * or its hosting country does not move this digest**, so continuity across a
 * reissue does not protect a person against that particular change. A relying
 * party that cares about model residency has to require it disclosed and check
 * it itself. That is a property of selective disclosure, not of this design,
 * and the honest place for it is here rather than in a footnote.
 *
 * Also excluded: iat, exp, jti, the status list index, and assurance. The first
 * four are bookkeeping. Assurance is excluded on purpose because an agent
 * *gaining* a certification should not invalidate delegations already granted
 * against it — the terms improved, and nobody needs re-asking.
 */
export async function termsDigest(card) {
  const material = {
    agent: { id: card.agent?.id },
    builder: card.builder,
    operator: card.operator,
    accountable: card.accountable,
    capabilities: [...(card.capabilities ?? [])].sort(),
    conduct: card.conduct,
    succession: card.succession === undefined ? undefined : { state: card.succession.state },
    // Included so a change of control is detectable even where the operator's
    // legal name does not move, which is what a share sale looks like.
    transfer: card.transfer === undefined ? undefined : { effective: card.transfer.effective },
  };
  const stable = (v) => {
    if (Array.isArray(v)) return v.map(stable);
    if (v && typeof v === 'object') {
      return Object.keys(v).sort().reduce((a, k) => {
        if (v[k] !== undefined) a[k] = stable(v[k]);
        return a;
      }, {});
    }
    return v;
  };
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(JSON.stringify(stable(material)), 'utf8').digest('base64url');
}

export async function cardThumbprint(presented) {
  const { createHash } = await import('node:crypto');
  const jwt = presented.split('~')[0];
  return createHash('sha256').update(jwt, 'ascii').digest('base64url');
}

export { thumbprint as jwkThumbprint };
