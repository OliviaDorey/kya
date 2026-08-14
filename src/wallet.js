/**
 * Minting an unlinkable set. The wallet side of the correlation problem.
 *
 * ── What the probe found, 14 August 2026 ───────────────────────────────────
 *
 * `pairwise.js` made `delegator.sub` per-verifier. `conformance.probeUnlinkability`
 * then compared two people across three offices and found the subject was the
 * only thing that varied. **Nine other always-disclosed fields were constant
 * across verifiers and unique to the person**, so any two offices could still
 * join their files exactly, and the pairwise subject achieved nothing on its own.
 * A correlation you move to the neighbouring field is a correlation you still
 * have.
 *
 * The nine split into two kinds, and only one of them is a bug.
 *
 * **Data hygiene, fixed here.** `purpose_commitment` reused one salt across the
 * set, so the same hash travelled to every office. `consent.record_uri` named one
 * consent act, correctly, and thereby handed every office the same string.
 * `consent.captured_at` carried millisecond precision, which is a fingerprint.
 * `revocation.revoke_uri` was one URI for a set. All four are avoidable and this
 * file avoids them.
 *
 * **Structural, and a real cost.** `iss`, `cnf.jwk`, `delegate.cnf_thumbprint`,
 * `delegate.aic_thumbprint` and `delegate.agent_id` are constant because the
 * person has *one agent*, holding *one key*, carrying *one card*, and their
 * wallet signs with *one identity*. No amount of field-level care fixes that.
 * Unlinkability requires a distinct agent key and a distinct Agent Identity Card
 * per verifier, and that is an architecture decision with a bill attached: the
 * issuer issues N cards instead of one, and the agent manages N keys.
 *
 * `issueSet()` does it properly and `describeCost()` states the bill, because a
 * privacy property whose cost is hidden gets removed by whoever discovers the
 * cost later.
 */

import { randomBytes } from 'node:crypto';
import { derive as derivePairwise } from './pairwise.js';
import { commitPurpose } from './capability.js';
import { issue as issueDelegation } from './adc.js';

/**
 * A per-verifier reference to one consent act.
 *
 * The person granted once and there is one consent record; what must not travel
 * is the same *pointer* to every office. So each credential carries a reference
 * derived for its verifier, and the wallet keeps the mapping back to the real
 * record. The person can still prove they all came from one grant, because they
 * hold the secret and can recompute any of them.
 */
export function consentReference({ walletSecret, consentId, verifierId }) {
  return derivePairwise({ walletSecret, verifierId: `consent:${consentId}:${verifierId}` }).replace(/^pw:/, 'cr:');
}

/**
 * Timestamps get rounded to the day.
 *
 * `captured_at` to the millisecond is unique to one person's one action, and it
 * was a confirmed correlator in the probe. The day is what a consent record
 * actually needs to be meaningful — it answers "when did they agree to this" for
 * every purpose a caseworker or an auditor has — and it puts the person in a
 * herd of everyone who consented that day instead of a herd of one.
 */
export function coarsenTimestamp(iso) {
  return `${new Date(iso).toISOString().slice(0, 10)}T00:00:00.000Z`;
}

/**
 * Mint one delegation per verifier from a single consent act, sharing nothing
 * that identifies the person.
 *
 * `perVerifier(verifierId)` must return `{ aic, walletKey, holderJwk }` — the
 * **distinct** card, wallet signing key and agent holder key for that verifier.
 * It is a required callback rather than an optional one because the structural
 * half of unlinkability cannot be done for the caller: this library does not
 * hold their keys and cannot issue their cards. Making it required means a
 * caller has to decide about it rather than discover it in a probe later.
 */
export async function issueSet({ base, verifiers, walletSecret, consentId, perVerifier, purpose }) {
  if (typeof perVerifier !== 'function') {
    throw new Error(
      'issueSet needs perVerifier(verifierId) returning a distinct { aic, walletKey, holderJwk } ' +
        'for each verifier. One agent key and one card across a set makes every other precaution ' +
        'decorative: see describeCost() for what this actually requires.',
    );
  }
  if (!walletSecret || !consentId) throw new Error('issueSet needs walletSecret and consentId');

  const out = [];
  const seen = new Map();

  for (const verifierId of verifiers) {
    const material = await perVerifier(verifierId);
    if (!material?.aic || !material?.walletKey || !material?.holderJwk) {
      throw new Error(`perVerifier("${verifierId}") must return { aic, walletKey, holderJwk }`);
    }

    // Refuse a caller who returns the same holder key twice. This is the exact
    // mistake the probe found, and catching it here is cheaper than catching it
    // in an audit.
    const keyId = JSON.stringify(material.holderJwk);
    if (seen.has(keyId)) {
      throw new Error(
        `perVerifier returned the same agent key for "${verifierId}" and "${seen.get(keyId)}". ` +
          'Those two offices can join their files on it, whatever else this set gets right.',
      );
    }
    seen.set(keyId, verifierId);

    // A fresh salt per credential, so the same sentence does not produce the
    // same commitment at every office.
    const committed = purpose ? commitPurpose(purpose, randomBytes(16).toString('base64url')) : null;

    const adcClaims = {
      ...base,
      ...(committed ? { purpose, purpose_commitment: committed.commitment } : {}),
      consent: {
        ...base.consent,
        record_uri: consentReference({ walletSecret, consentId, verifierId }),
        captured_at: coarsenTimestamp(base.consent?.captured_at ?? new Date().toISOString()),
      },
      revocation: {
        ...base.revocation,
        revoke_uri: `${String(base.revocation?.revoke_uri ?? 'https://revoke.agentcredential.ca/d').replace(/\/[^/]*$/, '')}/${consentReference({ walletSecret, consentId, verifierId }).slice(3, 19)}`,
      },
    };

    const issued = await issueDelegation({
      adc: adcClaims,
      aic: material.aic,
      walletKey: material.walletKey,
      holderJwk: material.holderJwk,
      pairwise: { walletSecret, verifierId },
    });

    out.push({ verifier: verifierId, ...issued, salt: committed?.salt ?? issued.salt });
  }

  return out;
}

/**
 * The bill, stated out loud.
 *
 * Every privacy property in this specification is a trade, and this one is the
 * most expensive. A person dealing with three offices needs three agent keys,
 * three Agent Identity Cards and three delegations, and the issuer has to issue
 * three cards rather than one. Someone will eventually propose sharing a card
 * "just for now" to reduce that, and the honest answer is that doing so reverts
 * the property entirely rather than weakening it a little.
 */
export function describeCost(verifierCount) {
  return {
    agent_keys: verifierCount,
    identity_cards: verifierCount,
    delegations: verifierCount,
    consent_acts: 1,
    what_the_person_sees: 'one grant, because the wallet groups the set behind a single consent record',
    what_it_costs:
      `${verifierCount} card issuances instead of 1, and ${verifierCount} keys for the agent to manage.`,
    if_you_share_a_card_instead:
      'the set becomes linkable on delegate.aic_thumbprint and the entire property is gone. This is ' +
      'not a partial weakening; two offices can join their files exactly, the same as before any of ' +
      'this was built.',
  };
}
