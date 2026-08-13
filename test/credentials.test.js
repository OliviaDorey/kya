/**
 * The properties this specification actually promises.
 *
 * Each test is named after the promise it defends, so a failure tells you which
 * commitment just stopped being true rather than which function returned the
 * wrong shape.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';

import * as sdjwt from '../src/sdjwt.js';
import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as status from '../src/status.js';
import * as determination from '../src/determination.js';
import * as capability from '../src/capability.js';
import * as revocation from '../src/revocation.js';

const issuer = await generateKeyPair('ES256', { extractable: true });
const wallet = await generateKeyPair('ES256', { extractable: true });
const agent = await generateKeyPair('ES256', { extractable: true });
const other = await generateKeyPair('ES256', { extractable: true });
const agentJwk = await exportJWK(agent.publicKey);

const sec = Math.floor(Date.now() / 1000);
const AGENT_ID = 'urn:agent:kindred:steward:test';

const baseCard = () => ({
  vct: aic.AIC_VCT,
  iss: 'https://kya.thekindredagency.com',
  iat: sec,
  exp: sec + 86400,
  agent: { id: AGENT_ID, name: 'Steward', version: '1.0.0' },
  builder: { legal_name: 'The Kindred Agency Inc.', jurisdiction: 'CA-NS', registry_id: '1', uri: 'https://thekindredagency.com' },
  accountable: { role: 'CTO', contact: 'trust@thekindredagency.com', redress_uri: 'https://thekindredagency.com/redress' },
  model: { disclosed: true, family: 'claude-opus', version: '5', hosted_in: 'CA' },
  capabilities: ['read:program-information', 'draft:application', 'submit:application', 'draft:appeal', 'submit:appeal'],
  conduct: { discloses_ai: 'always', acts_without_approval: false, retains_after_revocation: 'audit-record-only' },
  status: { status_list: { uri: 'https://status.agentcredential.ca/aic', idx: 1 } },
});

/**
 * The real thumbprints, computed from the card and key actually used below.
 *
 * These were the string 'x' and the string 'y' until v0.3, which passed because
 * nothing compared them to anything. They are computed now because the binding
 * is enforced now.
 */
const issuedBaseCard = await aic.issue({ card: baseCard(), privateKey: issuer.privateKey, holderJwk: agentJwk });
const BASE_CARD_THUMB = await aic.cardThumbprint(issuedBaseCard);
const AGENT_KEY_THUMB = await aic.jwkThumbprint(agentJwk);

const baseDelegation = (over = {}) => ({
  vct: adc.ADC_VCT,
  iss: 'https://wallet.example.ca/u/1',
  iat: sec,
  exp: sec + 7 * 86400,
  delegator: { sub: 'pw:abc', pairwise: true, verified_by: 'https://account.alberta.ca/dts', assurance: 'substantial' },
  delegate: { agent_id: AGENT_ID, aic_thumbprint: BASE_CARD_THUMB, cnf_thumbprint: AGENT_KEY_THUMB },
  purpose: 'Apply for the Alberta Assured Income for the Severely Handicapped on my behalf, and appeal if I am refused.',
  purpose_commitment: capability.commitPurpose('x').commitment,
  authorization_details: [
    {
      type: 'ca_public_service_request',
      capability: 'submit:form',
      actions: ['draft', 'submit'],
      constraints: { requires_human_approval: ['submit'] },
    },
    {
      type: 'ca_public_service_request',
      capability: 'request:review',
      actions: ['draft-appeal', 'appeal'],
      constraints: { requires_human_approval: ['appeal'] },
    },
  ],
  consent: { record_uri: 'https://wallet.example.ca/c/1', captured_at: new Date().toISOString(), language: 'en-CA', method: 'in-app-explicit' },
  revocation: { revoke_uri: 'https://revoke.agentcredential.ca/d/1', citizen_facing: true },
  status: { status_list: { uri: 'https://status.agentcredential.ca/adc', idx: 1 } },
  ...over,
});

/** What she holds while the application is in flight: submission, and nothing else. */
const submitOnlyDelegation = (over = {}) => baseDelegation({
  purpose: 'Apply for the programme on my behalf and tell me what happens.',
  authorization_details: [
    {
      type: 'ca_public_service_request',
      capability: 'submit:form',
      actions: ['draft', 'submit'],
      constraints: { requires_human_approval: ['submit'] },
    },
  ],
  ...over,
});

/** What she grants after the refusal. A different capability, not a wider one. */
const appealDelegation = (over = {}) => baseDelegation({
  purpose: 'The decision went against me. Appeal it on my behalf and keep me told.',
  authorization_details: [
    {
      type: 'ca_public_service_request',
      capability: 'request:review',
      actions: ['draft-appeal', 'appeal'],
      constraints: { requires_human_approval: ['appeal'] },
    },
  ],
  consent: { record_uri: 'https://wallet.example.ca/c/2', captured_at: new Date().toISOString(), language: 'en-CA', method: 'in-app-explicit' },
  revocation: { revoke_uri: 'https://revoke.agentcredential.ca/d/2', citizen_facing: true },
  status: { status_list: { uri: 'https://status.agentcredential.ca/adc', idx: 2 } },
  ...over,
});

/** The same agent, on a card that was never given any appeal capability. */
const cardWithoutAppeal = () => ({
  ...baseCard(),
  capabilities: baseCard().capabilities.filter((c) => c !== 'draft:appeal' && c !== 'submit:appeal'),
});

// ───────────────────────────────────────────────────── SD-JWT

test('a withheld claim is distinguishable from an absent one', async () => {
  const issued = await sdjwt.issue({
    payload: { vct: 'x', a: 1, b: 2 },
    selective: ['b'],
    privateKey: issuer.privateKey,
  });
  const withheld = await sdjwt.present(issued, { reveal: [] });
  const shown = await sdjwt.present(issued, { reveal: ['b'] });

  const v1 = await sdjwt.verify(withheld, { issuerKey: issuer.publicKey });
  const v2 = await sdjwt.verify(shown, { issuerKey: issuer.publicKey });

  assert.equal(v1.claims.b, undefined);
  assert.deepEqual(v1.disclosed, []);
  assert.equal(v2.claims.b, 2);
  assert.deepEqual(v2.disclosed, ['b']);
});

test('a disclosure the issuer never signed fails the whole credential', async () => {
  const issued = await sdjwt.issue({ payload: { vct: 'x', a: 1 }, selective: ['a'], privateKey: issuer.privateKey });
  const forged = sdjwt.makeDisclosure('admin', true);
  const tampered = issued.replace('~', `~${forged}~`);
  await assert.rejects(
    () => sdjwt.verify(tampered, { issuerKey: issuer.publicKey }),
    /does not match any digest/,
  );
});

test('a KB-JWT signed for one verifier does not work at another', async () => {
  const issued = await sdjwt.issue({ payload: { vct: 'x' }, privateKey: issuer.privateKey, holderJwk: agentJwk });
  const presented = await sdjwt.present(issued, { audience: 'https://a.ca', nonce: 'n1', holderKey: agent.privateKey });
  await assert.rejects(
    () => sdjwt.verify(presented, { issuerKey: issuer.publicKey, audience: 'https://b.ca', nonce: 'n1' }),
    /audience mismatch/,
  );
});

test('a replayed presentation with a different nonce is refused', async () => {
  const issued = await sdjwt.issue({ payload: { vct: 'x' }, privateKey: issuer.privateKey, holderJwk: agentJwk });
  const presented = await sdjwt.present(issued, { audience: 'https://a.ca', nonce: 'n1', holderKey: agent.privateKey });
  await assert.rejects(
    () => sdjwt.verify(presented, { issuerKey: issuer.publicKey, audience: 'https://a.ca', nonce: 'n2' }),
    /nonce mismatch/,
  );
});

test('an expired credential is refused', async () => {
  const issued = await sdjwt.issue({ payload: { vct: 'x', exp: sec - 1 }, privateKey: issuer.privateKey });
  await assert.rejects(() => sdjwt.verify(issued, { issuerKey: issuer.publicKey }), /expired/);
});

// ───────────────────────────────────────────────────── Agent Identity Card

test('an agent that can be configured to deny being an agent cannot be issued a card', async () => {
  const card = baseCard();
  card.conduct.discloses_ai = 'when-asked';
  await assert.rejects(
    () => aic.issue({ card, privateKey: issuer.privateKey, holderJwk: agentJwk }),
    /discloses_ai must be "always"/,
  );
});

test('accountability can never be selectively disclosed', async () => {
  for (const claim of ['accountable', 'conduct', 'capabilities', 'agent']) {
    await assert.rejects(
      () => aic.issue({ card: baseCard(), privateKey: issuer.privateKey, holderJwk: agentJwk, selective: [claim] }),
      /can never be selectively disclosed/,
      `${claim} should not be hideable`,
    );
  }
});

test('a card with no accountable human is refused', async () => {
  const card = baseCard();
  delete card.accountable;
  const { ok, problems } = aic.validate(card);
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('accountable.contact')));
});

test('silence about the model is refused; "undisclosed" is fine', () => {
  const quiet = baseCard();
  delete quiet.model;
  assert.equal(aic.validate(quiet).ok, false);

  const undisclosed = { ...baseCard(), model: { disclosed: false } };
  assert.equal(aic.validate(undisclosed).ok, true);
});

test('a card signed by the wrong key does not verify', async () => {
  const issued = await aic.issue({ card: baseCard(), privateKey: issuer.privateKey, holderJwk: agentJwk });
  const presented = await sdjwt.present(issued, { reveal: [], audience: 'https://v.ca', nonce: 'n', holderKey: agent.privateKey });
  await assert.rejects(() => aic.verify(presented, { issuerKey: other.publicKey, audience: 'https://v.ca', nonce: 'n' }));
});

// ───────────────────────────────────────────────────── Delegation

test('a delegation may never grant more than the card holds', () => {
  const card = baseCard();   // has no correspond:on-behalf
  const wider = baseDelegation({
    purpose: 'Apply on my behalf, appeal if refused, and write to them for me.',
    authorization_details: [
      { type: 'x', capability: 'correspond:administrative', actions: ['correspond'], constraints: {} },
      { type: 'x', capability: 'submit:form', actions: ['draft', 'submit'], constraints: { requires_human_approval: ['submit'] } },
    ],
  });
  const { ok, problems } = adc.validate(wider, { aic: card });
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('correspond:on-behalf')));
  assert.ok(problems.some((p) => p.includes('may only narrow')));
});

test('the narrower of the purpose sentence and the grant governs', () => {
  const quiet = baseDelegation({ purpose: 'Have a look at what I might be able to get.' });
  const { ok, problems } = adc.validate(quiet, { aic: baseCard() });
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('grants "submit"') && p.includes('never mentions it')));
});

test('a card that never acts without approval forces approval into the delegation', () => {
  const noApproval = baseDelegation({
    authorization_details: [{ type: 'x', capability: 'submit:form', actions: ['draft', 'submit'], constraints: {} }],
  });
  const { problems } = adc.validate(noApproval, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('requires_human_approval')));
});

test('a delegation lasting months is refused', () => {
  const long = baseDelegation({ exp: sec + 200 * 86400 });
  const { problems } = adc.validate(long, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('exceeds')));
});

test('a non-pairwise delegator identifier is refused', () => {
  const raw = baseDelegation({
    delegator: { sub: '780-555-0134', verified_by: 'https://account.alberta.ca/dts' },
  });
  const { problems } = adc.validate(raw, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('pairwise')));
});

test('a revocation endpoint that needs a government login is refused', () => {
  const gated = baseDelegation({
    revocation: { revoke_uri: 'https://account.alberta.ca/revoke', citizen_facing: false },
  });
  const { problems } = adc.validate(gated, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('citizen_facing')));
});

test('a delegation naming a different agent than the card is refused', () => {
  const wrong = baseDelegation({ delegate: { agent_id: 'urn:agent:someone:else', aic_thumbprint: 'x', cnf_thumbprint: 'y' } });
  const { problems } = adc.validate(wrong, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('but the card is for')));
});

test('a conforming delegation round-trips through issue and verify', async () => {
  const { credential, salt } = await adc.issue({
    adc: { ...baseDelegation(), purpose_commitment: undefined },
    aic: baseCard(),
    walletKey: wallet.privateKey,
    holderJwk: agentJwk,
  });
  const presented = await adc.present(credential, { audience: 'https://v.ca', nonce: 'n', holderKey: agent.privateKey });
  const { adc: got } = await adc.verify(presented, {
    walletKey: wallet.publicKey,
    aic: baseCard(),
    presentedCard: issuedBaseCard,
    audience: 'https://v.ca',
    nonce: 'n',
  });

  // The verifier gets the shape and not the sentence.
  assert.equal(got.purpose, undefined, 'the purpose must not reach the verifier by default');
  assert.ok(got.purpose_commitment, 'but the commitment must, so consent is provable');
  assert.ok(salt, 'and the person keeps the salt');
  assert.ok(capability.verifyPurpose(baseDelegation().purpose, salt, got.purpose_commitment));

  const shown = capability.explainToVerifier(got);
  assert.match(shown, /Submit a form and track its status/);
  assert.doesNotMatch(shown, /Handicapped|Assured Income/i);
  assert.match(shown, /withheld from you by design/);
});

// ───────────────────────────────────────────────────── The appeal

test('a delegation scoped to submitting an application cannot appeal the refusal', () => {
  const submitOnly = submitOnlyDelegation();
  assert.equal(adc.validate(submitOnly, { aic: baseCard() }).ok, true, 'the submission delegation is conforming');
  assert.equal(adc.permits(submitOnly, 'submit'), true);
  assert.equal(adc.permits(submitOnly, 'appeal'), false, 'an appeal is a different capability, not a later step');

  // And it cannot be quietly stretched to reach one, either.
  const stretched = submitOnlyDelegation({
    authorization_details: [
      {
        type: 'ca_public_service_request',
        capability: 'submit:form',
        actions: ['draft', 'submit', 'appeal'],
        constraints: { requires_human_approval: ['submit', 'appeal'] },
      },
    ],
  });
  const { ok, problems } = adc.validate(stretched, { aic: baseCard() });
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('grants appeal') && p.includes('only permits draft, submit')));
});

test('the appeal becomes possible because she grants a second delegation, and it verifies', async () => {
  const appeal = appealDelegation();
  const { credential, salt } = await adc.issue({
    adc: { ...appeal, purpose_commitment: undefined },
    aic: baseCard(),
    walletKey: wallet.privateKey,
    holderJwk: agentJwk,
  });
  const presented = await adc.present(credential, { audience: 'https://v.ca', nonce: 'n-appeal', holderKey: agent.privateKey });
  const { adc: got } = await adc.verify(presented, {
    walletKey: wallet.publicKey,
    aic: baseCard(),
    presentedCard: issuedBaseCard,
    audience: 'https://v.ca',
    nonce: 'n-appeal',
  });

  assert.equal(adc.permits(got, 'appeal'), true);
  assert.equal(adc.permits(got, 'submit'), false, 'the second delegation is no wider than the first was');

  // The same privacy properties hold on the way back up as on the way in.
  assert.equal(got.purpose, undefined, 'the sentence about being refused must not reach the verifier');
  assert.ok(capability.verifyPurpose(appeal.purpose, salt, got.purpose_commitment));

  const shown = capability.explainToVerifier(got);
  assert.match(shown, /Ask for a decision to be looked at again/);
  assert.match(shown, /before it can: appeal/);
  assert.doesNotMatch(shown, /Handicapped|Assured Income|refused/i);
});

test('an appeal the Agent Identity Card does not carry is refused, not trimmed', async () => {
  const appeal = appealDelegation();
  const { ok, problems } = adc.validate(appeal, { aic: cardWithoutAppeal() });
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('grants "draft-appeal"') && p.includes('does not carry "draft:appeal"')));
  assert.ok(problems.some((p) => p.includes('grants "appeal"') && p.includes('does not carry "submit:appeal"')));
  assert.ok(problems.some((p) => p.includes('may only narrow')));

  await assert.rejects(
    () => adc.issue({
      adc: { ...appeal, purpose_commitment: undefined },
      aic: cardWithoutAppeal(),
      walletKey: wallet.privateKey,
      holderJwk: agentJwk,
    }),
    /does not carry "draft:appeal"/,
  );

  // Refusal, not a silent trim: the grant is left exactly as it was written, so
  // whoever built it finds out rather than shipping a delegation that does less
  // than the person was told it does.
  assert.deepEqual(appeal.authorization_details[0].actions, ['draft-appeal', 'appeal']);
});

test('a card that may draft an appeal may not thereby file one', () => {
  // v0.3. Filing an appeal is irreversible and it starts or forfeits a clock, so
  // it is a separate grant from preparing one, exactly as submitting a form is a
  // separate grant from drafting it.
  const drafterOnly = { ...baseCard(), capabilities: baseCard().capabilities.filter((c) => c !== 'submit:appeal') };

  const drafting = appealDelegation({
    purpose: 'Draft an appeal of the decision for me to look at before anything is filed.',
    authorization_details: [
      { type: 'x', capability: 'request:review', actions: ['draft-appeal'], constraints: {} },
    ],
  });
  assert.equal(adc.validate(drafting, { aic: drafterOnly }).ok, true, 'drafting is within draft:appeal');
  assert.equal(adc.permits(drafting, 'draft-appeal'), true);
  assert.equal(adc.permits(drafting, 'appeal'), false, 'drafting an appeal is not filing one');

  const filing = appealDelegation();
  const { ok, problems } = adc.validate(filing, { aic: drafterOnly });
  assert.equal(ok, false);
  assert.ok(
    problems.some((p) => p.includes('grants "appeal"') && p.includes('does not carry "submit:appeal"')),
    'a card holding only draft:appeal must not be able to file',
  );
  // And it is refused rather than trimmed back to the drafting half.
  assert.deepEqual(filing.authorization_details[0].actions, ['draft-appeal', 'appeal']);
});

test('filing an appeal needs approval when the card never acts without it', () => {
  const noApproval = appealDelegation({
    authorization_details: [
      { type: 'x', capability: 'request:review', actions: ['draft-appeal', 'appeal'], constraints: {} },
    ],
  });
  const { problems } = adc.validate(noApproval, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('"appeal"') && p.includes('requires_human_approval')));

  // Drafting is the reversible half and does not need to appear there.
  const draftOnly = appealDelegation({
    purpose: 'Draft an appeal of the decision for me to look at.',
    authorization_details: [
      { type: 'x', capability: 'request:review', actions: ['draft-appeal'], constraints: {} },
    ],
  });
  assert.equal(adc.validate(draftOnly, { aic: baseCard() }).ok, true);
});

test('the narrower of the purpose sentence and the grant governs the appeal too', () => {
  const silent = appealDelegation({ purpose: 'Please keep working on my file now that the letter has come.' });
  const { ok, problems } = adc.validate(silent, { aic: baseCard() });
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('grants "appeal"') && p.includes('never mentions it')));

  // The check runs both ways round: a sentence that does say it passes.
  const spoken = appealDelegation({ purpose: 'Ask them to review the decision that went against me.' });
  assert.equal(adc.validate(spoken, { aic: baseCard() }).ok, true);
});

// ───────────────────────────────────────────────────── The binding

/** Issue, present, and verify a delegation, so each test below varies one thing. */
const roundTrip = async (delegation, { holderJwk = agentJwk, holderKey = agent.privateKey, nonce } = {}) => {
  const { credential } = await adc.issue({
    adc: { ...delegation, purpose_commitment: undefined },
    aic: baseCard(),
    walletKey: wallet.privateKey,
    holderJwk,
  });
  return adc.present(credential, { audience: 'https://v.ca', nonce, holderKey });
};

test('a delegation and the card it was granted against verify together', async () => {
  const presented = await roundTrip(baseDelegation(), { nonce: 'n-bound' });
  const presentedCard = await sdjwt.present(issuedBaseCard, {
    reveal: [], audience: 'https://v.ca', nonce: 'n-bound', holderKey: agent.privateKey,
  });
  const vCard = await aic.verify(presentedCard, { issuerKey: issuer.publicKey, audience: 'https://v.ca', nonce: 'n-bound' });

  const { adc: got } = await adc.verify(presented, {
    walletKey: wallet.publicKey,
    aic: vCard.card,
    aicThumbprint: vCard.thumbprint,
    audience: 'https://v.ca',
    nonce: 'n-bound',
  });
  assert.equal(got.delegate.aic_thumbprint, vCard.thumbprint, 'the binding is to the card that was actually presented');
});

test('a delegation presented with a different card is refused', async () => {
  // A second card, for the same agent, from the same issuer, valid in every way.
  // The only thing wrong with it is that it is not the card this delegation was
  // granted against, and that alone must be enough.
  const otherCard = await aic.issue({ card: baseCard(), privateKey: issuer.privateKey, holderJwk: agentJwk });
  assert.notEqual(await aic.cardThumbprint(otherCard), BASE_CARD_THUMB, 'the two cards must be distinguishable');

  const presented = await roundTrip(baseDelegation(), { nonce: 'n-swap' });
  await assert.rejects(
    () => adc.verify(presented, {
      walletKey: wallet.publicKey,
      aic: baseCard(),
      presentedCard: otherCard,
      audience: 'https://v.ca',
      nonce: 'n-swap',
    }),
    /aic_thumbprint binding failed/,
  );
});

test('a delegation presented with a different holder key is refused', async () => {
  // The delegation names the agent's key. It is presented, and key-bound, by
  // somebody else's key. The KB-JWT is valid; the binding is not.
  const otherJwk = await exportJWK(other.publicKey);
  const presented = await roundTrip(baseDelegation(), {
    holderJwk: otherJwk,
    holderKey: other.privateKey,
    nonce: 'n-key',
  });
  await assert.rejects(
    () => adc.verify(presented, {
      walletKey: wallet.publicKey,
      aic: baseCard(),
      presentedCard: issuedBaseCard,
      audience: 'https://v.ca',
      nonce: 'n-key',
    }),
    /cnf_thumbprint binding failed/,
  );
});

test('a valid card and a valid delegation held by two different agents cannot be stapled together', async () => {
  const otherJwk = await exportJWK(other.publicKey);
  const otherKeyThumb = await aic.jwkThumbprint(otherJwk);

  // This delegation is honestly bound to the other key, so the cnf check passes.
  // The card presented with it is held by a different key, and that is the breach.
  const delegation = baseDelegation({
    delegate: { agent_id: AGENT_ID, aic_thumbprint: BASE_CARD_THUMB, cnf_thumbprint: otherKeyThumb },
  });
  const presented = await roundTrip(delegation, {
    holderJwk: otherJwk,
    holderKey: other.privateKey,
    nonce: 'n-staple',
  });

  const cardClaims = await sdjwt.verify(issuedBaseCard, { issuerKey: issuer.publicKey });
  await assert.rejects(
    () => adc.verify(presented, {
      walletKey: wallet.publicKey,
      aic: cardClaims.claims,
      presentedCard: issuedBaseCard,
      audience: 'https://v.ca',
      nonce: 'n-staple',
    }),
    /holder binding failed/,
  );
});

test('a binding that could not be checked is a failed binding, not a passed one', async () => {
  const presented = await roundTrip(baseDelegation(), { nonce: 'n-none' });
  await assert.rejects(
    () => adc.verify(presented, {
      walletKey: wallet.publicKey,
      aic: baseCard(),
      audience: 'https://v.ca',
      nonce: 'n-none',
    }),
    /card binding could not be checked/,
  );
});

// ───────────────────────────────────────────────────── Status

test('a verifier that cannot reach the status list fails closed', () => {
  assert.equal(status.inForce({ reachable: false }).ok, false);
  assert.equal(status.inForce({ status: 0, stale: true }).ok, false);
  assert.equal(status.inForce({ status: 99, stale: false }).ok, false);
  assert.equal(status.inForce({ status: status.STATUS.VALID, stale: false }).ok, true);
});

test('a status list survives a round trip through the wire format', () => {
  const list = new status.StatusList({ size: 1000 });
  list.set(7, status.STATUS.INVALID).set(999, status.STATUS.INVALID);
  const back = status.StatusList.decode(list.encode(), 1000);
  assert.equal(back.get(7), status.STATUS.INVALID);
  assert.equal(back.get(999), status.STATUS.INVALID);
  assert.equal(back.get(8), status.STATUS.VALID);
  assert.equal(back.populated(), 2);
});

test('a status list published without a freshness window is refused', async () => {
  await assert.rejects(
    () => status.publish({ list: new status.StatusList({ size: 10 }), uri: 'u', issuer: 'i', privateKey: issuer.privateKey }),
    /positive ttl/,
  );
});

test('revocation shows up, and the person gets a receipt naming who was told', async () => {
  const list = new status.StatusList({ size: 100 });
  const before = await status.publish({ list, uri: 'u', issuer: 'i', privateKey: issuer.privateKey, ttl: 300 });
  assert.equal(status.inForce(await status.fetchStatus(before, { issuerKey: issuer.publicKey, idx: 5 })).ok, true);

  list.set(5, status.STATUS.INVALID);
  const after = await status.publish({ list, uri: 'u', issuer: 'i', privateKey: issuer.privateKey, ttl: 300 });
  const r = status.inForce(await status.fetchStatus(after, { issuerKey: issuer.publicKey, idx: 5 }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /revoked/);

  const rec = status.receipt({ credentialId: 'c', purpose: 'p', revokedAt: 'now', notified: ['https://v.ca'], listUri: 'u' });
  assert.equal(rec.notified_count, 1);
  assert.deepEqual(rec.verifiers_notified, ['https://v.ca']);
});

// ───────────────────────────────────────────────────── rule_basis

test('a tier 3 determination is a malformed credential', () => {
  assert.throws(
    () => determination.stamp({}, { kind: determination.KIND.DETERMINATION, basis: { tier: 3 } }),
    /may not carry a determination/,
  );
  assert.throws(
    () => determination.stamp({}, { kind: determination.KIND.DETERMINATION, basis: { tier: 2, authority: 'a', rule_id: 'r', version: 'v' } }),
    /may not carry a determination/,
  );
});

test('tier 1 must name what it called and when', () => {
  const { problems } = determination.validate({ tier: 1 }, { kind: determination.KIND.DETERMINATION });
  assert.equal(problems.length, 4);
  const good = determination.validate(
    { tier: 1, authority: 'https://rules.ca/x', rule_id: 'X-1', version: '2026-04-01', retrieved: 'now' },
    { kind: determination.KIND.DETERMINATION },
  );
  assert.equal(good.ok, true);
});

test('tier 3 must not name an authority it does not have', () => {
  const { problems } = determination.validate(
    { tier: 3, authority: 'https://looks-official.ca' },
    { kind: determination.KIND.NAVIGATION },
  );
  assert.ok(problems.some((p) => p.includes('no authority to name')));
});

test('only tier 1 may be shown in the visual language of a decision', () => {
  assert.equal(determination.presentation(1).may_use_decision_styling, true);
  assert.equal(determination.presentation(2).may_use_decision_styling, false);
  assert.equal(determination.presentation(3).may_use_decision_styling, false);
  assert.match(determination.presentation(3).must_say, /cannot tell you the answer/);
});

test('a tier 1 service going dark produces a sentence, not silence', () => {
  const d = determination.downgrade({ tier: 1, authority: 'https://rules.ca/x' }, 'timed out');
  assert.equal(d.basis.tier, 3);
  assert.equal(d.kind, determination.KIND.NAVIGATION);
  assert.match(d.tell_the_person, /could not reach/);
  assert.equal(d.logged.from, 1);
  assert.equal(d.logged.to, 3);
});

// ───────────────────────────────────────────────────── Capability scoping

test('the sensitive noun cannot reach a field a clerk can read', () => {
  const leaky = baseDelegation({
    authorization_details: [
      { type: 'aish_application', capability: 'submit:form', actions: ['draft', 'submit'], constraints: { requires_human_approval: ['submit'] } },
    ],
  });
  const { ok, problems } = adc.validate(leaky, { aic: baseCard() });
  assert.equal(ok, false);
  assert.ok(problems.some((p) => p.includes('aish') && p.includes('health information')));
});

test('naming the programme in the clear is refused', () => {
  const named = baseDelegation();
  named.authorization_details[0].programs = ['urn:ab:program:generic'];
  const { problems } = adc.validate(named, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('already knows which office')));
});

test('a capability cannot be stretched past the actions it permits', () => {
  const stretched = baseDelegation({
    authorization_details: [
      { type: 'x', capability: 'track:status', actions: ['monitor', 'submit'], constraints: {} },
    ],
  });
  const { problems } = adc.validate(stretched, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('only permits')));
});

test('an unknown capability is a typo, not a feature', () => {
  const odd = baseDelegation({
    authorization_details: [{ type: 'x', capability: 'do:anything', actions: ['submit'], constraints: {} }],
  });
  const { problems } = adc.validate(odd, { aic: baseCard() });
  assert.ok(problems.some((p) => p.includes('not in the vocabulary')));
});

test('issuing with the purpose in the clear is refused outright', async () => {
  await assert.rejects(
    () => adc.issue({
      adc: { ...baseDelegation(), purpose_commitment: undefined },
      aic: baseCard(),
      walletKey: wallet.privateKey,
      holderJwk: agentJwk,
      selective: [],
    }),
    /refusing to issue a delegation with the purpose in the clear/,
  );
});

test('presenting withholds the purpose unless the person chooses to show it', async () => {
  const { credential, salt } = await adc.issue({
    adc: { ...baseDelegation(), purpose_commitment: undefined },
    aic: baseCard(),
    walletKey: wallet.privateKey,
    holderJwk: agentJwk,
  });

  const quiet = await adc.present(credential, { audience: 'https://v.ca', nonce: 'n', holderKey: agent.privateKey });
  const shown = await adc.present(credential, { audience: 'https://v.ca', nonce: 'n', holderKey: agent.privateKey, disclosePurpose: true });

  const a = await sdjwt.verify(quiet, { issuerKey: wallet.publicKey, audience: 'https://v.ca', nonce: 'n' });
  const b = await sdjwt.verify(shown, { issuerKey: wallet.publicKey, audience: 'https://v.ca', nonce: 'n' });

  assert.equal(a.claims.purpose, undefined);
  assert.equal(b.claims.purpose, baseDelegation().purpose);
  // Both carry the commitment, so the verifier always knows a purpose exists.
  assert.equal(a.claims.purpose_commitment, b.claims.purpose_commitment);
  assert.ok(capability.verifyPurpose(b.claims.purpose, salt, b.claims.purpose_commitment));
});

test('a substituted purpose does not match the commitment', async () => {
  const { salt, purpose_commitment } = await adc.issue({
    adc: { ...baseDelegation(), purpose_commitment: undefined },
    aic: baseCard(),
    walletKey: wallet.privateKey,
    holderJwk: agentJwk,
  });
  assert.equal(capability.verifyPurpose('Something else entirely, honest.', salt, purpose_commitment), false);
});

test('the screen catches every sensitive category it claims to', () => {
  const samples = {
    health: 'aish_application',
    status: 'refugee claim',
    housing: 'eviction notice',
    safety: 'domestic violence support',
    family: 'custody matter',
    justice: 'parole check-in',
    income: 'social assistance file',
    reproductive: 'maternity leave',
  };
  for (const [expected, text] of Object.entries(samples)) {
    const hits = capability.screen(text);
    assert.ok(hits.length, `"${text}" should be caught`);
    assert.ok(hits.some((h) => h.category === expected), `"${text}" should be ${expected}`);
  }
  assert.deepEqual(capability.screen('submit a form and track its status'), []);
});

// ───────────────────────────────────────────────────── Revocation service

test('a revocation request must be signed by the key that granted the delegation', async () => {
  const { SignJWT } = await import('jose');
  const reg = new revocation.RevocationRegister({
    list: new status.StatusList({ size: 100 }),
    listUri: 'https://status.agentcredential.ca/adc',
  });
  const walletJwk = await exportJWK(wallet.publicKey);
  reg.register({ credentialId: 'c1', idx: 3, delegatorJwk: walletJwk, expiresAt: sec + 3600 });

  const good = await new SignJWT({ action: 'revoke', credential: 'c1' })
    .setProtectedHeader({ alg: 'ES256' }).setIssuedAt().sign(wallet.privateKey);
  assert.equal((await revocation.verifyRevocationRequest(good, { delegatorJwk: walletJwk, credentialId: 'c1' })).ok, true);

  // Somebody else's key.
  const impostor = await new SignJWT({ action: 'revoke', credential: 'c1' })
    .setProtectedHeader({ alg: 'ES256' }).setIssuedAt().sign(other.privateKey);
  const bad = await revocation.verifyRevocationRequest(impostor, { delegatorJwk: walletJwk, credentialId: 'c1' });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /not signed by the key/);

  // Right key, wrong credential.
  const wrongCred = await revocation.verifyRevocationRequest(good, { delegatorJwk: walletJwk, credentialId: 'c2' });
  assert.equal(wrongCred.ok, false);
  assert.match(wrongCred.reason, /different delegation/);
});

test('an old signed revocation request cannot be replayed later', async () => {
  const { SignJWT } = await import('jose');
  const walletJwk = await exportJWK(wallet.publicKey);
  const stale = await new SignJWT({ action: 'revoke', credential: 'c1', iat: sec - 3600 })
    .setProtectedHeader({ alg: 'ES256' }).sign(wallet.privateKey);
  const r = await revocation.verifyRevocationRequest(stale, { delegatorJwk: walletJwk, credentialId: 'c1' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /five minutes old/);
});

test('revoking updates the status list, tells every verifier, and returns a receipt', async () => {
  const list = new status.StatusList({ size: 100 });
  const reg = new revocation.RevocationRegister({ list, listUri: 'https://status.agentcredential.ca/adc' });
  reg.register({ credentialId: 'c1', idx: 7, delegatorJwk: {}, purposeCommitment: 'abc', expiresAt: sec + 3600 });
  reg.notePresentation('c1', 'https://a.ca', sec);
  reg.notePresentation('c1', 'https://b.ca', sec);

  const told = [];
  const r = await revocation.revoke(reg, { credentialId: 'c1', notify: async ({ verifier }) => told.push(verifier) });

  assert.equal(r.ok, true);
  assert.equal(list.get(7), status.STATUS.INVALID);
  assert.deepEqual(told.sort(), ['https://a.ca', 'https://b.ca']);
  assert.equal(r.receipt.notified_count, 2);
  assert.equal(r.receipt.revoked.purpose, null, 'her sentence is not ours to put in a receipt');
  assert.match(revocation.explainReceipt(r.receipt), /can no longer act for you/);
});

test('one unreachable verifier does not stop the others being told', async () => {
  const reg = new revocation.RevocationRegister({
    list: new status.StatusList({ size: 100 }),
    listUri: 'https://status.agentcredential.ca/adc',
  });
  reg.register({ credentialId: 'c1', idx: 1, delegatorJwk: {}, expiresAt: sec + 3600 });
  reg.notePresentation('c1', 'https://down.ca', sec);
  reg.notePresentation('c1', 'https://up.ca', sec);

  const r = await revocation.revoke(reg, {
    credentialId: 'c1',
    notify: async ({ verifier }) => {
      if (verifier === 'https://down.ca') throw new Error('connection refused');
    },
  });

  assert.deepEqual(r.notified, ['https://up.ca']);
  assert.equal(r.failed.length, 1);
  assert.match(r.receipt.note, /could not be reached/);
  assert.match(revocation.explainReceipt(r.receipt), /required to treat it as not in force/);
});

test('pressing revoke twice is not an error', async () => {
  const reg = new revocation.RevocationRegister({
    list: new status.StatusList({ size: 100 }),
    listUri: 'https://status.agentcredential.ca/adc',
  });
  reg.register({ credentialId: 'c1', idx: 1, delegatorJwk: {}, expiresAt: sec + 3600 });
  await revocation.revoke(reg, { credentialId: 'c1', notify: async () => {} });
  const again = await revocation.revoke(reg, { credentialId: 'c1', notify: async () => {} });
  assert.equal(again.ok, true);
  assert.equal(again.alreadyRevoked, true);
});

test('a freshness window nobody could rely on is refused', () => {
  assert.throws(
    () => new revocation.RevocationRegister({
      list: new status.StatusList({ size: 10 }),
      listUri: 'u',
      freshnessSeconds: 48 * 60 * 60,
    }),
    /exceeds the 24 hour maximum/,
  );
});
