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
  capabilities: ['read:program-information', 'draft:application', 'submit:application', 'draft:appeal'],
  conduct: { discloses_ai: 'always', acts_without_approval: false, retains_after_revocation: 'audit-record-only' },
  status: { status_list: { uri: 'https://status.agentcredential.ca/aic', idx: 1 } },
});

const baseDelegation = (over = {}) => ({
  vct: adc.ADC_VCT,
  iss: 'https://wallet.example.ca/u/1',
  iat: sec,
  exp: sec + 7 * 86400,
  delegator: { sub: 'pw:abc', pairwise: true, verified_by: 'https://account.alberta.ca/dts', assurance: 'substantial' },
  delegate: { agent_id: AGENT_ID, aic_thumbprint: 'x', cnf_thumbprint: 'y' },
  purpose: 'Apply for the Alberta Disability Assistance Program on my behalf, and appeal if I am refused.',
  authorization_details: [
    {
      type: 'gc_benefit_application',
      programs: ['urn:ab:program:adap'],
      actions: ['read', 'draft', 'submit', 'appeal'],
      constraints: { requires_human_approval: ['submit', 'appeal'] },
    },
  ],
  consent: { record_uri: 'https://wallet.example.ca/c/1', captured_at: new Date().toISOString(), language: 'en-CA', method: 'in-app-explicit' },
  revocation: { revoke_uri: 'https://revoke.agentcredential.ca/d/1', citizen_facing: true },
  status: { status_list: { uri: 'https://status.agentcredential.ca/adc', idx: 1 } },
  ...over,
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
      { type: 'x', programs: ['p'], actions: ['read', 'submit', 'correspond'], constraints: { requires_human_approval: ['submit'] } },
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
    authorization_details: [{ type: 'x', programs: ['p'], actions: ['read', 'submit'], constraints: {} }],
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
  const issued = await adc.issue({
    adc: baseDelegation(),
    aic: baseCard(),
    walletKey: wallet.privateKey,
    holderJwk: agentJwk,
  });
  const presented = await sdjwt.present(issued, { audience: 'https://v.ca', nonce: 'n', holderKey: agent.privateKey });
  const { adc: got } = await adc.verify(presented, {
    walletKey: wallet.publicKey,
    aic: baseCard(),
    audience: 'https://v.ca',
    nonce: 'n',
  });
  assert.equal(got.purpose, baseDelegation().purpose);
  assert.match(adc.explain(got), /must come back for approval/);
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
