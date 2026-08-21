/**
 * Transfer, succession, and what a delegation is bound to.
 *
 * Packages 1 to 3 of the specification scope of 20 August 2026. These are the
 * assertions from Part 6 of that note, written as tests so that somebody who
 * does not trust us can run them.
 *
 * The defect these exist for: a delegation bound to an Agent Identity Card by
 * hashing the issued credential, so reissuing the card broke every delegation
 * held against it — including a reissue with identical claims.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';
import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as status from '../src/status.js';

const sec = Math.floor(Date.now() / 1000);
const AGENT = 'urn:agent:kindred:steward:7f3a1c92';

async function world() {
  const issuer = await generateKeyPair('ES256', { extractable: true });
  const wallet = await generateKeyPair('ES256', { extractable: true });
  const agent = await generateKeyPair('ES256', { extractable: true });
  return { issuer, wallet, agent, agentJwk: await exportJWK(agent.publicKey) };
}

const card = (over = {}) => ({
  vct: aic.AIC_VCT,
  iss: 'https://kya.example.ca',
  iat: sec,
  exp: sec + 365 * 86400,
  agent: { id: AGENT, name: 'Steward', version: '1.4.2' },
  builder: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS' },
  operator: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS' },
  accountable: { role: 'CTO', contact: 'trust@example.ca', redress_uri: 'https://example.ca/r' },
  model: { disclosed: true, family: 'claude', version: '5', hosted_in: 'CA', residency_basis: 'asserted' },
  capabilities: ['read:program-information', 'draft:application'],
  conduct: { discloses_ai: 'always', acts_without_approval: false, retains_after_revocation: 'audit-record-only' },
  assurance: { framework: 'PCTF', level: 'pending', assessed_by: null, assessed_at: null },
  status: { status_list: { uri: 'https://s.example.ca/aic', idx: 1 } },
  ...over,
});

const delegation = (w, over = {}) => ({
  vct: adc.ADC_VCT,
  iss: 'https://wallet.example.ca/u/1',
  iat: sec,
  exp: sec + 14 * 86400,
  delegator: { sub: 'pw:abc', pairwise: true, sub_audience: 'https://verifier.example.ca', verified_by: 'https://idv.example.ca' },
  delegate: { agent_id: AGENT, aic_thumbprint: w.thumb, cnf_thumbprint: w.keyThumb },
  purpose: 'Read my file and tell me what is happening with it.',
  authorization_details: [{
    type: 'ab_program_file',
    capability: 'read:public-information',
    actions: ['read'],
    constraints: { file_id: 'BVW-2231' },
  }],
  consent: {
    record_uri: 'https://wallet.example.ca/consent/1',
    captured_at: new Date(sec * 1000).toISOString(),
    language: 'en-CA',
    method: 'in-app-explicit',
  },
  revocation: { revoke_uri: 'https://revoke.example.ca/d/1', citizen_facing: true },
  status: { status_list: { uri: 'https://s.example.ca/adc', idx: 2 } },
  ...over,
});

/** Issue a card, present it, and gather everything a verifier would hold. */
async function issued(w, over = {}) {
  const c = card(over);
  const credential = await aic.issue({ card: c, privateKey: w.issuer.privateKey, holderJwk: w.agentJwk });
  const presented = await (await import('../src/sdjwt.js')).present(credential, {
    audience: 'https://verifier.example.ca', nonce: 'n1', holderKey: w.agent.privateKey, reveal: [],
  });
  const v = await aic.verify(presented, {
    issuerKey: w.issuer.publicKey, audience: 'https://verifier.example.ca', nonce: 'n1',
  });
  return { claims: c, credential, presented, verified: v.card, thumb: await aic.cardThumbprint(presented) };
}

// ───────────────────────────────────────────── the defect, and the regression
test('a card reissued with identical claims does not break a live delegation', async () => {
  const w = await world();
  const first = await issued(w);
  w.thumb = first.thumb;
  w.keyThumb = await aic.jwkThumbprint(w.agentJwk);

  const d = delegation(w);
  const { credential } = await adc.issue({
    adc: d, aic: first.claims, walletKey: w.wallet.privateKey, holderJwk: w.agentJwk,
  });

  // Same claims, issued again. A different document; the same agent.
  const second = await issued(w);
  assert.notEqual(second.thumb, first.thumb, 'the reissued card must be a different document');

  const presentedDel = await adc.present(credential, {
    audience: 'https://verifier.example.ca', nonce: 'n2', holderKey: w.agent.privateKey,
  });
  const report = await adc.bindingReport(
    (await (await import('../src/sdjwt.js')).verify(presentedDel, {
      issuerKey: w.wallet.publicKey, audience: 'https://verifier.example.ca', nonce: 'n2',
    })).claims,
    { aic: second.verified, aicThumbprint: second.thumb },
  );

  assert.equal(report.continuity, adc.CONTINUITY.REISSUED_SAME_TERMS,
    'identical claims reissued is continuity, not a broken binding');
  assert.equal(report.bindings.agent.held, true);
  assert.equal(report.bindings.terms.held, true);
  assert.equal(report.bindings.document.held, false, 'the document did change, and we say so');
});

test('a card reissued with a widened capability ceiling DOES break it', async () => {
  const w = await world();
  const first = await issued(w);
  w.thumb = first.thumb;
  w.keyThumb = await aic.jwkThumbprint(w.agentJwk);
  const { credential } = await adc.issue({
    adc: delegation(w), aic: first.claims, walletKey: w.wallet.privateKey, holderJwk: w.agentJwk,
  });

  const wider = await issued(w, {
    capabilities: ['read:program-information', 'draft:application', 'submit:application'],
  });
  const presentedDel = await adc.present(credential, {
    audience: 'https://verifier.example.ca', nonce: 'n3', holderKey: w.agent.privateKey,
  });
  const claims = (await (await import('../src/sdjwt.js')).verify(presentedDel, {
    issuerKey: w.wallet.publicKey, audience: 'https://verifier.example.ca', nonce: 'n3',
  })).claims;
  const report = await adc.bindingReport(claims, { aic: wider.verified, aicThumbprint: wider.thumb });

  assert.equal(report.continuity, adc.CONTINUITY.REISSUED_TERMS_CHANGED);
  assert.equal(report.bindings.terms.held, false,
    'continuity must never become a quiet way to widen authority');
});

test('a change of operator moves the terms, which is what makes transfer detectable', async () => {
  const w = await world();
  const before = card();
  const after = card({ operator: { legal_name: 'Acquirer Co', jurisdiction: 'CA-ON' } });
  assert.notEqual(await aic.termsDigest(before), await aic.termsDigest(after));
});

test('LIMIT: a change of model hosting does NOT move the terms, and that is stated', async () => {
  const w = await world();
  const before = card();
  const after = card({ model: { disclosed: true, family: 'claude', version: '5', hosted_in: 'US', residency_basis: 'asserted' } });
  assert.equal(await aic.termsDigest(before), await aic.termsDigest(after),
    'model is selectively disclosable, so a verifier who was not shown it cannot detect a change');
});

test('the default is the strictest transfer policy: a reissue voids unless asked otherwise', async () => {
  const w = await world();
  const first = await issued(w);
  w.thumb = first.thumb;
  w.keyThumb = await aic.jwkThumbprint(w.agentJwk);
  const { credential } = await adc.issue({
    adc: delegation(w), aic: first.claims, walletKey: w.wallet.privateKey, holderJwk: w.agentJwk,
  });
  const second = await issued(w);
  const presentedDel = await adc.present(credential, {
    audience: 'https://verifier.example.ca', nonce: 'n4', holderKey: w.agent.privateKey,
  });
  const claims = (await (await import('../src/sdjwt.js')).verify(presentedDel, {
    issuerKey: w.wallet.publicKey, audience: 'https://verifier.example.ca', nonce: 'n4',
  })).claims;

  const strict = await adc.bindingBreaches(claims, { aic: second.verified, aicThumbprint: second.thumb });
  assert.ok(strict.length > 0, 'by default a reissued card voids the delegation');

  const lenient = await adc.bindingBreaches(claims, {
    aic: second.verified, aicThumbprint: second.thumb, allowReissue: true,
  });
  assert.deepEqual(lenient, [], 'continuity is available, and it has to be asked for');
});

test('agent_id is compared, having been a required field nothing checked', async () => {
  const w = await world();
  const first = await issued(w);
  w.thumb = first.thumb;
  w.keyThumb = await aic.jwkThumbprint(w.agentJwk);
  const d = delegation(w, { delegate: { agent_id: 'urn:agent:someone:else', aic_thumbprint: first.thumb, cnf_thumbprint: w.keyThumb } });
  const report = await adc.bindingReport(d, { aic: first.verified, aicThumbprint: first.thumb });
  assert.equal(report.bindings.agent.held, false);
  assert.equal(report.continuity, adc.CONTINUITY.DIFFERENT_AGENT);
});

// ───────────────────────────────────────────────────────── retirement, status
test('a retired agent and a revoked agent are distinguishable, and both fail closed', () => {
  const revoked = status.inForce({ status: status.STATUS.INVALID });
  const retired = status.inForce({ status: status.STATUS.RETIRED });
  const gone = status.inForce({ status: status.STATUS.VALID, reachable: false });

  assert.equal(revoked.ok, false);
  assert.equal(retired.ok, false);
  assert.equal(gone.ok, false);
  assert.equal(revoked.state, 'revoked');
  assert.equal(retired.state, 'retired');
  assert.equal(gone.state, 'unreachable');
  assert.match(retired.reason, /successor/, 'a retirement points somewhere before it points nowhere');
});

test('a one-bit status list cannot express RETIRED, and says so', () => {
  const one = new status.StatusList({ size: 8, bits: 1 });
  assert.throws(() => one.set(0, status.STATUS.RETIRED), /bits: 2 or wider/);
  const two = new status.StatusList({ size: 8, bits: 2 });
  two.set(0, status.STATUS.RETIRED);
  assert.equal(two.get(0), status.STATUS.RETIRED);
  assert.equal(status.bitsFor(status.STATUS.RETIRED), 2);
});

// ─────────────────────────────────────────────────────────────── succession
test('a retirement that names neither a successor nor an explicit none is refused', () => {
  const bad = card({ succession: { state: 'retired', effective: '2026-10-01', notice: { given_at: '2026-09-01' } } });
  const problems = aic.validate(bad).problems.join(' ');
  assert.match(problems, /successor is required/);
});

test('a retirement may say plainly that there is no successor', () => {
  const ok = card({
    succession: { state: 'retired', successor: null, effective: '2026-10-01', notice: { given_at: '2026-09-01', uri: 'https://example.ca/notice' } },
  });
  assert.deepEqual(aic.validate(ok).problems, []);
});

test('a retirement nobody was told about is refused', () => {
  const noNotice = card({ succession: { state: 'retiring', successor: null, effective: '2026-10-01' } });
  assert.match(aic.validate(noNotice).problems.join(' '), /notice is required/);

  const nulled = card({ succession: { state: 'retiring', successor: null, effective: '2026-10-01', notice: null } });
  assert.match(aic.validate(nulled).problems.join(' '), /Somebody has to have been told/);
});

test('succession may be absent, and may never be hidden', async () => {
  const w = await world();
  assert.deepEqual(aic.validate(card()).problems, [], 'absence is a state; cards predating this stay valid');
  await assert.rejects(
    aic.issue({
      card: card({ succession: { state: 'active' } }),
      privateKey: w.issuer.privateKey,
      holderJwk: w.agentJwk,
      selective: ['model', 'succession'],
    }),
    /may never be selectively withheld/,
  );
});

test('retiring changes the terms, so a delegation notices its agent is going away', async () => {
  const active = card();
  const retiring = card({
    succession: { state: 'retiring', successor: 'urn:agent:kindred:steward:v2', effective: '2026-10-01', notice: { given_at: '2026-09-01' } },
  });
  assert.notEqual(await aic.termsDigest(active), await aic.termsDigest(retiring),
    'an agent being wound down is a change to what the person agreed to');
});
