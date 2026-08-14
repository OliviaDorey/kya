/**
 * Unlinkability, which is a property of a set and not of a credential.
 *
 * The order these tests are written in is the order the work happened, because
 * it is the argument: a naive wallet fails, and the wallet that passes costs
 * three times as much to run. Both facts belong in the suite.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';

import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as sd from '../src/sdjwt.js';
import * as conf from '../src/conformance.js';
import * as wallet from '../src/wallet.js';

const sec = Math.floor(Date.now() / 1000);
const VERIFIERS = ['https://aish.alberta.ca', 'https://health.alberta.ca', 'https://housing.alberta.ca'];

const cardFor = (jwk, agentId) => ({
  vct: aic.AIC_VCT, iss: 'https://i.ca', iat: sec, exp: sec + 86400,
  agent: { id: agentId, name: 'Steward', version: '1' },
  builder: { legal_name: 'Kindred', jurisdiction: 'CA-NS' },
  accountable: { role: 'CTO', contact: 't@k.ca', redress_uri: 'https://k.ca/r' },
  model: { disclosed: true, family: 'f' },
  capabilities: ['draft:application', 'submit:application'],
  conduct: { discloses_ai: 'always', acts_without_approval: false },
  status: { status_list: { uri: 'https://s/aic', idx: 1 } },
  cnf: { jwk },
});

const baseFor = (m) => ({
  vct: adc.ADC_VCT, iss: 'https://wallet.example.ca', iat: sec, exp: sec + 86400,
  delegator: { verified_by: 'https://a.ca' },
  delegate: { agent_id: m.aic.agent.id, aic_thumbprint: m.cardThumb, cnf_thumbprint: m.keyThumb },
  authorization_details: [{ type: 't', capability: 'submit:form', actions: ['draft', 'submit'], constraints: { requires_human_approval: ['submit'] } }],
  consent: { record_uri: 'https://w.ca/c/x', captured_at: new Date().toISOString(), language: 'en-CA', method: 'in-app-explicit' },
  revocation: { revoke_uri: 'https://revoke.agentcredential.ca/d/x', citizen_facing: true },
  status: { status_list: { uri: 'https://s/adc', idx: 0 } },
});

/** One agent, one key, one card, reused everywhere. What a wallet does by default. */
async function naiveWallet(serial) {
  const iss = await generateKeyPair('ES256', { extractable: true });
  const wal = await generateKeyPair('ES256', { extractable: true });
  const ag = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(ag.publicKey);
  const card = cardFor(jwk, `urn:agent:k:s:${serial}`);
  const issued = await aic.issue({ card, privateKey: iss.privateKey, holderJwk: jwk });
  const m = { aic: card, walletKey: wal.privateKey, holderJwk: jwk, cardThumb: await aic.cardThumbprint(issued), keyThumb: await sd.thumbprint(jwk) };
  let idx = 900;
  return async (v) => {
    const b = baseFor(m);
    // Per-person wallet URL, one consent record, one commitment — all of it what
    // a wallet does without thinking about it.
    b.iss = `https://wallet.example.ca/u/${serial}`;
    b.consent.record_uri = `https://w.ca/consent/${serial}`;
    b.purpose_commitment = `commit-${serial}`;
    b.status.status_list.idx = idx++;
    // Note this wallet uses pairwise subjects *correctly*. That is the finding:
    // getting delegator.sub right while everything around it stays constant
    // buys nothing at all.
    const { credential } = await adc.issue({
      adc: b, aic: card, walletKey: m.walletKey, holderJwk: jwk,
      pairwise: { walletSecret: `secret-${serial}`, verifierId: v },
    });
    return JSON.parse(Buffer.from(credential.split('~')[0].split('.')[1], 'base64url').toString());
  };
}

/** A distinct key and card per verifier, minted through issueSet. */
async function unlinkableWallet(serial) {
  const iss = await generateKeyPair('ES256', { extractable: true });
  const material = new Map();
  for (const v of VERIFIERS) {
    const wal = await generateKeyPair('ES256', { extractable: true });
    const ag = await generateKeyPair('ES256', { extractable: true });
    const jwk = await exportJWK(ag.publicKey);
    const alias = `urn:agent:k:s:${serial}-${(await sd.thumbprint(jwk)).slice(0, 8)}`;
    const card = cardFor(jwk, alias);
    const issued = await aic.issue({ card, privateKey: iss.privateKey, holderJwk: jwk });
    material.set(v, { aic: card, walletKey: wal.privateKey, holderJwk: jwk, cardThumb: await aic.cardThumbprint(issued), keyThumb: await sd.thumbprint(jwk) });
  }
  let idx = 500;
  return async (v) => {
    const m = material.get(v);
    const b = baseFor(m);
    b.status.status_list.idx = idx++;
    const [out] = await wallet.issueSet({
      base: b, verifiers: [v], walletSecret: `secret-${serial}`, consentId: `c-${serial}`,
      purpose: 'Apply for the thing I need help with, on my behalf.',
      perVerifier: () => m,
    });
    return JSON.parse(Buffer.from(out.credential.split('~')[0].split('.')[1], 'base64url').toString());
  };
}

test('a pairwise subject on its own is decorative, and the probe says so', async () => {
  // This is the finding that produced wallet.js. delegator.sub varies perfectly
  // and nine other always-disclosed fields do not, so any two offices can still
  // join their files exactly. A correlation moved to the neighbouring field is a
  // correlation you still have.
  const result = await conf.probeUnlinkability({
    mintFor: await naiveWallet('alice'),
    mintForOther: await naiveWallet('bob'),
    verifiers: VERIFIERS,
  });

  assert.equal(result.ok, false);
  assert.ok(result.correlators.length >= 5, `expected several correlators, got ${result.correlators.length}`);
  for (const expected of ['iss', 'cnf.jwk.x', 'delegate.aic_thumbprint', 'delegate.cnf_thumbprint', 'purpose_commitment', 'consent.record_uri']) {
    assert.ok(result.correlators.includes(expected), `${expected} should be a confirmed correlator`);
  }
});

test('a distinct key and card per verifier links nothing at all', async () => {
  const result = await conf.probeUnlinkability({
    mintFor: await unlinkableWallet('alice'),
    mintForOther: await unlinkableWallet('bob'),
    verifiers: VERIFIERS,
  });

  assert.deepEqual(result.correlators, [], conf.explain(result));
  assert.equal(result.ok, true);
});

test('a constant everyone shares is not a correlator, and is not reported as one', async () => {
  // cnf.jwk.kty is "EC" on every credential ever issued. The first version of
  // this probe reported eighteen findings, half of them constants like this one,
  // and a wallet author reading that list would have concluded it was noise.
  const result = await conf.probeUnlinkability({
    mintFor: await naiveWallet('alice'),
    mintForOther: await naiveWallet('bob'),
    verifiers: VERIFIERS,
  });

  assert.ok(result.harmless.includes('cnf.jwk.kty'));
  assert.ok(result.harmless.includes('consent.language'));
  assert.ok(!result.correlators.includes('cnf.jwk.kty'));
});

test('without a second person the probe says it does not know, rather than guessing', async () => {
  const result = await conf.probeUnlinkability({ mintFor: await naiveWallet('alice'), verifiers: VERIFIERS });

  assert.equal(result.differentialRun, false);
  assert.equal(result.correlators.length, 0, 'nothing may be *confirmed* without a comparison person');
  assert.ok(result.shared.every((s) => s.identifying === null));
  assert.match(result.verdict, /differential not run/);
});

test('reusing one agent key across two verifiers is refused at mint time', async () => {
  const iss = await generateKeyPair('ES256', { extractable: true });
  const wal = await generateKeyPair('ES256', { extractable: true });
  const ag = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(ag.publicKey);
  const card = cardFor(jwk, 'urn:agent:k:s:one');
  const issued = await aic.issue({ card, privateKey: iss.privateKey, holderJwk: jwk });
  const m = { aic: card, walletKey: wal.privateKey, holderJwk: jwk, cardThumb: await aic.cardThumbprint(issued), keyThumb: await sd.thumbprint(jwk) };

  await assert.rejects(
    () => wallet.issueSet({
      base: baseFor(m), verifiers: VERIFIERS, walletSecret: 's', consentId: 'c',
      purpose: 'Apply for the thing I need, on my behalf.',
      perVerifier: () => m,   // the same material every time. The default mistake.
    }),
    /same agent key/,
  );
});

test('issueSet will not let a caller skip the expensive half by omission', async () => {
  await assert.rejects(
    () => wallet.issueSet({ base: {}, verifiers: VERIFIERS, walletSecret: 's', consentId: 'c' }),
    /needs perVerifier/,
  );
});

test('one consent act reaches each office under a different reference', () => {
  const args = { walletSecret: 's', consentId: 'c-44a1' };
  const a = wallet.consentReference({ ...args, verifierId: 'https://aish.alberta.ca' });
  const b = wallet.consentReference({ ...args, verifierId: 'https://health.alberta.ca' });

  assert.notEqual(a, b, 'one consent record must not hand every office the same pointer');
  assert.equal(a, wallet.consentReference({ ...args, verifierId: 'https://aish.alberta.ca' }), 'and it must be stable');
});

test('a consent timestamp is rounded to the day, because a millisecond is a fingerprint', () => {
  const coarse = wallet.coarsenTimestamp('2026-08-14T13:47:22.418Z');
  assert.equal(coarse, '2026-08-14T00:00:00.000Z');
  // The day is what a consent record needs to mean anything, and it puts the
  // person in a herd of everyone who consented that day rather than a herd of one.
  assert.equal(wallet.coarsenTimestamp('2026-08-14T02:11:00.001Z'), coarse);
});

test('the cost of unlinkability is stated rather than discovered later', () => {
  const cost = wallet.describeCost(3);
  assert.equal(cost.identity_cards, 3);
  assert.equal(cost.consent_acts, 1);
  assert.match(cost.what_the_person_sees, /one grant/);
  // Someone will propose sharing a card to reduce the bill. The answer has to be
  // written down before they ask.
  assert.match(cost.if_you_share_a_card_instead, /entire property is gone/);
});

// ── The honest-derivation probe ────────────────────────────────────────────

test('a wallet reusing one subject across verifiers is caught by asking it for several', async () => {
  const lying = async (v) => ({ delegator: { sub: 'pw:the-same-everywhere', pairwise: true, sub_audience: v } });
  const result = await conf.probePairwiseHonesty({ mintFor: lying, verifiers: VERIFIERS });

  assert.equal(result.ok, false);
  assert.match(result.problems.join('\n'), /SAME subject/);
});

test('an honest wallet passes the same probe', async () => {
  const honest = await unlinkableWallet('alice');
  const result = await conf.probePairwiseHonesty({ mintFor: honest, verifiers: VERIFIERS });
  assert.equal(result.ok, true, result.problems.join('; '));
});

// ── What these probes do not establish ─────────────────────────────────────

test('LIMITATION: a probe is only as honest as the wallet handed to it', async () => {
  // The first differential run reported delegate.agent_id as harmless, because
  // the fixture gave both people the *same* agent instance. With a per-person
  // agent it is a correlator, and it is the one already written up in
  // PRIVACY-GAP. A conformance probe measures the deployment it is pointed at,
  // and a flattering fixture produces a flattering certificate.
  const shared = 'urn:agent:k:s:SHARED';
  const mint = (serial) => async () => ({ delegate: { agent_id: shared }, delegator: { sub: `pw:${serial}` } });
  const result = await conf.probeUnlinkability({ mintFor: mint('a'), mintForOther: mint('b'), verifiers: VERIFIERS });

  assert.ok(result.harmless.includes('delegate.agent_id'), 'identical agents across people read as harmless, which is a fixture artefact');
  assert.ok(!result.correlators.includes('delegate.agent_id'));
});

test('LIMITATION: passing is a statement about test time, not about production', async () => {
  const honest = await unlinkableWallet('alice');
  const result = await conf.probePairwiseHonesty({ mintFor: honest, verifiers: VERIFIERS });

  // A wallet can derive properly while being assessed and reuse subjects
  // afterwards. Nothing here detects that, and the mitigation is unannounced
  // re-assessment, which is a register's job rather than a protocol's.
  assert.match(result.proves, /Not that it does so in\s+production/);
});
