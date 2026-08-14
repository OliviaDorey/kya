/**
 * Threat model remediation, priorities 2 to 4.
 *
 * Priority 1 (binding enforcement) closed on 13 August and is defended in
 * credentials.test.js. These are the next three, and as elsewhere in this suite
 * the things they do *not* achieve get a test too, because a remediation that
 * quietly does less than its entry in the priority list is worse than an open
 * item.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from 'jose';

import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as sdjwt from '../src/sdjwt.js';
import * as status from '../src/status.js';
import * as federation from '../src/federation.js';
import * as pairwise from '../src/pairwise.js';

const issuerKp = await generateKeyPair('ES256', { extractable: true });
const agentKp = await generateKeyPair('ES256', { extractable: true });
const agentJwk = await exportJWK(agentKp.publicKey);
const sec = Math.floor(Date.now() / 1000);

// ── Priority 2: issuer key resolution, and pinning by default ──────────────

test('an unpinned trust anchor is refused, because it signs its own configuration', async () => {
  // The circularity is the point: an anchor publishes the key it signed itself
  // with, so without a pin the fetch establishes nothing and every credential
  // verified beneath it inherits that. Refusing by default is what makes the
  // insecure path the one you have to ask for.
  await assert.rejects(
    () => federation.fetchTrustAnchor('https://anchor.example.ca'),
    (err) => {
      assert.match(err.message, /refusing to fetch .* unpinned/);
      assert.match(err.message, /trustOnFirstUse/, 'a refusal with no way forward is a dead end');
      return true;
    },
  );
});

test('bootstrapping without a pin has to be asked for by name', async () => {
  // Not a network test. It must get far enough to attempt a fetch, which proves
  // the pinning guard let it through rather than that the anchor exists.
  await assert.rejects(
    () => federation.fetchTrustAnchor('https://anchor.invalid', { trustOnFirstUse: true }),
    (err) => {
      assert.doesNotMatch(err.message, /refusing to fetch/, 'the pinning guard should have passed');
      return true;
    },
  );
});

test('verifying a card against no established key at all is refused', async () => {
  const card = await aic.issue({ card: baseCard(), privateKey: issuerKp.privateKey, holderJwk: agentJwk });
  await assert.rejects(
    () => aic.verify(card, {}),
    /needs either issuerKey, or trust: \{ anchor \}/,
  );
});

test('a caller-supplied key and a federation-resolved key are not recorded as the same fact', async () => {
  // A verifier that logs both identically cannot audit its own trust decisions
  // later, which is how "we verified it" survives a post-incident review it
  // should not have.
  const card = await aic.issue({ card: baseCard(), privateKey: issuerKp.privateKey, holderJwk: agentJwk });
  const presented = await sdjwt.present(card, { reveal: [], audience: 'https://v.ca', nonce: 'n', holderKey: agentKp.privateKey });
  const result = await aic.verify(presented, { issuerKey: issuerKp.publicKey, audience: 'https://v.ca', nonce: 'n' });

  assert.equal(result.issuerTrust.via, 'caller-supplied-key');
  assert.equal(result.issuerTrust.pinnedAnchor, false);
});

test('an issuer whose chain cannot be validated resolves no keys at all', async () => {
  // The distinction that matters is where a key comes from: the statement the
  // anchor signs about the subordinate, never the subordinate's own
  // self-published configuration. So when the chain cannot be established — for
  // any reason, including the anchor being unreachable — the answer is no keys
  // and an error, not a fallback to whatever the issuer says about itself. A
  // fallback there would quietly undo the whole point of resolving keys.
  const anchor = {
    entityId: 'https://anchor.invalid',
    pinned: true,
    payload: { metadata: { federation_entity: { federation_fetch_endpoint: 'https://anchor.invalid/fetch' } } },
    jwks: { keys: [] },
  };

  let resolved = null;
  await assert.rejects(
    async () => { resolved = await federation.resolveIssuerKeys(anchor, 'https://issuer.example.ca'); },
  );
  assert.equal(resolved, null, 'no keys may come back from a chain that was never established');
});

test('an anchor that publishes no fetch endpoint cannot vouch for anybody', async () => {
  await assert.rejects(
    () => federation.resolveIssuerKeys(
      { entityId: 'https://a.ca', pinned: true, payload: { metadata: {} }, jwks: { keys: [] } },
      'https://issuer.example.ca',
    ),
    /federation_fetch_endpoint/,
  );
});

// ── Priority 4: pairwise subjects, computed rather than asserted ───────────

test('the same person gets a different subject at every verifier', () => {
  const walletSecret = 'a-secret-that-never-leaves-the-wallet';
  const a = pairwise.derive({ walletSecret, verifierId: 'https://aish.alberta.ca' });
  const b = pairwise.derive({ walletSecret, verifierId: 'https://health.alberta.ca' });

  assert.notEqual(a, b, 'two departments must not be able to join records on this identifier');
  assert.equal(a, pairwise.derive({ walletSecret, verifierId: 'https://aish.alberta.ca' }), 'and it must be stable at one verifier');
});

test('a wallet can check its own derivation; a verifier deliberately cannot', () => {
  const walletSecret = 's';
  const sub = pairwise.derive({ walletSecret, verifierId: 'https://v.ca' });

  assert.ok(pairwise.selfCheck({ walletSecret, verifierId: 'https://v.ca', sub }));
  assert.ok(!pairwise.selfCheck({ walletSecret, verifierId: 'https://other.ca', sub }));
  // There is no verifier-side equivalent on purpose: the computation that would
  // satisfy a verifier is the same one that would let it derive the person's
  // subject at every other verifier.
  assert.equal(typeof pairwise.boundToVerifier, 'function');
  assert.ok(!('verifierCheck' in pairwise));
});

test('a subject minted for one verifier is refused at another', () => {
  const delegator = { sub: 'pw:x', pairwise: true, sub_audience: 'https://aish.alberta.ca' };
  const bound = pairwise.boundToVerifier(delegator, 'https://health.alberta.ca');

  assert.equal(bound.ok, false);
  assert.match(bound.problems[0], /derived for somebody else/);
});

test('a pairwise claim that cannot say which verifier is not a claim', () => {
  const bound = pairwise.boundToVerifier({ sub: 'pw:x', pairwise: true }, 'https://v.ca');
  assert.equal(bound.ok, false);
  assert.match(bound.problems[0], /sub_audience is absent/);
});

test('issuing computes the pairwise subject instead of trusting the caller to have done it', async () => {
  const walletKp = await generateKeyPair('ES256', { extractable: true });
  const card = baseCard();
  const issuedCard = await aic.issue({ card, privateKey: issuerKp.privateKey, holderJwk: agentJwk });

  const { credential } = await adc.issue({
    adc: delegation(await aic.cardThumbprint(issuedCard), await sdjwt.thumbprint(agentJwk), { delegator: { sub: 'WRONG', verified_by: 'https://account.alberta.ca/dts' } }),
    aic: card,
    walletKey: walletKp.privateKey,
    holderJwk: agentJwk,
    pairwise: { walletSecret: 'wallet-secret', verifierId: 'https://v.ca' },
  });

  const claims = JSON.parse(Buffer.from(credential.split('~')[0].split('.')[1], 'base64url').toString('utf8'));
  assert.equal(claims.delegator.sub, pairwise.derive({ walletSecret: 'wallet-secret', verifierId: 'https://v.ca' }));
  assert.equal(claims.delegator.sub_audience, 'https://v.ca');
  assert.notEqual(claims.delegator.sub, 'WRONG', 'the library computes it; the caller does not get to be wrong');
});

test('LIMITATION: a wallet that lies about its derivation still passes', () => {
  // The honest ceiling. The derivation input is the wallet's secret and never
  // travels, so nothing outside the wallet can recompute the subject. A wallet
  // that reuses one value everywhere while stamping each copy with the right
  // audience satisfies every check in this file. Closing it needs a
  // zero-knowledge proof of correct derivation or an attested wallet, and both
  // are out of scope for v0.4.
  const reused = 'pw:the-same-value-everywhere';
  for (const verifier of ['https://a.ca', 'https://b.ca']) {
    const bound = pairwise.boundToVerifier({ sub: reused, pairwise: true, sub_audience: verifier }, verifier);
    assert.equal(bound.ok, true, 'a lying wallet passes, and this is written down rather than implied');
  }
  assert.match(pairwise.boundToVerifier({ sub: reused, pairwise: true, sub_audience: 'https://a.ca' }, 'https://a.ca').proves, /Not that the wallet derived it correctly/);
});

// ── Priority 3: availability, mirroring, and the known outage ──────────────

test('a status list is read from every mirror before anything fails closed', async () => {
  const list = new status.StatusList({ size: 8 });
  const token = await status.publish({ list, uri: 'https://s.ca/adc', issuer: 'https://s.ca', privateKey: issuerKp.privateKey, ttl: 300 });

  const result = await status.fetchStatusMirrored(
    [() => { throw new Error('mirror one is down'); }, () => token],
    { issuerKey: issuerKp.publicKey, idx: 0 },
  );

  assert.equal(result.reachable, true);
  assert.equal(result.mirrorsTried, 2);
  assert.equal(result.failures.length, 1, 'the dead mirror is still reported, or two mirrors quietly become one');
  assert.equal(status.inForce(result).ok, true);
});

test('every mirror failing fails closed, which is the whole rule', async () => {
  const result = await status.fetchStatusMirrored(
    [() => { throw new Error('down'); }, () => { throw new Error('also down'); }],
    { issuerKey: issuerKp.publicKey, idx: 0 },
  );

  assert.equal(result.reachable, false);
  assert.equal(status.inForce(result).ok, false);
});

test('a deployment below the mirroring minimum is told so rather than passing quietly', async () => {
  const list = new status.StatusList({ size: 8 });
  const token = await status.publish({ list, uri: 'https://s.ca/adc', issuer: 'https://s.ca', privateKey: issuerKp.privateKey, ttl: 300 });
  const result = await status.fetchStatusMirrored([() => token], { issuerKey: issuerKp.publicKey, idx: 0 });

  assert.equal(result.underMirrored, true);
  assert.equal(status.AVAILABILITY.MIN_MIRRORS, 2);
});

test('a known outage buys no grace period, and does not strand the person either', () => {
  const g = status.outageGuidance({ listUri: 'https://s.ca/adc', since: '10:00', redressUri: 'https://k.ca/redress' });

  // No bypass. An attacker who can take down the status list would otherwise
  // have bought exactly the window they wanted.
  assert.equal(g.authority, 'refused');
  assert.equal(g.grace_period, null);

  // And the person is not the one who pays for it.
  assert.match(g.relying_party_must, /Do not turn anyone away/);
  assert.match(g.tell_the_person, /nothing you did/);
  assert.match(g.tell_the_person, /required to help you directly/);
});

test('LIMITATION: an availability target is a number, not a mechanism', () => {
  // Publishing 99.9% does not deliver 99.9%. There is no monitoring, no
  // alerting, no on-call and no deployment behind this constant; it is the
  // commitment a deployment would be held to, and the deployment does not exist.
  assert.equal(status.AVAILABILITY.TARGET, 0.999);
  assert.match(status.AVAILABILITY.MEASURED, /external probes/);
});

// ── fixtures ───────────────────────────────────────────────────────────────

function baseCard() {
  return {
    vct: aic.AIC_VCT,
    iss: 'https://kya.thekindredagency.com',
    iat: sec,
    exp: sec + 86400,
    agent: { id: 'urn:agent:kindred:steward:r', name: 'Steward', version: '1.0.0' },
    builder: { legal_name: 'The Kindred Agency Inc.', jurisdiction: 'CA-NS', registry_id: '1', uri: 'https://thekindredagency.com' },
    accountable: { role: 'CTO', contact: 'trust@thekindredagency.com', redress_uri: 'https://thekindredagency.com/redress' },
    model: { disclosed: true, family: 'claude-opus', version: '5', hosted_in: 'CA', residency_basis: 'asserted' },
    capabilities: ['read:program-information', 'draft:application', 'submit:application'],
    conduct: { discloses_ai: 'always', acts_without_approval: false, retains_after_revocation: 'audit-record-only' },
    status: { status_list: { uri: 'https://status.agentcredential.ca/aic', idx: 1 } },
    cnf: { jwk: agentJwk },
  };
}

function delegation(cardThumb, keyThumb, over = {}) {
  return {
    vct: adc.ADC_VCT,
    iss: 'https://wallet.example.ca/u/1',
    iat: sec,
    exp: sec + 7 * 86400,
    delegator: { sub: 'pw:x', pairwise: true, sub_audience: 'https://v.ca', verified_by: 'https://account.alberta.ca/dts' },
    delegate: { agent_id: 'urn:agent:kindred:steward:r', aic_thumbprint: cardThumb, cnf_thumbprint: keyThumb },
    purpose_commitment: 'commitment',
    authorization_details: [
      { type: 'ca_public_service_request', capability: 'submit:form', actions: ['draft', 'submit'], constraints: { requires_human_approval: ['submit'] } },
    ],
    consent: { record_uri: 'https://wallet.example.ca/c/1', captured_at: new Date().toISOString(), language: 'en-CA', method: 'in-app-explicit' },
    revocation: { revoke_uri: 'https://revoke.agentcredential.ca/d/1', citizen_facing: true },
    status: { status_list: { uri: 'https://status.agentcredential.ca/adc', idx: 1 } },
    ...over,
  };
}
