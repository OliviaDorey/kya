/**
 * The Gaia-X profile conformance test.
 *
 * The claim in the proposal is that "a credential issued in one form verifies
 * in the other". This file is what that claim means, and it is the test Gaia-X
 * Hub Canada would run on the Digital Trust Test Bench rather than take our
 * word for.
 *
 * Four properties, and the last two are the ones that matter:
 *
 *   1  the mapping is total for every field the profile claims to cover
 *   2  the mapping is deterministic, byte for byte
 *   3  a card round-trips with every always-disclosed field intact
 *   4  the mapping refuses to invent a mandatory Gaia-X field it does not have
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import * as aic from '../src/aic.js';
import * as gx from '../src/gaiax.js';

const sec = 1_780_000_000;

/** A complete, valid card. Deliberately the demo's own, so the test tracks reality. */
function card() {
  return {
    vct: aic.AIC_VCT,
    iss: 'https://kya.thekindredagency.com',
    iat: sec,
    exp: sec + 365 * 86400,
    agent: { id: 'urn:agent:kindred:steward:7f3a1c92', name: 'Steward', version: '1.4.2' },
    builder: {
      legal_name: 'The Kindred Agency',
      jurisdiction: 'CA-NS',
      uri: 'https://thekindredagency.com',
    },
    operator: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS' },
    accountable: {
      role: 'Chief Technology Officer',
      contact: 'trust@thekindredagency.com',
      redress_uri: 'https://thekindredagency.com/redress',
    },
    model: { disclosed: true, family: 'claude-opus', version: '5', hosted_in: 'CA', residency_basis: 'asserted' },
    capabilities: ['read:program-information', 'draft:application', 'submit:application', 'monitor:status'],
    conduct: { discloses_ai: 'always', acts_without_approval: false, retains_after_revocation: 'audit-record-only' },
    assurance: { framework: 'PCTF', level: 'pending', assessed_by: null, assessed_at: null },
    status: { status_list: { uri: 'https://status.agentcredential.ca/aic', idx: 4213 } },
  };
}

test('the card this test is built on is itself valid', () => {
  assert.deepEqual(aic.validate(card()).problems, []);
});

// ─────────────────────────────────────────────────────────── 1. totality
test('every field the profile claims to cover is present in the self-description', () => {
  const sd = gx.toGaiaX(card(), { license: 'Apache-2.0' });
  const s = sd.credentialSubject;

  assert.equal(sd.issuer, 'https://kya.thekindredagency.com');
  assert.ok(sd['@context'].includes(gx.CONTEXT.VC), 'the W3C VC context must be first-class');
  assert.deepEqual(s['@type'], ['gx:SoftwareResource', 'kya:AutonomousAgent']);

  // gx:VirtualResource makes these three mandatory. All three must be populated.
  assert.deepEqual(s['gx:copyrightOwnedBy'], ['https://thekindredagency.com']);
  assert.deepEqual(s['gx:license'], ['Apache-2.0']);
  assert.equal(s['gx:policy'].length, 1);

  assert.equal(s['kya:accountablePerson']['kya:contact'], 'trust@thekindredagency.com');
  assert.equal(s['kya:conduct']['kya:disclosesAi'], 'always');
  assert.equal(s['kya:builder']['gx:legalName'], 'The Kindred Agency');
  assert.equal(s['kya:builder']['gx:legalAddress']['gx:countryCode'], 'CA');
});

test('the capability ceiling becomes a Gaia-X policy a native verifier can read', () => {
  const c = card();
  const sd = gx.toGaiaX(c, { license: 'Apache-2.0' });
  const actions = sd.credentialSubject['gx:policy'][0]['odrl:permission'].map((p) => p['odrl:action']);
  assert.deepEqual(actions, c.capabilities);
  assert.equal(sd.credentialSubject['gx:policy'][0]['kya:closedVocabulary'], true,
    'the ceiling is closed, and a Gaia-X reader has to be told that or it reads as a sample');
});

test('an operator that differs from the builder is carried as a second legal person', () => {
  const c = card();
  c.operator = { legal_name: 'Some Operator Ltd', jurisdiction: 'CA-ON' };
  const s = gx.toGaiaX(c, { license: 'Apache-2.0' }).credentialSubject;
  assert.equal(s['kya:operator']['gx:legalName'], 'Some Operator Ltd');
  assert.equal(s['kya:operator']['gx:legalAddress']['gx:countryCode'], 'CA');
  assert.notEqual(s['gx:maintainedBy'][0], s['gx:copyrightOwnedBy'][0],
    'who made it and who runs it are different claims and must not collapse');
});

// ─────────────────────────────────────────────────────────── 2. determinism
test('the mapping is deterministic, byte for byte', () => {
  const a = gx.canonical(gx.toGaiaX(card(), { license: 'Apache-2.0' }));
  const b = gx.canonical(gx.toGaiaX(card(), { license: 'Apache-2.0' }));
  assert.equal(a, b);
});

test('key insertion order in the source card does not change the output bytes', () => {
  const forward = card();
  const shuffled = Object.fromEntries(Object.entries(forward).reverse());
  assert.equal(
    gx.canonical(gx.toGaiaX(forward, { license: 'Apache-2.0' })),
    gx.canonical(gx.toGaiaX(shuffled, { license: 'Apache-2.0' })),
  );
});

// ─────────────────────────────────────────────────────────── 3. round trip
test('a card round-trips with every always-disclosed field intact', () => {
  const { ok, findings } = gx.roundTrips(card());
  assert.deepEqual(findings, []);
  assert.ok(ok);
});

test('a round-tripped card is still a valid Agent Identity Card', () => {
  const back = gx.fromGaiaX(gx.toGaiaX(card(), { license: 'Apache-2.0' }));
  assert.deepEqual(aic.validate(back).problems, [],
    'a credential that survives the bridge but fails validation has not survived it');
});

test('claims the profile does not map are carried, not dropped', () => {
  const c = card();
  c.future_field = { something: 'the card is ahead of the profile' };
  const back = gx.fromGaiaX(gx.toGaiaX(c, { license: 'Apache-2.0' }));
  assert.deepEqual(back.future_field, { something: 'the card is ahead of the profile' });
});

test('an absent registry identifier stays absent rather than becoming null', () => {
  const s = gx.toGaiaX(card(), { license: 'Apache-2.0' }).credentialSubject;
  assert.equal('gx:registrationNumber' in s['kya:builder'], false,
    'question eight, in code: omitting a claim is conservative, asserting an empty one is not');
});

// ─────────────────────────────────────────────────────────── 4. refusals
test('the mapping refuses to invent a licence it does not have', () => {
  assert.throws(() => gx.toGaiaX(card(), {}), /license is required/);
  assert.throws(() => gx.toGaiaX(card(), { license: '   ' }), /license is required/);
});

test('the mapping refuses to guess a copyright owner', () => {
  const c = card();
  delete c.builder;
  assert.throws(() => gx.toGaiaX(c, { license: 'Apache-2.0' }), /builder.legal_name is required/);
});

test('roundTrips reports rather than throws, so a conformance run sees every finding', () => {
  const { ok, findings } = gx.roundTrips({ vct: 'nonsense' });
  assert.equal(ok, false);
  assert.ok(findings.length > 0);
});

// ─────────────────────────────────────────────────────────── the honest limits
test('LIMITATION: this proves semantic equivalence, not cryptographic equivalence', () => {
  const sd = gx.toGaiaX(card(), { license: 'Apache-2.0' });
  assert.equal('proof' in sd, false,
    'nothing here signs anything. A re-signed credential is a new credential, and the profile says so');
});

test('LIMITATION: the Gaia-X direction is a widening, so only one direction round-trips', () => {
  const sd = gx.toGaiaX(card(), { license: 'MIT' });
  const back = gx.fromGaiaX(sd);
  assert.equal(back.license, undefined,
    'gx:license has nowhere to live in an Agent Identity Card and is dropped on the way home');
  assert.equal(gx.toGaiaX(back, { license: 'MIT' }).credentialSubject['gx:license'][0], 'MIT',
    'which is why the licence must be supplied on every crossing rather than carried');
});
