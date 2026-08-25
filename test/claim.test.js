/**
 * The counter-claim: the person's half of an identity.
 *
 * Built 23 August 2026 out of the philosophy thread. Olivia: *"identity is about
 * who claims you, and who you claim back."* Three things are asserted here.
 *
 * 1. The claim is the person's and only the person can end it.
 * 2. A claim cannot be extended without somebody saying so.
 * 3. The registrar records the obligation and never the claimant.
 *
 * The third is the one to watch. It is the rule the first design of this feature
 * would have broken, and the test that fails is the only thing standing between
 * a register of agents and a register of the people relying on them.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPair } from 'jose';
import * as claim from '../src/claim.js';
import * as events from '../src/events.js';
import { AUTHORITY } from '../src/revocation.js';

const A = 'urn:agent:kindred:steward:7f3a1c92';
const keys = await generateKeyPair('ES256', { extractable: true });
const at = (d) => Date.parse(d);

const made = (over = {}) => claim.make({
  agent_id: A,
  aic_thumbprint: 'nOXY1z9Zk8sV',
  purpose: 'Help me sort out my file and tell me before anything is sent',
  made_at: '2026-01-01',
  ...over,
});

// ─────────────────────────────────────────────────── what a claim has to carry
test('a claim on "the agent" rather than on a card is refused', () => {
  assert.throws(
    () => claim.make({ agent_id: A, purpose: 'help me', made_at: '2026-01-01' }),
    /aic_thumbprint is required/,
  );
});

test('a claim with no purpose in the person\'s own words is refused', () => {
  assert.throws(
    () => claim.make({ agent_id: A, aic_thumbprint: 't', made_at: '2026-01-01' }),
    /purpose is required, in the person's own words/,
  );
});

// ───────────────────────────────────────────────────────── live, due, lapsed
test('a claim is live, then due, then lapsed, and the person is told before it lapses', () => {
  const c = made();
  assert.equal(claim.state(c, { now: at('2026-02-01') }).state, claim.CLAIM_STATE.LIVE);
  assert.equal(claim.state(c, { now: at('2026-03-25') }).state, claim.CLAIM_STATE.DUE);
  assert.equal(claim.state(c, { now: at('2026-06-01') }).state, claim.CLAIM_STATE.LAPSED);

  const warned = claim.state(c, { now: at('2026-03-25') });
  assert.ok(warned.days_left <= claim.WARNING_DAYS && warned.days_left >= 0);
  assert.ok(warned.live, 'a due claim is still a live claim; the warning is not a punishment');
});

test('quarterly is the default, because Keep in Touch is quarterly', () => {
  assert.equal(claim.DEFAULT_RENEWAL_DAYS, 90);
  assert.equal(claim.renewBy(made()), '2026-04-01');
});

test('renewing moves the date, and the renewal is recorded rather than assumed', () => {
  const c = claim.renew(made(), { at: '2026-03-20', note: 'quarterly check-in' });
  assert.equal(c.renewals.length, 1);
  assert.equal(claim.lastAffirmed(c), '2026-03-20');
  assert.equal(claim.state(c, { now: at('2026-05-01') }).state, claim.CLAIM_STATE.LIVE);
});

test('NO SILENT EXTENSION: nothing but renew() can move the renewal date', () => {
  // The failure mode this file exists to displace is the relationship that
  // renews while nobody is looking. So: exercise every exported function on a
  // claim and assert that only renew() changes when it was last affirmed.
  const c = made();
  const before = claim.lastAffirmed(c);
  const now = at('2026-06-01');

  claim.state(c, { now });
  claim.renewBy(c);
  claim.narrow(['read', 'submit'], claim.CLAIM_STATE.LAPSED);
  claim.forVerifier(c, { now });
  claim.explainToPerson(c, { now });
  claim.validate(c);
  claim.needsLiveClaim('submit');

  assert.equal(claim.lastAffirmed(c), before, 'a claim moved without anybody saying so');
  assert.equal(claim.state(c, { now }).state, claim.CLAIM_STATE.LAPSED,
    'and time passing still lapses it');
});

// ──────────────────────────────────────────────── degrade, do not collapse
test('a lapsed claim keeps watching and stops acting', () => {
  const actions = ['read', 'draft', 'submit', 'draft-appeal', 'appeal', 'monitor', 'correspond'];
  const left = claim.narrow(actions, claim.CLAIM_STATE.LAPSED);
  assert.deepEqual(left, ['read', 'monitor']);
  for (const gone of ['draft', 'submit', 'draft-appeal', 'appeal', 'correspond']) {
    assert.ok(claim.needsLiveClaim(gone), `${gone} must require a live claim`);
  }
});

test('a lapse narrows; only the person ends', () => {
  const c = made();
  assert.deepEqual(claim.narrow(['read', 'submit'], claim.CLAIM_STATE.LAPSED), ['read'],
    'a lapse is not an ending');
  assert.deepEqual(claim.narrow(['read', 'submit'], claim.CLAIM_STATE.ENDED), [],
    'an ending is an ending');
  assert.equal(claim.state(claim.end(c, { by: AUTHORITY.PRINCIPAL, at: '2026-02-01' }), { now: at('2026-02-02') }).state,
    claim.CLAIM_STATE.ENDED);
});

test('a lapsed claim can be renewed; an ended one cannot be revived', () => {
  const lapsed = made();
  assert.equal(claim.state(claim.renew(lapsed, { at: '2026-07-01' }), { now: at('2026-07-02') }).state,
    claim.CLAIM_STATE.LIVE);

  const ended = claim.end(made(), { by: AUTHORITY.PRINCIPAL, at: '2026-02-01' });
  assert.throws(() => claim.renew(ended, { at: '2026-03-01' }), /A new claim is a new claim/);
});

// ─────────────────────────────────────── light into dark, not dark into light
test('only the principal may end a claim; everyone else may stop the agent instead', () => {
  const c = made();
  assert.equal(claim.end(c, { by: AUTHORITY.PRINCIPAL }).ended_by, AUTHORITY.PRINCIPAL);
  for (const other of [AUTHORITY.ACCOUNTABLE, AUTHORITY.ISSUER, AUTHORITY.ANCESTOR, AUTHORITY.RELYING_PARTY]) {
    assert.throws(() => claim.end(c, { by: other }), /may stop the agent instead/,
      `${other} must not be able to end a person's claim`);
  }
});

test('ending a claim can take no payment and needs no reason', () => {
  // Vital-events pricing doctrine: a fee on switching something off prices the
  // exit. A reason field that were required would be a retention gate wearing a
  // record-keeping hat.
  const ended = claim.end(made(), { by: AUTHORITY.PRINCIPAL });
  assert.equal(ended.ended_reason, null);
  assert.ok(!/\b(price|fee|payment|charge)\b/.test(readFileSync(new URL('../src/claim.js', import.meta.url), 'utf8')
    .split('export function end(')[1].split('export function state(')[0]),
  'end() must not learn about money');
});

// ──────────────────────────────────────────────────── the person's own words
test('a verifier is never shown the purpose sentence', () => {
  const shown = claim.forVerifier(made(), { now: at('2026-02-01') });
  assert.equal(shown.purpose, undefined);
  assert.ok(!JSON.stringify(shown).includes('Help me sort out'));
  assert.equal(shown.claim_state, claim.CLAIM_STATE.LIVE);
  assert.ok(shown.renew_by, 'but it is told when this was last affirmed and when it is due');
});

test('the person is shown their own sentence back, and what happens next', () => {
  const words = claim.explainToPerson(made(), { agentName: 'Steward', now: at('2026-06-01') });
  assert.match(words, /Help me sort out my file/);
  assert.match(words, /keep watching your file/);
  assert.doesNotMatch(words, /suspended|invalid|error/i, 'a lapse is not an error state');
});

// ─────────────────────────── the registrar records the obligation, not the person
const reg = () => new events.Registry({ id: 'https://registry.sandbox.example.ca' });
const add = (r, e) => r.append(e, { privateKey: keys.privateKey });
const birth = () => ({
  agent_id: A, kind: events.EVENT.BIRTH, at: '2026-01-15',
  builder: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS' },
  operator: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS' },
  accountable: { role: 'CTO', contact: 'trust@example.ca' },
  capabilities: ['read:program-information'], version: '1.4.2',
});
const transfer = (over = {}) => ({
  agent_id: A, kind: events.EVENT.TRANSFER, at: '2026-06-01',
  from: { legal_name: 'The Kindred Agency' }, to: { legal_name: 'Acquirer Co' },
  notice: { given_at: '2026-05-01' },
  counter_claim: { policy: events.COUNTER_CLAIM.RECONSENT, window_days: 30 },
  ...over,
});

test('a transfer that says nothing about the people who claimed the agent is refused', async () => {
  const r = reg();
  await add(r, birth());
  const { counter_claim, ...silent } = transfer();
  await assert.rejects(add(r, silent), /transfer requires "counter_claim"/);
  assert.equal(r.entries.length, 1, 'and it is not stored');
});

test('a re-consent with no deadline is refused, because that is a notification', async () => {
  const r = reg();
  await add(r, birth());
  await assert.rejects(
    add(r, transfer({ counter_claim: { policy: events.COUNTER_CLAIM.RECONSENT } })),
    /notification with a longer word/,
  );
});

test('THE RULE: the register records how many, never whose', async () => {
  const r = reg();
  await add(r, birth());

  // Every plausible way somebody helpfully adds the people to the record.
  for (const smuggled of [
    { claimants: ['did:example:alice'] },
    { contact: 'alice@example.ca' },
    { segment: 'AISH recipients' },
    { claimant_count_by_region: { 'CA-AB': 4 } },
  ]) {
    await assert.rejects(
      add(r, transfer({ counter_claim: { policy: events.COUNTER_CLAIM.NOTIFY, ...smuggled } })),
      /is not a permitted field/,
      `${Object.keys(smuggled)[0]} must not reach the register`,
    );
  }

  await assert.rejects(
    add(r, { agent_id: A, kind: events.EVENT.RECONSENT, at: '2026-07-01', discharges: 2, method: 'wallet prompt', outstanding: ['did:example:alice'] }),
    /never a list of them/,
  );
  assert.equal(r.entries.length, 1, 'nothing identifying anybody was stored');
});

test('an outstanding counter-claim is reported, and discharging it is a recorded event', async () => {
  const r = reg();
  await add(r, birth());
  await add(r, transfer());

  let l = r.lookup(A);
  assert.equal(l.counter_claim_outstanding, true);
  assert.equal(l.counter_claims[0].policy, events.COUNTER_CLAIM.RECONSENT);
  assert.equal(l.counter_claims[0].window_days, 30);
  assert.equal(l.operator.legal_name, 'Acquirer Co', 'the transfer still happened');

  await add(r, {
    agent_id: A, kind: events.EVENT.RECONSENT, at: '2026-06-20',
    discharges: 2, method: 'wallet prompt', outstanding: 0,
  });
  l = r.lookup(A);
  assert.equal(l.counter_claim_outstanding, false);
  assert.equal(l.counter_claims[0].discharged, true);
  assert.equal(l.counter_claims[0].outstanding, 0);
});

test('an outstanding obligation does not silently change the status', async () => {
  // Deliberate. adc.transferOutcome() already refuses an unrecorded transfer on
  // the credential path; a registrar reaching the same verdict by a different
  // route is how two verifiers drift apart while both look correct. The register
  // surfaces the fact and the policy layer acts on it.
  const r = reg();
  await add(r, birth());
  await add(r, transfer());
  const l = r.lookup(A);
  assert.equal(l.counter_claim_outstanding, true);
  assert.equal(l.state, 'valid');
  assert.equal(l.inForce.ok, true);
});

test('LIMITATION: a lapse mid-appeal is mitigated, not solved', () => {
  // read and monitor survive so the agent can still tell the person what is
  // happening to their file. Nothing here stops a person losing a deadline they
  // were told about and did not act on. Written down so it is a known hazard
  // rather than a discovered one.
  assert.deepEqual(claim.SURVIVES_LAPSE, ['read', 'monitor']);
  assert.ok(claim.needsLiveClaim('appeal'), 'filing an appeal needs a live claim');
});
