/**
 * The registrar: packages 4 to 7 of the 20 August 2026 scope.
 *
 * Transfer semantics, the event log, the lookup, and the probes. The assertions
 * are from Part 6 of the scope note, and the load-bearing one is the last:
 * a verifier holding only the registrar lookup must reach the same decision as
 * one holding the credentials.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from 'jose';
import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as status from '../src/status.js';
import * as events from '../src/events.js';
import { probeRegistrar } from '../src/conformance.js';

const A = 'urn:agent:kindred:steward:7f3a1c92';
const keys = await generateKeyPair('ES256', { extractable: true });

const reg = async () => new events.Registry({ id: 'https://registry.sandbox.example.ca' });
const add = (r, e) => r.append(e, { privateKey: keys.privateKey });

const birth = (over = {}) => ({
  agent_id: A, kind: events.EVENT.BIRTH, at: '2026-01-15',
  builder: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS' },
  operator: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS' },
  accountable: { role: 'CTO', contact: 'trust@example.ca' },
  capabilities: ['read:program-information'], version: '1.4.2', ...over,
});

// ────────────────────────────────────────────────── package 4, transfer terms
test('a transfer with no notice is refused on the card', () => {
  const card = {
    vct: aic.AIC_VCT, iss: 'https://k.example.ca', iat: 1, exp: 2,
    agent: { id: A, name: 'Steward' },
    builder: { legal_name: 'K', jurisdiction: 'CA-NS' },
    operator: { legal_name: 'Acquirer Co', jurisdiction: 'CA-ON' },
    accountable: { role: 'CTO', contact: 'a@b.ca', redress_uri: 'https://x/r' },
    model: { disclosed: false },
    capabilities: [], conduct: { discloses_ai: 'always', acts_without_approval: false },
    status: {}, transfer: { from: { legal_name: 'K', jurisdiction: 'CA-NS' }, effective: '2026-06-01' },
  };
  assert.match(aic.validate(card).problems.join(' '), /transfer.notice is required/);
});

test('a transfer that transfers nothing is refused', () => {
  const card = {
    vct: aic.AIC_VCT, iss: 'https://k.example.ca', iat: 1, exp: 2,
    agent: { id: A, name: 'Steward' },
    builder: { legal_name: 'K', jurisdiction: 'CA-NS' },
    operator: { legal_name: 'K', jurisdiction: 'CA-NS' },
    accountable: { role: 'CTO', contact: 'a@b.ca', redress_uri: 'https://x/r' },
    model: { disclosed: false },
    capabilities: [], conduct: { discloses_ai: 'always', acts_without_approval: false },
    status: {},
    transfer: { from: { legal_name: 'K', jurisdiction: 'CA-NS' }, effective: '2026-06-01', notice: { given_at: '2026-05-01' } },
  };
  assert.match(aic.validate(card).problems.join(' '), /transfers nothing/);
});

test('the three transfer policies are settings on one mechanism', () => {
  const report = { continuity: adc.CONTINUITY.REISSUED_TERMS_CHANGED };
  const card = {
    operator: { legal_name: 'Acquirer Co' },
    transfer: { from: { legal_name: 'The Kindred Agency' }, effective: '2026-06-01', notice: { given_at: '2026-05-01' } },
  };
  const notify = adc.transferOutcome({ report, aic: card, policy: aic.TRANSFER_POLICY.NOTIFY });
  const reconsent = adc.transferOutcome({ report, aic: card, policy: aic.TRANSFER_POLICY.RE_CONSENT });
  const voided = adc.transferOutcome({ report, aic: card, policy: aic.TRANSFER_POLICY.VOID });

  assert.equal(notify.allow, true);
  assert.equal(notify.action, 'accept-and-notify');
  assert.equal(reconsent.allow, false);
  assert.equal(reconsent.action, 'suspend-pending-re-consent');
  assert.match(reconsent.reason, /not being asked to start again/);
  assert.equal(voided.allow, false);
  assert.equal(voided.action, 'refuse');
});

test('an unrecorded transfer is refused under EVERY policy, including notify', () => {
  const report = { continuity: adc.CONTINUITY.REISSUED_TERMS_CHANGED };
  const card = { operator: { legal_name: 'Acquirer Co' }, transfer: { from: { legal_name: 'K' }, effective: '2026-06-01' } };
  for (const policy of Object.values(aic.TRANSFER_POLICY)) {
    const out = adc.transferOutcome({ report, aic: card, policy });
    assert.equal(out.allow, false, `${policy} must not accept an unrecorded transfer`);
    assert.match(out.reason, /no record that anyone was told/);
  }
});

test('VOID is the default, so nobody gets continuity by forgetting to choose', () => {
  const report = { continuity: adc.CONTINUITY.REISSUED_TERMS_CHANGED };
  const out = adc.transferOutcome({ report, aic: { transfer: undefined } });
  assert.equal(out.allow, false);
  assert.equal(out.action, 'refuse');
});

// ────────────────────────────────────────────────────── package 5, the record
test('the record is chained, and editing one entry breaks that entry', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.TRANSFER, at: '2026-06-01',
    from: { legal_name: 'The Kindred Agency' }, to: { legal_name: 'Acquirer Co' }, notice: { given_at: '2026-05-01' } });
  await add(r, { agent_id: A, kind: events.EVENT.GUARDIAN, at: '2026-07-01',
    from: { role: 'CTO', contact: 'old@example.ca' }, to: { role: 'CTO', contact: 'new@example.ca' } });

  const clean = await r.verify({ publicKey: keys.publicKey });
  assert.equal(clean.ok, true);

  r.entries[1].to = { legal_name: 'Somebody Else' };
  const tampered = await r.verify({ publicKey: keys.publicKey });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.results[1].hashOk, false, 'the edited entry fails');
  assert.equal(tampered.results[0].hashOk, true, 'and nothing else is implicated');
});

test('a death that names neither a successor nor an explicit none is refused at the door', async () => {
  const r = await reg();
  await add(r, birth());
  await assert.rejects(
    add(r, { agent_id: A, kind: events.EVENT.DEATH, at: '2026-12-01', effective: '2026-12-01', notice: { given_at: '2026-11-01' } }),
    /death requires "successor"/,
  );
  assert.equal(r.entries.length, 1, 'and it is not stored');
});

test('a death may say plainly that nobody is taking this on', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.DEATH, at: '2026-12-01', effective: '2026-12-01',
    successor: null, notice: { given_at: '2026-11-01', uri: 'https://example.ca/notice' } });
  assert.equal(r.lookup(A).successor, null);
});

test('a correction amends without deleting, and the corrected entry stays in the history', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.SUSPENSION, at: '2026-05-01', by: 'https://verifier.example.ca', reason: 'recorded in error' });
  assert.equal(r.lookup(A).state, 'suspended');

  await add(r, { agent_id: A, kind: events.EVENT.CORRECTION, at: '2026-05-02', corrects: 2, reason: 'the suspension was recorded against the wrong agent' });
  const after = r.lookup(A);
  assert.equal(after.state, 'valid', 'the correction takes effect');
  assert.equal(after.history.length, 3, 'and nothing was deleted to achieve it');
  assert.equal(after.corrections, 1);
});

// ────────────────────────────────────────────────────── package 6, the lookup
test('the lookup carries the current operator, not the founding one', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.TRANSFER, at: '2026-06-01',
    from: { legal_name: 'The Kindred Agency' }, to: { legal_name: 'Acquirer Co' }, notice: { given_at: '2026-05-01' } });
  const l = r.lookup(A);
  assert.equal(l.operator.legal_name, 'Acquirer Co');
  assert.equal(l.transfers, 1);
  assert.equal(l.born, '2026-01-15');
});

test('an agent nobody registered fails closed, and says which it is', async () => {
  const r = await reg();
  const l = r.lookup('urn:agent:nobody:1');
  assert.equal(l.exists, false);
  assert.equal(l.inForce.ok, false);
  assert.match(l.inForce.reason, /no agent by that identifier/);
});

test('revocation outranks retirement, because a person asking why is owed the first answer', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.REVOCATION, at: '2026-08-01', by: 'https://registry.example.ca', reason: 'key compromise' });
  await add(r, { agent_id: A, kind: events.EVENT.DEATH, at: '2026-09-01', effective: '2026-09-01', successor: null, notice: { given_at: '2026-08-15' } });
  assert.equal(r.lookup(A).state, 'revoked');
});

test('THE PROPERTY: the registrar and the credentials reach the same decision', async () => {
  for (const [kind, extra, expected] of [
    [events.EVENT.SUSPENSION, { by: 'https://v.example.ca', reason: 'under review' }, status.STATUS.SUSPENDED],
    [events.EVENT.REVOCATION, { by: 'https://v.example.ca', reason: 'cause' }, status.STATUS.INVALID],
    [events.EVENT.DEATH, { effective: '2026-12-01', successor: null, notice: { given_at: '2026-11-01' } }, status.STATUS.RETIRED],
  ]) {
    const r = await reg();
    await add(r, birth());
    await add(r, { agent_id: A, kind, at: '2026-10-01', ...extra });

    const fromRegistrar = r.lookup(A).inForce;
    const fromStatusList = status.inForce({ status: expected });
    assert.deepEqual(fromRegistrar, fromStatusList,
      `${kind}: a verifier with only the register must decide as one with the credential`);
  }
});

// ─────────────────────────────────────────────────────── package 7, the probes
test('the probes pass a faithful registrar', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.TRANSFER, at: '2026-06-01',
    from: { legal_name: 'K' }, to: { legal_name: 'Acquirer Co' }, notice: { given_at: '2026-05-01' } });
  const { ok, findings } = await probeRegistrar(r, { publicKey: keys.publicKey, agentId: A });
  assert.equal(ok, true, JSON.stringify(findings, null, 1));
  assert.equal(findings.length, 4);
});

test('the probes catch an entry removed from the middle of the record', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.REVOCATION, at: '2026-08-01', by: 'https://v.example.ca', reason: 'cause' });
  await add(r, { agent_id: A, kind: events.EVENT.GUARDIAN, at: '2026-09-01', from: { role: 'CTO' }, to: { role: 'CTO' } });

  // A tidy registrar drops the entry it would rather not have.
  r.entries.splice(1, 1);
  const { ok, findings } = await probeRegistrar(r, { publicKey: keys.publicKey, agentId: A });
  assert.equal(ok, false, JSON.stringify(findings));
  assert.equal(findings.find((f) => f.id === 'chain-intact').ok, false,
    'the entry that followed it no longer follows anything');
});

test('LIMITATION: entries removed from the END of the record are not detectable here', async () => {
  const r = await reg();
  await add(r, birth());
  await add(r, { agent_id: A, kind: events.EVENT.REVOCATION, at: '2026-08-01', by: 'https://v.example.ca', reason: 'cause' });
  assert.equal(r.lookup(A).state, 'revoked');

  r.entries.splice(1, 1);   // drop the most recent entry
  const { ok } = await probeRegistrar(r, { publicKey: keys.publicKey, agentId: A });
  assert.equal(ok, true,
    'a shorter chain is still a valid chain. Closing this needs the head published somewhere the '
    + 'registrar does not control, and until then a registrar can drop its most recent entries '
    + 'and pass every check in this file.');
  assert.equal(r.lookup(A).state, 'valid', 'which is exactly how much that matters');
});

test('LIMITATION: a registrar that never wrote the entry passes every probe', async () => {
  const r = await reg();
  await add(r, birth());
  const { ok } = await probeRegistrar(r, { publicKey: keys.publicKey, agentId: A });
  assert.equal(ok, true,
    'nothing here can detect a record that was never written. These probes catch a record that '
    + 'contradicts itself, which is the failure that happens by accident rather than by intent.');
});
