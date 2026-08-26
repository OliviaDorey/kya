/**
 * The witness: the stranger at the dance.
 *
 * Built 26 August 2026. A tartan's fraud detection is distributed — nobody stops
 * you buying the cloth, and the check happens when somebody who knows the pattern
 * calls you on it. Every verification path in this library belonged to a party to
 * the transaction. This one belongs to the person who noticed.
 *
 * Four rules under test: a report never moves status, only the anchor determines,
 * the subject is always told, and nobody pays or is paid.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as witness from '../src/witness.js';

const A = 'urn:agent:kindred:steward:7f3a1c92';
const ANCHOR = 'https://anchor.example.ca';

const seen = (over = {}) => witness.make({
  subject_agent_id: A,
  observation: witness.OBSERVATION.NOT_THEIRS,
  observed_at: '2026-08-26',
  what: 'It presented a card naming an operator it plainly does not work for.',
  reporter: { id: 'did:example:bystander' },
  ...over,
});

const log = () => new witness.WitnessLog({ anchor: ANCHOR });

// ─────────────────────────────────────────── what a report has to carry
test('a report says what was seen, in the observer\'s own words', () => {
  assert.throws(() => witness.make({
    subject_agent_id: A, observation: witness.OBSERVATION.NOT_THEIRS,
    observed_at: '2026-08-26', reporter: { id: 'did:x' },
  }), /what is required/);
});

test('a grievance form is refused; the vocabulary is closed', () => {
  assert.throws(() => seen({ observation: 'rude-to-me' }), /observation must be one of/);
});

test('the anchor always knows who reported', () => {
  assert.throws(() => seen({ reporter: {} }), /reporter.id is required/);
});

// ─────────────────────────────────────────── rule 1: never a determination
test('RULE: recording a report changes nothing about the agent', () => {
  const l = log();
  const out = l.record(seen());
  assert.equal(out.effect.status_change, null);
  assert.match(out.effect.reason, /[Oo]nly the anchor determines/);
  assert.equal(witness.effect().status_change, null);
});

test('a report is not a revocation route for anybody who dislikes an agent', () => {
  // revocation.js refuses relying parties the power to destroy, because a
  // caseworker who disliked an agent could otherwise end a person's authority to
  // be helped. A public channel that moved status would reopen that to everyone.
  const l = log();
  for (let i = 0; i < 50; i += 1) l.record(seen({ what: `complaint number ${i}` }));
  assert.equal(witness.effect().status_change, null, 'fifty reports still change nothing');
  assert.equal(l.open().length, 50, 'they are all still owed an answer');
});

// ─────────────────────────────────────────── rule 2: only the anchor
test('RULE: an interested party may not determine a report about itself', () => {
  const l = log();
  l.record(seen());
  for (const interested of ['https://operator.example.ca', 'https://builder.example.ca', 'https://office.example.ca']) {
    assert.throws(() => l.determine(1, { by: interested, finding: witness.FINDING.NOT_UPHELD, at: '2026-08-27' }),
      /has an interest in the answer/);
  }
  const done = l.determine(1, { by: ANCHOR, finding: witness.FINDING.UPHELD, at: '2026-08-27', reason: 'the card was not its own' });
  assert.equal(done.finding, witness.FINDING.UPHELD);
  assert.equal(l.open().length, 0);
});

test('a determination is not edited; a second finding is a new report', () => {
  const l = log();
  l.record(seen());
  l.determine(1, { by: ANCHOR, finding: witness.FINDING.NOT_UPHELD, at: '2026-08-27' });
  assert.throws(() => l.determine(1, { by: ANCHOR, finding: witness.FINDING.UPHELD, at: '2026-08-28' }),
    /already determined/);
});

test('inconclusive is available, because most of them will be', () => {
  const l = log();
  l.record(seen());
  assert.equal(l.determine(1, { by: ANCHOR, finding: witness.FINDING.INCONCLUSIVE, at: '2026-08-27' }).finding,
    'inconclusive');
});

// ─────────────────────────────────────────── rule 3: the subject is told
test('RULE: every recorded report produces a notice to the subject', () => {
  const l = log();
  const { notice } = l.record(seen());
  assert.equal(notice.subject_agent_id, A);
  assert.match(notice.what, /does not work for/);
  assert.match(notice.standing, /Nothing about this agent has changed/,
    'because "a report has been filed" reads as a finding to everybody who is not a lawyer');
});

test('the subject can read everything said about it', () => {
  const l = log();
  l.record(seen());
  l.record(seen({ observation: witness.OBSERVATION.UNDISCLOSED, what: 'It did not say it was an agent.' }));
  l.record(witness.make({
    subject_agent_id: 'urn:agent:someone-else', observation: witness.OBSERVATION.UNDISCLOSED,
    observed_at: '2026-08-26', what: 'different agent', reporter: { id: 'did:example:x' },
  }));
  assert.equal(l.about(A).length, 2, 'its own, and only its own');
});

test('the reporter is named to the subject only if the reporter agreed', () => {
  const l = log();
  l.record(seen());
  l.record(seen({ disclose_reporter_to_subject: true }));
  assert.equal(l.about(A)[0].reporter, null);
  assert.equal(l.about(A)[1].reporter.id, 'did:example:bystander');
  // and the log itself always holds it, or the report is unanswerable
  assert.equal(l.reports[0].reporter.id, 'did:example:bystander');
});

// ─────────────────────────────────────────── rule 4: no fee, no bounty
test('RULE: a report carries no fee and no bounty', () => {
  // The first version of make() destructured the fields it knew and dropped the
  // rest, so { reward: 100 } passed straight through a guard written to refuse
  // it. The shape is closed now, and a fee of zero is refused as firmly as a
  // large one — a priced channel is the defect, not the price.
  assert.throws(() => seen({ fee: 0 }), /no fee and no bounty/);
  assert.throws(() => seen({ reward: 100 }), /no fee and no bounty/);
  assert.throws(() => seen({ priority_handling: true }), /fields this does not know/);

  const src = readFileSync(new URL('../src/witness.js', import.meta.url), 'utf8');
  const body = src.split('export function make(')[1];
  assert.ok(!/\b(price|charge|invoice|payout)\b/.test(body),
    'nothing in the reporting path may learn about money');
});

// ─────────────────────────────────────────── the limit
test('LIMITATION: the register substitutes for density, it does not improve on it', () => {
  // A tartan cannot be worn falsely for long because the community is dense and
  // knows each other. At national scale it is not dense, and this file is the
  // thin substitute. Recorded so the claim is never made the other way round.
  const l = log();
  assert.equal(l.reports.length, 0);
  assert.equal(l.open().length, 0, 'an empty log is silence, not innocence');
});
