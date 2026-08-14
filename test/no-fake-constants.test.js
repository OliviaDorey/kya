/**
 * A field defined as a function of other data must be computed, not typed.
 *
 * This class of defect has now shipped twice in eight days:
 *
 *   13 Aug  test fixtures carried `aic_thumbprint: 'x'` and `cnf_thumbprint: 'y'`.
 *           They passed because nothing compared them to anything. When the
 *           binding was finally enforced, the fixtures were the bug.
 *   14 Aug  the demo carried `sub: 'pw:9c1f4e77a2'` with a comment reading
 *           "pairwise for this verifier only" — a hand-written constant asserting
 *           a property nothing computed and nothing checked.
 *
 * Both were caught by a human reading code. Twice is a class, so this is the
 * mechanical version.
 *
 * Scope is `bin/` deliberately. The demo is the showcase: it is what a reviewer
 * runs, and a literal there is a claim with a comment attached. Test fixtures
 * are allowed literals, because a test about capability scoping should not have
 * to derive a thumbprint it never looks at — but a fixture that *asserts* the
 * derived property must compute it, and that is enforced by the property's own
 * test rather than by this one.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin');

/**
 * Fields whose value is a function of other data. A literal in any of these is
 * either wrong or lying, and both are worth failing over.
 */
const DERIVED_FIELDS = [
  'aic_thumbprint',
  'cnf_thumbprint',
  'purpose_commitment',
  'parent_thumbprint',
  'root_thumbprint',
];

/**
 * `delegator.sub` is handled separately: it is derived, but a literal is only
 * wrong when the credential also claims to be pairwise. A non-pairwise subject
 * is allowed to be any opaque string.
 */
const PAIRWISE_SUB = /\bsub:\s*['"`]/;

/** A quoted string literal assigned to one of the derived fields. */
const literalAssignment = (field) => new RegExp(`\\b${field}\\s*:\\s*['"\`]`, 'g');

function binFiles() {
  return readdirSync(BIN).filter((f) => f.endsWith('.js')).map((f) => ({ name: f, source: readFileSync(join(BIN, f), 'utf8') }));
}

/** Strip comments, so prose about a field never trips the check. */
function code(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

test('no demo hard-codes a value it is supposed to derive', () => {
  const offences = [];

  for (const { name, source } of binFiles()) {
    const body = code(source);
    for (const field of DERIVED_FIELDS) {
      const hits = body.match(literalAssignment(field));
      if (hits) {
        offences.push(
          `bin/${name}: ${field} is assigned a string literal ${hits.length} time(s). ` +
            'It is a function of the card, the key, or the sentence, so compute it. A constant here ' +
            'is a claim nothing checks, which is how the 13 August thumbprint bug survived.',
        );
      }
    }
  }

  assert.deepEqual(offences, [], `\n${offences.join('\n')}`);
});

test('no demo hard-codes a subject while claiming it is pairwise', () => {
  const offences = [];

  for (const { name, source } of binFiles()) {
    const body = code(source);
    if (!/pairwise\s*:\s*true/.test(body)) continue;
    if (PAIRWISE_SUB.test(body)) {
      offences.push(
        `bin/${name}: asserts pairwise: true and assigns sub a string literal. ` +
          'Derive it with pairwise.derive(). This is the exact defect fixed on 14 August.',
      );
    }
  }

  assert.deepEqual(offences, [], `\n${offences.join('\n')}`);
});

test('the check itself fails on the code it was written to catch', () => {
  // Mutation check, per the August lesson: a detector that has never been shown
  // to fire is the same defect in a smarter costume. These are the two real
  // offending lines, verbatim from the history.
  const thumbprintBug = `delegate: { agent_id: ID, aic_thumbprint: 'x', cnf_thumbprint: 'y' },`;
  const pairwiseBug = `delegator: { sub: 'pw:9c1f4e77a2', pairwise: true },`;

  assert.ok(literalAssignment('aic_thumbprint').test(thumbprintBug), 'would not have caught the 13 August bug');
  assert.ok(literalAssignment('cnf_thumbprint').test(thumbprintBug), 'would not have caught the 13 August bug');
  assert.ok(PAIRWISE_SUB.test(pairwiseBug) && /pairwise\s*:\s*true/.test(pairwiseBug), 'would not have caught the 14 August bug');

  // And does not fire on the corrected forms.
  assert.ok(!literalAssignment('aic_thumbprint').test('aic_thumbprint: cardThumb,'));
  assert.ok(!PAIRWISE_SUB.test('sub: derivePairwise({ walletSecret, verifierId }),'));
});

test('LIMITATION: this reads text, and text is not behaviour', () => {
  // A demo could compute a thumbprint and then ignore it, or derive a subject
  // and overwrite it two lines later, and this check would pass. It catches the
  // specific shape that has actually shipped twice, not the general problem of
  // a claim nothing verifies. The general problem is the claims register.
  assert.ok(binFiles().length > 0, 'there is at least something to check');
});
