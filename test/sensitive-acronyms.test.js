/**
 * The screen protects programme acronyms without blocking ordinary words.
 *
 * Each test is named after the promise it defends. The two halves are equally
 * load-bearing: a missed acronym puts a programme name in the clear at a
 * counter, and an over-broad one refuses a delegation, which denies somebody
 * help in the name of protecting them.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { screen, screenDelegation, SENSITIVE_ACRONYMS } from '../src/capability.js';

const terms = (s) => screen(s).map((h) => h.term);

test('programme acronyms do not travel in the clear', async (t) => {
  await t.test('ADAP is caught, in every shape a file reference takes', () => {
    for (const s of ['ADAP-1234', 'adap', 'adap application', 'ADAP_FILE', 'file: adap']) {
      assert.ok(terms(s).includes('adap'), `expected "adap" to be caught in ${JSON.stringify(s)}`);
    }
  });

  await t.test('AISH is still caught, including with a separator', () => {
    for (const s of ['AISH-2231', 'aish', 'aish_disability_application']) {
      assert.ok(terms(s).includes('aish'), `expected "aish" to be caught in ${JSON.stringify(s)}`);
    }
  });

  await t.test('the other Alberta and federal disability programmes are covered', () => {
    assert.ok(terms('PDD-77').includes('pdd'));
    assert.ok(terms('CDB payment').includes('cdb'));
    assert.ok(terms('RDSP transfer').includes('rdsp'));
  });

  await t.test('every acronym is screened in at least one category', () => {
    for (const [category, list] of Object.entries(SENSITIVE_ACRONYMS)) {
      for (const term of list) {
        assert.ok(
          screen(term).some((h) => h.term === term && h.category === category),
          `${term} is listed under ${category} but does not screen`,
        );
      }
    }
  });
});

test('ordinary disability vocabulary is not refused', async (t) => {
  // Alberta's own guide says "a vehicle adapted for a disability". If 'adap'
  // were a substring rule, every one of these would refuse the delegation.
  await t.test('"adapt" and its family do not trip the ADAP rule', () => {
    for (const s of ['adaptive equipment', 'adapted vehicle', 'home adaptation', 'adapter cable']) {
      assert.ok(!terms(s).includes('adap'), `${JSON.stringify(s)} must not trip "adap"`);
    }
  });

  await t.test('a name containing an acronym is not a programme reference', () => {
    assert.ok(!terms('Aisha Okafor').includes('aish'));
  });

  await t.test('a delegation about adaptive equipment issues cleanly', () => {
    const adc = {
      authorization_details: [
        {
          type: 'kya-capability',
          capability: 'provide:documents',
          actions: ['draft', 'submit'],
          constraints: { file: 'adaptive equipment request' },
        },
      ],
    };
    assert.deepEqual(screenDelegation(adc), []);
  });
});

test('a delegation naming a programme is refused, and told why', () => {
  const adc = {
    authorization_details: [
      {
        type: 'kya-capability',
        capability: 'request:review',
        actions: ['draft-appeal'],
        constraints: { file: 'ADAP-1234' },
      },
    ],
  };
  const problems = screenDelegation(adc);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /adap/);
  assert.match(problems[0], /health information/);
});
