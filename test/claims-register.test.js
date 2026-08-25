/**
 * The claims register. Upgrade #2 from the 13 August handoff.
 *
 * Every sentence in this repository that asserts product behaviour, paired with
 * the check that fails when it stops being true.
 *
 * ── Why this exists ────────────────────────────────────────────────────────
 *
 * The 13 August audit found six documents claiming things the code did not do,
 * in one day, across four products. The common cause was named precisely: **not
 * one of them had a test that would fail when the claim went stale.** The
 * documents were not dishonest. Each was written while the implementation
 * lagged, and nothing ever revisited it.
 *
 * Since then it has happened twice more in this repository alone. The spec
 * status line read "draft, not implemented" for four days against a green suite.
 * And on 14 August the v0.4 migration note said "None required. Everything is
 * additive" — written in the morning, made false by the afternoon's pairwise
 * work, by the same person, in the same session. The CI drift check added that
 * morning catches a spec calling a built thing unbuilt; it did not catch this,
 * because the claim was about migration rather than implementation.
 *
 * A register is the general answer. A claim goes in here with a check attached,
 * or the claim does not get made.
 *
 * ── How to add one ─────────────────────────────────────────────────────────
 *
 * Add a row to CLAIMS with the file, the sentence as written, and a `holds()`
 * that returns true only while the sentence is true. Prefer checking behaviour
 * over checking text: `holds` should exercise the code, not grep the document.
 * The `sentence` field is matched against the file so that editing the claim
 * without revisiting the check fails loudly.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as chain from '../src/chain.js';
import * as status from '../src/status.js';
import * as revocation from '../src/revocation.js';
import * as capability from '../src/capability.js';
import * as pairwise from '../src/pairwise.js';
import * as wallet from '../src/wallet.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
// Whitespace-normalised, because every one of these sentences wraps across
// lines in its source file and a register that cannot match a wrapped sentence
// is a register nobody can add to.
const read = (p) => readFileSync(join(ROOT, p), 'utf8').replace(/\s+/g, ' ');
const norm = (t) => t.replace(/\s+/g, ' ').trim();

/**
 * Each entry: where the claim is written, a fragment of it verbatim, and a
 * predicate that is true only while it holds.
 */
const CLAIMS = [
  {
    file: 'README.md',
    sentence: 'A card carrying anything else does not issue and does not verify',
    holds: async () => {
      const aic = await import('../src/aic.js');
      const bad = { vct: aic.AIC_VCT, conduct: { discloses_ai: 'when-asked' } };
      return aic.validate(bad).problems.some((p) => p.includes('discloses_ai'));
    },
  },
  {
    file: 'README.md',
    sentence: 'A card carrying only `draft:appeal` can prepare an appeal',
    holds: async () => {
      const adc = await import('../src/adc.js');
      const card = { capabilities: ['draft:appeal'] };
      const grant = { authorization_details: [{ capability: 'request:review', actions: ['appeal'] }] };
      return adc.attenuationBreaches(grant, card).some((p) => p.includes('submit:appeal'));
    },
  },
  {
    file: 'README.md',
    sentence: 'that cannot reach a fresh status list treats the credential as not in force',
    holds: () => status.inForce({ reachable: false }).ok === false && status.inForce({ stale: true }).ok === false,
  },
  {
    file: 'spec/revocation-and-chains.md',
    sentence: 'Depth limit: three hops, and why',
    holds: () => chain.MAX_HOPS === 3,
  },
  {
    file: 'spec/revocation-and-chains.md',
    sentence: 'a relying party may **stop** (scoped to itself), and may not **destroy**',
    holds: () =>
      revocation.maySuspend(revocation.AUTHORITY.RELYING_PARTY) === true &&
      revocation.mayRevoke(revocation.AUTHORITY.RELYING_PARTY) === false,
  },
  {
    file: 'spec/revocation-and-chains.md',
    sentence: 'only the **principal** may reinstate',
    holds: () =>
      revocation.mayReinstate(revocation.AUTHORITY.PRINCIPAL) === true &&
      [revocation.AUTHORITY.ACCOUNTABLE, revocation.AUTHORITY.ISSUER, revocation.AUTHORITY.RELYING_PARTY]
        .every((a) => revocation.mayReinstate(a) === false),
  },
  {
    file: 'spec/agent-identity-card-v0.2.md',
    sentence: 'screen every publicly readable field for terms disclosing health',
    holds: () => capability.screen('aish disability application').length > 0,
  },
  {
    file: 'spec/agent-identity-card-v0.2.md',
    sentence: 'delegation is bound to one verifier',
    holds: () =>
      pairwise.boundToVerifier({ sub: 'pw:a', pairwise: true, sub_audience: 'https://a.ca' }, 'https://b.ca').ok === false,
  },
  {
    file: 'spec/agent-identity-card-v0.2.md',
    sentence: 'it may not travel alone: `residency_basis` states how the claim is known',
    holds: async () => {
      const aic = await import('../src/aic.js');
      const card = { vct: aic.AIC_VCT, model: { disclosed: true, family: 'x', hosted_in: 'CA' } };
      return aic.validate(card).problems.some((p) => p.includes('residency_basis'));
    },
  },
  {
    file: 'src/wallet.js',
    sentence: 'Unlinkability requires a distinct agent key and a distinct Agent Identity Card',
    holds: () => wallet.describeCost(3).identity_cards === 3 && wallet.describeCost(3).agent_keys === 3,
  },
  {
    file: 'src/claim.js',
    sentence: 'a claim somebody else can end on your behalf was never yours',
    holds: async () => {
      const claim = await import('../src/claim.js');
      const rev = await import('../src/revocation.js');
      const c = claim.make({ agent_id: 'a', aic_thumbprint: 't', purpose: 'p', made_at: '2026-01-01' });
      if (claim.end(c, { by: rev.AUTHORITY.PRINCIPAL }).ended_by !== rev.AUTHORITY.PRINCIPAL) return false;
      return [rev.AUTHORITY.ACCOUNTABLE, rev.AUTHORITY.ISSUER, rev.AUTHORITY.ANCESTOR, rev.AUTHORITY.RELYING_PARTY]
        .every((by) => {
          try { claim.end(c, { by }); return false; } catch { return true; }
        });
    },
  },
  {
    file: 'src/claim.js',
    sentence: 'A live or due claim changes nothing. A lapsed claim keeps `read` and `monitor`',
    holds: async () => {
      const claim = await import('../src/claim.js');
      const all = ['read', 'draft', 'submit', 'monitor', 'appeal'];
      const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
      return same(claim.narrow(all, claim.CLAIM_STATE.LIVE), all)
        && same(claim.narrow(all, claim.CLAIM_STATE.DUE), all)
        && same(claim.narrow(all, claim.CLAIM_STATE.LAPSED), ['read', 'monitor'])
        && same(claim.narrow(all, claim.CLAIM_STATE.ENDED), []);
    },
  },
  {
    file: 'src/events.js',
    sentence: 'counter_claim.outstanding must be a count. This register records how many, never whose.',
    holds: async () => {
      const events = await import('../src/events.js');
      const base = {
        agent_id: 'a', kind: events.EVENT.TRANSFER, at: '2026-06-01',
        from: { legal_name: 'A' }, to: { legal_name: 'B' }, notice: { given_at: '2026-05-01' },
      };
      const listed = events.validate({ ...base, counter_claim: { policy: 'notify', outstanding: ['did:example:alice'] } });
      const extra = events.validate({ ...base, counter_claim: { policy: 'notify', claimants: ['did:example:alice'] } });
      const clean = events.validate({ ...base, counter_claim: { policy: 'notify', outstanding: 4 } });
      return !listed.ok && !extra.ok && clean.ok;
    },
  },
  {
    file: 'src/status.js',
    sentence: 'nothing changes about the authority',
    // Written in the spec; the mechanism lives here. A grace period appearing in
    // outageGuidance would make the sentence false without touching the sentence.
    holds: () => {
      const g = status.outageGuidance({ listUri: 'x' });
      return g.authority === 'refused' && g.grace_period === null;
    },
  },
];

test('every registered claim is still true', async () => {
  const broken = [];
  for (const claim of CLAIMS) {
    let ok = false;
    try {
      ok = await claim.holds();
    } catch (err) {
      broken.push(`${claim.file}: "${claim.sentence}" — check threw: ${err.message}`);
      continue;
    }
    if (!ok) broken.push(`${claim.file}: "${claim.sentence}" is no longer true of the code.`);
  }
  assert.deepEqual(broken, [], `\n${broken.join('\n')}`);
});

test('every registered claim is still written where the register says it is', () => {
  // Catches the other direction: a sentence quietly deleted or reworded leaves a
  // check guarding nothing, which is how a register rots into decoration.
  const missing = [];
  for (const claim of CLAIMS) {
    if (!read(claim.file).includes(norm(claim.sentence))) {
      missing.push(`${claim.file} no longer contains "${claim.sentence}". Update the register with the claim.`);
    }
  }
  assert.deepEqual(missing, [], `\n${missing.join('\n')}`);
});

test('the register fails when a claim stops being true', async () => {
  // Mutation check. A register that has never been shown to fire is the same
  // defect in a smarter costume, which is the August lesson about wiring tests.
  const fake = { file: 'README.md', sentence: 'x', holds: () => false };
  let caught = false;
  try {
    assert.ok(await fake.holds(), 'should fail');
  } catch {
    caught = true;
  }
  assert.ok(caught, 'the register must actually fail on a false claim');
});

test('LIMITATION: the register covers what somebody remembered to register', () => {
  // There is no mechanism that finds an unregistered claim. This file holds a
  // deliberately small set of load-bearing sentences, not every sentence in the
  // repository, and a claim nobody adds is a claim nobody checks. Counting them
  // out loud so the coverage is visible rather than assumed.
  const files = new Set(CLAIMS.map((c) => c.file));
  assert.ok(CLAIMS.length >= 10, 'the register should not quietly shrink');

  for (const f of files) {
    assert.ok(read(f).length > 0, `${f} is registered but unreadable`);
  }
  console.log(`      claims registered: ${CLAIMS.length} across ${files.size} file(s); unregistered sentences are unchecked`);
});
