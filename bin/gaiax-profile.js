#!/usr/bin/env node
/**
 * Emit a sample Gaia-X self-description for a Kindred agent, and run the
 * profile's own conformance probe over it.
 *
 * This is what to send Gaia-X Hub Canada. It is deliberately one command with
 * no arguments, because a reviewer who has to configure something before they
 * can look at anything usually does not look at anything.
 */
import * as aic from '../src/aic.js';
import * as gx from '../src/gaiax.js';

const sec = Math.floor(Date.now() / 1000);

const card = {
  vct: aic.AIC_VCT,
  iss: 'https://kya.thekindredagency.com',
  iat: sec,
  exp: sec + 365 * 86400,
  agent: { id: 'urn:agent:kindred:steward:7f3a1c92', name: 'Steward', version: '1.4.2' },
  builder: { legal_name: 'The Kindred Agency', jurisdiction: 'CA-NS', uri: 'https://thekindredagency.com' },
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

const line = (t) => console.log(`\n${'─'.repeat(74)}\n${t}\n${'─'.repeat(74)}`);

line('The Agent Identity Card, as issued');
const v = aic.validate(card);
console.log(v.ok ? '  ✓ valid against agent-identity-card-v0.2' : `  ✗ ${JSON.stringify(v.problems)}`);

line(`The same claims as a Gaia-X self-description (profile v${gx.PROFILE_VERSION})`);
const sd = gx.toGaiaX(card, { license: 'Apache-2.0' });
console.log(JSON.stringify(sd, null, 2));

line('Conformance probe: does it verify in the other form');
const { ok, findings } = gx.roundTrips(card);
if (ok) {
  console.log('  ✓ round-trips with every always-disclosed field intact');
  console.log(`  ✓ still valid as an Agent Identity Card: ${aic.validate(gx.fromGaiaX(sd)).ok}`);
  console.log('  ✓ deterministic: identical bytes on repeat');
} else {
  for (const f of findings) console.log(`  ✗ ${f.path}: ${f.problem}`);
  process.exitCode = 1;
}

line('What this does not prove');
console.log('  · semantic equivalence, not cryptographic. Nothing here signs anything.');
console.log('  · one direction only. Card -> Gaia-X is a widening; the licence is supplied, not carried.');
console.log('  · the delegation credential has no Gaia-X equivalent and is deliberately out of scope.');
console.log('  · nobody has certified this. Kindred wrote it and does not mark its own homework.\n');
