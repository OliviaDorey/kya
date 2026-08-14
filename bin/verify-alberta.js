#!/usr/bin/env node
/**
 * Proof of interoperability with the Government of Alberta's live federation.
 *
 * Fetches Alberta's trust anchor, verifies its signature, lists its members,
 * fetches and cryptographically verifies the subordinate statement for each one,
 * and reports where Alberta's credential profile departs from the specifications.
 *
 *   npm run verify:alberta
 */

import { fetchTrustAnchor, listSubordinates, validateTrustChain } from '../src/federation.js';
import { ALBERTA_TRUST_ANCHOR, describeDeviations, summariseIssuer } from '../src/alberta.js';

const ok = (s) => `  \x1b[32m✓\x1b[0m ${s}`;
const bad = (s) => `  \x1b[31m✗\x1b[0m ${s}`;
const note = (s) => `    \x1b[90m${s}\x1b[0m`;
const head = (s) => `\n\x1b[1m${s}\x1b[0m`;

let failures = 0;

console.log(head('1. Trust anchor'));
let anchor;
try {
  // trustOnFirstUse, said out loud. Pinning became the default on 14 August
  // 2026 and this tool is precisely the bootstrap case: its job is to discover
  // what Alberta publishes, so it cannot already know the thumbprints. The
  // right end state is to record what this prints and pin it thereafter.
  anchor = await fetchTrustAnchor(ALBERTA_TRUST_ANCHOR, { trustOnFirstUse: true });
  const fe = anchor.payload.metadata?.federation_entity ?? {};
  console.log(ok(`fetched and signature verified: ${anchor.entityId}`));
  console.log(note(`${fe.organization_name ?? 'unnamed'} · contact ${(fe.contacts ?? []).join(', ') || 'none published'}`));
  console.log(note(`signed ${anchor.header.alg}, kid ${anchor.header.kid}, expires ${new Date(anchor.payload.exp * 1000).toISOString().slice(0, 10)}`));
  console.log(note(`UNPINNED (trust on first use). An anchor signs its own configuration, so this`));
  console.log(note(`establishes nothing until pinned. Pin these thumbprints: ${anchor.thumbprints.join(', ')}`));

  const allowed = anchor.payload.constraints?.allowed_leaf_entity_types;
  if (allowed) {
    console.log(ok(`anchor constrains leaf entity types to: ${allowed.join(', ')}`));
    for (const want of ['openid_credential_issuer', 'openid_verifier']) {
      console.log(allowed.includes(want)
        ? ok(`"${want}" is permitted — Kindred can register in this role`)
        : bad(`"${want}" is NOT permitted`));
      if (!allowed.includes(want)) failures++;
    }
  }
} catch (e) {
  console.log(bad(`could not establish trust anchor: ${e.message}`));
  process.exit(1);
}

console.log(head('2. Federation members'));
let members = [];
try {
  members = await listSubordinates(anchor);
  console.log(ok(`list endpoint returned ${members.length} subordinate(s)`));
  members.forEach((m) => console.log(note(m)));
} catch (e) {
  console.log(bad(`list endpoint unusable: ${e.message}`));
  failures++;
}

console.log(head('3. Trust chain validation'));
for (const member of members) {
  const subject = member.replace(/\/$/, '');
  try {
    const chain = await validateTrustChain(anchor, subject);
    if (chain.valid) {
      console.log(ok(`chain verified: ${subject} → ${chain.anchor}`));
    } else {
      console.log(bad(`chain invalid for ${subject}: ${chain.problems.join('; ')}`));
      failures++;
    }
    console.log(note(`entity types declared: ${chain.entityTypes.join(', ')}`));
    if (chain.unpermittedEntityTypes.length) {
      console.log(note(`NOTE: ${chain.unpermittedEntityTypes.join(', ')} are outside the anchor's own allowed_leaf_entity_types`));
    }
    const summary = summariseIssuer(chain.statement.payload);
    if (summary) Object.entries(summary).forEach(([k, v]) => console.log(note(`${k}: ${v}`)));
  } catch (e) {
    console.log(bad(`could not validate ${subject}: ${e.message}`));
    failures++;
  }
}

console.log(head('4. Profile deviations Kindred must adapt to'));
for (const d of describeDeviations()) {
  console.log(`  \x1b[33m•\x1b[0m ${d.what}`);
  console.log(note(`Alberta: ${d.alberta}`));
  console.log(note(`Spec:    ${d.spec}`));
}

console.log(head(failures === 0 ? 'Result: interoperable' : `Result: ${failures} problem(s)`));
if (failures === 0) {
  console.log('  Kindred can verify Government of Alberta credentials against their live');
  console.log('  trust anchor, and the anchor permits the entity type Kindred needs.\n');
}
process.exit(failures === 0 ? 0 : 1);
