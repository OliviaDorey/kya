#!/usr/bin/env node
/**
 * End to end, in the order it would actually happen.
 *
 *   1  an issuer gives an agent an Agent Identity Card
 *   2  a person's wallet issues a Delegation Credential to that specific agent
 *   3  the agent presents both to a verifier, with key binding
 *   4  the verifier checks the status list and fails closed if it cannot
 *   5  the agent tries to overreach, and is refused
 *   6  the person revokes, and gets a receipt
 *
 * No network. Everything is generated in-process so this runs anywhere.
 */

import { generateKeyPair, exportJWK } from 'jose';
import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as status from '../src/status.js';
import * as determination from '../src/determination.js';

const say = (s = '') => console.log(s);
const rule = (t) => say(`\n${'─'.repeat(74)}\n${t}\n${'─'.repeat(74)}`);
const ok = (s) => say(`  ✓ ${s}`);
const no = (s) => say(`  ✗ ${s}`);

const now = Date.now();
const sec = Math.floor(now / 1000);

const issuer = await generateKeyPair('ES256', { extractable: true });
const wallet = await generateKeyPair('ES256', { extractable: true });
const agent = await generateKeyPair('ES256', { extractable: true });
const agentJwk = await exportJWK(agent.publicKey);

const AGENT_ID = 'urn:agent:kindred:steward:7f3a1c92';
const AIC_LIST = 'https://status.agentcredential.ca/aic';
const ADC_LIST = 'https://status.agentcredential.ca/adc';

// ─────────────────────────────────────────────────────────── 1
rule('1. The issuer gives Steward an Agent Identity Card');

const card = {
  vct: aic.AIC_VCT,
  iss: 'https://kya.thekindredagency.com',
  iat: sec,
  exp: sec + 365 * 86400,
  agent: { id: AGENT_ID, name: 'Steward', version: '1.4.2' },
  builder: {
    legal_name: 'The Kindred Agency Inc.',
    jurisdiction: 'CA-NS',
    registry_id: '1234567',
    uri: 'https://thekindredagency.com',
  },
  operator: { legal_name: 'The Kindred Agency Inc.', jurisdiction: 'CA-NS' },
  accountable: {
    role: 'Chief Technology Officer',
    contact: 'trust@thekindredagency.com',
    redress_uri: 'https://thekindredagency.com/redress',
  },
  model: { disclosed: true, family: 'claude-opus', version: '5', hosted_in: 'CA' },
  capabilities: ['read:program-information', 'draft:application', 'submit:application', 'draft:appeal', 'monitor:status'],
  conduct: { discloses_ai: 'always', acts_without_approval: false, retains_after_revocation: 'audit-record-only' },
  assurance: { framework: 'PCTF', level: 'pending', assessed_by: null, assessed_at: null },
  status: { status_list: { uri: AIC_LIST, idx: 4213 } },
};

const issuedCard = await aic.issue({ card, privateKey: issuer.privateKey, holderJwk: agentJwk });
ok(`issued, ${issuedCard.split('~')[0].length} char JWT plus ${issuedCard.split('~').length - 2} disclosure(s)`);
ok('model and assurance are selectively disclosable');
ok('accountable, conduct and capabilities are not, and the library refuses to hide them');

try {
  await aic.issue({ card, privateKey: issuer.privateKey, holderJwk: agentJwk, selective: ['accountable'] });
  no('hiding accountable was allowed. That is a bug.');
} catch (e) {
  ok(`refused to hide accountable: ${e.message.split('.')[0]}`);
}

try {
  await aic.issue({
    card: { ...card, conduct: { ...card.conduct, discloses_ai: 'when-asked' } },
    privateKey: issuer.privateKey,
    holderJwk: agentJwk,
  });
  no('an agent that hides being an agent was issued a card. That is a bug.');
} catch {
  ok('refused a card whose conduct.discloses_ai is anything but "always"');
}

// ─────────────────────────────────────────────────────────── 2
rule("2. The person's wallet issues a delegation to that specific agent");

const cardThumb = await aic.cardThumbprint(issuedCard);
const agentKeyThumb = await aic.jwkThumbprint(agentJwk);

const delegation = {
  vct: adc.ADC_VCT,
  iss: 'https://wallet.example.ca/u/8f22b1',
  iat: sec,
  exp: sec + 14 * 86400,
  delegator: {
    sub: 'pw:9c1f4e77a2',           // pairwise for this verifier only
    pairwise: true,
    verified_by: 'https://account.alberta.ca/dts',
    assurance: 'substantial',
  },
  delegate: { agent_id: AGENT_ID, aic_thumbprint: cardThumb, cnf_thumbprint: agentKeyThumb },
  purpose:
    'Apply for the Alberta Disability Assistance Program on my behalf, and appeal if I am refused.',
  authorization_details: [
    {
      type: 'gc_benefit_application',
      programs: ['urn:ab:program:adap'],
      actions: ['read', 'draft', 'submit', 'appeal'],
      constraints: {
        max_submissions: 1,
        requires_human_approval: ['submit', 'appeal'],
        valid_until: '2026-09-30',
      },
    },
  ],
  consent: {
    record_uri: 'https://wallet.example.ca/consent/44a1',
    captured_at: new Date(now).toISOString(),
    language: 'en-CA',
    method: 'in-app-explicit',
  },
  revocation: { revoke_uri: 'https://revoke.agentcredential.ca/d/44a1', citizen_facing: true },
  status: { status_list: { uri: ADC_LIST, idx: 88117 } },
};

const issuedDelegation = await adc.issue({
  adc: delegation,
  aic: card,
  walletKey: wallet.privateKey,
  holderJwk: agentJwk,
});
ok('delegation issued, bound to one card and one key');
ok(`valid for ${Math.round((delegation.exp - delegation.iat) / 86400)} days`);
say();
say(adc.explain(delegation).split('\n').map((l) => `    ${l}`).join('\n'));

// ─────────────────────────────────────────────────────────── 3
rule('3. The agent presents both to a caseworker, with key binding');

const AUD = 'https://caseworker.alberta.ca';
const NONCE = 'n-3f9a2c';

const presentedCard = await aic.jwkThumbprint(agentJwk).then(() =>
  import('../src/sdjwt.js').then(({ present }) =>
    present(issuedCard, { reveal: [], audience: AUD, nonce: NONCE, holderKey: agent.privateKey }),
  ),
);
const presentedDelegation = await import('../src/sdjwt.js').then(({ present }) =>
  present(issuedDelegation, { audience: AUD, nonce: NONCE, holderKey: agent.privateKey }),
);

const vCard = await aic.verify(presentedCard, { issuerKey: issuer.publicKey, audience: AUD, nonce: NONCE });
ok(`card verified. Agent "${vCard.card.agent.name}", built by ${vCard.card.builder.legal_name}`);
ok(`accountable: ${vCard.card.accountable.role}, ${vCard.card.accountable.contact}`);
ok(`model withheld this time: ${vCard.card.model === undefined ? 'yes, and the verifier can tell' : 'no'}`);

const vDel = await adc.verify(presentedDelegation, {
  walletKey: wallet.publicKey,
  aic: vCard.card,
  audience: AUD,
  nonce: NONCE,
});
ok('delegation verified, key-bound to the presenting agent');

// ─────────────────────────────────────────────────────────── 4
rule('4. The verifier checks the status list, and fails closed when it cannot');

const list = new status.StatusList({ size: 100_000, bits: 1 });
const listToken = await status.publish({
  list,
  uri: ADC_LIST,
  issuer: 'https://kya.thekindredagency.com',
  privateKey: issuer.privateKey,
  ttl: 300,
  now,
});

let s = await status.fetchStatus(listToken, { issuerKey: issuer.publicKey, idx: 88117, now });
say(`  live:      ${JSON.stringify(status.inForce(s))}`);

const laterOn = now + 600 * 1000;
s = await status.fetchStatus(listToken, { issuerKey: issuer.publicKey, idx: 88117, now: laterOn });
say(`  stale:     ${JSON.stringify(status.inForce(s))}`);
say(`  offline:   ${JSON.stringify(status.inForce({ reachable: false }))}`);
ok('a verifier that cannot see fresh status treats the delegation as not in force');

// ─────────────────────────────────────────────────────────── 5
rule('5. Overreach is refused, not trimmed');

const wider = {
  ...delegation,
  authorization_details: [
    { ...delegation.authorization_details[0], actions: ['read', 'draft', 'submit', 'appeal', 'correspond'] },
  ],
};
const breach = adc.validate(wider, { aic: card });
breach.problems.forEach((p) => no(p));

const quieterPurpose = { ...delegation, purpose: 'Have a look at what I might be able to get.' };
adc.validate(quieterPurpose, { aic: card }).problems
  .filter((p) => p.includes('purpose sentence'))
  .forEach((p) => no(p));
ok('the narrower of the sentence and the grant governs');

// ─────────────────────────────────────────────────────────── 5b
rule('5b. A tier 3 determination is a malformed credential');

try {
  determination.stamp(
    { answer: 'You are eligible.' },
    { kind: determination.KIND.DETERMINATION, basis: { tier: determination.TIER.UNPUBLISHED } },
  );
  no('a tier 3 determination was allowed. That is a bug.');
} catch (e) {
  no(e.message.split('\n')[1].trim());
}

const navigation = determination.stamp(
  { next: 'Take your decision letter to the Service Alberta office on 108 Street.' },
  { kind: determination.KIND.NAVIGATION, basis: { tier: determination.TIER.UNPUBLISHED } },
);
ok(`navigation at tier 3 is fine: "${navigation.next}"`);
say(`    the person is shown: ${determination.presentation(determination.TIER.UNPUBLISHED).must_say}`);

const dropped = determination.downgrade(
  { tier: determination.TIER.CALLABLE, authority: 'https://rules.alberta.ca/adap/eligibility' },
  'connection timed out',
);
ok('a tier 1 service going dark changes what the person sees, every time');
say(`    "${dropped.tell_the_person}"`);

// ─────────────────────────────────────────────────────────── 6
rule('6. The person revokes, and is told what happened');

list.set(88117, status.STATUS.INVALID);
const afterToken = await status.publish({
  list,
  uri: ADC_LIST,
  issuer: 'https://kya.thekindredagency.com',
  privateKey: issuer.privateKey,
  ttl: 300,
  now,
});
const after = await status.fetchStatus(afterToken, { issuerKey: issuer.publicKey, idx: 88117, now });
say(`  ${JSON.stringify(status.inForce(after))}`);

const r = status.receipt({
  credentialId: 'urn:adc:44a1',
  purpose: delegation.purpose,
  revokedAt: new Date(now).toISOString(),
  notified: [AUD],
  listUri: ADC_LIST,
});
say();
say(JSON.stringify(r, null, 2).split('\n').map((l) => `    ${l}`).join('\n'));

say(`
${'═'.repeat(74)}
Everything above ran locally with no network. The federation half, verified
against Alberta's live anchor, is a separate script: npm run verify:alberta
${'═'.repeat(74)}
`);
