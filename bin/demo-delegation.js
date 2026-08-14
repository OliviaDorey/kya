#!/usr/bin/env node
/**
 * End to end, in the order it would actually happen.
 *
 *   1  an issuer gives an agent an Agent Identity Card
 *   2  a person's wallet issues a Delegation Credential to that specific agent
 *   3  the agent presents both to a verifier, with key binding
 *   4  the verifier checks the status list and fails closed if it cannot
 *   5  the agent tries to overreach, and is refused
 *  5a  the application is refused, and appealing takes a second delegation
 *   6  the person revokes, and gets a receipt
 *
 * No network. Everything is generated in-process so this runs anywhere.
 */

import { generateKeyPair, exportJWK } from 'jose';
import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as status from '../src/status.js';
import * as determination from '../src/determination.js';
import * as capability from '../src/capability.js';

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
  capabilities: [
    'read:program-information',
    'draft:application',
    'submit:application',
    'draft:appeal',
    'submit:appeal',
    'monitor:status',
  ],
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
  // Her sentence, in her words. It names what she is going through, and it
  // never leaves her wallet unless she chooses to show it.
  purpose:
    'Apply for Assured Income for the Severely Handicapped on my behalf.',
  // Submission, and nothing else. She is applying; she has not been refused and
  // has no reason yet to authorise an appeal. Step 5a is what happens when she does.
  authorization_details: [
    {
      type: 'ca_public_service_request',
      capability: 'submit:form',
      actions: ['draft', 'submit'],
      constraints: { max_submissions: 1, requires_human_approval: ['submit'], valid_until: '2026-09-30' },
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

const { credential: issuedDelegation, salt, purpose_commitment } = await adc.issue({
  adc: delegation,
  aic: card,
  walletKey: wallet.privateKey,
  holderJwk: agentJwk,
});
ok('delegation issued, bound to one card and one key');
ok(`valid for ${Math.round((delegation.exp - delegation.iat) / 86400)} days`);
ok('her sentence is committed to and withheld; she keeps the salt');

try {
  await adc.issue({ adc: { ...delegation, purpose_commitment: undefined }, aic: card, walletKey: wallet.privateKey, holderJwk: agentJwk, selective: [] });
  no('the purpose was issued in the clear. That is a bug.');
} catch {
  ok('refused to issue with her sentence readable by the office');
}

say();
say('  What SHE sees:');
say(adc.explain({ ...delegation, purpose_commitment }).split('\n').map((l) => `    ${l}`).join('\n'));

// ─────────────────────────────────────────────────────────── 3
rule('3. The agent presents both to a caseworker, with key binding');

const AUD = 'https://caseworker.alberta.ca';
const NONCE = 'n-3f9a2c';

const presentedCard = await aic.jwkThumbprint(agentJwk).then(() =>
  import('../src/sdjwt.js').then(({ present }) =>
    present(issuedCard, { reveal: [], audience: AUD, nonce: NONCE, holderKey: agent.privateKey }),
  ),
);
const presentedDelegation = await adc.present(issuedDelegation, {
  audience: AUD,
  nonce: NONCE,
  holderKey: agent.privateKey,
});

const vCard = await aic.verify(presentedCard, { issuerKey: issuer.publicKey, audience: AUD, nonce: NONCE });
ok(`card verified. Agent "${vCard.card.agent.name}", built by ${vCard.card.builder.legal_name}`);
ok(`accountable: ${vCard.card.accountable.role}, ${vCard.card.accountable.contact}`);
ok(`model withheld this time: ${vCard.card.model === undefined ? 'yes, and the verifier can tell' : 'no'}`);

const vDel = await adc.verify(presentedDelegation, {
  walletKey: wallet.publicKey,
  aic: vCard.card,
  aicThumbprint: vCard.thumbprint,   // recomputed from the card just presented
  audience: AUD,
  nonce: NONCE,
});
ok('delegation verified, key-bound to the presenting agent');
ok('and bound to the card presented with it: both thumbprints recomputed and compared');

// The binding is the reason there are two credentials rather than one. A
// delegation carried alongside somebody else's card is refused outright.
const strangersCard = await aic.issue({ card, privateKey: issuer.privateKey, holderJwk: agentJwk });
try {
  await adc.verify(presentedDelegation, {
    walletKey: wallet.publicKey,
    aic: vCard.card,
    presentedCard: strangersCard,
    audience: AUD,
    nonce: NONCE,
  });
  no('a delegation verified against a card it was not granted against. That is a bug.');
} catch (e) {
  no(e.message.split('\n')[1].replace(/^\s*-\s*/, '').split('.')[0]);
}
say();
say('  What the CASEWORKER sees:');
say(capability.explainToVerifier(vDel.adc).split('\n').map((l) => `    ${l}`).join('\n'));
say();
if (vDel.adc.purpose === undefined) {
  ok('the words "Severely Handicapped" never reached the office');
} else {
  no('her sentence reached the office. That is a bug.');
}
ok(`and she can still prove what she consented to: ${capability.verifyPurpose(delegation.purpose, salt, vDel.adc.purpose_commitment)}`);

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
  purpose_commitment,
  authorization_details: [
    ...delegation.authorization_details,
    { type: 'ca_public_service_request', capability: 'correspond:administrative', actions: ['correspond'], constraints: {} },
  ],
};
const breach = adc.validate(wider, { aic: card });
breach.problems.forEach((p) => no(p));

const quieterPurpose = { ...delegation, purpose_commitment, purpose: 'Have a look at what I might be able to get.' };
adc.validate(quieterPurpose, { aic: card }).problems
  .filter((p) => p.includes('purpose sentence'))
  .forEach((p) => no(p));
ok('the narrower of the sentence and the grant governs');

const leaky = {
  ...delegation,
  purpose_commitment,
  authorization_details: [{ ...delegation.authorization_details[0], type: 'aish_disability_application' }],
};
adc.validate(leaky, { aic: card }).problems
  .filter((p) => p.includes('information'))
  .forEach((p) => no(p));

// ─────────────────────────────────────────────────────────── 5a
rule('5a. The application is refused. Appealing takes a second delegation');

say('  The decision letter says no. She wants to appeal.');
say(`  The delegation she granted permits: submit ${adc.permits(delegation, 'submit')}, appeal ${adc.permits(delegation, 'appeal')}`);
no('an appeal is a different capability, not a later step of the same one');

const stretched = {
  ...delegation,
  purpose_commitment,
  authorization_details: [
    { ...delegation.authorization_details[0], actions: ['draft', 'submit', 'appeal'] },
  ],
};
adc.validate(stretched, { aic: card }).problems
  .filter((p) => p.includes('only permits'))
  .forEach((p) => no(p));

// She grants a fresh one. It is granted only because the card already carries
// draft:appeal and submit:appeal; a delegation can narrow what the card holds and
// never widen it. Drafting the appeal and filing it are two separate grants, for
// the same reason drafting a form and submitting it are: filing is irreversible
// and it starts or forfeits a clock.
const appeal = {
  ...delegation,
  purpose: 'The decision went against me. Appeal it on my behalf and keep me told.',
  purpose_commitment: undefined,
  iat: sec,
  exp: sec + 14 * 86400,
  authorization_details: [
    {
      type: 'ca_public_service_request',
      capability: 'request:review',
      actions: ['draft-appeal', 'appeal'],
      constraints: { requires_human_approval: ['appeal'], valid_until: '2026-12-31' },
    },
  ],
  consent: {
    record_uri: 'https://wallet.example.ca/consent/44a2',
    captured_at: new Date(now).toISOString(),
    language: 'en-CA',
    method: 'in-app-explicit',
  },
  revocation: { revoke_uri: 'https://revoke.agentcredential.ca/d/44a2', citizen_facing: true },
  status: { status_list: { uri: ADC_LIST, idx: 88118 } },
};

const { credential: issuedAppeal, salt: appealSalt } = await adc.issue({
  adc: appeal,
  aic: card,
  walletKey: wallet.privateKey,
  holderJwk: agentJwk,
});
ok('second delegation issued, granted only because the card carries draft:appeal and submit:appeal');

// Drafting an appeal is not filing one. A card that may prepare an appeal but was
// never given submit:appeal cannot lodge it, and finds that out here rather than
// after the clock has started.
const drafterOnly = { ...card, capabilities: card.capabilities.filter((c) => c !== 'submit:appeal') };
adc.validate(appeal, { aic: drafterOnly }).problems
  .filter((p) => p.includes('submit:appeal'))
  .forEach((p) => no(p));

const APPEAL_NONCE = 'n-8b21d4';
const presentedAppeal = await adc.present(issuedAppeal, {
  audience: AUD,
  nonce: APPEAL_NONCE,
  holderKey: agent.privateKey,
});
const vAppeal = await adc.verify(presentedAppeal, {
  walletKey: wallet.publicKey,
  aic: vCard.card,
  aicThumbprint: vCard.thumbprint,
  audience: AUD,
  nonce: APPEAL_NONCE,
});
ok(`appeal delegation verified. It permits appeal ${adc.permits(vAppeal.adc, 'appeal')}, submit ${adc.permits(vAppeal.adc, 'submit')}`);
ok(`and she can still prove what she consented to: ${capability.verifyPurpose(appeal.purpose, appealSalt, vAppeal.adc.purpose_commitment)}`);
say();
say('  What the CASEWORKER sees this time:');
say(capability.explainToVerifier(vAppeal.adc).split('\n').map((l) => `    ${l}`).join('\n'));
say();
if (vAppeal.adc.purpose === undefined) {
  ok('that she was refused, and what for, never reached the office');
} else {
  no('her sentence reached the office. That is a bug.');
}

// The narrower governs here exactly as it does for the application.
adc.validate({ ...appeal, purpose_commitment: 'x', purpose: 'Please keep working on my file now that the letter has come.' }, { aic: card })
  .problems.filter((p) => p.includes('purpose sentence'))
  .forEach((p) => no(p));
ok('the narrower of the sentence and the grant governs the appeal too');

// And on a card that was never given the capability, the appeal is refused
// outright rather than trimmed down to something she did not ask for.
const cardWithoutAppeal = { ...card, capabilities: card.capabilities.filter((c) => c !== 'draft:appeal') };
adc.validate(appeal, { aic: cardWithoutAppeal }).problems
  .filter((p) => p.includes('draft:appeal'))
  .forEach((p) => no(p));
ok('refused, not trimmed. The grant is left as written so whoever built it finds out');

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
