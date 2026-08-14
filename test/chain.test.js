/**
 * Chained delegation, and revocation that knows about chains.
 *
 * Named after the promise each one defends, like the rest of the suite. The
 * cases come from spec/revocation-and-chains.md section A, and the ones this
 * design does *not* cover get a test that documents the limitation rather than
 * silence, because a threat model whose gaps are untested is a threat model
 * nobody has to keep honest.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';

import * as sdjwt from '../src/sdjwt.js';
import * as aic from '../src/aic.js';
import * as status from '../src/status.js';
import * as chain from '../src/chain.js';
import * as revocation from '../src/revocation.js';
import * as register from '../src/register.js';

const issuerKp = await generateKeyPair('ES256', { extractable: true });
const walletKp = await generateKeyPair('ES256', { extractable: true });
const agentA = await generateKeyPair('ES256', { extractable: true });   // the person's agent
const agentB = await generateKeyPair('ES256', { extractable: true });   // a navigator's agent
const agentC = await generateKeyPair('ES256', { extractable: true });   // a third-party service
const impostor = await generateKeyPair('ES256', { extractable: true });

const jwkA = await exportJWK(agentA.publicKey);
const jwkB = await exportJWK(agentB.publicKey);
const jwkC = await exportJWK(agentC.publicKey);

const sec = Math.floor(Date.now() / 1000);
const AGENT_A = 'urn:agent:kindred:steward:a';
const AGENT_B = 'urn:agent:navigator:grace:b';
const AGENT_C = 'urn:agent:service:filing:c';

const rootCard = {
  vct: aic.AIC_VCT,
  iss: 'https://kya.thekindredagency.com',
  iat: sec,
  exp: sec + 86400,
  agent: { id: AGENT_A, name: 'Steward', version: '1.0.0' },
  builder: { legal_name: 'The Kindred Agency Inc.', jurisdiction: 'CA-NS', registry_id: '1', uri: 'https://thekindredagency.com' },
  accountable: { role: 'CTO', contact: 'trust@thekindredagency.com', redress_uri: 'https://thekindredagency.com/redress' },
  model: { disclosed: true, family: 'claude-opus', version: '5', hosted_in: 'CA', residency_basis: 'asserted' },
  capabilities: ['read:program-information', 'draft:application', 'submit:application', 'monitor:status'],
  conduct: { discloses_ai: 'always', acts_without_approval: false, retains_after_revocation: 'audit-record-only' },
  status: { status_list: { uri: 'https://status.agentcredential.ca/aic', idx: 1 } },
  cnf: { jwk: jwkA },
};

const issuedCard = await aic.issue({ card: rootCard, privateKey: issuerKp.privateKey, holderJwk: jwkA });
const CARD_THUMB = await aic.cardThumbprint(issuedCard);

const THUMB_A = await sdjwt.thumbprint(jwkA);
const THUMB_B = await sdjwt.thumbprint(jwkB);
const THUMB_C = await sdjwt.thumbprint(jwkC);

const boilerplate = (n) => ({
  consent: { record_uri: `https://wallet.example.ca/c/${n}`, captured_at: new Date().toISOString(), language: 'en-CA', method: 'in-app-explicit' },
  revocation: { revoke_uri: `https://revoke.agentcredential.ca/d/${n}`, citizen_facing: true },
  status: { status_list: { uri: 'https://status.agentcredential.ca/adc', idx: n } },
  purpose_commitment: `commitment-${n}`,
});

/** Link 0. The person's own grant: submit a form, with approval, and watch it. */
const rootLink = (over = {}) => ({
  vct: 'https://agentcredential.ca/adc/v1',
  iss: 'https://wallet.example.ca/u/1',
  iat: sec,
  exp: sec + 7 * 86400,
  delegator: { sub: 'pw:person', pairwise: true, verified_by: 'https://account.alberta.ca/dts' },
  delegate: { agent_id: AGENT_A, aic_thumbprint: CARD_THUMB, cnf_thumbprint: THUMB_A },
  chain: chain.chainClaim({ depth: 0 }),
  authorization_details: [
    {
      type: 'ca_public_service_request',
      capability: 'submit:form',
      actions: ['draft', 'submit'],
      constraints: { requires_human_approval: ['submit'], max_submissions: 2, valid_until: '2026-09-30' },
    },
    { type: 'ca_public_service_request', capability: 'track:status', actions: ['monitor'], constraints: {} },
  ],
  ...boilerplate(1),
  ...over,
});

/** Link 1. The agent hands the filing half to a navigator's agent. Narrower. */
const midLink = (parentThumb, rootThumb, over = {}) => ({
  vct: 'https://agentcredential.ca/adc/v1',
  iss: AGENT_A,
  iat: sec,
  exp: sec + 3 * 86400,
  delegator: { sub: 'pw:agent-a', pairwise: true, verified_by: 'https://account.alberta.ca/dts', agent_id: AGENT_A },
  delegate: { agent_id: AGENT_B, aic_thumbprint: CARD_THUMB, cnf_thumbprint: THUMB_B },
  chain: chain.chainClaim({ depth: 1, parentThumbprint: parentThumb, rootThumbprint: rootThumb }),
  authorization_details: [
    {
      type: 'ca_public_service_request',
      capability: 'submit:form',
      actions: ['draft', 'submit'],
      constraints: { requires_human_approval: ['submit'], max_submissions: 1, valid_until: '2026-09-15' },
    },
  ],
  ...boilerplate(2),
  ...over,
});

/** Link 2. Drafting only. Narrower again. */
const leafLink = (parentThumb, rootThumb, over = {}) => ({
  vct: 'https://agentcredential.ca/adc/v1',
  iss: AGENT_B,
  iat: sec,
  exp: sec + 86400,
  delegator: { sub: 'pw:agent-b', pairwise: true, verified_by: 'https://account.alberta.ca/dts', agent_id: AGENT_B },
  delegate: { agent_id: AGENT_C, aic_thumbprint: CARD_THUMB, cnf_thumbprint: THUMB_C },
  chain: chain.chainClaim({ depth: 2, parentThumbprint: parentThumb, rootThumbprint: rootThumb }),
  authorization_details: [
    { type: 'ca_public_service_request', capability: 'submit:form', actions: ['draft'], constraints: { max_submissions: 1 } },
  ],
  ...boilerplate(3),
  ...over,
});

/** Issue a chain for real, so the key path is exercised rather than asserted. */
async function buildChain({ midOver = {}, leafOver = {}, leafSigner = agentB, hops = 3 } = {}) {
  const l0 = await sdjwt.issue({ payload: rootLink(), privateKey: walletKp.privateKey, holderJwk: jwkA });
  const t0 = await chain.linkThumbprint(l0);
  if (hops === 1) return [l0];

  const l1 = await sdjwt.issue({ payload: midLink(t0, t0, midOver), privateKey: agentA.privateKey, holderJwk: jwkB });
  const t1 = await chain.linkThumbprint(l1);
  if (hops === 2) return [l0, l1];

  const l2 = await sdjwt.issue({ payload: leafLink(t1, t0, leafOver), privateKey: leafSigner.privateKey, holderJwk: jwkC });
  return [l0, l1, l2];
}

// ── C. Chained delegation ──────────────────────────────────────────────────

test('a chain that narrows at every hop verifies across an organisational boundary', async () => {
  const links = await buildChain();
  const result = await chain.verifyChain(links, { rootIssuerKey: walletKp.publicKey, aic: rootCard });

  assert.equal(result.hops, 3);
  // The verifier was given exactly one key from outside the chain: the wallet's.
  // Every other signing key came from the link above it, which is what makes a
  // party with no relationship to the person able to check the whole thing.
  assert.equal(result.claims[2].delegate.agent_id, AGENT_C);
});

test('the last link is what the chain authorises, not the widest one in it', async () => {
  const links = await buildChain();
  const { claims } = await chain.verifyChain(links, { rootIssuerKey: walletKp.publicKey, aic: rootCard });

  const grant = chain.effectiveGrant(claims);
  assert.deepEqual(grant.actions, ['draft']);
  assert.ok(!chain.chainPermits(claims, 'submit'), 'the person granted submit; the last hop does not hold it');
  assert.equal(grant.expires, claims[2].exp, 'the chain ends when its shortest link ends');
});

test('a link cannot grant an action the delegation above it does not hold', () => {
  const parent = { exp: sec + 100, authorization_details: [{ capability: 'submit:form', actions: ['draft'], constraints: {} }] };
  const child = { exp: sec + 50, authorization_details: [{ capability: 'submit:form', actions: ['draft', 'submit'], constraints: {} }] };

  const breaches = chain.narrowingBreaches(child, parent);
  assert.ok(breaches.some((b) => b.includes('submit') && b.includes('narrows and never widens')));
});

test('a link cannot grant a capability the delegation above it does not hold', () => {
  const parent = { exp: sec + 100, authorization_details: [{ capability: 'track:status', actions: ['monitor'], constraints: {} }] };
  const child = { exp: sec + 50, authorization_details: [{ capability: 'request:review', actions: ['appeal'], constraints: {} }] };

  assert.ok(chain.narrowingBreaches(child, parent).some((b) => b.includes('request:review')));
});

test('a link cannot outlive the delegation above it', () => {
  const parent = { exp: sec + 100, authorization_details: [{ capability: 'submit:form', actions: ['draft'], constraints: {} }] };
  const child = { exp: sec + 500, authorization_details: [{ capability: 'submit:form', actions: ['draft'], constraints: {} }] };

  assert.ok(chain.narrowingBreaches(child, parent).some((b) => b.includes('narrows and never widens')));
});

test('a link cannot raise a numeric limit the delegation above it set', () => {
  const parent = { exp: sec + 100, authorization_details: [{ capability: 'submit:form', actions: ['submit'], constraints: { max_submissions: 1 } }] };
  const child = { exp: sec + 50, authorization_details: [{ capability: 'submit:form', actions: ['submit'], constraints: { max_submissions: 5 } }] };

  assert.ok(chain.narrowingBreaches(child, parent).some((b) => b.includes('max_submissions')));
});

test('a link cannot run a date limit past the one above it', () => {
  const parent = { exp: sec + 100, authorization_details: [{ capability: 'submit:form', actions: ['submit'], constraints: { valid_until: '2026-09-01' } }] };
  const child = { exp: sec + 50, authorization_details: [{ capability: 'submit:form', actions: ['submit'], constraints: { valid_until: '2026-12-01' } }] };

  assert.ok(chain.narrowingBreaches(child, parent).some((b) => b.includes('valid_until')));
});

test('a link cannot drop an approval requirement the delegation above it carried', () => {
  // The axis that narrows by growing, and the one an implementer gets wrong.
  // Every set this child carries is smaller than its parent's, and it has still
  // widened authority, because fewer approvals is more freedom to act.
  const parent = {
    exp: sec + 100,
    authorization_details: [{ capability: 'submit:form', actions: ['draft', 'submit'], constraints: { requires_human_approval: ['submit'] } }],
  };
  const child = {
    exp: sec + 50,
    authorization_details: [{ capability: 'submit:form', actions: ['submit'], constraints: {} }],
  };

  const breaches = chain.narrowingBreaches(child, parent);
  assert.ok(breaches.some((b) => b.includes('may be added going down a chain and never dropped')));
});

test('a widening link is rejected rather than quietly trimmed', async () => {
  const links = await buildChain({
    midOver: {
      authorization_details: [
        { type: 'ca_public_service_request', capability: 'submit:form', actions: ['draft', 'submit'], constraints: { requires_human_approval: ['submit'], max_submissions: 99 } },
      ],
    },
  });

  await assert.rejects(
    () => chain.verifyChain(links, { rootIssuerKey: walletKp.publicKey, aic: rootCard }),
    (err) => {
      assert.match(err.message, /max_submissions/);
      // Rejected, not clamped. The party who built the chain is the one who
      // needs to know it is broken.
      assert.match(err.message, /not conforming/);
      return true;
    },
  );
});

test('a link signed by a key the delegation above it did not name is not part of the chain', async () => {
  const links = await buildChain({ leafSigner: impostor });

  await assert.rejects(
    () => chain.verifyChain(links, { rootIssuerKey: walletKp.publicKey, aic: rootCard }),
    /was not signed by the key the delegation above it committed to/,
  );
});

test('two chains cannot be spliced at a shared hop', async () => {
  const [l0] = await buildChain({ hops: 1 });
  const t0 = await chain.linkThumbprint(l0);
  // A link whose delegator is not the party the link above delegated to.
  const orphan = midLink(t0, t0, { delegator: { sub: 'pw:x', pairwise: true, verified_by: 'https://account.alberta.ca/dts', agent_id: 'urn:agent:somebody:else' } });

  const breaches = chain.structureBreaches([rootLink(), orphan], { thumbprints: [t0, 'x'] });
  assert.ok(breaches.some((b) => b.includes('The chain does not connect')));
});

test('a chain deeper than three hops is refused, not warned about', async () => {
  const links = await buildChain();
  const fourth = await sdjwt.issue({ payload: leafLink('x', 'y'), privateKey: agentC.privateKey, holderJwk: jwkC });

  await assert.rejects(
    () => chain.verifyChain([...links, fourth], { rootIssuerKey: walletKp.publicKey, aic: rootCard }),
    /maximum is 3/,
  );
});

test('a chain verified without the root card is refused rather than partly checked', async () => {
  const links = await buildChain();
  await assert.rejects(
    () => chain.verifyChain(links, { rootIssuerKey: walletKp.publicKey }),
    /requires the root Agent Identity Card/,
  );
});

test('an unchecked parent binding is a failed binding, not a skipped one', () => {
  // Same rule as bindingBreaches: a caller who supplies no thumbprints has not
  // checked the chain, and must not be told it passed.
  const breaches = chain.structureBreaches([rootLink(), midLink('t0', 't0')]);
  assert.ok(breaches.some((b) => b.includes('An unchecked binding is a failed binding')));
});

test('a person is told what a chain does in language they can hold in their head', async () => {
  const { claims } = await chain.verifyChain(await buildChain(), { rootIssuerKey: walletKp.publicKey, aic: rootCard });
  const text = chain.explainChainToPerson(claims);

  assert.match(text, /Each step can do less than the one before it/);
  assert.match(text, /You can stop the whole thing at any time/);
});

// ── A. The five failure cases revocation must cover ────────────────────────

function freshRegister() {
  // Two bits, because suspension needs a third state. A deployment publishing a
  // one-bit list can revoke and cannot suspend, and suspend() says so.
  const list = new status.StatusList({ size: 64, bits: 2 });
  return new revocation.RevocationRegister({ list, listUri: 'https://status.agentcredential.ca/adc' });
}

/** A registered three-link chain, so cascade has a tree to walk. */
function registeredChain() {
  const reg = freshRegister();
  reg.register({ credentialId: 'root', idx: 1, aicThumbprint: CARD_THUMB, chain: { depth: 0, parentId: null, rootId: 'root' } });
  reg.register({ credentialId: 'mid', idx: 2, aicThumbprint: CARD_THUMB, chain: { depth: 1, parentId: 'root', rootId: 'root' } });
  reg.register({ credentialId: 'leaf', idx: 3, aicThumbprint: CARD_THUMB, chain: { depth: 2, parentId: 'mid', rootId: 'root' } });
  return reg;
}

// R1 — the principal revokes deliberately

test('R1: a relying party that checked one second earlier keeps the act it already took', async () => {
  const reg = registeredChain();
  reg.notePresentation('root', 'https://aish.alberta.ca', '2026-08-14T10:00:00Z');

  const before = reg.get('root').presentedTo.get('https://aish.alberta.ca');
  const result = await revocation.revoke(reg, { credentialId: 'root', notify: async () => {} });

  // Revocation is a fact about what happens next, not about the past. The
  // presentation record is untouched and the receipt dates the stop, so a
  // relying party can tell an act inside the grant from one after it.
  assert.equal(reg.get('root').presentedTo.get('https://aish.alberta.ca'), before);
  assert.ok(result.receipt.revoked_at);
  assert.equal(result.receipt.revoked_by, revocation.AUTHORITY.PRINCIPAL);
});

// R2 — the agent is compromised

test('R2: revoking a compromised agent stops every delegation held by its key, not one', async () => {
  const reg = registeredChain();
  reg.register({ credentialId: 'other-person', idx: 9, aicThumbprint: CARD_THUMB, chain: null });

  const cardList = new status.StatusList({ size: 8 });
  const result = await revocation.revokeCard(reg, {
    aicThumbprint: CARD_THUMB,
    cardIdx: 1,
    cardList,
    authority: revocation.AUTHORITY.ACCOUNTABLE,
    notify: async () => {},
  });

  assert.ok(result.ok);
  assert.equal(cardList.get(1), status.STATUS.INVALID);
  // The unit of harm is the agent's holder key, so the unit of revocation is too.
  for (const id of ['root', 'mid', 'leaf', 'other-person']) {
    assert.equal(reg.get(id).revoked, true, `${id} was held by the compromised key and should have stopped`);
  }
});

test('R2: the accountable human named in the card can pull the switch, which is what that field is for', async () => {
  const reg = registeredChain();
  const result = await revocation.revoke(reg, {
    credentialId: 'root',
    authority: revocation.AUTHORITY.ACCOUNTABLE,
    reason: revocation.REASONS.AGENT_COMPROMISED,
    notify: async () => {},
  });
  assert.ok(result.ok);
  assert.equal(result.receipt.revoked_by, revocation.AUTHORITY.ACCOUNTABLE);
});

// R3 — the agent behaves within scope, against the principal's interest

test('R3: a relying party can stop an agent it is watching without the person being there', () => {
  const reg = registeredChain();
  const result = revocation.suspend(reg, {
    credentialId: 'root',
    authority: revocation.AUTHORITY.RELYING_PARTY,
    by: 'https://aish.alberta.ca',
    scope: 'https://aish.alberta.ca',
    reason: revocation.REASONS.CONDUCT,
  });

  assert.ok(result.ok);
  assert.equal(reg.stopped('root', { atVerifier: 'https://aish.alberta.ca' }).stopped, true);
  // And nowhere else. One office's judgement does not follow the person around.
  assert.equal(reg.stopped('root', { atVerifier: 'https://health.alberta.ca' }).stopped, false);
});

test('R3: a relying party may not revoke, because that would let one office end a person\'s help', async () => {
  const reg = registeredChain();
  const result = await revocation.revoke(reg, {
    credentialId: 'root',
    authority: revocation.AUTHORITY.RELYING_PARTY,
    notify: async () => {},
  });

  assert.equal(result.ok, false);
  assert.equal(result.refused, true);
  assert.match(result.reason, /may not revoke/);
  assert.equal(reg.get('root').revoked, false);
});

test('R3: a relying party may not suspend globally either', () => {
  const reg = registeredChain();
  const result = revocation.suspend(reg, {
    credentialId: 'root',
    authority: revocation.AUTHORITY.RELYING_PARTY,
    by: 'https://aish.alberta.ca',
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /may only suspend at itself/);
});

test('R3: only the person can start it again', () => {
  const reg = registeredChain();
  revocation.suspend(reg, { credentialId: 'root', authority: revocation.AUTHORITY.ACCOUNTABLE, by: 'CTO' });

  const refused = revocation.reinstate(reg, { credentialId: 'root', authority: revocation.AUTHORITY.RELYING_PARTY });
  assert.equal(refused.ok, false);
  assert.match(refused.reason, /Only the person who granted it/);

  const allowed = revocation.reinstate(reg, { credentialId: 'root', authority: revocation.AUTHORITY.PRINCIPAL });
  assert.ok(allowed.ok);
  assert.equal(reg.stopped('root').stopped, false);
});

test('R3: reinstating an ancestor does not overrule an office that stopped a step for its own reasons', () => {
  const reg = registeredChain();
  revocation.suspend(reg, { credentialId: 'root', authority: revocation.AUTHORITY.PRINCIPAL, by: 'the person' });
  revocation.suspend(reg, { credentialId: 'leaf', authority: revocation.AUTHORITY.ISSUER, by: 'the issuer', reason: revocation.REASONS.CONDUCT });

  const result = revocation.reinstate(reg, { credentialId: 'root', authority: revocation.AUTHORITY.PRINCIPAL });
  assert.equal(reg.stopped('mid').stopped, false, 'the cascade lifted');
  assert.equal(reg.stopped('leaf').stopped, true, 'the issuer\'s own suspension did not');
  assert.ok(result.still_stopped.some((s) => s.credentialId === 'leaf'));
});

test('R3: a suspension is a sentence to the person, not a status code', () => {
  const reg = registeredChain();
  const result = revocation.suspend(reg, {
    credentialId: 'root',
    authority: revocation.AUTHORITY.RELYING_PARTY,
    by: 'https://aish.alberta.ca',
    scope: 'https://aish.alberta.ca',
  });

  assert.match(result.continuation.tell_the_person, /has not been taken away|stopped at one office/);
  assert.match(result.continuation.tell_the_person, /Nothing you have already submitted has been withdrawn/);
  assert.ok(result.continuation.contact, 'a stop with no way to reach a human is a dead end');
});

// R4 — the issuer itself is wrong or compromised

test('R4: a compromised issuer cannot be stopped by its own status list, and the register is the switch', async () => {
  // The issuer signs the list. So a compromised issuer publishes a list saying
  // everything is fine, and every conformant verifier believes it. This test
  // exists to make that structural fact visible rather than implied.
  const list = new status.StatusList({ size: 8 });
  const token = await status.publish({ list, uri: 'https://status.example/adc', issuer: 'https://liar.example', privateKey: issuerKp.privateKey, ttl: 300 });
  const seen = await status.fetchStatus(token, { issuerKey: issuerKp.publicKey, idx: 0 });

  assert.equal(status.inForce(seen).ok, true, 'the issuer\'s own list says everything is fine, because it would');

  const reg = new register.TrustRegister({ operator: 'https://trustmark.thekindredagency.com' });
  reg.attest({ issuer: 'https://liar.example', assessedBy: 'Kindred', assessedAt: '2026-08-01', conformanceLevel: 'v0.3' });
  reg.withdraw({ issuer: 'https://liar.example', reason: register.WITHDRAWAL.KEY_COMPROMISE });

  const standing = reg.check('https://liar.example');
  assert.equal(register.issuerTrusted(standing).ok, false);
  assert.match(register.issuerTrusted(standing).reason, /withdrawn from the register/);
});

test('R4: an unreachable or stale register fails closed, the same as a status list', () => {
  assert.equal(register.issuerTrusted({ standing: register.STANDING.ATTESTED, reachable: false }).ok, false);
  assert.equal(register.issuerTrusted({ standing: register.STANDING.ATTESTED, stale: true }).ok, false);
});

test('R4: never assessed is not the same answer as withdrawn', () => {
  const reg = new register.TrustRegister({ operator: 'https://trustmark.thekindredagency.com' });
  const unknown = register.issuerTrusted(reg.check('https://nobody.example'));

  assert.equal(unknown.ok, true);
  assert.equal(unknown.unattested, true, 'a verifier is entitled to know it is making a policy call, not being told an answer');
  assert.equal(register.issuerTrusted({ ...reg.check('https://nobody.example'), requireAttestation: true }).ok, false);
});

test('R4: an attestation nobody signed is a rumour and is refused', () => {
  const reg = new register.TrustRegister({ operator: 'https://trustmark.thekindredagency.com' });
  assert.throws(() => reg.attest({ issuer: 'https://x.example', assessedAt: '2026-08-01' }), /must name who assessed it/);
});

test('R4: a person whose issuer was withdrawn is told it was not their fault and where to go', () => {
  const text = register.explainWithdrawal({
    issuer: 'https://liar.example',
    reason: register.WITHDRAWAL.KEY_COMPROMISE,
    redressUri: 'https://thekindredagency.com/redress',
    alternatives: ['the AISH office directly'],
  });

  assert.match(text, /it is not anything you did/);
  assert.match(text, /Nothing you have already submitted is affected/);
  assert.match(text, /a person will sort it out/);
});

// R5 — an agent three hops down misbehaves

test('R5: revoking a link stops everything below it and nothing above it', async () => {
  const reg = registeredChain();
  const result = await revocation.revoke(reg, {
    credentialId: 'mid',
    authority: revocation.AUTHORITY.ANCESTOR,
    notify: async () => {},
  });

  assert.deepEqual(result.cascaded, ['leaf']);
  assert.equal(reg.get('leaf').revoked, true);
  assert.equal(reg.get('leaf').reason, revocation.REASONS.ANCESTOR_REVOKED);
  assert.equal(reg.get('root').revoked, false, 'the person\'s own grant is untouched by a sub-agent being stopped');
  assert.equal(reg.list.get(3), status.STATUS.INVALID);
});

test('R5: the person\'s stop button reaches the whole tree however far it travelled', async () => {
  const reg = registeredChain();
  const result = await revocation.revoke(reg, { credentialId: 'root', notify: async () => {} });

  assert.deepEqual(result.cascaded.sort(), ['leaf', 'mid']);
  assert.match(result.receipt.note, /onward steps? that this authority had been passed to/);
});

test('R5: a broken chain hands the person a way forward, not a dead end', async () => {
  const reg = registeredChain();
  await revocation.revoke(reg, { credentialId: 'mid', authority: revocation.AUTHORITY.ANCESTOR, notify: async () => {} });

  const path = revocation.continuation(reg, { credentialId: 'mid', stoppedBy: 'the agency', reason: revocation.REASONS.CONDUCT });
  assert.match(path.tell_the_person, /no deadline has been given up/);
  assert.match(path.tell_the_person, /you can grant it again/);
  assert.ok(path.contact);
  assert.equal(path.what_is_unaffected, 'anything already submitted, and every deadline already met');
});

// ── The gift boundary, as an acceptance test ───────────────────────────────

test('B: a third party can run a complete revocation service with nothing from Kindred', async () => {
  // If this test needs a Kindred key, a Kindred endpoint, or Kindred's
  // permission, the gift is not a gift. It is the acceptance criterion for the
  // boundary drawn in spec/revocation-and-chains.md section B.
  const theirKp = await generateKeyPair('ES256', { extractable: true });
  const list = new status.StatusList({ size: 16 });
  const reg = new revocation.RevocationRegister({ list, listUri: 'https://revoke.gov.bc.ca/adc' });
  reg.register({ credentialId: 'theirs', idx: 0, aicThumbprint: 'their-card', chain: { depth: 0, parentId: null, rootId: 'theirs' } });

  const revoked = await revocation.revoke(reg, { credentialId: 'theirs', notify: async () => {} });
  const theirRegister = new register.TrustRegister({ operator: 'https://trust.gov.bc.ca' });
  theirRegister.attest({ issuer: 'https://issuer.gov.bc.ca', assessedBy: 'Province of British Columbia', assessedAt: '2026-08-14', conformanceLevel: 'v0.3' });

  const published = await status.publish({ list, uri: 'https://revoke.gov.bc.ca/adc', issuer: 'https://revoke.gov.bc.ca', privateKey: theirKp.privateKey, ttl: 300 });

  assert.ok(revoked.ok);
  assert.ok(published);
  assert.equal(register.issuerTrusted(theirRegister.check('https://issuer.gov.bc.ca')).ok, true);
});

// ── What this does not solve. Tested, so the gaps stay honest ──────────────

test('LIMITATION: nothing here detects an agent misbehaving inside its grant', async () => {
  // Criticism 1, stated as a passing test rather than as prose. The chain below
  // is perfectly conformant. Every narrowing rule holds, every signature
  // verifies, and the agent at the end of it can do the authorised thing at the
  // wrong time, with the wrong content, for the wrong reason, and this library
  // will not notice. Suspension is a stop, not a detector.
  const links = await buildChain();
  const result = await chain.verifyChain(links, { rootIssuerKey: walletKp.publicKey, aic: rootCard });

  assert.equal(result.hops, 3);
  assert.ok(chain.chainPermits(result.claims, 'draft'));
  assert.ok(!('conduct_observed' in result), 'there is no conduct signal here, and adding one is not a credential problem');
});

test('LIMITATION: a chain the register never saw does not cascade', async () => {
  // A chain built entirely off-register verifies correctly by signature and
  // narrowing, which is the point: it works without Kindred. What it does not
  // get is a proactive stop. It fails on its next verification when the root's
  // status is checked, which is slower than a cascade and is the protocol's
  // honest answer rather than a fixable bug.
  const reg = freshRegister();
  reg.register({ credentialId: 'root', idx: 1, chain: { depth: 0, parentId: null, rootId: 'root' } });
  // 'mid' exists in the world; the register was never told.

  const result = await revocation.revoke(reg, { credentialId: 'root', notify: async () => {} });
  assert.deepEqual(result.cascaded, [], 'no cascade, because there is no tree to walk');
});

test('LIMITATION: suspension needs a two-bit status list, and a one-bit deployment is told so', () => {
  const list = new status.StatusList({ size: 8 });
  const reg = new revocation.RevocationRegister({ list, listUri: 'https://status.example/adc' });
  reg.register({ credentialId: 'x', idx: 0 });

  const result = revocation.suspend(reg, { credentialId: 'x', authority: revocation.AUTHORITY.PRINCIPAL, by: 'the person' });
  assert.equal(result.ok, false);
  assert.match(result.reason, /one-bit status list/);
  assert.match(result.reason, /revoke instead/, 'a refusal with no way forward is a dead end');
});

test('LIMITATION: a scoped suspension is invisible in the status list', () => {
  // A status list has one value per credential and no room for "stopped at one
  // office". So a scoped suspension is enforced by the party that imposed it,
  // at its own door, and a different verifier reading the list sees VALID. That
  // is a limitation of the data structure, not of the intent, and aligning with
  // KYA-OS's StatusList2021 would make it worse rather than better.
  const reg = registeredChain();
  revocation.suspend(reg, {
    credentialId: 'root',
    authority: revocation.AUTHORITY.RELYING_PARTY,
    by: 'https://aish.alberta.ca',
    scope: 'https://aish.alberta.ca',
  });

  assert.equal(reg.list.get(1), status.STATUS.VALID, 'the global list cannot express a scoped stop');
  assert.equal(reg.stopped('root', { atVerifier: 'https://aish.alberta.ca' }).stopped, true);
});

test('LIMITATION: revocation stops the next act and cannot undo the last one', async () => {
  const reg = registeredChain();
  reg.notePresentation('root', 'https://aish.alberta.ca', '2026-08-14T10:00:00Z');
  const result = await revocation.revoke(reg, { credentialId: 'root', notify: async () => {} });

  // There is no unfile, no unsend, and a forfeited appeal deadline stays
  // forfeited. The remedy is a named human, which is why accountable.redress_uri
  // can never be withheld.
  assert.equal(result.receipt.revoked.id, 'root');
  assert.ok(!('undone' in result.receipt));
  assert.match(
    revocation.continuation(reg, { credentialId: 'root', stoppedBy: 'the person', reason: revocation.REASONS.PERSON_REVOKED }).tell_the_person,
    /a person will sort it out/,
  );
});

test('LIMITATION: depth is capped by a constant, and three reachable status lists is three chances to fail closed', async () => {
  assert.equal(chain.MAX_HOPS, 3);
  const { claims } = await chain.verifyChain(await buildChain(), { rootIssuerKey: walletKp.publicKey, aic: rootCard });

  // One unreachable link fails the whole chain. Correct, and an availability
  // multiplier that this design makes worse rather than better. No availability
  // target exists anywhere in this repository.
  const perLink = claims.map(() => status.inForce({ status: status.STATUS.VALID, stale: false, reachable: true }));
  assert.ok(perLink.every((r) => r.ok));
  assert.equal(status.inForce({ status: status.STATUS.VALID, stale: false, reachable: false }).ok, false);
});
