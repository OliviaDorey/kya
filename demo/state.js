/**
 * The demonstration's world, in memory.
 *
 * One agent, one person, one delegation. Everything is generated at boot so the
 * demo has no setup step and no network dependency. Restarting resets it, which
 * is exactly what you want between rehearsals.
 */

import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import * as aic from '../src/aic.js';
import * as adc from '../src/adc.js';
import * as status from '../src/status.js';
import * as revocation from '../src/revocation.js';

const LIST_URI = 'https://status.agentcredential.ca/adc';
const IDX = 88117;
const CREDENTIAL_ID = 'urn:adc:demo:44a1';

export const world = {};

export async function boot() {
  const now = Date.now();
  const sec = Math.floor(now / 1000);

  const issuer = await generateKeyPair('ES256', { extractable: true });
  const wallet = await generateKeyPair('ES256', { extractable: true });
  const agent = await generateKeyPair('ES256', { extractable: true });
  const agentJwk = await exportJWK(agent.publicKey);
  const walletJwk = await exportJWK(wallet.publicKey);

  const AGENT_ID = 'urn:agent:kindred:steward:7f3a1c92';

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
    status: { status_list: { uri: 'https://status.agentcredential.ca/aic', idx: 4213 } },
  };

  const issuedCard = await aic.issue({ card, privateKey: issuer.privateKey, holderJwk: agentJwk });

  const delegation = {
    vct: adc.ADC_VCT,
    iss: 'https://wallet.example.ca/u/8f22b1',
    iat: sec,
    exp: sec + 14 * 86400,
    delegator: {
      sub: 'pw:9c1f4e77a2',
      pairwise: true,
      verified_by: 'https://account.alberta.ca/dts',
      assurance: 'substantial',
    },
    delegate: {
      agent_id: AGENT_ID,
      aic_thumbprint: await aic.cardThumbprint(issuedCard),
      cnf_thumbprint: await aic.jwkThumbprint(agentJwk),
    },
    // Her words. They never leave her wallet unless she chooses otherwise.
    purpose: 'Apply for Assured Income for the Severely Handicapped on my behalf, and appeal if I am refused.',
    authorization_details: [
      {
        type: 'ca_public_service_request',
        capability: 'submit:form',
        actions: ['draft', 'submit'],
        constraints: { max_submissions: 1, requires_human_approval: ['submit'] },
      },
      {
        type: 'ca_public_service_request',
        capability: 'request:review',
        actions: ['draft-appeal', 'appeal'],
        constraints: { requires_human_approval: ['appeal'] },
      },
    ],
    consent: {
      record_uri: 'https://wallet.example.ca/consent/44a1',
      captured_at: new Date(now).toISOString(),
      language: 'en-CA',
      method: 'in-app-explicit',
    },
    revocation: { revoke_uri: '/withdraw', citizen_facing: true },
    status: { status_list: { uri: LIST_URI, idx: IDX } },
  };

  const { credential, salt, purpose_commitment } = await adc.issue({
    adc: delegation,
    aic: card,
    walletKey: wallet.privateKey,
    holderJwk: agentJwk,
  });

  const list = new status.StatusList({ size: 100_000, bits: 1 });
  const register = new revocation.RevocationRegister({ list, listUri: LIST_URI, freshnessSeconds: 300 });
  register.register({
    credentialId: CREDENTIAL_ID,
    idx: IDX,
    delegatorJwk: walletJwk,
    purposeCommitment: purpose_commitment,
    expiresAt: delegation.exp,
  });

  Object.assign(world, {
    CREDENTIAL_ID,
    LIST_URI,
    IDX,
    keys: { issuer, wallet, agent },
    agentJwk,
    walletJwk,
    card,
    issuedCard,
    delegation: { ...delegation, purpose_commitment },
    credential,
    salt,
    purpose_commitment,
    list,
    register,
    /** Who has been told what. Drives the "verifiers notified" line on the receipt. */
    notifications: [],
    /** The person's own record of what happened. Minute 6 shows this. */
    receipt: null,
    /** Presentations, newest first, for the caseworker screen's history. */
    presentations: [],
  });

  return world;
}

/** The person signs a withdrawal with the key her wallet used. No account, no login. */
export async function signWithdrawal() {
  return new SignJWT({ action: 'revoke', credential: world.CREDENTIAL_ID })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .sign(world.keys.wallet.privateKey);
}

/** A fresh presentation to a named verifier, key-bound, purpose withheld. */
export async function presentTo(verifier, nonce) {
  const { present } = await import('../src/sdjwt.js');
  const presentedCard = await present(world.issuedCard, {
    reveal: [],
    audience: verifier,
    nonce,
    holderKey: world.keys.agent.privateKey,
  });
  const presentedDelegation = await adc.present(world.credential, {
    audience: verifier,
    nonce,
    holderKey: world.keys.agent.privateKey,
  });
  return { presentedCard, presentedDelegation };
}

export { LIST_URI, IDX, CREDENTIAL_ID };
