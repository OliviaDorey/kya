#!/usr/bin/env node
/**
 * Build and sign the Entity Configuration we would publish at
 * /.well-known/openid-federation to register as an openid_credential_issuer
 * leaf under a government trust anchor.
 *
 * Alberta's anchor permits openid_credential_issuer and openid_verifier as leaf
 * types, so this is the door we would walk through. Run make-keys first.
 */

import { SignJWT, importJWK } from 'jose';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALBERTA_TRUST_ANCHOR } from '../src/alberta.js';
import { sanitiseJwk } from '../src/federation.js';
import { AIC_VCT } from '../src/aic.js';
import { ADC_VCT } from '../src/adc.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const keyPath = join(root, 'keys', 'issuer.private.jwk.json');
const pubPath = join(root, 'keys', 'issuer.public.jwk.json');

if (!existsSync(keyPath)) {
  console.error('No issuer key. Run: npm run make:keys');
  process.exitCode = 1;
} else {
  const arg = (name, fallback) => {
    const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
    return hit ? hit.split('=').slice(1).join('=') : fallback;
  };

  const entityId = arg('entity', 'https://kya.thekindredagency.com');
  const anchor = arg('anchor', ALBERTA_TRUST_ANCHOR);
  const lifetimeDays = Number(arg('days', '30'));

  const privJwk = JSON.parse(readFileSync(keyPath, 'utf8'));
  const pubJwk = JSON.parse(readFileSync(pubPath, 'utf8'));

  // Run our own key through the sanitiser that exists because of Alberta's
  // anchor. If it reports a quirk on a key we generated, we introduced it.
  const { jwk: cleanPub, quirks } = sanitiseJwk(pubJwk);
  if (quirks.length) {
    console.error(`Refusing to publish: our own key carries ${quirks.join(', ')}.`);
    console.error('That is the exact defect we reported to Alberta. Fix it before publishing.');
    process.exitCode = 1;
  } else {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + lifetimeDays * 86400;

    const statement = {
      iss: entityId,
      sub: entityId,
      iat: now,
      exp,
      jwks: { keys: [cleanPub] },
      authority_hints: [anchor],

      metadata: {
        federation_entity: {
          organization_name: 'The Kindred Agency Inc.',
          homepage_uri: 'https://thekindredagency.com',
          contacts: ['trust@thekindredagency.com'],
          policy_uri: 'https://thekindredagency.com/kya/policy',
        },

        openid_credential_issuer: {
          credential_issuer: entityId,
          credential_endpoint: `${entityId}/credential`,
          display: [{ name: 'Kindred Agent Credentials', locale: 'en-CA' }],
          credential_configurations_supported: {
            agent_identity_card: {
              format: 'dc+sd-jwt',
              vct: AIC_VCT,
              cryptographic_binding_methods_supported: ['jwk'],
              credential_signing_alg_values_supported: ['ES256'],
              display: [{ name: 'Agent Identity Card', locale: 'en-CA' }],
            },
            agent_delegation_credential: {
              format: 'dc+sd-jwt',
              vct: ADC_VCT,
              cryptographic_binding_methods_supported: ['jwk'],
              credential_signing_alg_values_supported: ['ES256'],
              display: [{ name: 'Agent Delegation Credential', locale: 'en-CA' }],
            },
          },
        },
      },
    };

    const key = await importJWK(privJwk, 'ES256');
    const jwt = await new SignJWT(statement)
      .setProtectedHeader({ alg: 'ES256', typ: 'entity-statement+jwt', kid: privJwk.kid })
      .sign(key);

    const outJwt = join(root, 'entity-configuration.jwt');
    const outJson = join(root, 'entity-configuration.json');
    writeFileSync(outJwt, `${jwt}\n`);
    writeFileSync(outJson, `${JSON.stringify(statement, null, 2)}\n`);

    console.log(`
Entity Configuration signed.

  entity     ${entityId}
  anchor     ${anchor}
  expires    ${new Date(exp * 1000).toISOString()}
  kid        ${privJwk.kid}

  entity-configuration.jwt    serve this at /.well-known/openid-federation
                              with Content-Type application/entity-statement+jwt
  entity-configuration.json   the same payload, readable

Registering as a subordinate needs the anchor to accept us, and Alberta's
policy_uri currently returns 404, so there is nothing published to follow.
That question is asked in the trust@alberta.ca message.
`);
  }
}
