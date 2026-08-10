#!/usr/bin/env node
/**
 * Generate the three key pairs a deployment needs and write them where the
 * other scripts expect to find them.
 *
 *   issuer  signs Agent Identity Cards, and is the key the federation knows about
 *   wallet  signs Agent Delegation Credentials, and belongs to the person
 *   agent   holds the credential, and signs Key Binding JWTs
 *
 * Private keys go to keys/ and keys/ is gitignored. If that ever stops being
 * true this script is the wrong place to find out, so it checks.
 */

import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const keyDir = join(root, 'keys');

const ALG = 'ES256';
const ROLES = ['issuer', 'wallet', 'agent'];

function assertIgnored() {
  const gitignore = join(root, '.gitignore');
  const body = existsSync(gitignore) ? readFileSync(gitignore, 'utf8') : '';
  if (!/^keys\/?$/m.test(body)) {
    writeFileSync(gitignore, `${body}${body.endsWith('\n') || body === '' ? '' : '\n'}keys/\n`);
    console.log('  added keys/ to .gitignore');
  }
}

const force = process.argv.includes('--force');

mkdirSync(keyDir, { recursive: true });
assertIgnored();

console.log(`\nGenerating ${ALG} key pairs in keys/\n`);

for (const role of ROLES) {
  const privPath = join(keyDir, `${role}.private.jwk.json`);
  const pubPath = join(keyDir, `${role}.public.jwk.json`);

  if (existsSync(privPath) && !force) {
    console.log(`  ${role.padEnd(7)} already exists, left alone. Use --force to replace it.`);
    continue;
  }

  const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(pub, 'sha256');

  Object.assign(pub, { alg: ALG, use: 'sig', kid });
  Object.assign(priv, { alg: ALG, use: 'sig', kid });

  writeFileSync(privPath, `${JSON.stringify(priv, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(pubPath, `${JSON.stringify(pub, null, 2)}\n`);
  console.log(`  ${role.padEnd(7)} kid ${kid}`);
}

console.log(`
Note on what we did NOT write: no "key_ops": [], no empty "x5c", no "oth" on an
EC key. Alberta's live anchor carries all three and it stops strict verifiers
cold. See src/federation.js sanitiseJwk() and the report in the outreach set.
`);
