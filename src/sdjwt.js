/**
 * SD-JWT VC, the subset this specification needs.
 *
 * Enough of RFC 9901 and SD-JWT VC to issue, present, and verify the two
 * credentials in spec/agent-identity-card-v0.1.md. Not a general SD-JWT
 * library, and deliberately not trying to be one: a smaller surface is a
 * smaller thing to get wrong, and the parts we skipped are listed at the
 * bottom of this file rather than left for someone to discover.
 */

import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, compactVerify, calculateJwkThumbprint } from 'jose';

export const SD_ALG = 'sha-256';
export const EMITTED_TYP = 'dc+sd-jwt';
export const ACCEPTED_TYP = ['dc+sd-jwt', 'vc+sd-jwt', 'sd-jwt'];

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => Buffer.from(s, 'base64url');

// jose hands back a Uint8Array. Uint8Array.toString() ignores the encoding
// argument and cheerfully returns comma-separated byte values, so every decode
// goes through here rather than through a .toString('utf8') that looks right.
const decodeJson = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));

/** Digest of a disclosure, over its ASCII base64url form. Not over the JSON. */
export function digest(disclosure) {
  return createHash('sha256').update(disclosure, 'ascii').digest('base64url');
}

/**
 * A disclosure is base64url(JSON([salt, claimName, claimValue])).
 *
 * The JSON must be serialised exactly once and never re-serialised, because the
 * digest is over the encoded string. Re-encoding through a different serialiser
 * changes the whitespace and silently breaks every digest.
 */
export function makeDisclosure(name, value, salt = b64u(randomBytes(16))) {
  return b64u(JSON.stringify([salt, name, value]));
}

export function readDisclosure(disclosure) {
  const [salt, name, value] = JSON.parse(unb64u(disclosure).toString('utf8'));
  return { salt, name, value, encoded: disclosure };
}

/**
 * Issue an SD-JWT VC.
 *
 * `selective` names the top-level claims to hide behind digests. Anything not
 * named stays in the clear. Nested selective disclosure is not supported, see
 * the limitations note.
 */
export async function issue({ payload, selective = [], privateKey, alg = 'ES256', kid, holderJwk }) {
  const clear = {};
  const disclosures = [];

  for (const [k, v] of Object.entries(payload)) {
    if (selective.includes(k)) {
      if (v === undefined) continue;
      disclosures.push(makeDisclosure(k, v));
    } else {
      clear[k] = v;
    }
  }

  const missing = selective.filter((k) => !(k in payload));
  if (missing.length) {
    throw new Error(`cannot hide claims that are not present: ${missing.join(', ')}`);
  }

  if (holderJwk) clear.cnf = { jwk: holderJwk };
  if (disclosures.length) {
    clear._sd = disclosures.map(digest).sort();   // sorted so order leaks nothing
    clear._sd_alg = SD_ALG;
  }

  const header = { alg, typ: EMITTED_TYP };
  if (kid) header.kid = kid;

  const jwt = await new SignJWT(clear).setProtectedHeader(header).sign(privateKey);
  return [jwt, ...disclosures, ''].join('~');   // trailing ~ means "no KB-JWT yet"
}

/** Split the combined format without verifying anything. */
export function parse(combined) {
  const [jwt, ...rest] = combined.split('~');
  // The last element is the KB-JWT slot. Empty means none was attached.
  const kbJwt = rest.pop() || null;
  return { jwt, disclosures: rest.filter(Boolean), kbJwt };
}

/**
 * Present a subset. The holder chooses which disclosures to forward and, where
 * the verifier requires it, signs a Key Binding JWT over what is being sent.
 */
export async function present(combined, { reveal, audience, nonce, holderKey, alg = 'ES256' }) {
  const { jwt, disclosures } = parse(combined);
  const kept = disclosures.filter((d) => reveal === undefined || reveal.includes(readDisclosure(d).name));

  if (!holderKey) return [jwt, ...kept, ''].join('~');

  const withoutKb = [jwt, ...kept, ''].join('~');
  const kb = await new SignJWT({
    aud: audience,
    nonce,
    sd_hash: createHash('sha256').update(withoutKb, 'ascii').digest('base64url'),
  })
    .setProtectedHeader({ alg, typ: 'kb+jwt' })
    .setIssuedAt()
    .sign(holderKey);

  return [jwt, ...kept, kb].join('~');
}

/**
 * Verify signature, reassemble disclosed claims, and check the Key Binding JWT
 * if one is present.
 *
 * Returns the reassembled claim set plus a `disclosed` list of the claim names
 * that arrived by disclosure, so a caller can tell an absent claim from one that
 * was withheld. Those are different facts, and conflating them is how a verifier
 * ends up treating "not shown" as "not true".
 */
export async function verify(combined, { issuerKey, audience, nonce, requireKeyBinding = false, now = Date.now() }) {
  const { jwt, disclosures, kbJwt } = parse(combined);

  const { payload: raw, protectedHeader } = await compactVerify(jwt, issuerKey)
    .then(({ payload, protectedHeader }) => ({ payload: decodeJson(payload), protectedHeader }));

  if (!ACCEPTED_TYP.includes(protectedHeader.typ)) {
    throw new Error(`unacceptable typ "${protectedHeader.typ}", expected one of ${ACCEPTED_TYP.join(', ')}`);
  }
  if (raw._sd_alg && raw._sd_alg !== SD_ALG) {
    throw new Error(`unsupported _sd_alg "${raw._sd_alg}"`);
  }

  const nowSec = Math.floor(now / 1000);
  if (raw.exp !== undefined && nowSec >= raw.exp) throw new Error('credential has expired');
  if (raw.nbf !== undefined && nowSec < raw.nbf) throw new Error('credential is not yet valid');

  const expected = new Set(raw._sd ?? []);
  const claims = { ...raw };
  delete claims._sd;
  delete claims._sd_alg;

  const disclosed = [];
  for (const d of disclosures) {
    if (!expected.has(digest(d))) {
      // An unmatched disclosure means someone attached a claim the issuer never
      // signed. Fail the whole credential rather than ignoring the extra.
      throw new Error('disclosure does not match any digest in the credential');
    }
    const { name, value } = readDisclosure(d);
    if (name in claims) throw new Error(`disclosure "${name}" collides with a cleartext claim`);
    claims[name] = value;
    disclosed.push(name);
  }

  if (requireKeyBinding || kbJwt) {
    if (!kbJwt) throw new Error('key binding required but no KB-JWT was presented');
    if (!raw.cnf?.jwk) throw new Error('KB-JWT presented but the credential carries no cnf.jwk');

    const { payload: kbRaw, protectedHeader: kbHeader } = await compactVerify(
      kbJwt,
      await importHolderJwk(raw.cnf.jwk),
    ).then(({ payload, protectedHeader }) => ({ payload: decodeJson(payload), protectedHeader }));

    if (kbHeader.typ !== 'kb+jwt') throw new Error(`KB-JWT has wrong typ "${kbHeader.typ}"`);
    if (audience !== undefined && kbRaw.aud !== audience) throw new Error('KB-JWT audience mismatch');
    if (nonce !== undefined && kbRaw.nonce !== nonce) throw new Error('KB-JWT nonce mismatch');

    const rebuilt = [jwt, ...disclosures, ''].join('~');
    const want = createHash('sha256').update(rebuilt, 'ascii').digest('base64url');
    if (kbRaw.sd_hash !== want) throw new Error('KB-JWT sd_hash does not cover what was presented');
  }

  return { claims, disclosed, header: protectedHeader, keyBound: Boolean(kbJwt) };
}

async function importHolderJwk(jwk) {
  const { importJWK } = await import('jose');
  return importJWK(jwk, jwk.alg ?? 'ES256');
}

export async function thumbprint(jwk) {
  return calculateJwkThumbprint(jwk, 'sha256');
}

/**
 * Not implemented, on purpose, and each of these is a real gap rather than an
 * oversight:
 *
 *   - Nested and array-element selective disclosure (`...` digests). Both
 *     credentials here hide only whole top-level claims.
 *   - Decoy digests. Adding them is a one-line change and the reason to wait is
 *     that a fixed decoy count leaks as much as none at all.
 *   - Type metadata resolution from `vct`. The verifier here trusts the caller
 *     to know which credential type it asked for.
 */
