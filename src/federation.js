/**
 * OpenID Federation 1.0 — the leaf-entity subset.
 *
 * Kindred needs to do two things in a federation, and only two:
 *   1. publish a signed Entity Configuration describing itself, and
 *   2. validate a trust chain from some other entity up to a trust anchor.
 *
 * Publishing statements about subordinates, metadata-policy evaluation, and the
 * /resolve endpoint all belong to trust anchors and intermediates. We are a leaf,
 * so none of that is implemented here.
 *
 * Spec: OpenID Federation 1.0 (final, 17 Feb 2026).
 */

import { importJWK, jwtVerify, decodeProtectedHeader, decodeJwt } from 'jose';

export const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';

/** Where an entity publishes the statement it signs about itself. */
export function wellKnownUrl(entityId) {
  return `${entityId.replace(/\/$/, '')}/.well-known/openid-federation`;
}

async function getJwt(url, { timeoutMs = 15000 } = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ac.signal,
      headers: { accept: 'application/entity-statement+jwt, application/jwt, */*' },
    });
    const body = (await res.text()).trim();
    if (!res.ok) {
      throw new Error(`GET ${url} returned HTTP ${res.status}`);
    }
    // A federation endpoint that is declared but not implemented tends to answer
    // with a static 404 page rather than a JWT, so check the shape, not just the code.
    if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(body)) {
      throw new Error(`GET ${url} did not return a compact JWS (got ${body.slice(0, 60)}…)`);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verify an entity statement against a specific JWK set.
 * Returns the payload, or throws with a reason a human can act on.
 */
/**
 * Some published JWK sets carry members that are present but empty, and strict
 * libraries take them literally. Alberta's trust anchor is one: its signing key
 * ships `"key_ops": []`, which reads as "this key may be used for no operation"
 * and makes verification fail, while also setting `"use": "sig"`, which says the
 * opposite. It also carries `"oth": []` and `"x5c": []` — `oth` is an RSA-only
 * parameter (RFC 7518 §6.3.2.7) and has no meaning on an EC key at all.
 *
 * We drop empty members rather than reject the key. The contradiction is theirs
 * to fix; refusing to interoperate over it would help nobody.
 */
export function sanitiseJwk(jwk) {
  const cleaned = { ...jwk };
  const quirks = [];
  for (const member of ['key_ops', 'oth', 'x5c', 'x5t', 'x5u']) {
    if (Array.isArray(cleaned[member]) && cleaned[member].length === 0) {
      delete cleaned[member];
      quirks.push(`empty "${member}"`);
    }
  }
  if (cleaned.oth !== undefined && cleaned.kty !== 'RSA') {
    delete cleaned.oth;
    quirks.push(`"oth" on a ${cleaned.kty} key`);
  }
  return { jwk: cleaned, quirks };
}

export async function verifyStatement(jwt, jwks, { expectedIssuer, expectedSubject } = {}) {
  const header = decodeProtectedHeader(jwt);
  const key = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!key) {
    throw new Error(
      `no key with kid "${header.kid}" in the supplied JWK set ` +
        `(set contains: ${(jwks.keys || []).map((k) => k.kid).join(', ') || 'nothing'})`,
    );
  }

  const { jwk, quirks } = sanitiseJwk(key);
  const publicKey = await importJWK(jwk, header.alg);
  const { payload } = await jwtVerify(jwt, publicKey, {
    typ: ENTITY_STATEMENT_TYP,
    ...(expectedIssuer ? { issuer: expectedIssuer } : {}),
    ...(expectedSubject ? { subject: expectedSubject } : {}),
  });

  return { payload, header, keyUsed: key, keyQuirks: quirks };
}

/**
 * Fetch and self-verify a trust anchor's Entity Configuration.
 *
 * A trust anchor signs its own configuration with a key published inside that
 * same configuration. That is circular on its own, which is exactly why the
 * anchor's identity has to be pinned out of band. Pass `expectedKid` or
 * `expectedThumbprints` once you know them, and this becomes a real trust root.
 */
export async function fetchTrustAnchor(entityId, { expectedKid, expectedThumbprints, trustOnFirstUse = false } = {}) {
  // Pinning is now the default and not-pinning is the thing you have to ask for
  // by name. Threat model item 13: an anchor signs its own configuration with a
  // key published inside that configuration, so an unpinned anchor is a
  // self-assertion and the whole chain below it inherits that. Making the
  // insecure path the shorter one to type is how it becomes the deployed one.
  //
  // `trustOnFirstUse` is deliberately ugly to write and returns the thumbprints
  // it saw, so the intended use is: run once, record what came back, pin it
  // thereafter.
  if (!expectedKid && !expectedThumbprints?.length && !trustOnFirstUse) {
    throw new Error(
      `refusing to fetch ${entityId} unpinned. A trust anchor signs its own Entity Configuration ` +
        'with a key published inside it, so without a pin this establishes nothing and every ' +
        'credential verified beneath it inherits that. Pass expectedKid or expectedThumbprints. ' +
        'If you are bootstrapping and do not yet know them, pass trustOnFirstUse: true, record ' +
        'the thumbprints it returns, and pin them from then on.',
    );
  }

  const url = wellKnownUrl(entityId);
  const jwt = await getJwt(url);
  const unverified = decodeJwt(jwt);

  if (unverified.iss !== unverified.sub) {
    throw new Error(
      `${url} is not a self-issued Entity Configuration (iss ${unverified.iss} != sub ${unverified.sub})`,
    );
  }
  if (!unverified.jwks?.keys?.length) {
    throw new Error(`${url} carries no jwks, so nothing can be verified against it`);
  }

  const { payload, header, keyQuirks } = await verifyStatement(jwt, unverified.jwks, {
    expectedIssuer: entityId,
    expectedSubject: entityId,
  });

  if (expectedKid && header.kid !== expectedKid) {
    throw new Error(
      `trust anchor signed with kid "${header.kid}" but "${expectedKid}" was pinned. ` +
        `Either they rotated keys or this is not the anchor you think it is.`,
    );
  }

  const { calculateJwkThumbprint } = await import('jose');
  const thumbprints = await Promise.all(
    (payload.jwks?.keys ?? []).map((k) => calculateJwkThumbprint(sanitiseJwk(k), 'sha256').catch(() => null)),
  );

  if (expectedThumbprints?.length) {
    const matched = thumbprints.some((t) => t && expectedThumbprints.includes(t));
    if (!matched) {
      throw new Error(
        `trust anchor ${entityId} published keys ${thumbprints.filter(Boolean).join(', ')} and none of the ` +
          `pinned thumbprints ${expectedThumbprints.join(', ')} were among them. Either they rotated ` +
          'keys or this is not the anchor you think it is, and those two need different responses.',
      );
    }
  }

  return {
    entityId,
    jwt,
    payload,
    header,
    jwks: payload.jwks,
    url,
    keyQuirks,
    thumbprints: thumbprints.filter(Boolean),
    // Surfaced so an unpinned bootstrap run cannot be mistaken for a pinned one
    // by anything downstream that only looks at whether the call succeeded.
    pinned: Boolean(expectedKid || expectedThumbprints?.length),
  };
}

/**
 * Resolve the key an issuer is actually entitled to sign credentials with.
 *
 * Threat model item 6, and priority 2: `aic.verify` verified against whatever
 * key the caller handed it, and the federation code that could establish which
 * key is legitimate sat in the same repository, unconnected to the credential
 * path. A signature check against an unvetted key answers "was this signed by
 * the key you gave me", which is a question nobody needed answered.
 *
 * The key comes from the **superior's statement about the subordinate**, never
 * from the subordinate's own self-published configuration. That distinction is
 * the entire value of a federation: an entity's claims about itself prove
 * nothing, and the statement its anchor signs about it proves everything.
 */
export async function resolveIssuerKeys(anchor, issuerEntityId) {
  const chain = await validateTrustChain(anchor, issuerEntityId);
  if (!chain.valid) {
    throw new Error(
      `cannot resolve keys for ${issuerEntityId}: its trust chain to ${anchor.entityId} is not valid ` +
        `(${chain.problems.join('; ')})`,
    );
  }

  const keys = chain.statement.payload.jwks?.keys ?? [];
  if (!keys.length) {
    throw new Error(
      `${anchor.entityId} signs a statement about ${issuerEntityId} that carries no jwks, so the ` +
        'federation names no key this issuer may sign with.',
    );
  }

  const { importJWK: imp } = await import('jose');
  const imported = [];
  for (const jwk of keys) {
    const clean = sanitiseJwk(jwk);
    try {
      imported.push({ jwk: clean, key: await imp(clean, clean.alg ?? 'ES256') });
    } catch {
      // A key the federation publishes that this library cannot import is worth
      // reporting rather than silently dropping, but it must not stop the ones
      // that do work, or one bad key takes down a whole issuer.
    }
  }
  if (!imported.length) throw new Error(`no usable signing key for ${issuerEntityId}; ${keys.length} published and none importable`);

  return { issuer: issuerEntityId, anchor: anchor.entityId, keys: imported, pinnedAnchor: anchor.pinned === true, chain };
}

/** List an anchor's immediate subordinates. */
export async function listSubordinates(anchor) {
  const endpoint = anchor.payload.metadata?.federation_entity?.federation_list_endpoint;
  if (!endpoint) throw new Error('trust anchor publishes no federation_list_endpoint');
  const res = await fetch(endpoint, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`list endpoint returned HTTP ${res.status}`);
  return res.json();
}

/**
 * Fetch the statement a superior signs about one of its subordinates.
 * This is the link that actually carries trust; the subordinate's own
 * self-signed configuration proves nothing by itself.
 */
export async function fetchSubordinateStatement(anchor, subjectEntityId) {
  const endpoint = anchor.payload.metadata?.federation_entity?.federation_fetch_endpoint;
  if (!endpoint) throw new Error('trust anchor publishes no federation_fetch_endpoint');

  const url = `${endpoint}?sub=${encodeURIComponent(subjectEntityId)}`;
  const jwt = await getJwt(url);

  const { payload, header } = await verifyStatement(jwt, anchor.jwks, {
    expectedIssuer: anchor.entityId,
    expectedSubject: subjectEntityId,
  });

  return { jwt, payload, header, url };
}

/**
 * Validate a one-hop trust chain: subject → trust anchor.
 *
 * One hop is the whole chain in Alberta's federation today, because the anchor
 * has no intermediates. If they add one later this needs to walk authority_hints.
 */
export async function validateTrustChain(anchor, subjectEntityId) {
  const statement = await fetchSubordinateStatement(anchor, subjectEntityId);

  const now = Math.floor(Date.now() / 1000);
  const problems = [];
  if (statement.payload.exp && statement.payload.exp < now) problems.push('subordinate statement has expired');
  if (statement.payload.iat && statement.payload.iat > now + 300) problems.push('subordinate statement is issued in the future');

  // Constraints on the anchor limit what a leaf is permitted to be.
  const allowed = anchor.payload.constraints?.allowed_leaf_entity_types;
  const declared = Object.keys(statement.payload.metadata || {});
  const permitted = allowed ? declared.filter((t) => allowed.includes(t)) : declared;
  const notPermitted = allowed ? declared.filter((t) => !allowed.includes(t)) : [];

  return {
    valid: problems.length === 0,
    problems,
    anchor: anchor.entityId,
    subject: subjectEntityId,
    entityTypes: declared,
    permittedEntityTypes: permitted,
    unpermittedEntityTypes: notPermitted,
    allowedByAnchor: allowed || null,
    statement,
  };
}
