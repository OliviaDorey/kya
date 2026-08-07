/**
 * Government of Alberta profile.
 *
 * Alberta is genuinely SD-JWT plus OpenID Federation, which is the right stack.
 * At the credential layer they run a profile of their own that is not conformant
 * with SD-JWT VC or the IETF status list. None of that is a criticism: their
 * wallet shipped in August 2025, before several of these specs were final. It
 * does mean everything Alberta-specific belongs behind this boundary so it can
 * be deleted when they converge.
 *
 * Verified against their live endpoints on 6 August 2026.
 */

export const ALBERTA_TRUST_ANCHOR = 'https://account.alberta.ca/dts';

/** Entity types their anchor will admit as leaves. */
export const ALLOWED_LEAF_ENTITY_TYPES = [
  'alberta_wallet_issuer',
  'openid_credential_issuer',
  'openid_verifier',
  'wallet_provider',
];

/** typ header values seen in the wild that we accept on ingest. */
export const ACCEPTED_SD_JWT_TYP = ['sd-jwt', 'vc+sd-jwt', 'dc+sd-jwt'];

/** What we emit ourselves. Current spec, not their legacy value. */
export const EMITTED_SD_JWT_TYP = 'dc+sd-jwt';

/**
 * Alberta puts status list pointers at the top level of the credential.
 * The IETF shape nests them under `status.status_list`. Normalise on the way in.
 */
export function normaliseStatusClaim(claims) {
  const s = claims?.status;
  if (!s) return null;
  if (s.status_list?.uri) {
    return { uri: s.status_list.uri, index: s.status_list.idx, shape: 'ietf' };
  }
  if (s.status_list_uri) {
    return { uri: s.status_list_uri, index: s.status_list_index, shape: 'alberta' };
  }
  return null;
}

/** Pull the human-readable bits out of a verified subordinate statement. */
export function summariseIssuer(payload) {
  const md = payload.metadata || {};
  const issuer = md.alberta_credential_issuer || md.openid_credential_issuer;
  if (!issuer) return null;

  const out = {};
  if (issuer.organization_name) out['organization'] = issuer.organization_name;
  const creds = issuer.credential_configurations_supported || issuer.credentials || issuer.credential_types;
  if (creds) {
    const list = Array.isArray(creds) ? creds : Object.values(creds);
    const shapes = list
      .map((c) => [c.typ ?? c.vct ?? c.type, c.credential_format ?? c.format].filter(Boolean).join(' as '))
      .filter(Boolean);
    if (shapes.length) out['credentials'] = shapes.join('; ');
    const rev = list.map((c) => c.revocation_method).filter(Boolean);
    if (rev.length) out['revocation'] = [...new Set(rev)].join(', ');
    // proof_type appears both as a string and as a keyed object depending on the
    // credential, so flatten either shape to readable names.
    const proofs = list.flatMap((c) => {
      const p = c.proof_type ?? c.proof_types;
      if (!p) return [];
      if (typeof p === 'string') return [p];
      if (Array.isArray(p)) return p.map((x) => (typeof x === 'string' ? x : x?.type)).filter(Boolean);
      return Object.keys(p);
    });
    if (proofs.length) out['holder proof'] = [...new Set(proofs)].join(', ');
  }
  return Object.keys(out).length ? out : null;
}

/**
 * The gaps between Alberta's live profile and the current specifications.
 * Written out because a bid that names these is a bid that read the deployment
 * rather than the press release.
 */
export function describeDeviations() {
  return [
    {
      what: 'Credential media type',
      alberta: 'typ is "sd-jwt" or "vc+sd-jwt"',
      spec: 'SD-JWT VC draft-18 §3.2.1 says typ MUST be "dc+sd-jwt"; "vc+sd-jwt" is transitional only',
    },
    {
      what: 'Revocation / status pointer',
      alberta: 'flat { status_list_uri, status_list_index }, method "status-list-jti"',
      spec: 'IETF Token Status List nests { status: { status_list: { uri, idx } } } — not wire-compatible',
    },
    {
      what: 'Holder binding proof',
      alberta: '"secure-qr-jwt" and "ckapp" (a compact binary attestation)',
      spec: 'SD-JWT VC expects a Key Binding JWT (KB-JWT)',
    },
    {
      what: 'Selective disclosure marking',
      alberta: 'a bespoke "sd": true/false annotation in the credential JSON Schema',
      spec: 'no standard schema annotation exists; disclosure is carried in the SD-JWT itself',
    },
    {
      what: 'Federation endpoints',
      alberta: '/fetch and /list serve; /resolve and the advertised policy_uri both return 404',
      spec: 'OpenID Federation 1.0 defines all four; a leaf must therefore do its own chain validation',
    },
  ];
}
