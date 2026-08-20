/**
 * The Gaia-X bridge.
 *
 * Written 20 August 2026, for spec/gaia-x-participant-profile-v0.1.md.
 *
 * ── What this is, and what it deliberately is not ──────────────────────────
 *
 * Gaia-X self-descriptions and Agent Identity Cards are the same W3C data model
 * in two serialisations: Gaia-X expresses claims as JSON-LD over an RDF
 * ontology, this specification expresses them as SD-JWT. That difference is a
 * serialisation and a signature envelope, not a semantic gap, so a mapping is
 * ordinary standards engineering rather than a research problem.
 *
 * This module is the *mapping*. It is deterministic, total in both directions
 * for the fields it covers, and it round-trips. What it is not, and must never
 * become, is a conformance authority: nothing here asserts that a mapped
 * credential is trustworthy, and nothing here signs anything. The party that
 * wrote the mapping must not be the party that marks it. Gaia-X Hub Canada
 * publishes the profile and runs the test; this file is the homework.
 *
 * ── The modelling decision, which is the only interesting part ─────────────
 *
 * An AI agent is not a legal person, so it is not a Gaia-X Participant. It is a
 * thing a legal person made and operates, which in the Gaia-X ontology is a
 * Virtual Resource and specifically a SoftwareResource. So:
 *
 *   builder / operator  ->  gx:LegalPerson       (two of them, where they differ)
 *   the agent itself    ->  gx:SoftwareResource  (a subclass of gx:VirtualResource)
 *   the delegation      ->  kya:Delegation       (an extension; see below)
 *
 * Gaia-X has no concept of a natural person mandating a piece of software to
 * act for them against a third party. That is the whole subject of the
 * delegation credential and there is nothing to map it onto, so the profile
 * declares it as an extension class rather than bending an existing one.
 * Bending gx:consent to carry it would have been available and would have been
 * wrong: consent to process data about me is not authority to act as me.
 *
 * ── Three things this module refuses to do ─────────────────────────────────
 *
 * gx:VirtualResource makes copyrightOwnedBy, license and policy mandatory. An
 * Agent Identity Card carries the first, can derive the third, and does not
 * carry the second at all. So toGaiaX() requires the licence to be supplied by
 * the caller and throws without it, rather than defaulting to something
 * plausible. Inventing a licence claim in a signed document is precisely the
 * failure this specification exists to prevent, and a mapping that quietly
 * fills a mandatory field is worse than one that stops.
 */

/**
 * Namespaces.
 *
 * The Gaia-X core context is still moving. The Trust Framework text read on
 * 20 August 2026 says the context "will be published together with the
 * machine-executable implementation of the Trust Framework at
 * https://w3id.org/gaia-x/core/ with the release of this specification", and
 * deployments in the field currently point at the trusted shape registry
 * instead. Both are recorded here, the profile names which one a given
 * ecosystem uses, and neither is hardcoded into the mapping logic.
 */
export const CONTEXT = {
  VC: 'https://www.w3.org/2018/credentials/v1',
  GX_CORE: 'https://w3id.org/gaia-x/core/',
  GX_SHAPES: 'https://registry.gaia-x.eu/v1/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#',
  KYA: 'https://agentcredential.ca/gaia-x/v1#',
};

export const PROFILE_VERSION = '0.1.0';

/** Claim paths this mapping covers. Anything outside it survives in kya:unmapped. */
export const MAPPED_PATHS = Object.freeze([
  'vct', 'iss', 'iat', 'exp', 'nbf',
  'agent', 'builder', 'operator', 'accountable',
  'model', 'capabilities', 'conduct', 'assurance', 'status', 'cnf',
]);

/** ISO 3166-2 country code out of a KYA jurisdiction like "CA-NS". */
function countryOf(jurisdiction) {
  if (typeof jurisdiction !== 'string' || !jurisdiction) return undefined;
  return jurisdiction.split('-')[0].toUpperCase();
}

/** Stable key order, so the same input serialises to the same bytes every time. */
function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((acc, k) => {
      if (value[k] !== undefined) acc[k] = ordered(value[k]);
      return acc;
    }, {});
  }
  return value;
}

function legalPerson(party, { id }) {
  if (!party?.legal_name) return undefined;
  const p = {
    '@id': id,
    '@type': 'gx:LegalPerson',
    'gx:legalName': party.legal_name,
    // Gaia-X addresses are country-level: gx:countryCode is ISO 3166-2 alpha2.
    // A KYA jurisdiction is subdivision-level, "CA-NS" rather than "CA", and the
    // subdivision is load-bearing — it is which registry the builder is
    // incorporated in. So the full value rides in the extension and the Gaia-X
    // field carries the country it narrows to. Found by the round-trip test,
    // which is the entire reason the round-trip test exists.
    'kya:jurisdiction': party.jurisdiction,
    'gx:headquartersAddress': { '@type': 'gx:Address', 'gx:countryCode': countryOf(party.jurisdiction) },
    'gx:legalAddress': { '@type': 'gx:Address', 'gx:countryCode': countryOf(party.jurisdiction) },
  };
  // Absent rather than null. An omitted claim is honest; a null one asserts a
  // shape and then declines to fill it. This is question eight, in code.
  if (party.registry_id) {
    p['gx:registrationNumber'] = { '@type': 'gx:registrationNumber', 'gx:local': party.registry_id };
  }
  return p;
}

/**
 * Capability ceiling -> gx:policy.
 *
 * A Gaia-X policy is an access/usage rule expressed in a DSL. The capability
 * ceiling is exactly that: the closed set of actions this agent may ever be
 * delegated. Expressing it as an ODRL-shaped permission set is the honest
 * translation, and it means a Gaia-X-native verifier reads the ceiling as a
 * policy without being taught anything about agents.
 */
function policyFromCapabilities(capabilities = []) {
  return [{
    '@type': 'odrl:Set',
    'odrl:permission': capabilities.map((c) => ({
      '@type': 'odrl:Permission',
      'odrl:action': c,
    })),
    'kya:closedVocabulary': true,
  }];
}

function capabilitiesFromPolicy(policy = []) {
  const set = policy.find((p) => p?.['kya:closedVocabulary']);
  const perms = set?.['odrl:permission'] ?? [];
  return perms.map((p) => p['odrl:action']).filter((a) => typeof a === 'string');
}

/**
 * Agent Identity Card -> Gaia-X self-description.
 *
 * @param {object} card         a validated Agent Identity Card claim set
 * @param {object} opts
 * @param {string|string[]} opts.license   SPDX identifier(s) or document URL(s). REQUIRED.
 * @param {string} [opts.context]          which Gaia-X context this ecosystem uses
 * @param {string} [opts.id]               the resource @id; defaults to the agent urn
 */
export function toGaiaX(card, { license, context = CONTEXT.GX_SHAPES, id } = {}) {
  if (!card || typeof card !== 'object') throw new TypeError('card is required');

  const licenses = license === undefined ? [] : (Array.isArray(license) ? license : [license]);
  if (licenses.length === 0 || licenses.some((l) => typeof l !== 'string' || !l.trim())) {
    throw new Error(
      'license is required and must be supplied by the caller. gx:VirtualResource makes it '
      + 'mandatory and the Agent Identity Card does not carry it. This mapping will not invent one.',
    );
  }
  if (!card.builder?.legal_name) {
    throw new Error('builder.legal_name is required; gx:copyrightOwnedBy cannot be derived without it');
  }

  const builderId = card.builder?.uri ?? `urn:kya:builder:${encodeURIComponent(card.builder.legal_name)}`;
  const operatorSame = !card.operator || card.operator.legal_name === card.builder.legal_name;
  const operatorId = operatorSame
    ? builderId
    : (card.operator.uri ?? `urn:kya:operator:${encodeURIComponent(card.operator.legal_name)}`);

  const subject = {
    '@id': id ?? card.agent?.id,
    '@type': ['gx:SoftwareResource', 'kya:AutonomousAgent'],

    // gx:VirtualResource, mandatory triple
    'gx:copyrightOwnedBy': [builderId],
    'gx:license': licenses,
    'gx:policy': policyFromCapabilities(card.capabilities),

    // gx:Resource, optional
    'gx:name': card.agent?.name,
    'gx:maintainedBy': [operatorId],

    // the extension, which is where everything that makes this an agent lives
    'kya:profileVersion': PROFILE_VERSION,
    'kya:vct': card.vct,
    'kya:agentId': card.agent?.id,
    'kya:agentVersion': card.agent?.version,
    'kya:builder': legalPerson(card.builder, { id: builderId }),
    'kya:operator': operatorSame ? undefined : legalPerson(card.operator, { id: operatorId }),
    'kya:accountablePerson': card.accountable
      ? {
        '@type': 'kya:AccountablePerson',
        'kya:role': card.accountable.role,
        'kya:contact': card.accountable.contact,
        'kya:redressUri': card.accountable.redress_uri,
      }
      : undefined,
    'kya:conduct': card.conduct
      ? {
        'kya:disclosesAi': card.conduct.discloses_ai,
        'kya:actsWithoutApproval': card.conduct.acts_without_approval,
        'kya:retainsAfterRevocation': card.conduct.retains_after_revocation,
      }
      : undefined,
    'kya:model': card.model,
    'kya:assurance': card.assurance,
    'kya:status': card.status,
    'kya:confirmationKey': card.cnf,
  };

  // Anything the card carries that this version does not map. Carried rather
  // than dropped, so a round trip is lossless even when the card is ahead of
  // the profile.
  const unmapped = Object.fromEntries(
    Object.entries(card).filter(([k]) => !MAPPED_PATHS.includes(k)),
  );
  if (Object.keys(unmapped).length) subject['kya:unmapped'] = unmapped;

  const vc = {
    '@context': [CONTEXT.VC, context, { kya: CONTEXT.KYA, odrl: 'http://www.w3.org/ns/odrl/2/' }],
    type: ['VerifiableCredential', 'gx:SoftwareResource'],
    id: `${card.iss ?? 'urn:kya'}#${card.agent?.id ?? 'agent'}`,
    issuer: card.iss,
    issuanceDate: card.iat ? new Date(card.iat * 1000).toISOString() : undefined,
    expirationDate: card.exp ? new Date(card.exp * 1000).toISOString() : undefined,
    credentialSubject: subject,
  };
  return ordered(vc);
}

/**
 * Gaia-X self-description -> Agent Identity Card.
 *
 * The inverse of toGaiaX for every field it maps. Fields Gaia-X requires and
 * the Card does not have (license, copyrightOwnedBy) are dropped on the way
 * back, which is why round-tripping is tested Card -> Gaia-X -> Card and not
 * the other way: the Gaia-X direction is a widening.
 */
export function fromGaiaX(vc) {
  const s = vc?.credentialSubject;
  if (!s) throw new TypeError('credentialSubject is required');

  const lp = (p) => (p
    ? {
      legal_name: p['gx:legalName'],
      jurisdiction: p['kya:jurisdiction'] ?? p['gx:legalAddress']?.['gx:countryCode'],
      registry_id: p['gx:registrationNumber']?.['gx:local'],
      uri: typeof p['@id'] === 'string' && /^https?:/.test(p['@id']) ? p['@id'] : undefined,
    }
    : undefined);

  const card = {
    vct: s['kya:vct'],
    iss: vc.issuer,
    iat: vc.issuanceDate ? Math.floor(Date.parse(vc.issuanceDate) / 1000) : undefined,
    exp: vc.expirationDate ? Math.floor(Date.parse(vc.expirationDate) / 1000) : undefined,
    agent: {
      id: s['kya:agentId'] ?? s['@id'],
      name: s['gx:name'],
      version: s['kya:agentVersion'],
    },
    builder: lp(s['kya:builder']),
    operator: lp(s['kya:operator'] ?? s['kya:builder']),
    accountable: s['kya:accountablePerson']
      ? {
        role: s['kya:accountablePerson']['kya:role'],
        contact: s['kya:accountablePerson']['kya:contact'],
        redress_uri: s['kya:accountablePerson']['kya:redressUri'],
      }
      : undefined,
    model: s['kya:model'],
    capabilities: capabilitiesFromPolicy(s['gx:policy']),
    conduct: s['kya:conduct']
      ? {
        discloses_ai: s['kya:conduct']['kya:disclosesAi'],
        acts_without_approval: s['kya:conduct']['kya:actsWithoutApproval'],
        retains_after_revocation: s['kya:conduct']['kya:retainsAfterRevocation'],
      }
      : undefined,
    assurance: s['kya:assurance'],
    status: s['kya:status'],
    cnf: s['kya:confirmationKey'],
    ...(s['kya:unmapped'] ?? {}),
  };

  for (const k of Object.keys(card)) if (card[k] === undefined) delete card[k];
  if (card.builder) for (const k of Object.keys(card.builder)) {
    if (card.builder[k] === undefined) delete card.builder[k];
  }
  if (card.operator) for (const k of Object.keys(card.operator)) {
    if (card.operator[k] === undefined) delete card.operator[k];
  }
  if (card.agent) for (const k of Object.keys(card.agent)) {
    if (card.agent[k] === undefined) delete card.agent[k];
  }
  return card;
}

/**
 * The conformance probe the profile is judged by.
 *
 * A credential issued in one form must verify in the other. "Verify" here means
 * the claim set survives the round trip with every always-disclosed field
 * intact, because those are the fields a verifier is never allowed to have to
 * ask for. Cryptographic verification is not in scope: the two ecosystems sign
 * differently, and a re-signed credential is a new credential, which the
 * profile says in terms.
 *
 * Returns { ok, findings[] } rather than throwing, because a conformance run
 * reports everything wrong at once.
 */
export function roundTrips(card, { license = 'Apache-2.0', context } = {}) {
  const findings = [];
  let back;
  try {
    back = fromGaiaX(toGaiaX(card, { license, context }));
  } catch (e) {
    return { ok: false, findings: [{ path: '-', problem: `mapping threw: ${e.message}` }] };
  }

  const ALWAYS = ['agent', 'builder', 'accountable', 'conduct', 'capabilities', 'status', 'cnf'];
  for (const path of ALWAYS) {
    if (card[path] === undefined) continue;
    const a = JSON.stringify(ordered(card[path]));
    const b = JSON.stringify(ordered(back[path]));
    if (a !== b) findings.push({ path, problem: 'always-disclosed field did not survive the round trip', was: a, now: b });
  }
  for (const path of ['vct', 'iss', 'iat', 'exp']) {
    if (card[path] !== undefined && card[path] !== back[path]) {
      findings.push({ path, problem: 'header claim did not survive the round trip', was: card[path], now: back[path] });
    }
  }
  return { ok: findings.length === 0, findings };
}

/** Byte-stable serialisation, so "deterministic" is testable rather than asserted. */
export function canonical(vc) {
  return JSON.stringify(ordered(vc));
}
