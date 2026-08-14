/**
 * Conformance probes. The wallet is tested, not trusted.
 *
 * ── Why this is in the open repository ─────────────────────────────────────
 *
 * The gift boundary in spec/revocation-and-chains.md §B gives away the
 * conformance *tests* and retains only the *attestation* that a named
 * deployment passed them on a named date. A conformance suite nobody can read
 * certifies nothing, and DIF's KYA-OS already publishes its conformance levels
 * openly, so closing these would be both futile and bad faith. What Kindred
 * retains is the signed statement by an assessor who can be held to it.
 *
 * ── What these probes are for ──────────────────────────────────────────────
 *
 * Two properties in this specification cannot be verified from a single
 * credential, no matter how carefully it is checked, because they are
 * statements about a *set*:
 *
 *   unlinkability   two verifiers holding presentations from the same person
 *                   must not be able to join their records on any field
 *   honest derivation
 *                   a wallet asserting pairwise subjects must actually derive
 *                   them, and no verifier can tell from one credential
 *
 * A verifier sees one credential and cannot see the set. An auditor can ask for
 * the set. That asymmetry is the whole reason conformance testing exists here,
 * and it is why "a lying wallet passes" is a testing gap rather than a
 * cryptographic one.
 */

/** Fields that are always disclosed, and so are always available to correlate on. */
const IGNORE_PATHS = [
  // Varies by construction and carries no identity: timestamps and the credential's
  // own type. Flagging them would bury the real findings in noise.
  'iat', 'exp', 'nbf', 'vct', '_sd_alg',
];

/** Flatten a claim set to leaf paths, so nothing hides inside an object. */
function leaves(obj, prefix = '', out = new Map()) {
  for (const [k, v] of Object.entries(obj ?? {})) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (IGNORE_PATHS.includes(path)) continue;
    if (v && typeof v === 'object' && !Array.isArray(v)) leaves(v, path, out);
    else out.set(path, Array.isArray(v) ? JSON.stringify(v) : v);
  }
  return out;
}

/**
 * The unlinkability probe.
 *
 * `mintFor(verifierId)` must return the claim set a wallet would issue for that
 * verifier, from **one** consent act — the real case, a person granting once and
 * dealing with several offices. Anything identical across two or more of them is
 * a join key for those two offices, whatever else the credential gets right.
 *
 * Deliberately reports every shared field rather than the first. A wallet author
 * fixing one correlator at a time will ship while three remain.
 */
/**
 * ── Why a second person is required ────────────────────────────────────────
 *
 * A field shared across verifiers is only a *correlator* if it also differs
 * between people. `cnf.jwk.kty` is `"EC"` on every credential ever issued: it is
 * shared across every verifier and identifies nobody. `purpose_commitment` is
 * also shared across verifiers, and is unique to one person's one grant, so two
 * offices holding it have joined their files exactly.
 *
 * Reporting both as "shared" buries the second in the first. The first run of
 * this probe returned eighteen findings, of which about half were constants
 * like `"EC"` and `"en-CA"`, and a wallet author reading that list would
 * reasonably have concluded the probe was noise and stopped reading.
 *
 * So `mintForOther` mints the same set for a **different person**, and a field
 * is only reported as a correlator when it is constant across verifiers *and*
 * differs between the two people. That is the experiment that answers the actual
 * question, and it needs no hand-maintained list of which fields are low
 * entropy — which would have been wrong within a release anyway.
 */
export async function probeUnlinkability({ mintFor, mintForOther, verifiers }) {
  if (typeof mintFor !== 'function') throw new Error('probeUnlinkability needs mintFor(verifierId)');
  if (!Array.isArray(verifiers) || verifiers.length < 2) {
    throw new Error('unlinkability is a property of a set; probe at least two verifiers');
  }

  const sets = [];
  for (const v of verifiers) sets.push({ verifier: v, claims: leaves(await mintFor(v)) });

  // The second person. Optional, and its absence is reported rather than
  // silently downgrading the result to the noisy version.
  const otherSets = [];
  if (typeof mintForOther === 'function') {
    for (const v of verifiers) otherSets.push({ verifier: v, claims: leaves(await mintForOther(v)) });
  }
  const differsBetweenPeople = (path) => {
    if (!otherSets.length) return null;   // unknown, not false
    const mine = sets.map((s) => String(s.claims.get(path)));
    const theirs = otherSets.map((s) => String(s.claims.get(path)));
    return mine.some((v, i) => v !== theirs[i]);
  };

  const paths = new Set(sets.flatMap((s) => [...s.claims.keys()]));
  const shared = [];
  const varied = [];
  const harmless = [];

  for (const path of paths) {
    const values = sets.map((s) => s.claims.get(path));
    const present = values.filter((v) => v !== undefined);
    if (present.length < 2) continue;

    const distinct = new Set(present.map((v) => String(v)));
    if (distinct.size === present.length) { varied.push(path); continue; }

    const identifying = differsBetweenPeople(path);
    if (identifying === false) {
      // Shared across verifiers and identical between people: a constant like
      // "EC" or "en-CA". It links nobody to anybody.
      harmless.push(path);
      continue;
    }

    shared.push({
      path,
      value: String(present[0]).slice(0, 48),
      identifying,   // true = confirmed correlator, null = no second person supplied
      verifiers: sets.map((s) => s.verifier),
      consequence:
        identifying === true
          ? `any two of these offices can join their files on ${path}, which is unique to this person`
          : `${path} is constant across verifiers; supply mintForOther to establish whether it identifies anyone`,
    });
  }

  const confirmed = shared.filter((s) => s.identifying === true);
  return {
    ok: shared.length === 0,
    shared: shared.sort((a, b) => a.path.localeCompare(b.path)),
    correlators: confirmed.map((s) => s.path),
    varied: varied.sort(),
    harmless: harmless.sort(),
    differentialRun: otherSets.length > 0,
    verifiers,
    verdict:
      shared.length === 0
        ? 'No always-disclosed field links this person across these verifiers.'
        : `${confirmed.length} confirmed correlator(s)` +
          (otherSets.length ? '' : ' (differential not run: pass mintForOther)') +
          `, and ${harmless.length} shared-but-harmless constant(s). A pairwise subject alongside a ` +
          'confirmed correlator is decorative: the correlation moves to the neighbouring field.',
  };
}

/**
 * The honest-derivation probe. Answers the question no verifier can.
 *
 * A wallet claiming pairwise subjects is asked for several, addressed to
 * different verifiers. If any two match, it is reusing one identifier and
 * stamping each copy with the right audience — which passes every runtime check
 * in this repository and is exactly the gap recorded as threat model item 22.
 *
 * **What this does not close.** It is a test-time answer, not a runtime one. A
 * wallet can behave while being assessed and reuse subjects in production, and
 * nothing here detects that. The mitigation is unannounced re-assessment, which
 * is a register's job rather than a protocol's, and is the reason the retained
 * asset is an operated register rather than a document.
 */
export async function probePairwiseHonesty({ mintFor, verifiers }) {
  const subs = [];
  for (const v of verifiers) {
    const claims = await mintFor(v);
    subs.push({ verifier: v, sub: claims?.delegator?.sub, audience: claims?.delegator?.sub_audience, asserted: claims?.delegator?.pairwise === true });
  }

  const problems = [];
  const seen = new Map();
  for (const s of subs) {
    if (!s.asserted) {
      problems.push(`${s.verifier}: delegator.pairwise is not asserted`);
      continue;
    }
    if (s.audience !== s.verifier) {
      problems.push(`${s.verifier}: sub_audience is "${s.audience}", so this subject was minted for somebody else`);
    }
    if (seen.has(s.sub)) {
      problems.push(
        `${s.verifier} and ${seen.get(s.sub)} were given the SAME subject while both claiming to be ` +
          'pairwise. The wallet is reusing one identifier and stamping each copy with the right audience.',
      );
    }
    seen.set(s.sub, s.verifier);
  }

  return {
    ok: problems.length === 0,
    problems,
    probed: subs.length,
    proves:
      'that this wallet derived distinct subjects while being watched. Not that it does so in ' +
      'production, which only unannounced re-assessment reaches.',
  };
}

/** Human-readable, because a conformance report nobody reads certifies nothing. */
export function explain(result) {
  if (result.ok) return `PASS. ${result.verdict ?? 'No problems found.'}`;
  const lines = [`FAIL. ${result.verdict ?? ''}`.trim()];
  for (const s of result.shared ?? []) lines.push(`  ${s.path}: ${s.consequence}`);
  for (const p of result.problems ?? []) lines.push(`  ${p}`);
  return lines.join('\n');
}
