/**
 * Chained delegation. Principal → agent → sub-agent → third-party service.
 *
 * Section 6 said "chain per Delegate SD-JWT and mirror the chain in the RFC 8693
 * `act` claim", pinned to a draft that expires in October, and left it there.
 * This is the mechanism, written so the claim set does not depend on which
 * chaining draft wins. See spec/revocation-and-chains.md section C.
 *
 * The cross-boundary property, which is the whole reason this exists:
 *
 *   link n+1 must be signed by the key committed to in link n's
 *   delegate.cnf_thumbprint
 *
 * A verifier trusts exactly one thing from outside the chain — the issuer of
 * link 0, the person's wallet, whose standing comes from the federation anchor.
 * Every subsequent signing key is named in advance by its parent, so the
 * verifier authenticates each hop using material it has already verified. It
 * never needs a prior relationship with the principal, the intermediary, or
 * anybody in between. That is what lets a navigator at a settlement agency act
 * for a client at a provincial office that has heard of neither of them.
 *
 * Everything here narrows and nothing widens, and a link that widens is
 * rejected rather than clamped, because silently trimming hides a bug in
 * whoever built the chain and they are the party who needs to know.
 */

import { compactVerify, importJWK } from 'jose';
import { thumbprint, parse as parseSd } from './sdjwt.js';
import { validate as validateAdc, permits } from './adc.js';
import { actionsFor } from './capability.js';

/**
 * Three hops. Principal → agent → sub-agent → service.
 *
 * Not derived from anything. It is the smallest number that covers the real
 * case, and the reasons it is not larger are in section C of the design note:
 * availability compounds and the person pays for it, every hop is another party
 * who can misbehave inside scope, a chain a person cannot hold in their head is
 * not consent, and verification cost is linear in depth while the verifier pays
 * it. A deployment that needs four changes this constant deliberately and says
 * why.
 */
export const MAX_HOPS = 3;

/** Constraints that narrow by getting smaller. */
const NUMERIC_CONSTRAINTS = ['max_submissions', 'max_requests', 'max_documents'];

/** Constraints that narrow by getting earlier. */
const DATE_CONSTRAINTS = ['valid_until'];

/**
 * The chain claim a link carries. Link 0 carries depth 0 and no parent.
 *
 * `root_thumbprint` lets a verifier and a register identify the tree a link
 * belongs to without walking it, which is what makes cascade cheap.
 */
export function chainClaim({ depth, parentThumbprint = null, rootThumbprint = null }) {
  if (!Number.isInteger(depth) || depth < 0) throw new Error('chain depth must be a non-negative integer');
  if (depth === 0 && parentThumbprint) throw new Error('the root of a chain has no parent');
  if (depth > 0 && !parentThumbprint) throw new Error(`a link at depth ${depth} must name its parent`);
  return {
    depth,
    parent_thumbprint: parentThumbprint,
    root_thumbprint: depth === 0 ? null : rootThumbprint,
  };
}

/** The thumbprint of a link, over its issuer JWT. Same construction as cardThumbprint. */
export async function linkThumbprint(presented) {
  const { createHash } = await import('node:crypto');
  const jwt = typeof presented === 'string' ? presented.split('~')[0] : presented;
  return createHash('sha256').update(jwt, 'ascii').digest('base64url');
}

/**
 * Does the child narrow the parent, on every axis.
 *
 * Six axes, and one of them runs the opposite way to the other five.
 * `requires_human_approval` narrows by *growing*: more actions needing approval
 * is a tighter grant. A sub-agent that drops an approval requirement its parent
 * carried has widened authority while every set it carries got smaller, which is
 * the mistake this function exists to catch and the one an implementer makes.
 */
export function narrowingBreaches(child, parent) {
  const out = [];

  const parentCaps = new Set((parent.authorization_details ?? []).map((d) => d.capability));
  const parentActions = new Set((parent.authorization_details ?? []).flatMap((d) => d.actions ?? []));

  for (const d of child.authorization_details ?? []) {
    if (!parentCaps.has(d.capability)) {
      out.push(
        `this link grants the capability "${d.capability}", which the delegation above it does not hold. ` +
          'A chain narrows and never widens.',
      );
      continue;
    }

    const beyond = (d.actions ?? []).filter((a) => !parentActions.has(a));
    if (beyond.length) {
      out.push(
        `this link grants ${beyond.join(', ')}, which the delegation above it does not hold. ` +
          'A chain narrows and never widens.',
      );
    }

    // The action must also still be inside what the capability itself permits.
    // Narrowing against the parent does not excuse a link from the rule every
    // delegation obeys.
    const permitted = actionsFor([d.capability]);
    const impossible = (d.actions ?? []).filter((a) => !permitted.includes(a));
    if (impossible.length) {
      out.push(`this link grants ${impossible.join(', ')}, which the capability "${d.capability}" never permits`);
    }

    const parentDetail = (parent.authorization_details ?? []).find((p) => p.capability === d.capability);

    for (const key of NUMERIC_CONSTRAINTS) {
      const mine = d.constraints?.[key];
      const theirs = parentDetail?.constraints?.[key];
      if (mine === undefined) continue;
      if (theirs === undefined) continue;
      if (mine > theirs) {
        out.push(
          `this link allows ${key} of ${mine} where the delegation above it allows ${theirs}. ` +
            'A chain narrows and never widens.',
        );
      }
    }

    for (const key of DATE_CONSTRAINTS) {
      const mine = d.constraints?.[key];
      const theirs = parentDetail?.constraints?.[key];
      if (mine === undefined || theirs === undefined) continue;
      if (Date.parse(mine) > Date.parse(theirs)) {
        out.push(
          `this link runs ${key} to ${mine} where the delegation above it ends ${theirs}. ` +
            'A chain narrows and never widens.',
        );
      }
    }

    // The axis that narrows by growing. Checked per action so that a link
    // dropping approval on one action cannot hide behind carrying it on another.
    const parentNeeds = new Set(parentDetail?.constraints?.requires_human_approval ?? []);
    const mineNeeds = new Set(d.constraints?.requires_human_approval ?? []);
    for (const action of parentNeeds) {
      if ((d.actions ?? []).includes(action) && !mineNeeds.has(action)) {
        out.push(
          `the delegation above requires a human to approve "${action}" and this link does not. ` +
            'Approval requirements may be added going down a chain and never dropped: fewer approvals is ' +
            'more authority, however much smaller the rest of the grant got.',
        );
      }
    }
  }

  if (child.exp > parent.exp) {
    out.push(
      `this link runs until ${new Date(child.exp * 1000).toISOString()} and the delegation above it ends ` +
        `${new Date(parent.exp * 1000).toISOString()}. A chain narrows and never widens.`,
    );
  }

  return out;
}

/**
 * Structural checks on a chain: depth, connectedness, and the key path.
 *
 * `parentThumbprints[i]` is the recomputed thumbprint of link i, supplied by the
 * caller because it is computed over the wire form and this function takes
 * claim sets. Absent, the parent-thumbprint check is reported as unchecked
 * rather than skipped in silence, on the same principle as bindingBreaches: an
 * unchecked binding is a failed binding.
 */
export function structureBreaches(links, { thumbprints } = {}) {
  const out = [];

  if (!Array.isArray(links) || links.length === 0) {
    return ['a chain must have at least one link'];
  }

  if (links.length > MAX_HOPS) {
    out.push(
      `this chain is ${links.length} hops and the maximum is ${MAX_HOPS}. ` +
        'Each hop is another status list a verifier must reach, another party who can misbehave inside ' +
        'scope, and another party between the person and the thing acting in their name.',
    );
  }

  links.forEach((link, i) => {
    const chain = link.chain;
    if (!chain) {
      out.push(`link ${i} carries no chain claim, so its position cannot be checked`);
      return;
    }
    if (chain.depth !== i) {
      out.push(`link ${i} claims depth ${chain.depth}. A link cannot be moved up or down a chain.`);
    }

    if (i === 0) {
      if (chain.parent_thumbprint) out.push('link 0 is the root and must not name a parent');
      return;
    }

    const parent = links[i - 1];

    // The chain must actually connect: the party this link delegates *from*
    // must be the party the link above delegated *to*. Without this, two valid
    // chains for two different agents could be spliced.
    if (link.delegator?.agent_id && parent.delegate?.agent_id && link.delegator.agent_id !== parent.delegate.agent_id) {
      out.push(
        `link ${i} is granted by ${link.delegator.agent_id} but the delegation above it was granted to ` +
          `${parent.delegate.agent_id}. The chain does not connect.`,
      );
    }

    if (chain.root_thumbprint && links[0].chain && thumbprints) {
      if (chain.root_thumbprint !== thumbprints[0]) {
        out.push(`link ${i} names a root this chain does not have`);
      }
    }

    if (!thumbprints) {
      out.push(
        `the parent binding on link ${i} could not be checked: no link thumbprints were supplied. ` +
          'Pass them as "thumbprints" from verifyChain(). An unchecked binding is a failed binding.',
      );
    } else if (chain.parent_thumbprint !== thumbprints[i - 1]) {
      out.push(
        `link ${i} names parent ${chain.parent_thumbprint} and the link above it is ${thumbprints[i - 1]}. ` +
          'A link is not transferable between chains.',
      );
    }
  });

  return out;
}

/**
 * Validate a whole chain of claim sets.
 *
 * Every link is a delegation in its own right and gets the full section 6
 * treatment, then the chain rules on top. `aic` is the Agent Identity Card at
 * the *root*, which bounds the whole tree: nothing anywhere down a chain may
 * exceed what the card the person delegated to actually holds.
 */
export function validateChain(links, { aic, thumbprints, now = Date.now() } = {}) {
  const problems = [];

  problems.push(...structureBreaches(links, { thumbprints }));

  (links ?? []).forEach((link, i) => {
    const { problems: own } = validateAdc(link, { aic: i === 0 ? aic : undefined, now });
    problems.push(...own.map((p) => `link ${i}: ${p}`));
    if (i > 0) {
      problems.push(...narrowingBreaches(link, links[i - 1]).map((p) => `link ${i}: ${p}`));
    }
  });

  return { ok: problems.length === 0, problems };
}

/**
 * Verify a chain cryptographically, hop by hop.
 *
 * `rootIssuerKey` is the only key that comes from outside. It is the person's
 * wallet key, and its standing comes from the federation trust anchor. Every
 * later key is taken from the parent's `delegate.cnf_thumbprint` and confirmed
 * against the key that actually signed the child, which is the property that
 * makes this verifiable across an organisational boundary.
 */
export async function verifyChain(presented, { rootIssuerKey, aic, now = Date.now() }) {
  if (!Array.isArray(presented) || presented.length === 0) {
    throw new Error('a chain must have at least one link');
  }
  if (presented.length > MAX_HOPS) {
    throw new Error(
      `refusing to verify a ${presented.length}-hop chain; the maximum is ${MAX_HOPS}. ` +
        'See spec/revocation-and-chains.md section C for why depth is capped rather than warned about.',
    );
  }
  if (!aic) {
    throw new Error(
      'verifyChain requires the root Agent Identity Card as "aic". The card bounds the whole tree, ' +
        'so a chain verified without one has not been checked against the outer bound at all.',
    );
  }

  const claims = [];
  const thumbprints = [];
  let expectedSignerJwk = null;

  for (let i = 0; i < presented.length; i += 1) {
    const wire = presented[i];
    const { jwt } = parseSd(wire);

    let key;
    if (i === 0) {
      key = rootIssuerKey;
    } else {
      if (!expectedSignerJwk) {
        throw new Error(`link ${i - 1} commits to no signing key, so link ${i} cannot be authenticated`);
      }
      key = await importJWK(expectedSignerJwk, expectedSignerJwk.alg ?? 'ES256');
    }

    let payload;
    try {
      const result = await compactVerify(jwt, key);
      payload = JSON.parse(Buffer.from(result.payload).toString('utf8'));
    } catch (cause) {
      throw new Error(
        `link ${i} was not signed by the key the delegation above it committed to. ` +
          'A chain authenticates each hop with material already verified; a hop that does not ' +
          'match is not a weaker chain, it is a different one.',
        { cause },
      );
    }

    // Confirm the parent named this exact key, not merely a key that works.
    if (i > 0) {
      const actual = await thumbprint(expectedSignerJwk);
      const promised = claims[i - 1].delegate?.cnf_thumbprint;
      if (actual !== promised) {
        throw new Error(`link ${i - 1} promised signing key ${promised} and the key used was ${actual}`);
      }
    }

    const nowSec = Math.floor(now / 1000);
    if (payload.exp !== undefined && nowSec >= payload.exp) throw new Error(`link ${i} has expired`);

    claims.push(payload);
    thumbprints.push(await linkThumbprint(wire));
    expectedSignerJwk = payload.delegate?.cnf_jwk ?? payload.cnf?.jwk ?? null;
  }

  const { ok, problems } = validateChain(claims, { aic, thumbprints, now });
  if (!ok) {
    throw new Error(`this delegation chain is not conforming:\n  - ${problems.join('\n  - ')}`);
  }

  return { claims, thumbprints, hops: claims.length };
}

/**
 * What the chain as a whole authorises. The intersection, not the union.
 *
 * The last link is the narrowest by construction, so this is the last link's
 * grant. It is a function rather than a property read so that a caller reaching
 * for "what may this thing do" cannot accidentally read the root's grant, which
 * is the widest one in the tree and the wrong answer.
 */
export function effectiveGrant(links) {
  const last = links[links.length - 1];
  return {
    actions: [...new Set((last.authorization_details ?? []).flatMap((d) => d.actions ?? []))],
    capabilities: [...new Set((last.authorization_details ?? []).map((d) => d.capability))],
    expires: Math.min(...links.map((l) => l.exp)),
    hops: links.length,
  };
}

/** Does the chain, as a whole, authorise this action. */
export function chainPermits(links, action) {
  return permits(links[links.length - 1], action);
}

/**
 * What the person is shown about a chain they are at the root of.
 *
 * Plain language is normative and it has to survive chaining, which is one of
 * the four reasons depth is capped. A person who cannot describe what they
 * agreed to has not agreed to it.
 */
export function explainChainToPerson(links) {
  const grant = effectiveGrant(links);
  const lines = [`You authorised help, and it is being carried out by ${links.length} step${links.length === 1 ? '' : 's'}.`];

  links.forEach((link, i) => {
    const who = link.delegate?.agent_id ?? 'an agent';
    lines.push(
      i === 0
        ? `  You asked ${who} to help you.`
        : `  ${links[i - 1].delegate?.agent_id ?? 'that agent'} passed part of it to ${who}.`,
    );
  });

  lines.push(`In the end, what can actually be done is: ${grant.actions.join(', ')}.`);
  lines.push('Each step can do less than the one before it. None of them can do more.');
  lines.push(`All of it ends ${new Date(grant.expires * 1000).toISOString().slice(0, 10)}.`);
  lines.push('You can stop the whole thing at any time, however far along it has travelled.');
  return lines.join('\n');
}
