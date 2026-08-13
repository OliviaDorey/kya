/**
 * The Agency 2026 demonstration harness.
 *
 *   /            the walkthrough
 *   /caseworker  minute 3, what an Alberta office sees
 *   /withdraw    minute 6, citizen-facing revocation, no login
 *   /receipt     what she is handed afterwards
 *   /slide       minute 7, the honest slide, meant to be projected
 *   /status      the published status list, as a signed JWT
 *   /health      what commit is running
 *
 * Everything runs locally against generated keys. Nothing here talks to Alberta;
 * that half is `npm run verify:alberta` in the parent package, and keeping them
 * separate means a network problem in the room cannot take the demo down.
 */

import express from 'express';
import * as adc from '../src/adc.js';
import * as aic from '../src/aic.js';
import * as status from '../src/status.js';
import * as revocation from '../src/revocation.js';
import { CAPABILITIES } from '../src/capability.js';
import { boot, world, signWithdrawal, presentTo } from './state.js';
import * as views from './views.js';

const app = express();

/**
 * Headers, even on a demonstration.
 *
 * Not because this is exposed, but because a government identity team will open
 * developer tools during the demo, and a page served without them says something
 * about how we build that no slide can undo. There is no external script, style,
 * font or image anywhere in this app, so the policy can be as tight as it reads.
 */
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), interest-cohort=()');
  res.setHeader('Cache-Control', 'no-store');
  res.removeHeader('X-Powered-By');
  next();
});

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
const PORT = process.env.PORT || 4173;
const VERIFIER = process.env.VERIFIER_ID || 'https://caseworker.alberta.ca';

await boot();

app.get('/', (req, res) => res.send(views.start({ delegation: world.delegation })));

/**
 * Minute 3. Verifies for real on every load rather than rendering a fixture,
 * so that a broken credential shows as broken on stage instead of looking fine.
 */
app.get('/caseworker', async (req, res, next) => {
  try {
    const nonce = `n-${Date.now().toString(36)}`;
    const { presentedCard, presentedDelegation } = await presentTo(VERIFIER, nonce);

    const vCard = await aic.verify(presentedCard, {
      issuerKey: world.keys.issuer.publicKey,
      audience: VERIFIER,
      nonce,
    });

    let adcClaims;
    let verifyError = null;
    try {
      const vDel = await adc.verify(presentedDelegation, {
        walletKey: world.keys.wallet.publicKey,
        aic: vCard.card,
        // The binding, recomputed from the card that just verified. Without
        // this the delegation is checked against a card object rather than
        // against the card actually presented, which is no check at all.
        aicThumbprint: vCard.thumbprint,
        audience: VERIFIER,
        nonce,
      });
      adcClaims = vDel.adc;
    } catch (err) {
      verifyError = err;
      adcClaims = world.delegation;
    }

    // Fail closed. A status list we cannot read means not in force, every time.
    const token = await status.publish({
      list: world.list,
      uri: world.LIST_URI,
      issuer: 'https://kya.thekindredagency.com',
      privateKey: world.keys.issuer.privateKey,
      ttl: world.register.freshnessSeconds,
    });
    const s = await status.fetchStatus(token, { issuerKey: world.keys.issuer.publicKey, idx: world.IDX });
    let statusLine = status.inForce(s);
    if (verifyError) statusLine = { ok: false, reason: verifyError.message.split('\n')[0] };
    statusLine.checked = new Date().toLocaleTimeString('en-CA');

    world.register.notePresentation(world.CREDENTIAL_ID, VERIFIER, Math.floor(Date.now() / 1000));
    world.presentations.unshift({ at: Date.now(), verifier: VERIFIER });

    res.send(views.caseworker({
      card: vCard.card,
      explained: { capabilities: CAPABILITIES },
      adcClaims,
      statusLine,
      presentations: world.presentations,
    }));
  } catch (err) {
    next(err);
  }
});

app.get('/withdraw', (req, res) =>
  res.send(views.withdraw({ delegation: world.delegation, revoked: Boolean(world.receipt) })));

/**
 * Minute 6.
 *
 * The person's key signs the request. No account, no government login, no email
 * round trip. Section 7 requires this be reachable without signing in to
 * anything, and the whole point is that it works at the moment somebody most
 * needs it, which is not a moment to be resetting a password.
 */
app.post('/withdraw', async (req, res, next) => {
  try {
    if (world.receipt) return res.redirect('/receipt');

    const jws = await signWithdrawal();
    const proof = await revocation.verifyRevocationRequest(jws, {
      delegatorJwk: world.walletJwk,
      credentialId: world.CREDENTIAL_ID,
    });
    if (!proof.ok) return res.status(403).send(`<p>${proof.reason}</p>`);

    const result = await revocation.revoke(world.register, {
      credentialId: world.CREDENTIAL_ID,
      notify: async ({ verifier, revokedAt }) => {
        // Best effort, logged. A real deployment posts to the verifier's
        // notification endpoint; here we record that we did.
        world.notifications.push({ verifier, revokedAt });
      },
    });

    world.receipt = result.receipt;
    res.redirect('/receipt');
  } catch (err) {
    next(err);
  }
});

app.get('/receipt', (req, res) => {
  if (!world.receipt) return res.redirect('/withdraw');
  res.send(views.receipt({
    receipt: world.receipt,
    explained: revocation.explainReceipt(world.receipt),
  }));
});

app.get('/slide', (req, res) => res.send(views.slide()));

/** The published status list. A verifier fetches the whole list, not one entry. */
app.get('/status', async (req, res, next) => {
  try {
    const token = await status.publish({
      list: world.list,
      uri: world.LIST_URI,
      issuer: 'https://kya.thekindredagency.com',
      privateKey: world.keys.issuer.privateKey,
      ttl: world.register.freshnessSeconds,
    });
    res.type('application/statuslist+jwt').send(token);
  } catch (err) {
    next(err);
  }
});

app.get('/health', (req, res) =>
  res.json({
    status: 'ok',
    revoked: Boolean(world.receipt),
    freshness_seconds: world.register.freshnessSeconds,
    notifications: world.notifications.length,
    build: { commit: process.env.GIT_COMMIT ?? null, node: process.version },
  }));

/** Reset between rehearsals without restarting the process. */
app.post('/reset', async (req, res) => {
  await boot();
  res.redirect('/');
});

app.use((err, req, res, next) => {
  // Stack traces go to the operator's console, never to the page. On a stage in
  // front of a Minister, a wall of internals is the worst possible failure mode
  // and the one most likely to be photographed.
  console.error(err);
  res.status(500).send(
    '<p style="font:17px/1.5 Georgia,serif;padding:2rem">Something went wrong. ' +
    'The detail is in the server log.</p>',
  );
});

app.listen(PORT, () => {
  console.log(`\n  The Agency demonstration\n  http://localhost:${PORT}\n`);
  console.log('  /caseworker  minute 3, what the office sees');
  console.log('  /withdraw    minute 6, she stops it');
  console.log('  /slide       minute 7, project this one\n');
});
