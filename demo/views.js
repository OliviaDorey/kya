/**
 * Every page the demonstration shows, as functions returning HTML.
 *
 * No template engine and no client framework, because this runs on a stage in
 * front of a Minister and the number of things that can fail should be as close
 * to zero as it can get. One stylesheet, no fonts to fetch, no build step.
 */

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const CSS = `
:root {
  --ink: #17211c; --paper: #fbfaf7; --line: #d9d5cc;
  --green: #1f6b45; --green-soft: #eaf3ee;
  --red: #9b2c2c; --red-soft: #fbeceb;
  --amber: #8a6300; --amber-soft: #fdf4e0;
  --muted: #5f6b64;
}
@media (prefers-color-scheme: dark) {
  :root { --ink:#eef1ee; --paper:#121714; --line:#2f3a34; --green:#7ad3a3; --green-soft:#16281f;
          --red:#f2a5a0; --red-soft:#2a1817; --amber:#e6c169; --amber-soft:#2a2314; --muted:#9aa8a0; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--paper); color:var(--ink);
  font: 17px/1.55 ui-serif, Georgia, 'Times New Roman', serif; }
main { max-width: 46rem; margin: 0 auto; padding: 2.5rem 1.5rem 5rem; }
h1 { font-size: 2rem; line-height:1.15; margin: 0 0 .3rem; }
h2 { font-size: 1.3rem; margin: 2.2rem 0 .6rem; font-weight: 600; }
.sub { color: var(--muted); margin: 0 0 2rem; }
.card { border:1px solid var(--line); border-radius:10px; padding:1.3rem 1.5rem; margin:1.2rem 0; background:transparent; }
.card.good { border-color:var(--green); background:var(--green-soft); }
.card.bad  { border-color:var(--red);   background:var(--red-soft); }
.card.note { border-color:var(--amber); background:var(--amber-soft); }
.verdict { font-size:1.35rem; font-weight:700; margin:0 0 .4rem; }
.verdict.good { color:var(--green); } .verdict.bad { color:var(--red); }
dl { display:grid; grid-template-columns: 12rem 1fr; gap:.45rem 1.2rem; margin:0; }
dt { color:var(--muted); } dd { margin:0; }
ul.plain { list-style:none; padding:0; margin:.4rem 0; }
ul.plain li { padding:.35rem 0 .35rem 1.6rem; position:relative; }
ul.plain li::before { content:'✓'; position:absolute; left:0; color:var(--green); font-weight:700; }
ul.plain li.stop::before { content:'✋'; }
.withheld { color:var(--muted); font-style:italic; }
button, .btn { font:inherit; font-size:1.05rem; padding:.75rem 1.4rem; border-radius:8px;
  border:1px solid var(--ink); background:var(--ink); color:var(--paper); cursor:pointer; text-decoration:none;
  display:inline-block; }
button.quiet { background:transparent; color:var(--ink); }
button.danger { background:var(--red); border-color:var(--red); color:#fff; }
nav { border-bottom:1px solid var(--line); padding:.7rem 1.5rem; font-size:.95rem; }
nav a { color:var(--muted); text-decoration:none; margin-right:1.4rem; }
nav a:hover, nav a.on { color:var(--ink); text-decoration:underline; }
code { font: .92em ui-monospace, Menlo, Consolas, monospace; word-break:break-all; }
.stamp { font-size:.9rem; color:var(--muted); margin-top:2.5rem; border-top:1px solid var(--line); padding-top:1rem; }
table { border-collapse:collapse; width:100%; margin:.8rem 0; }
th, td { text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
.overflow { overflow-x:auto; }

/* A caseworker may well be on a phone, and a fixed two-column definition list
   overflows the moment the screen is narrower than the columns. Stack it. */
@media (max-width: 34rem) {
  dl { grid-template-columns: 1fr; gap:.1rem; }
  dt { margin-top:.7rem; font-size:.92rem; }
  main { padding: 1.75rem 1.1rem 4rem; }
  h1 { font-size: 1.6rem; }
  nav { padding:.7rem 1.1rem; }
  nav a { margin-right:1rem; display:inline-block; }
  .card { padding:1rem 1.1rem; }
}
`;

function page(title, body, { nav = true, active = '' } = {}) {
  const links = [
    ['/', 'Start'],
    ['/caseworker', 'What the office sees'],
    ['/withdraw', 'Withdraw'],
    ['/slide', 'The honest slide'],
  ];
  return `<!doctype html><html lang="en-CA"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body>
${nav ? `<nav>${links.map(([h, t]) => `<a href="${h}"${h === active ? ' class="on"' : ''}>${esc(t)}</a>`).join('')}</nav>` : ''}
<main>${body}</main></body></html>`;
}

// ─────────────────────────────────────────────────────────── the caseworker

/**
 * Minute 3, and the screen the whole technical argument rests on.
 *
 * Rules for this page, in order of importance:
 *   who is accountable is never below the fold
 *   what is withheld is shown as withheld, never omitted
 *   nothing on it names what she is going through
 */
export function caseworker({ card, explained, adcClaims, statusLine, presentations }) {
  const ok = statusLine.ok;
  const rows = (adcClaims.authorization_details ?? [])
    .map((d) => `<li>${esc(explained.capabilities[d.capability] ?? d.capability)}</li>`)
    .join('');
  const approval = [
    ...new Set((adcClaims.authorization_details ?? []).flatMap((d) => d.constraints?.requires_human_approval ?? [])),
  ];

  return page('Agent presenting — Alberta caseworker view', `
<h1>An agent is acting for someone</h1>
<p class="sub">Presented ${esc(new Date().toLocaleString('en-CA'))} · checked against
<code>account.alberta.ca/dts</code></p>

<div class="card ${ok ? 'good' : 'bad'}">
  <p class="verdict ${ok ? 'good' : 'bad'}">${ok ? 'Authority in force' : 'Not in force'}</p>
  <p style="margin:0">${esc(statusLine.reason)}</p>
</div>

<h2>Who you are dealing with</h2>
<div class="card">
  <dl>
    <dt>Agent</dt><dd><strong>${esc(card.agent.name)}</strong> version ${esc(card.agent.version)}</dd>
    <dt>Built by</dt><dd>${esc(card.builder.legal_name)}, ${esc(card.builder.jurisdiction)}</dd>
    <dt>Operated by</dt><dd>${esc(card.operator?.legal_name ?? card.builder.legal_name)}</dd>
    <dt>Accountable</dt><dd><strong>${esc(card.accountable.role)}</strong><br>
      ${esc(card.accountable.contact)}<br>
      <a href="${esc(card.accountable.redress_uri)}">${esc(card.accountable.redress_uri)}</a></dd>
    <dt>Discloses it is AI</dt><dd>${esc(card.conduct.discloses_ai)}, and cannot be configured otherwise</dd>
    <dt>Model</dt><dd>${card.model ? esc(`${card.model.family} ${card.model.version}, hosted in ${card.model.hosted_in}`) : '<span class="withheld">withheld on this presentation</span>'}</dd>
  </dl>
</div>

<h2>What this person has authorised</h2>
<div class="card">
  <ul class="plain">${rows}</ul>
  ${approval.length ? `<ul class="plain"><li class="stop">Must return to them for approval before it can ${esc(approval.join(' or '))}</li></ul>` : ''}
  <dl style="margin-top:1rem">
    <dt>Authority ends</dt><dd>${esc(new Date(adcClaims.exp * 1000).toLocaleDateString('en-CA'))}</dd>
    <dt>They can withdraw</dt><dd>at any time, without signing in to anything of ours</dd>
  </dl>
</div>

<div class="card note">
  <p style="margin:0"><strong>Why this does not say what they are applying for.</strong>
  They wrote a purpose in their own words and it is withheld from you by design. You already know
  which office you are. Everyone else who handles this credential does not need to.
  They can choose to show you the sentence, and you can check it against the signed commitment
  <code>${esc(String(adcClaims.purpose_commitment ?? '').slice(0, 16))}…</code> to be sure it has not been changed.</p>
</div>

<h2>How this was checked</h2>
<div class="card">
  <ul class="plain">
    <li>Both credentials are signed, and the signatures verify</li>
    <li>The agent proved it holds the key the credentials were issued to</li>
    <li>This presentation was made to you specifically and cannot be replayed elsewhere</li>
    <li>The delegation grants no more than the agent's own card allows</li>
    <li>The delegation was granted against <em>this</em> card and <em>this</em> key, and both
        thumbprints were recomputed here rather than taken on trust</li>
    <li>Revocation status checked ${esc(statusLine.checked)}; if we could not reach it, this reads "not in force"</li>
  </ul>
</div>

${presentations.length > 1 ? `<h2>Earlier presentations</h2><div class="card overflow"><table>
<tr><th>When</th><th>To</th></tr>
${presentations.slice(0, 8).map((p) => `<tr><td>${esc(new Date(p.at).toLocaleTimeString('en-CA'))}</td><td>${esc(p.verifier)}</td></tr>`).join('')}
</table></div>` : ''}

<p class="stamp">Kindred Agent Credentials · KYA v1.0 · specification and implementation given away
under CC BY 4.0 and Apache-2.0 with an irrevocable patent covenant</p>
`, { active: '/caseworker' });
}

// ─────────────────────────────────────────────────────────── the person

export function withdraw({ delegation, revoked }) {
  if (revoked) {
    return page('Withdrawn', `
<h1>Done. Steward can no longer act for you.</h1>
<p class="sub">You can grant it again whenever you want to.</p>
<p><a class="btn" href="/receipt">See what happened</a></p>
`, { active: '/withdraw' });
  }

  return page('Withdraw', `
<h1>Do you want Steward to stop?</h1>
<p class="sub">You do not need to sign in to anything, and you do not need to give a reason.</p>

<div class="card">
  <p style="margin:0 0 .6rem"><strong>Right now you have asked Steward to:</strong></p>
  <p style="margin:0">${esc(delegation.purpose)}</p>
  <p class="withheld" style="margin:.8rem 0 0">Those are your words. Nobody at any office has been shown them.</p>
</div>

<form method="post" action="/withdraw">
  <p><button class="danger" type="submit">Yes, stop Steward now</button>
  &nbsp; <a class="btn quiet" href="/" style="border-color:var(--line)">Not right now</a></p>
</form>

<div class="card note">
  <p style="margin:0">Stopping takes effect immediately. Every office that has used this
  authority will be told, and any office we cannot reach is required to treat it as stopped
  within five minutes.</p>
</div>
`, { active: '/withdraw' });
}

export function receipt({ receipt, explained }) {
  return page('Your receipt', `
<h1>Your receipt</h1>
<p class="sub">Keep this. It is proof of what you stopped and who was told.</p>

<div class="card good">
  ${explained.split('\n').map((l) => `<p style="margin:.3rem 0">${esc(l)}</p>`).join('')}
</div>

<h2>The detail, if you ever need it</h2>
<div class="card">
  <dl>
    <dt>Withdrawn on</dt><dd>${esc(new Date(receipt.revoked_at).toLocaleString('en-CA'))}</dd>
    <dt>Reason recorded</dt><dd>${esc(receipt.reason)}</dd>
    <dt>Offices told</dt><dd>${receipt.verifiers_notified.length ? receipt.verifiers_notified.map(esc).join('<br>') : 'none had used it yet'}</dd>
    <dt>Everywhere within</dt><dd>${esc(receipt.in_force_everywhere_within)}</dd>
  </dl>
</div>

<p><a class="btn" href="/caseworker">See what the office sees now</a></p>
`, { active: '/withdraw' });
}

// ─────────────────────────────────────────────────────────── minute 7

/**
 * The honest slide. Full bleed, large type, meant to be projected.
 *
 * It is the last thing shown and it is the only slide a competitor cannot copy,
 * because copying it would mean having done the work of finding their own
 * unsolved problem and publishing it first.
 *
 * ── TRUTH CHECK, and this is not optional ─────────────────────────────────
 *
 * Four claims below are stated in the past tense. A slide about honesty that
 * contains a claim which is not yet true would be the worst possible thing to
 * put on a screen in that room. Confirm every one before the rehearsal on
 * 7 October, and delete any that has not happened:
 *
 *   threat model published            due 21 Aug 2026
 *   Privacy Commissioners written to  due 28 Aug 2026
 *   DIACC and DGC submission          due 31 Oct 2026  ← after the demo, so
 *                                      say "submitted to" only once it is
 *   capability scoping shipped        done 10 Aug 2026 ✓
 */
export function slide() {
  return `<!doctype html><html lang="en-CA"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>What does not work yet</title><style>${CSS}
body { display:flex; align-items:center; justify-content:center; min-height:100vh; }
main { max-width: 60rem; padding: 3rem 2.5rem; }
h1 { font-size: clamp(2.2rem, 5vw, 3.4rem); margin:0 0 .2rem; }
.lede { font-size: clamp(1.1rem, 2vw, 1.45rem); color:var(--muted); margin:0 0 2.2rem; }
.grid { display:grid; gap:1rem; grid-template-columns: repeat(auto-fit, minmax(17rem, 1fr)); }
.grid .card { margin:0; }
.grid h3 { margin:0 0 .4rem; font-size:1.1rem; }
.grid p { margin:0; font-size:1rem; }
.foot { margin-top:2.2rem; font-size:1.05rem; }
</style></head><body><main>
<h1>What does not work yet</h1>
<p class="lede">Every vendor here has a specification. This is the slide none of them will show you.</p>

<div class="grid">
  <div class="card bad">
    <h3>The correlation problem</h3>
    <p>An agent with one stable identifier is a lifetime tracking number for the person it acts
    for. Two offices could join their files on you exactly, without either doing anything wrong.
    We have not solved it.</p>
  </div>
  <div class="card bad">
    <h3>The person who shares your house</h3>
    <p>A credential is proof that you sought help. Unlike a browser history, you cannot deny it.
    Nothing in the cryptography helps, and the threat model says so rather than implying otherwise.</p>
  </div>
  <div class="card note">
    <h3>Chained delegation</h3>
    <p>A navigator acting alongside a client. Specified, not built, waiting on a draft standard
    to settle.</p>
  </div>
</div>

<div class="card" style="margin-top:1.4rem">
  <p style="margin:0 0 .5rem"><strong>What we did instead of waiting to be asked</strong></p>
  <ul class="plain" style="margin:0">
    <li>Published the threat model, naming seven adversaries and costing five mitigations</li>
    <li>Took it to the federal and Alberta Privacy Commissioners <em>before</em> any customer</li>
    <li>Are putting the per-office identifier question to DIACC and the Digital Governance
        Council, because it belongs in a national standard rather than in one company's
        source code</li>
    <li>Shipped the one you just watched: the office never learns what she is going through</li>
  </ul>
</div>

<p class="foot"><strong>Three commitments you can check without taking our word for it.</strong>
No stable cross-office identifier in production. No sensitive word in a credential a clerk can read.
What we retain, and for how long, published before we retain it.</p>

<p class="stamp">The Kindred Agency · specification and implementation given away under CC BY 4.0 and
Apache-2.0 with an irrevocable patent covenant · agentcredential.ca</p>
</main></body></html>`;
}

export function start({ delegation }) {
  return page('The Agency demonstration', `
<h1>Seven minutes</h1>
<p class="sub">A person, a real pathway, one thing going wrong, and an honest ending.</p>

<div class="card">
  <p style="margin:0 0 .6rem"><strong>What she asked for, in her words:</strong></p>
  <p style="margin:0">${esc(delegation.purpose)}</p>
  <p class="withheld" style="margin:.8rem 0 0">This sentence stays in her wallet. No office sees it
  unless she decides to show them.</p>
</div>

<h2>Walk it</h2>
<table>
  <tr><td><strong>3</strong></td><td><a href="/caseworker">What the office sees</a> when Steward
    presents itself</td></tr>
  <tr><td><strong>6</strong></td><td><a href="/withdraw">She changes her mind</a> and stops it</td></tr>
  <tr><td><strong>7</strong></td><td><a href="/slide">The honest slide</a></td></tr>
</table>

<div class="card note">
  <p style="margin:0">Everything here runs locally with generated keys. The federation half,
  verified against Alberta's live trust anchor, is <code>npm run verify:alberta</code> in the
  parent package.</p>
</div>
`, { active: '/' });
}
