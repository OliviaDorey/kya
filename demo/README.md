# The Agency 2026 demonstration harness

The three pieces of the seven minutes that do not depend on Alberta answering
anything: the caseworker screen, citizen-facing revocation, and the honest slide.

```bash
npm install
npm start          # http://localhost:4173
```

| Route | Minute | What it is |
|---|---|---|
| `/` | | The walkthrough |
| `/caseworker` | 3 | What an Alberta office sees when Steward presents itself |
| `/withdraw` | 6 | She stops it. No login, no account, no reason required |
| `/receipt` | 6 | What she is handed afterwards |
| `/slide` | 7 | The honest slide. Project this one |
| `/status` | | The published status list, signed, `ttl` 300s |
| `/health` | | Whether it has been revoked yet, and what commit is running |

`POST /reset` puts everything back between rehearsals without restarting.

## What is real here and what is not

**Real.** Every credential is genuinely issued and genuinely verified on each
page load, not rendered from a fixture. The caseworker screen re-verifies
signatures, key binding, audience, attenuation and revocation status every time
you load it, so a broken credential shows as broken on stage rather than looking
fine. Revocation really updates the status list, really notifies, and really
produces the receipt.

**Not real.** The keys are generated at boot, so this is our own trust anchor
standing in for Alberta's. The federation half, verified against their live
anchor, is `npm run verify:alberta` in the parent package. They are deliberately
separate: a network problem in the room cannot take the demonstration down.

## Three things to check before the rehearsal

**The slide contains claims in the past tense.** `views.js` carries a TRUTH
CHECK comment listing each one and the date it becomes true. A slide about
honesty containing something that has not happened yet would be the worst
possible thing to put on that screen. Delete any that has not.

**The caseworker page must never name what she is going through.** The
regression check is one line:

```bash
curl -s http://localhost:4173/caseworker | grep -i "handicapped\|assured income\|disab\|aish"
```

Empty output is a pass. Anything else means capability scoping has regressed and
the demo does not run.

**Load it on a phone.** A caseworker may well be on one.
