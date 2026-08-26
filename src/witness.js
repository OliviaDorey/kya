/**
 * The witness. The part of a tartan the register does not have.
 *
 * ── Where this came from ───────────────────────────────────────────────────
 *
 * Olivia, 26 August 2026, on why a tartan is a credential: *"There are some
 * things that you can't claim unless they're truly yours. If you buy a tartan and
 * it doesn't belong to you and someone calls you on it, it is not hard to figure
 * that out."*
 *
 * Nobody stops you buying the cloth. There is no gate at the mill. The check
 * happens later, in public, performed by somebody who knows the pattern and has
 * no relationship to you at all. Everything else in this library models
 * verification as an institution: a holder presents, a verifier checks, a
 * register answers. All three are parties to the transaction. **None of them is
 * the stranger at the dance.**
 *
 * So a claim could be false, and readable as false by anyone who looked, and this
 * codebase gave that person nowhere to say so. `redress_uri` belongs to the
 * person harmed. There was no channel belonging to the person who noticed.
 *
 * ── Four rules, and each one is load-bearing ───────────────────────────────
 *
 * **1. A report is never a determination.** Recording it changes no status.
 * `revocation.js` refuses relying parties the power to destroy because a
 * caseworker who disliked an agent could otherwise end a person's authority to be
 * helped. A witness channel that moved status directly would reopen that hole to
 * the entire public. A report is an observation; only the anchor determines.
 *
 * **2. Only the anchor determines.** Three of the four bindings in the model are
 * assertions by interested parties. An operator adjudicating reports about its own
 * agents is the issuer-signs-its-own-status-list problem wearing a complaints
 * department. The anchor is the only party with nothing to gain from the answer.
 *
 * **3. The subject is always told.** A record of accusations the subject cannot
 * see is a denunciation system, whatever it is called. Every recorded report
 * produces a notice, and a test asserts it. The reporter's identity is disclosed
 * to the anchor always and to the subject only if the reporter says so — face to
 * face at a dance the caller-out is visible, but at national scale a named
 * complaint against a well-resourced operator is a different act, and the
 * asymmetry is real.
 *
 * **4. No fee and no bounty.** A fee suppresses the report. A bounty manufactures
 * them, and manufactured reports fall hardest on the operators least able to
 * answer. Nothing in this file may take a payment or pay one, and a test reads
 * the source to check.
 *
 * ── The limit, stated ──────────────────────────────────────────────────────
 *
 * A tartan cannot be worn falsely for long because the community is dense and
 * knows each other. At national scale it is not dense. A register **substitutes**
 * for that density; it does not improve on it. This file is the substitute's thin
 * half, and it is worse than a room full of people who know the pattern.
 */

export const FINDING = {
  UPHELD: 'upheld',                 // the claim was false
  NOT_UPHELD: 'not-upheld',         // the claim held up
  INCONCLUSIVE: 'inconclusive',     // could not be established either way
};

/** What the report is about. Closed list: an observation, not a grievance form. */
export const OBSERVATION = {
  NOT_THEIRS: 'not-theirs',         // presenting a card or claim that is not this agent's
  BEYOND_AUTHORITY: 'beyond-authority', // acting outside what the delegation permits
  UNDISCLOSED: 'undisclosed',       // not disclosing that it is an agent
  NO_ACCOUNTABLE: 'no-accountable', // no reachable accountable human
};

function problemsWith(r) {
  const out = [];
  if (!r.subject_agent_id) out.push('subject_agent_id is required: which agent was observed');
  if (!Object.values(OBSERVATION).includes(r.observation)) {
    out.push(`observation must be one of: ${Object.values(OBSERVATION).join(', ')}`);
  }
  if (!r.observed_at) out.push('observed_at is required: when this was seen, not when it was filed');
  if (!r.what) out.push('what is required: what the observer saw, in their own words');
  if (!r.reporter?.id) {
    out.push(
      'reporter.id is required. The anchor always knows who reported; anonymity to the anchor '
      + 'makes a report unanswerable and makes the channel trivial to flood.',
    );
  }
  if (r.reward !== undefined || r.fee !== undefined) {
    out.push('a report carries no fee and no bounty. A fee suppresses reports; a bounty manufactures them.');
  }
  return out;
}

export function validate(report) {
  const problems = problemsWith(report);
  return { ok: problems.length === 0, problems };
}

/**
 * Build a report.
 *
 * The shape is closed. An unknown field is refused rather than dropped, because
 * a guard that silently discards what it is guarding against is decoration — the
 * first version of this function accepted `{ reward: 100 }`, ignored it, and
 * passed its own test for refusing bounties.
 */
export function make({
  subject_agent_id,
  observation,
  observed_at,
  what,
  where = null,
  reporter,
  disclose_reporter_to_subject = false,
  ...rest
}) {
  const unknown = Object.keys(rest);
  if (unknown.length) {
    throw new Error(
      `refusing a report with fields this does not know: ${unknown.join(', ')}. `
      + 'A report carries no fee and no bounty. A fee suppresses reports; a bounty manufactures them, '
      + 'and manufactured reports fall hardest on the operators least able to answer.',
    );
  }
  const r = {
    subject_agent_id,
    observation,
    observed_at,
    what,
    where,
    reporter,
    disclose_reporter_to_subject,
    finding: null,
    determined_by: null,
    determined_at: null,
  };
  const { ok, problems } = validate(r);
  if (!ok) throw new Error(`refusing to record a malformed report:\n  - ${problems.join('\n  - ')}`);
  return r;
}

/**
 * What a recorded report does to the agent's standing.
 *
 * Nothing. Stated as a function so that it is a thing somebody has to edit, with
 * a test attached, rather than an absence that could be filled in by accident.
 */
export function effect() {
  return {
    status_change: null,
    reason: 'a report is an observation. Only the anchor determines, and only a determination moves anything.',
  };
}

/** The notice owed to the subject, produced for every recorded report. */
export function noticeFor(report) {
  return {
    subject_agent_id: report.subject_agent_id,
    observation: report.observation,
    observed_at: report.observed_at,
    what: report.what,
    reporter: report.disclose_reporter_to_subject ? report.reporter : null,
    // Said plainly, because "a report has been filed" reads as a finding to
    // everybody who is not a lawyer.
    standing: 'Nothing about this agent has changed. Somebody says they saw this. You may answer it.',
  };
}

/**
 * The log. Append-only in the same spirit as the registrar, and deliberately
 * separate from it: the registrar records what an operator did, this records what
 * a stranger says they saw, and merging the two would let an accusation read as a
 * fact of record.
 */
export class WitnessLog {
  constructor({ anchor }) {
    if (!anchor) throw new Error('a witness log needs an anchor: the party who may determine');
    this.anchor = anchor;
    this.reports = [];
  }

  /** Record one. Returns the report and the notice owed to the subject. */
  record(report) {
    const { ok, problems } = validate(report);
    if (!ok) throw new Error(`refusing to record a malformed report:\n  - ${problems.join('\n  - ')}`);
    const stored = { ...report, seq: this.reports.length + 1 };
    this.reports.push(stored);
    return { report: stored, notice: noticeFor(stored), effect: effect() };
  }

  /** Everything said about one agent. The subject may read this in full. */
  about(agentId) {
    return this.reports.filter((r) => r.subject_agent_id === agentId).map((r) => this.visibleToSubject(r));
  }

  /** The subject's view: everything except a reporter who did not agree to be named. */
  visibleToSubject(report) {
    return report.disclose_reporter_to_subject ? { ...report } : { ...report, reporter: null };
  }

  /** Undetermined reports. What the anchor owes an answer on. */
  open() {
    return this.reports.filter((r) => r.finding === null);
  }

  /**
   * Determine one. The anchor only.
   *
   * `by` is the party making the finding. Anyone with an interest in the answer —
   * the operator, the builder, the relying party — is refused, for the reason in
   * the header.
   */
  determine(seq, { by, finding, at, reason = null }) {
    if (by !== this.anchor) {
      throw new Error(
        `only the anchor (${this.anchor}) may determine a report; "${by}" has an interest in the answer. `
        + 'An operator adjudicating reports about its own agents is an issuer signing its own status list.',
      );
    }
    if (!Object.values(FINDING).includes(finding)) {
      throw new Error(`finding must be one of: ${Object.values(FINDING).join(', ')}`);
    }
    const r = this.reports.find((x) => x.seq === seq);
    if (!r) throw new Error(`no report ${seq}`);
    if (r.finding !== null) {
      throw new Error('this report was already determined. A second finding is a new report, not an edit.');
    }
    r.finding = finding;
    r.determined_by = by;
    r.determined_at = at;
    r.reason = reason;
    return { ...r };
  }
}
