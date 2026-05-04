# OpenFRAMP V1 Project Plan

> **Status:** In active development
> **Target ship:** July 31, 2026
> **Current week:** Week 1 of approximately 13 (week of April 27, 2026)
> **Pace assumption:** 2 hours per night, 6 nights per week (~12 hrs/week, ~10 effective)
>
> **Last updated:** 2026-04-29 (Tuesday)
>
> This is the source-of-truth project plan for OpenFRAMP V1. It lives in the repo because the discipline of shipping V1 is part of what OpenFRAMP is. Every visitor sees what's done, what's in flight, and what's left.

## How this document works

Every night when you finish a session, do three things:

1. Tick any boxes you completed
2. Update the **Today's session** entry at the top of the [Daily Log](#daily-log) with what you did
3. If you blocked on something, add it to [Blockers](#blockers)

That's it. No ceremony. The discipline is showing up to the doc, not the doc itself.

Once a week (Sunday recommended), do the [Weekly Review](#weekly-review-template) — 10 minutes, structured, captured below.

---

## At-a-glance status

```
Tier A (V1-Critical):     ░░░░░░░░░░  10%  (1/10 items done)
Tier B (V1-Supporting):   ░░░░░░░░░░   0%  (0/6 items done)
Tier C (V1.5 / Polish):   ░░░░░░░░░░   0%  (0/5 items done)

Overall V1:                ▓░░░░░░░░░   5%  (1/21 items done)
```

> Update this manually when status changes. Keep it visual — easy to skim.

---

## V1 Definition of Done

V1 ships when ALL of these are true. Not "almost true." All.

- [ ] A stranger can run `git clone && docker compose up` and see the OSCAL Viewer dashboard with results
- [ ] An SSP `.docx` file goes in, an OSCAL 1.1 SSP JSON comes out
- [ ] AWS scan produces OSCAL 1.1 Assessment Results JSON with FedRAMP 20x KSI references
- [ ] Azure scan produces OSCAL 1.1 Assessment Results JSON with FedRAMP 20x KSI references
- [ ] `INSTALL.md`, `CONTRIBUTING.md`, `ARCHITECTURE.md` exist and have been verified by following them on a clean machine
- [ ] Repo has branch protection, signed commits required on main, secret scanning enabled
- [ ] At least 3 strangers (not friends, not coworkers) have successfully run the tool and opened either an issue or a star
- [ ] A 5-minute end-to-end demo video exists, recorded once
- [ ] README clearly states what V1 does and does NOT do (FedRAMP Moderate only, AWS+Azure only, etc.)
- [ ] v1.0.0 tag exists on a commit on main, with release notes

When all 10 are checked, V1 is shipped. Don't move the goalposts.

---

## Tier A — V1-Critical Path (10 items)

**Goal:** Ship the minimum viable V1 — a working pipeline a stranger can clone and use.
**Target completion:** July 1, 2026

### A1. SSP docx parser ⏳

The novel piece. Nothing else in the open-source FedRAMP space does this. This is what makes OpenFRAMP a *pipeline* and not just a scanner.

- [ ] Identify the canonical FedRAMP SSP docx template structure (FedRAMP PMO publishes the Word template)
- [ ] Catalog the sections that need to extract (control implementations, system info, contacts, boundary diagram references)
- [ ] Choose docx library (`python-docx` is the obvious pick)
- [ ] Build extractor for system characteristics section
- [ ] Build extractor for control implementation statements (the longest section — 300+ controls)
- [ ] Build extractor for points of contact
- [ ] Build extractor for inventory section
- [ ] Test against a real (sanitized) FedRAMP Moderate SSP
- [ ] Output structured Python objects (intermediate representation)
- [ ] Add unit tests covering at least 3 SSP variants

**Estimate:** 25-35 hours · **Status:** not started · **Owner:** RPS

### A2. OSCAL SSP JSON generator ⏳

Take the parsed SSP structure and emit valid OSCAL 1.1 JSON.

- [ ] Read OSCAL 1.1 SSP JSON schema (NIST publishes it)
- [ ] Build JSON serializer from the intermediate representation
- [ ] Validate output against the OSCAL JSON schema using `jsonschema` or `oscal-cli`
- [ ] Round-trip test: parse → emit → parse → emit, confirm idempotent
- [ ] Handle the OSCAL `back-matter` and `metadata` sections correctly

**Estimate:** 8-12 hours · **Status:** not started · **Owner:** RPS

### A3. KSI metadata layer in catalogs ⏳

The strategic positioning move. Adds FedRAMP 20x relevance without rewriting checks.

- [ ] Read the official FedRAMP 20x KSI spec (already done — see Obsidian note FedRAMP-20x-KSI-Explainer)
- [ ] Add `fedramp_20x_ksi` array to every check in `catalog/fedramp-moderate-aws.json` (use mapping table from Obsidian note)
- [ ] Add `fedramp_20x_ksi` array to every check in `catalog/fedramp-moderate-azure.json`
- [ ] Update scanner output banner to show "FedRAMP 20x KSI coverage: X / 61"
- [ ] Update OSCAL Assessment Results emission to include KSI references
- [ ] Verify scan still passes after schema change

**Estimate:** 6-10 hours · **Status:** not started · **Owner:** RPS

### A4. OSCAL Viewer wired into Docker compose ⏳

Right now `docker compose up` produces JSON but no UI. Wire the existing React viewer into the stack so the demo is "one command, see dashboard."

- [ ] Add nginx service to docker-compose.yml to serve the built React app
- [ ] Build step for the React app inside the container or as a multi-stage Dockerfile
- [ ] Configure CORS so the viewer can read OSCAL JSON from the scanner output volume
- [ ] Test on fresh machine: clone repo, `docker compose up`, browser shows dashboard
- [ ] Document the access URL in `README.md` and `INSTALL.md`

**Estimate:** 6-10 hours · **Status:** not started · **Owner:** RPS

### A5. Codify IAM hardening into OpenTofu ⏳

The drift from Tuesday's IAM lesson. Currently AWS state has changes that Tofu doesn't reflect. Reconcile or `tofu apply` will revert work.

- [ ] Update `bootstrap/scanner-role/` Tofu module to declare the no-MFA trust policy currently live
- [ ] Update Tofu module to declare `MaxSessionDuration` of 3600 (or current 4200, decide which)
- [ ] Update Tofu module to declare the `openframp-scanner-readonly` policy with v2 contents
- [ ] Run `tofu plan` and confirm zero drift
- [ ] Add note in `bootstrap/README.md` about the rupinder-admin user (out of scope for the module but documented)

**Estimate:** 3-4 hours · **Status:** not started · **Owner:** RPS

### A6. INSTALL.md ⏳

Real install instructions, verified by running them on a fresh machine.

- [ ] Write prerequisites section (Docker, AWS account, Azure account, Steampipe optional, Python optional)
- [ ] Write step-by-step: clone, configure AWS creds, configure Azure creds, run scan, view results
- [ ] Spin up a fresh VM (or fresh user account on Mac), follow the INSTALL.md exactly, document what breaks
- [ ] Fix the breaks
- [ ] Add troubleshooting section based on what broke
- [ ] Add a "first scan in 5 minutes" quickstart at the top

**Estimate:** 6-8 hours · **Status:** not started · **Owner:** RPS

### A7. CONTRIBUTING.md ⏳

How someone else can add a check, add a catalog, fix a bug.

- [ ] Document the catalog file format with annotated example
- [ ] Document how to add a new check (Steampipe query + JSON entry)
- [ ] Document the test workflow before submitting a PR
- [ ] Document the commit message format and PR template expectations
- [ ] Document the CLA expectation if any (lean toward DCO for simplicity)
- [ ] Add `CODE_OF_CONDUCT.md` (use Contributor Covenant 2.1, no need to write your own)

**Estimate:** 4-6 hours · **Status:** not started · **Owner:** RPS

### A8. ARCHITECTURE.md ⏳

The technical-credibility document. Why catalog-driven? Why Steampipe? How does the data flow?

- [ ] Diagram the pipeline: SSP docx → parser → OSCAL SSP → scanner + catalogs → OSCAL AR → viewer
- [ ] Document the catalog-driven design and why
- [ ] Document the framework-agnostic check model (Rev 5, KSI, PCI, SOC 2 — same check, different mappings)
- [ ] Document the choice of Steampipe over alternatives (Prowler, Cloud Custodian, custom)
- [ ] Document the choice of running inside the boundary vs SaaS
- [ ] Add a section on what V1 deliberately does NOT do, with rationale

**Estimate:** 4-6 hours · **Status:** not started · **Owner:** RPS

### A9. Repo security hardening ⏳

Public repo. Free GitHub features, no excuse not to enable.

- [ ] Enable branch protection on `main` (require PR review, require status checks, no force push, no deletion)
- [ ] Enable secret scanning + push protection
- [ ] Enable Dependabot for Python and JavaScript dependencies
- [ ] Add `CODEOWNERS` file
- [ ] Set up GPG signing for commits, require signed commits on main
- [ ] Add issue templates (bug report, feature request)
- [ ] Add PR template with checklist

**Estimate:** 2-3 hours · **Status:** not started · **Owner:** RPS

### A10. End-to-end demo video ⏳

5 minutes. Cold start to dashboard. Recorded once. Hosted on YouTube/Loom unlisted, linked from README.

- [ ] Write a script of what to show: fresh machine, clone, configure, run, view results
- [ ] Practice once, time it
- [ ] Record (use Loom or OBS)
- [ ] Upload, get URL
- [ ] Add to README under "See it in action"
- [ ] Cross-post to LinkedIn and BSides talk follow-up

**Estimate:** 3-5 hours · **Status:** not started · **Owner:** RPS

**Tier A subtotal: 67-99 hours**

✅ Items already complete (carrying credit forward):
- ~~Custom least-privilege IAM scanner role with policy versioning~~ (April 28, 2026)

---

## Tier B — V1-Supporting (6 items)

**Goal:** The security baseline any real AWS/Azure account doing security work should have. Strengthens OpenFRAMP's claim of being FedRAMP-grade itself.
**Target completion:** July 31, 2026 (parallel with Tier A late stage)

### B1. CloudTrail + Config + GuardDuty trifecta in lab account ⏳

So OpenFRAMP development happens on a properly-monitored AWS account. Also lets IAM Access Analyzer generate a real least-privilege policy from actual scan usage.

- [ ] Enable CloudTrail multi-region with log file validation, KMS encryption, dedicated S3 bucket
- [ ] Enable AWS Config recorder + delivery channel
- [ ] Enable GuardDuty in primary region (us-west-2)
- [ ] Verify trail is logging AssumeRole calls properly
- [ ] After 30 days of usage, run IAM Access Analyzer to generate a tighter scanner policy

**Estimate:** 4-6 hours · **Status:** not started

### B2. KMS key for OpenFRAMP artifact encryption ⏳

When OpenFRAMP V1 starts persisting OSCAL artifacts to S3, this is the key. CMK with rotation.

- [ ] Create CMK with descriptive alias
- [ ] Enable automatic key rotation
- [ ] Document key policy in repo
- [ ] Reference key by alias in any Tofu modules

**Estimate:** 1-2 hours · **Status:** not started

### B3. S3 bucket for OSCAL artifacts (FedRAMP-grade) ⏳

The bucket from old Lesson 1. KMS encrypted, TLS-only, public access blocked, versioning, separate logs bucket.

- [ ] Apply the FedRAMP-grade S3 hardening sequence (see Build-and-Secure-CLI-Lab v2 Lesson 4)
- [ ] Codify in Tofu module so re-deployable
- [ ] Document in `INSTALL.md` for users who want OpenFRAMP to persist artifacts

**Estimate:** 3-4 hours · **Status:** not started

### B4. Branch protection + signed commits enforcement ⏳

Already in A9. Cross-listed here for completeness, no double-counting.

### B5. Secrets handling cleanup ⏳

Make sure no AWS keys, no Azure secrets, no .env files have leaked into the repo history.

- [ ] Run `gitleaks` or `trufflehog` against the entire repo history
- [ ] If any leaks found: rotate, then `git filter-repo` to scrub history
- [ ] Add pre-commit hook to prevent future leaks
- [ ] Document the secret-handling policy in CONTRIBUTING.md

**Estimate:** 2-4 hours · **Status:** not started

### B6. Container image scan + SBOM ⏳

Before publishing the OpenFRAMP Docker image to a registry.

- [ ] Run Trivy scan against the image, document any CVEs
- [ ] Generate SBOM in CycloneDX format
- [ ] Sign the image with cosign (keyless via Sigstore + GitHub OIDC)
- [ ] Publish image to GitHub Container Registry
- [ ] Document signature verification in INSTALL.md

**Estimate:** 4-6 hours · **Status:** not started

**Tier B subtotal: 14-22 hours**

---

## Tier C — V1.5 / Polish (5 items)

**Goal:** What separates a tool that exists from a tool that gets used. Marketing, growth, and CI/CD plumbing.
**Target completion:** August 31, 2026 (post-V1)

### C1. GitHub Actions CI for the repo itself ⏳

OpenFRAMP's own CI. Run linters, run tests, build the Docker image on every PR.

- [ ] Lint Python (ruff, mypy)
- [ ] Lint JS (eslint for the React viewer)
- [ ] Run unit tests on every PR
- [ ] Build the Docker image, run a smoke test scan
- [ ] Block merge on failure

**Estimate:** 4-6 hours · **Status:** not started

### C2. GitHub Actions OIDC for nightly scheduled scans ⏳

Demonstrates the proper pattern for OpenFRAMP users who want to run scans in their own CI.

- [ ] Set up OIDC trust between GitHub and AWS for the lab account
- [ ] Create a workflow that runs the scanner against the lab account nightly
- [ ] Publishes the OSCAL output as a workflow artifact
- [ ] Documents the OIDC pattern in INSTALL.md as the recommended deployment

**Estimate:** 3-5 hours · **Status:** not started

### C3. Public website / GitHub Pages ⏳

Simple site at `rupindersecurity.github.io/openframp` or similar. Not fancy. Hero, what it is, how to install, link to repo.

- [ ] Pick template (use GitHub Pages with Jekyll minimal theme, or just a single HTML file)
- [ ] Write hero copy (lift from README, distill)
- [ ] Add embed of the demo video
- [ ] Add "for federal contractors" pitch section
- [ ] Wire up DNS if using a custom domain (optional)

**Estimate:** 4-6 hours · **Status:** not started

### C4. First three real users ⏳

This is the one that matters most strategically and the one with the most uncertainty.

- [ ] Post launch announcement on LinkedIn the day V1 ships
- [ ] Post in `r/devops`, `r/aws`, `r/cybersecurity`, possibly Hacker News
- [ ] Email federal contractor contacts you have through NICE
- [ ] Email FedRAMP 3PAOs you know
- [ ] Track who tries it, who provides feedback, who opens issues
- [ ] Goal: 3 confirmed strangers running the tool by August 31, 2026

**Estimate:** 4-8 hours of outreach · **Status:** not started

### C5. InfoSec World 2026 talk prep ⏳

October. The talk that establishes OpenFRAMP credibility on the conference circuit.

- [ ] Outline the talk (mid-July)
- [ ] Build slide deck (early August)
- [ ] Practice run with a friend (mid-August)
- [ ] Practice run with the talk recorded (late August)
- [ ] Final iteration based on recording (September)

**Estimate:** 15-25 hours over July-September · **Status:** not started

**Tier C subtotal: 30-50 hours**

---

## Total V1 effort estimate

| Tier | Hours (low) | Hours (high) |
|---|---|---|
| Tier A — V1-Critical | 67 | 99 |
| Tier B — V1-Supporting | 14 | 22 |
| Tier C — V1.5 / Polish | 30 | 50 |
| Buffer (20%) | 22 | 34 |
| **Total** | **133** | **205** |

At 10 effective hours/week, that's 13-21 weeks. Today (April 29, 2026) → V1 ships somewhere between **late July and late September 2026.**

July 31 is the aggressive target. August 31 is realistic. September 15 is the worst-case I'd accept before declaring scope creep.

---

## Daily Log

> Update at the end of every working session. Format: `YYYY-MM-DD (Day) — what you did. Hours: N. Tier: X. Items touched: [list].` Keep entries to 2-4 lines max.

### 2026-04-29 (Tuesday) — IAM hardening lesson, V1 plan creation
Worked through Lesson 1 of the Build-and-Secure CLI Lab. Created `openframp-scanner-readonly` policy v1 then v2. Set up `rupinder-admin` user with MFA. Locked self out then recovered (educational). Built this project plan.
Hours: ~3. Tier: A (planning) + B-equivalent learning. Items touched: A5 (background), B (lesson learning).

### Template for future entries:
```
### YYYY-MM-DD (Day) — short title
What you did, in 2-4 lines. Note any wins, surprises, or things that took longer than expected.
Hours: N. Tier: X. Items touched: [A1, A4, etc].
```

> Tip: If you skip a night, write `### YYYY-MM-DD — skipped (reason)`. Don't pretend you worked when you didn't. The honest log is what makes the discipline real.

---

## Weekly Review Template

Every Sunday (or your weekly cadence day), 10 minutes, fill this in:

### Week of YYYY-MM-DD

**Hours worked this week:** N
**Items completed:** [list]
**Items in progress:** [list]
**Estimated weeks to V1 ship at current pace:** N

**What worked this week:**
- (one or two things, briefly)

**What slowed me down:**
- (one or two things, briefly — be honest)

**Adjustment for next week:**
- (one specific change)

**Discipline check (be honest):**
- Am I expanding scope? Y/N. If yes, what got added that wasn't in this plan?
- Am I tempted to add multi-framework / multi-cloud / new features? Y/N
- If yes, write it in the V2 backlog at the bottom of this doc and *do not start it.*

---

## V2 Backlog (DO NOT BUILD IN V1)

Anything that comes up but isn't V1-critical goes here. Re-read this list when tempted to expand scope.

- SOC 2 catalog content
- PCI DSS catalog content
- ISO 27001 catalog content
- HIPAA catalog content
- FedRAMP High catalog content
- GCP plugin
- OCI plugin
- On-prem support
- Hosted SaaS version
- Multi-tenant deployment
- IdP / LMS integration for training KSI evidence
- LLM-assisted analysis features
- Continuous validation pipeline (cron-based scheduled scans with timestamped JSON evidence)
- 3PAO digital signature integration
- UK / sovereign region adaptations
- Web-based UI for configuring scans
- Marketplace integration
- Paid support tier infrastructure

**Rule:** When you add to this list, do not start it. The list grows. V1 ships first.

---

## Blockers

> Use this section for things that are stopping you from making progress. Empty is good.

(none currently)

---

## Decisions log

> When you make a meaningful technical or strategic decision, capture it here so future-you understands why. One line each.

- 2026-04-29 — Replaced MFA-required trust policy on scanner role with no-MFA version for solo lab. Will revisit at Lesson 8 (OIDC federation). Documented as conscious trade-off in IAM hardening notes.
- 2026-04-29 — Adopted FedRAMP 20x KSI positioning. OpenFRAMP V1 will emit OSCAL Assessment Results with both Rev 5 control references and KSI references. Same checks, additional metadata layer.
- 2026-04-29 — V1 scope locked to FedRAMP Moderate, AWS+Azure only, single contributor. SOC 2/PCI/ISO 27001 deferred to V2. UK/sovereign regions deferred to V2.

---

## Setting up a GitHub Project board (optional but recommended)

If you want a visual kanban view that mirrors this doc:

1. Go to your `RupinderSecurity/openframp` repo on GitHub
2. Click the "Projects" tab → "New project" → "Board" template
3. Name it "OpenFRAMP V1"
4. Create columns: `Backlog` / `Up next` / `In progress` / `Done`
5. For each Tier A/B/C item above, create a card. The card title can mirror the section heading. Drag to the appropriate column.
6. Set up custom fields: `Tier` (A/B/C) and `Estimated hours`
7. Set the project visibility to public so visitors to the repo see momentum

This mirror gives you a visual board for at-a-glance progress while this markdown doc remains the canonical source of truth. When you finish an item, tick it here AND drag the card to Done.

---

## File location and update workflow

This file lives at `docs/V1-PROJECT-PLAN.md` in the OpenFRAMP repo (or wherever you put it). Recommended workflow:

1. Open this file in VS Code at the start of every session
2. Look at "Up next" items in Tier A
3. Pick one, work on it
4. At end of session, tick boxes, add Daily Log entry, save
5. Commit with message like `docs: V1 plan update — completed A5 sub-items`
6. Push

That's it. The plan stays current. Visitors to the repo see momentum. You see your own progress.
