---
name: designing-feature-specs
description: Write, revise, audit or finalise a feature specification for a WSO2 API Platform component (gateway, platform-api, portals, operator). Use when asked to prepare a spec or design doc for a new feature, turn research into decisions, review a spec for gaps or contradictions, close open questions with the product owner, or get a spec ready for team review or hand-off to an implementer.
allowed-tools: Bash, Read, Edit, Write, Glob, Grep, WebFetch, Agent
---

# Designing Feature Specs

A feature spec is the document an implementer builds from and a reviewer approves. It is **not**
the research that led to it, not a changelog of how it evolved, and not a comparison of other
products. This skill is the process for producing one that an independent engineer or agent can
implement without guessing and without disturbing existing product behaviour.

Three files next to this one:

- `references/spec-template.md` — the section skeleton, with what each section must contain.
- `references/quality-bar.md` — the finalisation checklist and the anti-patterns to strip.
- `scripts/lint-spec.py` — structural and cross-reference lint; run it after every batch of edits.

## Where specs live

```
<component>/spec/impls/<N>-<feature-slug>/
  research.md          analysis: protocol, prior art, other products, codebase survey  (input, not the spec)
  spec.md              the deliverable
  spec-review.md       output of the adversarial review (§ Phase 4)
  <topic>.md           one options paper per open question that needs more than a paragraph
```

`<N>` continues the existing numbering in `impls/`. Check `<component>/spec/README.md` for any
component-specific convention before creating the directory.

## Principles

These are the rules that separate a spec that ships from one that gets re-litigated. Each was
learned the hard way; do not relax them without saying so in the spec.

1. **The spec is not the research.** Product comparisons, history, "an earlier draft said",
   retractions, and research option codes stay in `research.md`. The spec links to it once, as
   background that is *not required reading*, and stands alone.
2. **Every claim is verified before it enters the spec.** A claim about this codebase carries a
   `path:line` reference you have read. A claim about an external system (a proxy, a library, a
   standard) is checked against its documentation or source, not memory. Anything you could not
   verify is marked `UNVERIFIED` inline and resolved before finalisation — never silently kept.
3. **Decisions are a register, rationale is an appendix.** §2 holds a table `D1…Dn` with *chosen*
   and *rejected* columns and nothing else. Why each won lives in Appendix A, one entry per
   decision. Readers get the map first and the argument only when they want it.
4. **Nothing provisional survives finalisation.** No `(proposed)` rows, no `verify` tags, no
   `TODO`, no "the team will decide". Every proposed behaviour is put to the owner **one at a
   time** (§ Phase 5) and recorded. What genuinely cannot be decided yet becomes an open question
   in §10 with a link to an options paper.
5. **Response contracts are decided, not assumed.** Reuse the component's existing error schema,
   status conventions and any sibling feature's parameters verbatim. Fix message texts, make codes
   and reasons closed enums, and give one example body per shape. An implementer must never
   invent a body.
6. **Fail closed, and refuse ambiguity at write time.** An input with two plausible readings
   (empty list vs omitted, twin fields for one concept, a block that a parser would silently drop)
   is a `400` when written, never interpreted. Check how the component's request binding treats
   unknown keys before assuming a `400` will fire.
7. **Derive rather than switch.** Before adding a configuration key, ask whether the behaviour can
   be derived from resources that already exist. A component-wide switch that duplicates what
   deployed resources already say is a second source of truth.
8. **Check scope assumptions against the tables.** Organisation, tenant, gateway, user — look at
   what the component's tables are actually keyed by before writing any cross-scope reasoning.
9. **IDs are stable, sections are not.** `D`, `S`, `O`, `N`, `G`, `Q` identifiers never change once
   assigned; removing one leaves a gap. Section numbers may be reorganised freely, but always by a
   scripted remap followed by the lint — never by hand.
10. **The body must agree with the decisions.** After every batch of decisions, re-read the whole
    spec for passages that still describe the pre-decision state. Contradictions accumulate
    silently in tests and examples.
11. **Observability is a section, not an afterthought.** Every feature gets an Observability
    subsection in Implementation that decides, per signal — metrics, traces, access logs,
    analytics, logs, and any operator-facing diagnostic — what is emitted, on which existing rail,
    and what is new. Start by reading what the platform already emits (metric registries, tracer
    packages, the access-log format, the analytics policy) so the feature reuses those rails and
    adds only what is missing. A design that makes a class of failure invisible (a rejection with
    no HTTP response, a background job with no request) must say where an operator looks instead.
    Each signal gets a test.

## Workflow

Run the phases in order. Phases 1 and 4 are good candidates for a subagent; everything else is
yours because it needs the conversation with the owner.

### Phase 0 — Confirm the gap

Before anything else, establish from the codebase that the feature does not already exist, and
write down what *adjacent* machinery does exist (the same protocol on another channel, a sibling
feature whose shape you should mirror, a table you must not touch). This becomes §1 and saves the
research phase from re-discovering it.

### Phase 1 — Research (delegate)

Produce `research.md`: the protocol or domain fundamentals, how this product's architecture
constrains the options, how comparable products solve it, and a survey of the code paths that
would change. The research may propose options and label them (`Option A`, `Option B`, …) — those
labels **stay in research.md**. Ask the researcher to cite documentation and source for every
external claim and `path:line` for every internal one.

### Phase 2 — Verify

Read the code paths the research names. Confirm every `path:line`. Confirm every external claim
you will rely on against its source. Record what the research got wrong in `research.md` itself
(dated note), not in the spec. This phase routinely overturns a research conclusion; that is its
job.

### Phase 3 — Draft

Copy `references/spec-template.md` and fill it top down. Rules while drafting:

- Write the decision table first. If you cannot state a decision in one row, it is not decided.
- Put load-bearing technical constraints (what the platform exposes, what a protocol forbids)
  at the start of the implementation section, not in the decisions section.
- Write the security requirements as a numbered table `S1…Sn`, each mapped to a repo rule under
  `.claude/rules/` and each with a test in the testing section.
- Write the tests in the five shapes the template describes. The input matrix is the most
  important: every shape a user can write, and what the product does with it.
- Write the Observability subsection from the platform's existing signals outward: list the
  metric registries, tracer packages, access-log format and analytics hooks the component has
  (with `path:line`), state which the feature rides unchanged, then name every new metric, span
  attribute, log field and diagnostic endpoint with its labels or fields. Anything you cannot
  observe, you cannot operate.
- Mark anything you are asserting rather than deciding with `(proposed)`. It will be removed in
  Phase 5, and marking it now is what makes Phase 5 possible.

### Phase 4 — Adversarial review (delegate)

Hand the spec and the research to an independent agent with a strong model and ask it to break
the design: security bypasses, fail-open paths, unstated assumptions, contradictions, things the
platform cannot actually do. Write its output to `spec-review.md`. Fold accepted findings into the
spec as decisions or requirements; record rejected ones in the review file with the reason.

### Phase 5 — Decide, one at a time

For each `(proposed)` row, each `verify` tag and each open question, in order:

1. Explain the case to the owner with a **concrete example** (the YAML they would write, the call
   they would make), what the ambiguity or risk is, and what the alternatives cost.
2. If other products face the same case, check what they do (fetch their docs) and say so — as
   evidence for the recommendation, not as content for the spec.
3. Make a recommendation. When the owner asks "what do you think", answer.
4. Record the answer **immediately** in every place it touches, then run the lint. Do not batch.

If a decision changes a field name or a schema shape, grep the whole spec and any companion
documents for the old form before moving on.

### Phase 6 — Audit for contradictions

Re-read the entire spec against the decision table. Look specifically at: test rows that assert
pre-decision behaviour, examples that use a renamed field, prose that says "decided in the spike"
for something now decided, cross-references to sections that were moved. Fix them in one pass and
lint.

### Phase 7 — Finalise

Work through `references/quality-bar.md`. Run `scripts/lint-spec.py`. Confirm every failure mode in
the test matrices leaves evidence somewhere an operator can find it (a metric, a log field, a
diagnostic) and that the Observability subsection names it. Set the status line to
"Ready for team review" and state the number of open questions honestly. If companion documents
exist (a setup guide, a teaching page), update them for every decision made since they were last
synced, and mark anything they show that does not exist yet as a proposal.

### Phase 8 — Hand-off notes (on request)

A design spec decides *what*; an implementer also needs *where*. When asked to prepare the spec
for an independent implementer, add **Appendix B — Implementation notes**: per component, the
files and functions to change, new types with fields, data flow and triggers, exact proto or
schema fragments. Verify every path against the code before writing it. Do this only when asked;
it is expensive and it dates quickly.

## Options papers

When an open question needs more than a paragraph — several viable shapes, preconditions, example
configurations — write `<topic>.md` next to the spec and have §10 carry a one-paragraph statement
of the question plus a link. The paper holds: the problem, what other products do (with quotes),
why the platform can or cannot do each option, preconditions, verified platform facts with
`path:line`, example user-facing config, target generated config, the tests each option would add,
an options table, and a recommendation. The spec body stays decision-only.

## Working with the owner

- One question per turn. Wait for the answer. Record it. Then the next.
- Explain with an example the owner would actually write, not with a description of the example.
- When they ask why something is needed, answer the question first; offer to remove it second.
- When they correct a premise ("this component has no organisation concept"), grep the whole spec
  for that premise and fix every occurrence, not just the one they pointed at.
- When they say a section is hard to read, restructure it: numbered sub-headings, one example per
  shape, tables split by audience or endpoint, full field paths instead of abbreviations.

## Lint

```
python3 <path-to-this-skill>/scripts/lint-spec.py <spec.md> [--ids D,S,O,N,G,A,Q] [--allow-marker <substring>]...
```

Checks: balanced code fences; `##`/`###`/`####` numbering consecutive at each level; duplicate
headings; every table has a separator row, consistent column count, and a blank line before it;
`---` separators and headings surrounded by blank lines; every `§x`, `§x.y`, `§x.y.z` resolves to a
heading; every `D/S/O/N/G/A/Q` reference resolves to a definition; relative links resolve; and it
lists residual `(proposed)`, `— verify`, `UNVERIFIED`, `TODO` markers. Use `--allow-marker` for a
line that legitimately quotes one of those words (a rule forbidding `TODO` comments) or for spike
items deliberately left for M0. Exit code is non-zero on any issue. Run it after every edit batch;
a clean run is a precondition for saying "done".
