# Feature spec template

Copy this skeleton into `<component>/spec/impls/<N>-<feature>/spec.md` and fill it top down.
Text in `<angle brackets>` is a placeholder. Text in *italics* under a heading says what the section
must contain and is deleted once written. Section numbers may be reorganised later; identifiers
(`D`, `S`, `O`, `N`, `G`, `Q`) may not.

---

```markdown
# Feature Spec: <Feature name> for the <Component>

**Status:** Draft | Ready for team review — all decisions recorded (D1–Dn); <k> open question(s) (§10)
**Branch:** `<branch>`
**Scope:** <one line: what is in, what is out>
**Background:** [`research.md`](./research.md) holds the analysis this spec draws on; it is not required reading.

---

## 1. Summary

*Two to four paragraphs. What exists today (verified), what this adds, and the one architectural
statement a reader must hold before reading anything else. No history, no product comparisons.*

### 1.1 Goals

- G1. <capability, stated as what a user can do>
- G2. <boundary: what this feature is and is not>
- G3. …

### 1.2 Non-goals (this increment)

- N1. **<Thing deliberately excluded>.** <Why, in two sentences. If it becomes a follow-on, say so.>
- N2. …

*A non-goal is something a reader would reasonably expect and must be told is out. It is not a
place to list every unrelated idea.*

---

## 2. Decisions

Each decision states what was chosen and why.

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | <the question> | **<the answer>** — <one clause of consequence> | <alternatives, named> |
| D2 | … | | |

The rationale for each decision, including what was rejected and why, is in Appendix A.

*Ten rows is a healthy size. If a row needs a paragraph, it belongs in Appendix A. If a row cannot
be written, it is not yet a decision — it is an open question (§10).*

---

## 3. Implementation

*One subsection per direction or major component, in dependency order. Each opens with the
constraints the platform imposes (what it exposes, what a protocol forbids — verified), then the
component walk, then the user-facing surface, and ends with the response that component returns
to its caller.*

### 3.1 <Direction or component A>

#### 3.1.1 What the platform gives us, and what we must establish ourselves
*Verified attributes, hooks, limits. Tables of exact names. Point at `path:line`.*

#### 3.1.2 <The core model>
*The user-facing shape and its semantics, fully specified: every field, every default, every
narrowing rule. Include a YAML or JSON example that a user would actually write.*

#### 3.1.3 Component walk
*Numbered components in dependency order. For each: which repo, which file/function today,
what changes, pseudocode where the shape matters. Name the cross-repo critical path.*

#### 3.1.4 The user-facing surface
*Who does what (roles), with the exact call or YAML. The controller's deploy-time refusals as a
table: condition → why it is refused.*

#### 3.1.5 Composition with existing features
*Ordering, interaction, what does and does not need reconciling.*

#### 3.1.n The response this component returns
*Reuse the sibling feature's parameters and body verbatim if one exists. State the exact default
body. State that every failure cause produces the same body if that is a requirement.*

### 3.2 <Direction or component B>

#### 3.2.1 Config surface
*The YAML block, with every field, default and constraint. Say what it is NOT if a reader would
reach for the wrong analogy.*

#### 3.2.2 Translator / generator changes
#### 3.2.3 Secret handling
#### 3.2.4 Existing violations fixed while here
*If touching a function that has a standing rule violation, fix it and say so. Cost the blast
radius honestly in §9.*

#### 3.2.n The response this component returns

### 3.3 Observability

*Cross-cutting, stated once. Open with what the platform already emits that this feature rides
unchanged — cite the metric registry, tracer package, access-log format and analytics hook with
`path:line` — then decide each signal below. Every row is a decision with a test in §8; "we'll add
metrics later" is not a row.*

**Metrics.** *Existing counters/gauges the feature is already covered by (per-policy, per-request,
per-resource). New ones as a table: name, type, labels (closed enums), set from where. Include any
existing metric that is declared but never set and that this feature should populate.*

**Traces.** *Which tracer(s) exist and where spans are created. Which span carries the feature's
attributes and why that one (what can and cannot read the data). Attribute table using the
OpenTelemetry semantic conventions where they exist; state what is never an attribute (secrets,
full payloads, raw credentials).*

**Access log.** *Fields added to the default format(s), operator by operator, with the reason each
is needed. Say which formats change; adding to a positional format is a breaking change and needs a
compatibility note in §6.*

**Analytics.** *Which existing hook picks the feature up and which fields it will carry; what is
deliberately not attributed. If a hook fires only for HTTP requests, say what a non-HTTP failure
produces instead.*

**Logs.** *Level and fields for the feature's own decisions, matched to sibling features' volume.
What is never logged.*

**Diagnostics.** *Any operator-facing endpoint the feature adds because a failure class is
otherwise invisible; point at its contract in §5.2.*

---

## 4. Data model

*New tables or columns, one table each: column → notes. State which schema rule governs
(`.claude/rules/db-schema-changes.md`) and why a new table rather than a change to a shipped one.
State the scoping key by reading what existing tables use. State write-time validation.*

---

## 5. Interfaces

*Everything a person touches from outside the component: the management API that admins and
developers call, and the deployment configuration an operator sets. Say where the API-definition
additions are specified (§3) rather than repeating them.*

### 5.1 Management API

| Endpoint | Roles | Purpose |
|---|---|---|
| `POST /<resource>` | `admin` | <one line> |
| … | | |

*List only what this feature adds. Name unchanged endpoints the feature depends on in a sentence
below the table, never as rows.*

### 5.2 Response contracts

*Nothing left to the implementer. Group by audience.*

#### 5.2.1 Management API — errors
*The existing error schema, by name. One full example. Rules (field paths, one entry per problem,
nothing leaks). Then one table per endpoint family: input → `field` → `message`. Explain the
placeholder letters in field paths with a YAML example annotated with the paths. Then conflicts
(`409`) with an example and a table.*

#### 5.2.2 Management API — warnings
*The field (name it, show it in an example), where it lives on responses that lack the usual
status block, and a closed table of codes: code → raised when → field.*

#### 5.2.3 Diagnostics — <endpoint>
*Source of the data, retention, query parameters, one example response, closed enum for any
`reason`/`result` field with the mapping from raw values.*

### 5.3 <Component config file> — what changes (or "nothing new", and why)
### 5.4 CRDs / operator
### 5.5 Helm

---

## 6. Cross-repo delivery and compatibility

*Shipping order across repos and why it is forced. A table of version-skew combinations → result,
with the dangerous row called out. Compatibility notes for any behaviour change to existing
traffic (e.g. a changed error body), flagged for release notes. Platform version floors, verified.*

---

## 7. Security requirements

Each maps to a project rule. These are requirements, not suggestions; §8 has the test that proves
each one.

| # | Requirement | Rule |
|---|---|---|
| S1 | <fail-closed statement> | <rule file / directive> |
| S2 | … | |

*Every S has at least one test in §8 that names it. Include the "no deferring behind a comment"
rule as its own S.*

---

## 8. Testing

*Organised by user story first, because the failure modes that matter are behavioural. Five shapes
are mandatory: stories, input matrices, ordering scenarios, request-time matrix, contract checks.*

### 8.1 Fixtures
*Every artefact the tests need, as a table: fixture → purpose. Name the new test steps to add.*

### 8.2–8.n Stories
*One subsection per user story: admin does X, developer does Y, client does Z. Bullets of
observable behaviour, each naming the S or D it proves where relevant.*

### 8.n Unit tests
*Grouped by component. Name the single most important test.*

### 8.n Security and abuse
*The tests that would catch a regression into a vulnerability. Forged inputs, cross-scope,
enumeration, disclosure sweeps, privilege, version skew in both directions.*

### 8.n Edge cases
### 8.n Operability
*One bullet per signal decided in §3.3: the metric increments with the right labels, the span
carries the attributes, the log line has the fields (and the unchanged format is byte-identical),
the analytics record has the expected attribution, the diagnostic shows the failure. Assert
absence where absence is the diagnosis (a failure that must appear in exactly one place).*
### 8.n Performance

### 8.n Input matrix — <user-facing surface 1>
*Every shape a user can write, and what the product does: input → deploy-time → request-time.
Every row a decided behaviour with its status code. Draft rows as `(proposed)`; none may remain at
finalisation.*

### 8.n Input matrix — <user-facing surface 2>
### 8.n Input matrix — management endpoints
*Per endpoint: payload → result.*

### 8.n Ordering scenarios — sequences where order changes the outcome
*Grouped by theme. Columns: # | Given | Sequence | Why. Given = state before; Sequence = numbered
steps naming who acts and the exact response including `field` paths; Why = the D or S proved.*

| # | Given | Sequence | Why |
|---|---|---|---|
| O1 | <state> | 1. <actor> <action> → **`<code>`** <detail> 2. … | <D/S> |

### 8.n Request-time matrix
*Client shape × resource shape → outcome, with a legend for non-HTTP outcomes. Assert byte-identical
bodies where a uniformity requirement exists.*

### 8.n Response-contract checks
*Every error matches the shape and texts in §5.2; every warning carries a closed code; nothing leaks.*

---

## 9. Phasing

*Milestones M0…Mn. M0 is a spike answering a named question that gates the rest. State what each
milestone ships, what it does not, and where the risk sits. Say which milestones run in parallel
and what the shared bottleneck is. Deferred items are named with the interim behaviour.*

---

## 10. Open questions

*Either "None." or a numbered list of `Q-<letter>` entries. Each is one paragraph: the question,
why it is open, who decides, and a link to an options paper if it needs more than a paragraph.
Nothing in the body may depend on the answer unless the entry says so.*

---

## Appendix A — Decision rationale

One entry per decision in §2: why the chosen option beat the alternatives. Nothing here is needed to
implement the feature; it is here so the decisions are not re-litigated.

### A.1 D1 — <title>
*The constraint that forced it, the rejected options and what each would have cost, and any
verified evidence (with `path:line` or a documentation quote).*

### A.2 D2 — <title>
…
```

---

## Notes on filling it

- **Write the decision table before the implementation.** If the table is hard to write, the
  design is not ready and the implementation section will drift.
- **Every `(proposed)` you write is a debt** to be paid in Phase 5. Write them freely in the draft;
  the marker is what makes them findable.
- **Tables over prose for anything enumerable**: fields, codes, endpoints, fixtures, scenarios.
  Prose for rationale and for the one architectural statement per section.
- **One example per shape.** A reader understands a JSON body from one example faster than from
  ten table rows; give both.
- **Full field paths.** `spec.policies[i].params.list[j].name`, never `…list[j].name`. Explain the
  placeholder letters once, with an annotated example.
- **Name files and lines** for every claim about existing code. If you have not read it, do not
  cite it.
