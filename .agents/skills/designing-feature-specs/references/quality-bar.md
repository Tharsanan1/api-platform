# Quality bar — finalisation checklist and anti-patterns

Work through every item before setting the status line to "Ready for team review". Each item is
a yes/no question; a "no" is work, not a note.

## A. Structure

- [ ] The decision table (§2) is short, front, and every row has a *chosen* and a *rejected* column.
- [ ] Rationale lives in Appendix A, one entry per decision; none is inline in §2.
- [ ] Load-bearing technical constraints sit at the start of the implementation section, not in §2.
- [ ] Implementation is one section with one subsection per direction or component, each ending
      with the response that component returns.
- [ ] Interfaces (§5) contains only what a person touches from outside: management API, response
      contracts, config file, CRDs, Helm. API-definition additions are specified in §3, not repeated.
- [ ] The endpoint table lists only endpoints this feature adds. Unchanged dependencies are a
      sentence, not a row.
- [ ] Sections use numbered headings at every level (`##`, `###`, `####`); no bold run-in paragraphs
      standing in for headings.
- [ ] `scripts/lint-spec.py` exits clean.

## B. Decisions and provisional content

- [ ] Zero `(proposed)` markers remain.
- [ ] Zero `verify` / `UNVERIFIED` markers remain, except items explicitly assigned to the M0 spike.
- [ ] Zero `TODO` / `FIXME` in the spec body (a rule may *quote* the words as a prohibition).
- [ ] §10 is either "None" or a list of `Q-` entries, each with a link to an options paper when it
      needs more than a paragraph, and each stating that nothing in the body depends on it (or what does).
- [ ] Every decision made with the owner is recorded in **every** place it touches: decision table,
      body, tests, examples, companion documents. Grep for the old form of any renamed field.

## C. Verification

- [ ] Every claim about this codebase carries a `path:line` that you have read in this session.
- [ ] Every claim about an external system is checked against its docs or source, and the spec
      states the version it applies to.
- [ ] Scope assumptions (organisation, tenant, gateway, user) match what the component's tables are
      actually keyed by.
- [ ] Version floors are stated from the one place that pins them, not from a sample config.
- [ ] Any "the platform already does X" statement has been confirmed by reading the code path, not
      by the presence of a struct or a field. (A CRD field that nothing reads is not a feature.)

## D. Contracts

- [ ] Every status code in the test matrices resolves to a fixed body shape in §5.2 or in the
      implementation section that produces it.
- [ ] Error bodies reuse the component's existing error schema by name; message texts are fixed;
      `field` paths are full, with the placeholder letters explained by an annotated example.
- [ ] Warning codes, reason codes and result codes are closed enums, each with a table.
- [ ] Any data-plane response reuses a sibling feature's parameters and default body verbatim, and
      states that every failure cause yields the same body if uniformity is required.
- [ ] Any change to an **existing** response body for existing traffic is flagged as a
      compatibility note in §6.

## E. Safety

- [ ] Every ambiguous input (empty list vs omitted, twin fields, a block a parser would drop) is a
      `400` at write time, and the spec notes whether the request binding is strict enough for that
      `400` to fire.
- [ ] Every "absent" case fails closed. A nil accessor, a missing attribute, an unpopulated field
      never means "not required".
- [ ] Deleting a referenced resource is refused, or its fail-closed effect is named per referrer;
      never a silent change to a running resource.
- [ ] No new configuration switch exists for behaviour derivable from deployed resources; where one
      is added, §5.3 says why derivation was not possible.
- [ ] Secrets never appear in read responses, config dumps, logs or generated config as inline
      bytes; the spec names the delivery mechanism.
- [ ] Every security requirement `S` has at least one test that names it.

## F. Tests

- [ ] Fixtures table exists and names the new test steps.
- [ ] At least one input matrix per user-facing surface: every writable shape → outcome.
- [ ] Management endpoints have a payload → result table each.
- [ ] Ordering scenarios use Given / Sequence / Why, grouped by theme, with exact responses and
      `field` paths in the sequence.
- [ ] A request-time matrix exists with a legend for non-HTTP outcomes.
- [ ] Security-and-abuse tests cover forged inputs, cross-scope access, enumeration, disclosure
      sweeps, privilege, and version skew in both directions.
- [ ] Response-contract checks assert on codes and schemas, not on prose.

## G. Observability

- [ ] Implementation has an Observability subsection that opens with the platform's existing
      signals (metrics registry, tracer, access-log format, analytics hook) cited by `path:line`.
- [ ] Every new metric has a name, type, closed-enum labels and a stated source; every existing
      metric the feature should populate (including declared-but-unset ones) is named.
- [ ] Span attributes follow OpenTelemetry semantic conventions where they exist, live on the span
      that can actually read the data, and never carry secrets or full payloads.
- [ ] Access-log additions name the format(s) they change; a change to a positional format has a
      compatibility note in §6.
- [ ] Analytics attribution is stated: which hook, which fields, what is deliberately absent.
- [ ] Every failure class in the test matrices leaves evidence in at least one named place, and any
      class with **no** HTTP response has a dedicated diagnostic.
- [ ] §8 Operability has one test per signal, including "absent from X" assertions where absence is
      the diagnosis.

## H. Companion documents

- [ ] Any teaching page or setup guide reflects every decision made since it was last synced.
- [ ] Anything shown in a guide that does not exist yet is marked as a proposal, visibly.
- [ ] Options papers point at the spec with current section numbers.

---

## Anti-patterns to strip

Each of these appeared in a real spec and had to be removed. Grep for them.

| Pattern | Why it is wrong | Fix |
|---|---|---|
| Product or competitor names in the body | The spec is not a comparison; the reader did not ask | Move to `research.md`; keep only a standards reference if it justifies a technical constraint |
| "An earlier draft…", "this was retracted", revision-history header | Process narrative, not specification | Delete; the decision table and Appendix A are the record |
| Research option codes (`Option A`, `D-B`) in the spec | Vocabulary the reader has no key for | Replace with descriptive words |
| `// TODO`, `FIXME`, "decide later", "verify in code" | Provisional content shipped as spec | Decide it, or make it a `Q-` with an options paper |
| An unchanged endpoint in the "new endpoints" table | Reads as new or modified | One sentence below the table |
| A guide showing a proposed endpoint as if it existed | Misleads the reader | Red banner: "Design proposal — not implemented" |
| Abbreviated field paths (`…list[j].name`) | Implementer cannot construct the real path | Full path from the document root |
| Placeholder letters (`i`, `j`) explained in a sentence | Nobody understands the sentence | One annotated YAML example mapping lines to paths |
| Two fields for one concept (`thing` and `things`) | Precedence question with no good answer | One field; a list if it must ever hold more than one |
| A component-wide enable/disable switch | Second source of truth that can disagree with deployed resources | Derive from the resources |
| Organisation/tenant reasoning on a component that has no such column | Whole passages describe impossible states | Check the tables first; scope by what they are keyed by |
| "Refused with a clear message" | The message is the contract | Write the message |
| "Uniform error body" without the body | Implementer picks one | Write the body, byte for byte |
| A milestone paragraph repeating a section verbatim | Drift when one is edited | State once, point to it |
| Bold run-in paragraphs as headings inside a long subsection | Not navigable, not linkable | Numbered `####` sub-headings |
| A row reading `deploy X → then add Y \| first step 400; after adding, redeploy → 201` | Nobody can follow it | Given / Sequence / Why with numbered steps |
| "Metrics and tracing will be added" / no Observability subsection | A failure class ships with nowhere to look | §3.3 with a decision per signal, each tested in §8 |
| A rejection or background failure that produces no HTTP response and no named diagnostic | Operators debug by absence | Name the one place it appears, and assert it appears nowhere else |
| "Configured horizon" / "configurable threshold" with no config key decided | Contradicts a no-new-config posture and leaves the value to the implementer | Fix the constant, or name the key and default |
| A metric declared in the registry and never set | Looks observable, is not | Populate it or delete it; say which in the spec |
