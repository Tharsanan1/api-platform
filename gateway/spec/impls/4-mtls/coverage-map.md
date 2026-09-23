# Coverage map — spec rows to tests

Working file for the implementation. Lives with the spec and is discarded with it; tests carry no
reference back to spec row ids by design. One row per spec case: where it is tested, or why not.

Legend: **IT** = `gateway/it/features/<file>.feature` scenario title; **UT** = Go unit test name.

## Slice 1 — the client-CA pool (§8.2, §8.13 certificates rows, §5.2.1, §5.2.2)

| Spec case | Test |
|---|---|
| §8.2 add an authority → appears in GET, `referencedByApis` 0 | IT mtls-client-ca-pool: *A CA certificate uploaded with usage client becomes a pooled client authority* |
| §8.2 add several → all present | IT: *The same certificate may be pooled under a second name*; *A second authority with the same subject DN…* |
| §8.2 adding grants no access (S16) | slice 4 (needs `mtls-auth`) |
| §8.2 remove unreferenced → succeeds | IT: *A client authority that no API references can be removed* |
| §8.2 remove referenced (S19) → 409 | slice 4 |
| §8.2 chain upload → leaf under intermediate validates | IT: *An issuing CA uploaded together with its root…* (upload half); validation half in slice 3 |
| §8.2 leaf upload → 201 `isLeaf` | IT: *A leaf certificate is accepted as a one-member authority and flagged* |
| §8.2 same-DN second authority (S15) | IT: *A second authority with the same subject DN as a pooled one is accepted*; 401 half in slice 3 |
| §8.2 role enforcement | IT: *A developer can read the pool*; *…cannot add…*; *…cannot remove…* |
| §8.13 one CA → 201 | IT: *A CA certificate uploaded with usage client…* |
| §8.13 `role: relay` → 201, listing shows role | IT: *A client authority can be marked as a relay…*; "header mode turns on" half in slice 6 |
| §8.13 `usage` omitted → upstream | IT: *A certificate uploaded without usage is backend trust, exactly as before* |
| §8.13 name used by upstream cert → 409 | IT: *A client authority may not reuse the name of an upstream certificate* |
| §8.13 `role: proxy` → 400 | IT: *An unknown role is rejected*; UT clientca/handler |
| §8.13 issuing + root → 201, subject is issuing | IT: *An issuing CA uploaded together with its root…*; UT `TestInspect_ChainIdentityIsIssuingCA` |
| §8.13 two unrelated CAs → 400 | IT: *Two unrelated authorities in one PEM are rejected*; UT `TestInspect_TwoUnrelatedAuthorities` |
| §8.13 private key in PEM → 400, not persisted, not logged | IT: *A PEM that carries a private key is rejected and nothing is stored*; UT `TestInspect_PrivateKeyPresent` |
| §8.13 malformed → 400 | IT: *A value that is not a PEM certificate is rejected* |
| §8.13 expired → 400 | IT: *An expired certificate is rejected…*; UT `TestInspect_Expired` |
| §8.13 not-yet-valid → 201 + warning | IT: *A not-yet-valid authority is accepted with a warning* |
| §8.13 duplicate name → 409 | IT: *A duplicate client authority name is a conflict* |
| §8.13 same cert, second name → 201 | IT: *The same certificate may be pooled under a second name* (`issuedBy` reporting deferred: no such field exists yet; revisit in slice 4) |
| §8.13 bad `name` → 400 | IT: *A name with characters outside…* |
| §8.13 same DN → 201 | IT: *A second authority with the same subject DN…* |
| §8.13 body over size → 413 generic | IT: *A body over the size limit is rejected without stating the limit*; UT handler |
| §8.13 developer → 403; unauthenticated → 401 | IT roles scenarios |
| §8.13 GET `?usage=client` roles, `referencedByApis`, no private material | IT: first scenario + *A developer can read the pool* |
| §8.13 DELETE unreferenced client row | IT: *A client authority that no API references can be removed* |
| §8.13 DELETE referenced only by inheriting APIs / named in accept / last authority | slice 4 |
| §8.13 DELETE unknown id → 404 | IT: *Removing an unknown certificate is not found* |
| §5.2.1 `usage`/`role`/`role`-with-upstream 400 texts | IT: *An unknown usage…*, *An unknown role…*, *A role given on an upstream certificate…* |
| §5.2.1 all problems reported in one 400 | IT: *Several problems in one upload are all reported at once* |
| §5.2.2 `CLIENT_CA_IS_LEAF`, `CLIENT_CA_NOT_YET_VALID`, `CERT_EXPIRES_SOON` (30 days) | IT leaf / not-yet-valid / expiring scenarios; UT `TestExpiryWarning_Horizon` |
| §5.2.2 warnings logged at WARN | UT handler log capture (developer to add) |
| S7 client rows never enter the upstream bundle | UT `TestCertStore_ExcludesClientUsageFromCombinedBundle` |
| §4 additive columns with per-dialect upgrade path | UT `TestSQLite_UpgradeAddsCertificateUsageColumns`; postgres/sqlserver by DDL review |

### Decisions taken while writing slice 1 tests

- **DELETE of a client row returns the existing `200` body, not `204`.** §8.13 lists `204`, but §5.2
  says platform conventions win where one exists, and the endpoint returns `200` with a JSON body
  today. One handler, one contract. Flagged to the author.
- `referencedByApis` is present only on `usage: client` items; upstream items are byte-compatible
  with today's response apart from the new `usage` field.
- Upload body cap is a constant 1 MiB, enforced with `http.MaxBytesReader`; no configuration key.
