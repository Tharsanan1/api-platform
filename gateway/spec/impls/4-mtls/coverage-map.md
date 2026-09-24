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

## Slice 2 — derived listener, mtls-auth skeleton, deploy rules (§3.1.1, §3.1.4 steps 1–4, §3.1.5, §3.1.6, §3.1.8, D8, §5.2.1 accept rows, §5.2.2)

| Spec case | Test |
|---|---|
| §3.1.5 listener asks iff an API attaches `mtls-auth`; no switch | IT mtls-listener: *The listener asks for a client certificate only while an API attaches mtls-auth*; UT `TestTranslator_TranslateConfigs_HTTPSListener_*` |
| §3.1.1 request-not-require; ACCEPT_UNTRUSTED never drops (D9) | IT: *Callers of other APIs are not affected…* (no cert, valid, wrong CA, expired, self-signed all 200); *The listener validates against the pool without requiring…*; UT `TestTranslator_CreateDownstreamTLSContext_ClientCARequired`, `TestSDSSecretManager_GetSecrets_*` (ACCEPT_UNTRUSTED) |
| §3.1.8 uniform 401 body, no WWW-Authenticate | IT: *A protected operation denies a caller who presents no certificate with the uniform body*; UT dev-policies/mtls-auth (json/plain/minimal/status) |
| D8 listener key via SDS, never inline | IT: *The listener's private key is delivered as a secret…*; UT `..._ListenerCertViaSDS`, `TestSnapshotReferencesSDSSecret` |
| §3.1.4 (3) snapshot gate covers listener-referenced secrets | UT `TestSnapshotReferencesSDSSecret` |
| §3.1.4 (4) ext_proc connection.* attributes | UT `TestTranslator_CreateExtProcFilter` (attributes subtest) |
| S7 client CA bundle disjoint from upstream bundle | UT `TestSDSSecretManager_GetSecrets_UpstreamAndClientRows_HTTPSEnabled`, `TestCertStore_GetClientCABundle_OnlyClientRows` |
| §3.1.5 deploy refusals: pool empty; accept []; no ca; unknown ca; relay ca; upstream ca; empty/blank SANs; empty/malformed thumbprints; unknown params; twice per scope; API+operation | IT: *Attaching mtls-auth while the pool is empty is refused*; outline *An accept list that cannot select anyone is refused…* (11 rows); *mtls-auth may appear once per scope*; *…both API and operation level is refused*; UT `TestMtlsAuthValidator_ValidateRestAPI_*` |
| §3.1.5 `https_enabled` false → deploy 400 and startup refusal (GO-AUTH-011) | UT `_HTTPSDisabled`, `ValidateMTLSStartupInvariant` (the IT stack always has HTTPS on) |
| §3.1.5 refused deploy leaves listener unchanged | IT: *A refused deployment leaves the listener alone* |
| §5.2.2 `MTLS_ACCEPT_INHERITS_POOL` + resolved echo; `MTLS_ACCEPT_UNNARROWED`; `MTLS_AUTH_NOT_FIRST`; `MTLS_THUMBPRINT_NORMALISED`; no warning for single authority | IT warnings scenarios; UT `ResolveMtlsAuthForResponse` tests |
| §3.1.5 stored config unchanged by resolution | UT (input untouched assertion) |

Decisions taken while writing slice 2 tests: unknown-parameter message is `unknown parameter <name>` generically, with the `thumbprints` hint only for `thumbprint`; warnings and the resolved `accept` echo appear on create/update responses only, not on later GETs.

## Slice 3 — certificate evaluation, trust anchors, forwarded header (§3.1.1, §3.1.2, §3.1.4 steps 4b–6, §3.1.7, §8.15, §8.17)

| Spec case | Test |
|---|---|
| §8.15 API-M rows (nothing, valid, extra SANs, SAN≠U, no SAN, renewed, wrong CA, same CN, same-DN CA, self-signed unpooled, expired, not-yet-valid, serverAuth-only) | IT mtls-auth outline *An API accepting one authority narrowed by URI SAN decides per certificate* (15 rows); UT mtlsauth_test evaluate branches |
| §8.15 API-M chain depth > max | not automated: the listener uses Envoy's default depth, so no fixture exceeds it; revisit if a max_verify_depth is ever configured |
| §8.15 API-P rows (cert ignored, XFCC stripped) | IT outline *A public API ignores whatever certificate arrives…* (6 rows) |
| §8.15 API-T rows (thumbprint; renewed 401 until updated) | IT *An API accepting exact thumbprints…*; *A renewed certificate is admitted once its thumbprint is listed…* |
| §8.15 forged XFCC with/without cert; header stripped | IT *A forged forwarded-certificate header never reaches a backend or stands in for a handshake*; UT SDK accessor never reads headers; UT policy: XFCC read only when MTLS true, chain never becomes a root |
| §8.15 HTTP/1.1 and TLS 1.2 clients; one HTTP/2 connection across APIs | not automated: the request steps open a fresh connection per request; covered by the per-request evaluation design (UT) |
| §8.15 mtls-auth + jwt-auth composition (4 rows, identical 401 bodies) | IT *A certificate and a token are both required when both policies are attached* |
| §8.15 mtls-auth + subscription-validation | slice 4/8 |
| §8.17 Entry A root only (6 rows) | IT outline *A pool entry holding only the root anchors everything the root signed…* |
| §8.17 Entry B root + intermediate (5 rows; Issuer = entry name) | IT outline *…holding the root and its issuing intermediate…*; Issuer asserted in UT |
| §8.17 Entry C intermediate only (5 rows; leaf+intermediate+root row not automated: no such chain fixture) | IT outline *…holding only an issuing intermediate…* |
| §8.17 Entry D self-signed (4 rows) | IT outline *A self-signed certificate pooled as its own authority admits exactly itself* |
| §8.17 cross-entry (4 rows) | IT outline *With the root and the intermediate pooled separately…* |
| §8.17 unit tests: KeyUsages ExtKeyUsageAny; XFCC only when mtls; chain never in Roots | UT mtlsauth_test |
| §3.1.2 D10 per-request re-evaluation | IT *Narrowing the accept list takes effect on the caller's next request* |
| S16 pool membership grants nothing; inheriting API follows the pool | IT *Adding an authority to the pool grants no access…*; *An API that inherits the whole pool follows the pool as it changes*; UT re-push on client upload only |
| §3.1.7 SANITIZE_SET + details; strip on non-mtls routes | IT public-API and per-operation scenarios; UT translator HCM and route tests |
| §3.1.4 (5) SDK DownstreamTLS + fail-closed accessor; proto mirror; kernel population | UT sdk accessor; kernel extractDownstreamTLS; pythonbridge and Python translator |
| §3.1.5 per-operation attachment | IT *Attached to one operation, the policy protects that operation only* |

### Decisions taken while implementing slice 3

- **Pool material reaches the policy inside the policy chain.** The spec did not say how the running
  policy obtains the certificates named by `accept`. The controller resolves each entry into the pool
  row's certificates and adds two engine-internal parameters (`__wso2_internal_mtls_accept`,
  `__wso2_internal_mtls_pool`) to the `mtls-auth` instance when it builds the chain, and re-pushes
  every `mtls-auth` API when a `usage: client` row is uploaded or deleted. The policy engine stays
  free of database access and inheriting APIs follow the pool on the next request.
- The policy engine and the dev policy carry a local `replace` for `sdk/core` (as the repo does for
  `common` and `httpkit`) so the image build compiles against the workspace SDK before it is tagged.
- The legacy per-API translation path (used only when no transformers are wired) has no header
  stripping; production always wires transformers.

## Slice 4 — pool references and revocation levers (§8.4, §8.13 delete rows, S8, S19), header relay (§3.1.3, §5.3, §8.18, S21)

| Spec case | Test |
|---|---|
| §8.13 GET `referencedByApis` counts naming APIs only | IT mtls-pool-references: *The listing counts the APIs that name an authority…*; UT handlers |
| §8.13 DELETE named in `accept` → 409 (S19) | IT: *An authority named in an API's accept list cannot be removed…*; UT |
| §8.13 DELETE referenced only by inheriting APIs → allowed, silent stop | IT: *An authority referenced only by inheriting APIs can be removed…* |
| §8.13 DELETE last authority while mTLS APIs exist → 409 (S8) | IT: *The last client authority cannot be removed…*; UT |
| §3.1.3 last relay entry deletable | IT: *A relay entry can be removed even when it is the last one…* |
| §8.13 upstream row DELETE unchanged | IT: *An upstream trust certificate keeps today's removal behaviour* |
| §8.4 revoke by removing a SAN; by removing an entry; thumbprint cut-over; renewed 401 until listed | IT: *Removing one SAN…*, *Removing one partner's entry…*, *A thumbprint cut-over…*; slice 3 thumbprint scenarios |
| §8.4 pool removal → new handshakes only; inheriting APIs stop silently | IT inheriting-removal scenario (per-request accept resolution makes it immediate in practice) |
| §8.8 same authority twice in `accept`; twice in pool under two names | IT: *Listing the same authority twice…*, *The same authority pooled under two names…* |
| §8.18 H1–H13, H16, H19, H20 (default config) | IT mtls-header-relay (outline + scenarios); UT mtlsauth_test header relay |
| §8.18 H14, H15 + `HEADER_CERT_BYPASS_ACTIVE` (trust_any) | IT mtls-header-bypass via `make test-mtls-header-bypass` |
| §8.18 H17, H18 (forward_to_backend) | IT mtls-header-forward via `make test-mtls-header-forward` (H17 narrowed: see decision) |
| §3.1.3 relay entry narrowed by `match` | IT: *A relay entry narrowed by SAN vouches only for the proxy carrying that SAN*; UT |
| §3.1.3 header decodings: URL-encoded PEM, PEM, bare base64; garbage → 401 | IT outline rows + garbage scenario; UT (found and fixed the space-joined PEM gap) |
| §5.3 TOML block, defaults, startup WARN | UT config; startup WARN by review |
| §3.1.5 https_enabled false allowed with trust_any | UT validator / startup invariant |
| S21 impersonation via header from a direct partner connection | IT relay outline row (client-valid + header carrying client-wrong-ca → 200 as A) and (client-wrong-ca + header client-valid → 401) |

### Decisions taken in slice 4

- **Forwarding applies only where `mtls-auth` evaluated the header.** No component evaluates the
  header on a public route, so a believed-header forward on a public route (spec H17) is not
  implementable without a kernel-level feature; public routes always strip the configured header.
- **Relay narrowing is stored on the certificate row** (`match_json`, nullable), folded into the one
  additive migration this feature ships (schema 4 → 5).
- `Properties.source` values are `handshake`, `header`, `bypass` (the slice 3 tests said `connection`;
  corrected to the spec's wording).

### Decision taken at the start of slice 5

- **Gateway identities are certificate rows (`usage: identity`), not a separate endpoint or table.**
  The product owner chose to extend the pattern already used for the pool: `POST /certificates` with
  `usage: identity` and a `privateKey`; `PUT /certificates/{id}` rotates an identity and is refused for
  other usages; the key lives in `private_key_ciphertext` (encrypted) on the same table, inside the one
  additive migration; `tls.identity` names such a row. The spec, discussion text, design doc and
  diagram were updated to match.

### Finding during slice 5

- **The upstream URL validators have no SSRF guard today.** The spec (§5.2.4, ssrf-prevention rule)
  assumed a shared private-address/metadata check the TLS test could reuse. None exists in
  `api_validator.go`, `mcp_validator.go` or `llm_validator.go`; they check syntax only. The TLS test
  dials through a new shared helper (`pkg/config/upstream_ssrf.go`). Retrofitting the deploy-time
  validators would add a live DNS lookup to every deploy and is a separate decision; tracked as a
  follow-up, not part of this feature.

## Slice 5 — outbound: identities, upstream tls block, per-upstream trust, sterile 503, TLS test (§3.2, §5.2.4, §8.5, §8.12, §8.13 identity rows, S17, S18, S19)

| Spec case | Test |
|---|---|
| §8.13 identity upload rows (cert+key, chain, mismatch, cert/key only, encrypted key, expired, EKU warning, duplicate, developer 403) | IT mtls-outbound: identity scenarios and the refusal outline; UT gatewayidentity, handlers |
| S17 key never returned (any role) | IT: *An identity is uploaded with its key and the key is never returned*; UT schema-by-key assertions |
| §8.13 PUT rotation, refused for other usages | IT: *An identity is rotated in place…*; UT |
| §8.12 tls block rows: omitted, `{}`, identity missing/not identity, trustedCAs missing/empty/client/identity, http target, mixed targets, inline upstream, unknown key, verifyHostName warning | IT refusal outline, inline scenario, usage-mismatch scenario, warning scenario; UT upstream_tls_validator (incl. TLS_IDENTITY_EXPIRED) |
| §8.5 identity presented and accepted | IT: *The gateway presents the named identity and the backend accepts it* |
| §8.5 identity removed → sterile failure | IT: per-upstream trust and hostname scenarios (503 body); no-identity case returns the backend's own 400 because nginx completes the handshake and refuses at HTTP level |
| §8.5 two definitions, two identities, never crossed | IT: *Two definitions with two identities keep each backend seeing only its own* |
| §8.5 per-upstream trustedCAs replaces the bundle | IT: *Per-upstream trust replaces the gateway bundle for that upstream only* |
| §8.5 verifyHostName true rejects, false connects | IT: *Hostname verification is on by default…* |
| §8.5 rotation: pooled connections finish on old material | UT only (`pooledConnectionsUsingPrevious` reported as 0; not observable in the IT stack) |
| S19 identity / trust certificate named by a deployed upstream → 409 | IT: *An identity or trust certificate named by a deployed upstream cannot be removed*; UT |
| §5.2.4 tls-test results OK, UNTRUSTED_BACKEND, HOSTNAME_MISMATCH, BACKEND_REJECTED_IDENTITY, CONNECT_FAILED; developer allowed | IT: *The TLS test reports what a handshake to the upstream would do* (strict Go backend for the rejection); UT probe against in-test TLS servers |
| §3.2.6 sterile 503 body for UF | IT per-upstream trust scenario; UT LocalReplyConfig on both listeners |
| §3.2.5 cert-store fail-open → startup failure | UT `CertStoreInitError` surfaced from NewTranslator; main refuses to start |
| §3.2.3 key never inline in xDS; encrypted at rest | UT sds (key only inside the identity secret), translator (no inline_bytes) |
| §8.5 several targets under one definition | UT translator (same identity secret per endpoint) |

### Decisions taken in slice 5

- A missing identity or trust row for a referenced cluster degrades only that cluster (its secret is
  skipped and Envoy leaves it warming, sterile 503); listener cert and client-CA bundle failures stay
  fatal to the snapshot.
- Referential-integrity checks consult both the database and the in-memory store.
- The TLS test dials through the repo's shared `netguard` policy, which blocks loopback; a backend
  bound to loopback reports `CONNECT_FAILED`.
- An identity that cannot be loaded makes the TLS test return a sterile 500 rather than dialling
  without a certificate.

## Slice 6 — observability (§3.3, §8.9, §8.16; §5.2.3 dropped, §8.10 noted)

| Spec case | Test |
|---|---|
| §3.3 access log: `sni`, `tlsVer`, `peerSubj`, `peerFp` populated with a certificate, empty without one; `upTlsFail` on a backend TLS failure; text format unchanged | IT mtls-observability: *An accepted certificate is named in the access log…*, *A rejected certificate is an HTTP outcome…*, *A request without a certificate logs the certificate fields empty*, *A backend TLS failure is logged with its reason…*; UT config defaults (five JSON keys present, text format byte-identical) |
| §3.3 analytics: `authType = mtls`, `userId` = subject, no application | IT: *An accepted certificate is named…* (`user_id`, no `applicationId`); UT policy `AuthContext.AuthType == "mtls"`; the analytics system policy stamps auth type generically (its own tests) |
| §3.3 span attributes (`tls.client.*`, `enduser.id`, `mtls_auth.result/reason/matched_entry/source/relayed_by`), never a PEM | UT policy with an in-memory span recorder (allow, each deny reason, header source, bypass); UT executor: a policy receives its own span in `ctx` |
| §3.3 deny reasons `authority_not_accepted`, `san_mismatch`, `thumbprint_mismatch` (most specific failure wins) | UT policy evaluation table |
| §3.3 policy WARN when an `accept` entry names an authority the policy cannot find | UT policy log capture |
| §3.3 / §8.9 `policy_executions_total{policy_name="mtls-auth", status="denied"}` and nothing `mtls-auth`-specific | IT: *A policy deny is counted like any other policy deny and nothing more* |
| §3.3 `certificates_total{usage}`, `certificate_expiry_seconds{cert_id,cert_name}` set at startup and after every write, series removed on delete | IT: *Certificate gauges follow the pool…*; UT metrics refresh |
| §8.9 an invalid certificate is a `401` with `peerSubj`/`peerFp` and in analytics | IT: *A rejected certificate is an HTTP outcome…* |
| §8.9 expiry: `CERT_EXPIRES_SOON` in the response, WARN in the controller log, gauge set | IT: *Certificate gauges follow the pool and expiry is warned on every channel*; UT daily sweep (one WARN per certificate per run) |
| §8.16 every warning `code` is from the closed set | UT: every code the controller can emit is in the OpenAPI `enum` |
| §8.16 no private key in any response | already covered (S17) |
| §5.2.3 `GET /tls/handshake-failures`, `tls_handshake_failures_total` | dropped — see decisions |
| §8.10 performance items | not automated here: measured in the performance environment before any default changes |

### Decisions taken in slice 6

- `GET /tls/handshake-failures` and `tls_handshake_failures_total` are dropped from the feature.
  With accept-untrusted, every certificate outcome is an HTTP outcome; what still dies before HTTP
  (protocol version, cipher or ALPN mismatch, malformed ClientHello, resets) is unrelated to mTLS and
  fails identically on a listener without it. Envoy's per-listener `ssl.*` stats already count those.
  Per-connection handshake diagnostics, if wanted, are a separate feature for every HTTPS listener.
- Gateway identities are certificate rows, so there is no separate identities gauge:
  `certificates_total{usage="identity"}` is the count. The gauge's never-populated `type` label is
  renamed `usage`.
- Expiry warnings are logged by a daily sweep (also run at startup) rather than throttled from the
  listing handler; the listing keeps returning the warning in the body.
- The policy receives its own span through `ctx`, so it sets attributes with the OpenTelemetry API
  and the executor stays generic.
- Span attributes are unit-tested: the integration stack runs without a trace collector.
- The analytics publisher used by the test stack exports the user id but not the auth type, so the
  auth-type assertion is a unit test; the integration scenario asserts the user id and the absence of
  an application.
- The integration stack's router access log switches to the JSON format so the five fields can be
  asserted; no scenario depended on the text format.
- Go- and Java-style TLS clients withhold a certificate whose issuer is not among the authorities the
  listener names in its CertificateRequest (the pool), so the gateway sees no certificate at all
  and the policy reports `no_certificate`; curl and OpenSSL-based clients present it and the policy
  reports `untrusted_chain`. Both end in the same 401. The integration client presents its
  certificate unconditionally so the accept-untrusted verdict path is exercised. Worth a line in the
  user documentation: which reason an operator sees for a foreign certificate depends on the client.
- Envoy renders an empty access-log operator as JSON `null`, not an empty string; the
  no-certificate scenario asserts `null`.
- `policy_executions_total` gains the `status="denied"` value for a policy that short-circuits with
  an immediate response (previously every executed policy counted as `executed`); this applies to
  every policy, not only mtls-auth.
- The warning `code` fields in the OpenAPI document are closed enums; a unit test checks every code
  the controller can emit is listed.

## Hardening — fail-closed gaps found in review (§3.1, §5.2, §8.11, §8.12, §8.13, S16, S20, S21)

| Case | Test |
|---|---|
| `accept` given as an object, a bare-string entry, scalar `thumbprints` or `uriSANs`, `match: {}`, scalar `match` are refused with the offending path | IT mtls-listener refusal outline (six new rows); UT validator table |
| `executionCondition` on mtls-auth is refused | IT: *mtls-auth cannot be made conditional*; UT |
| a pool holding only relay entries counts as empty | IT: *Attaching mtls-auth while the pool holds only relay entries is refused*; UT |
| relay upload: unknown body field, unknown `match` field, `match: {}`, scalar SAN list are refused and nothing is stored | IT mtls-client-ca-pool: *A relay upload with a narrowing the gateway does not understand is rejected*; UT handler |
| identity upload with a private key in the certificate field is refused | IT mtls-outbound refusal row; UT handler |
| mtls-auth on LLM and MCP kinds is refused | UT policy validator |
| a `tls` block asking for trust or hostname verification while `router.upstream.tls.disable_ssl_verification` is on is refused | UT upstream TLS validator |
| certificate delete refuses on a store read failure; chain build fails on a store read failure instead of pushing an empty pool | UT handler; UT transform |
| WebSub and legacy-path routes strip both certificate headers | UT translator |
| the policy refuses a present-but-malformed narrowing at bind | UT policy |
| SDS runs without `custom_certs_path`; a `tls` block against an empty trust bundle is refused at translation | UT translator |
| an empty relay header name in config becomes the default | UT config |

### Decisions taken during hardening

- The certificate store always exists: it backs the listener certificate, client-CA pool and
  identities over SDS, so it no longer depends on `custom_certs_path`. An empty upstream trust bundle
  is a loud WARN, not a startup failure; a database read failure at load is a startup failure.
- The sterile 503 body also covers Envoy's `UC` and `UR` flags, so a backend that accepts the
  connection and then resets it gets the same body as a failed connection.
- `pooledConnectionsUsingPrevious` is removed from the rotation response: the controller cannot
  observe it, and a fabricated zero is worse than no field.
- Expiry warnings are listed for every usage, not only client and identity rows.
- Deploy-time warnings are logged at WARN by the REST API handler.
- SAN and thumbprint comparisons are constant-time.
- The integration client presents its certificate unconditionally; the after-scenario cleanup of
  APIs and certificates applies only to scenarios tagged `@mtls`, because other features share an API
  across scenarios. A rejected mutation no longer pays the propagation wait.
- Not changed here, awaiting product decisions: relay connection with no header; forwarded
  certificate header on a relayed identity; who may name a gateway identity; a revocation denylist;
  pool material per route; certificate events across controller replicas.
