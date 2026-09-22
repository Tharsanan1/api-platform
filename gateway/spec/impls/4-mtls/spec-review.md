# Review: `spec.md` — Mutual TLS for the API Platform Gateway

**Reviewed:** `gateway/spec/impls/4-mtls/spec.md` (784 lines) against `research.md`, the `mtls` worktree, the `gateway-controllers` clone, Envoy v1.38.0/v1.39.0 docs, and Envoy v1.39.0 source (`source/common/tls/cert_validator/default_validator.cc`, `source/extensions/filters/common/expr/context.cc`).
**Reviewer posture:** adversarial. Everything below is ranked by impact. Code claims cite `file:line`; anything I could not confirm is marked UNVERIFIED.

---

## Verdict

The architecture is right and the spec is unusually honest about its own risks, but it is **not yet buildable as written**. The four load-bearing decisions (D1 hybrid inbound, D6 outbound-is-transport, D7 new tables, D8 key-to-SDS) are sound and verified against the code. What is missing is the *identity model underneath D4/D5*: the spec never states how a pinned (default-mode) certificate gets through Envoy's handshake-level validation context at all; CA mode has a cross-org identity-confusion hole because the trust bundle is listener-wide and the policy only ever sees the leaf; thumbprint pinning breaks on every renewal and the spec is silent on rotation; and the "uniform 401" requirement (S2) is impossible by construction once Envoy rejects at the handshake, which the spec's own §2.7 expects it to. Separately, the CP-connected deployment (where applications and API keys arrive by platform events) is not designed for at all, so G2 is only delivered for standalone gateways, and not at all for CA mode. Two of the spec's premises also look wrong: the M0-1 spike is resolvable from Envoy source today (I did it — request-and-validate is real), and the §2.7 "fleet skew" floor is built on an operator config key that no operator code appears to read. Fix B1–B6 and the spec is solid enough to start M0/M1 on.

---

## Blocking findings

### B1. Pinned mode (the default) has no handshake story — a pinned leaf that does not chain to the listener bundle never reaches the policy

**What's wrong.** D2 configures a validation context on the shared listener. Envoy v1.39.0 sets `verify_mode = SSL_VERIFY_PEER` the moment `trusted_ca` is non-empty (`default_validator.cc`, `initializeSslContexts`: `verify_mode = SSL_VERIFY_PEER; verify_trusted_ca_ = true;`). With `SSL_VERIFY_PEER`, a *presented* certificate that fails chain verification fails the handshake. So in **pinned mode** — the spec's default (§2.3: "Pinned mode (default): identity is the SHA-256 thumbprint of the leaf") — the leaf must chain to something in `gw_client_ca_certificate`, or Envoy rejects it before `mtls-auth` ever runs. The spec's pinned-mode YAML (§3.2, `clientIdentities: [{thumbprint, applicationId}]`) has no CA reference and the spec never says what the listener bundle must contain for a pinned client.

**Why it matters.** The canonical pinning use case is a self-signed or partner-issued leaf with no shared CA. Under this design either (a) every pinned leaf (or its issuer) must be uploaded to the *listener-wide* client-CA bundle — an SDS push to the listener per client onboarding, and it works only because BoringSSL is given `X509_V_FLAG_PARTIAL_CHAIN` (same source block), an undocumented reliance; or (b) the listener is set to `trust_chain_verification: ACCEPT_UNTRUSTED`, which flips `verify_mode` to `SSL_VERIFY_PEER` *without* failing on chain errors — and then expiry, chain and CA checks all move into the policy, `connection.peer_certificate_valid` becomes load-bearing (contradicting §2.7), and the "Envoy validates" half of the D-B argument (§2.1) evaporates. The spec has chosen neither; the design cannot be implemented without choosing.

A related trap worth writing down: Envoy's own pinning fields (`verify_certificate_hash`, `verify_certificate_spki`) set `verify_mode = verify_mode_validation_context` = `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` (same source), i.e. they silently make the client certificate **mandatory** on the listener regardless of `require_client_certificate: false`. If anyone later "optimises" pinning into the validation context, D2 breaks.

**Fix.** State explicitly: pinned mode requires the leaf's issuer (or the self-signed leaf itself) to be present in `gw_client_ca_certificate`; make the management API reject a `clientIdentities[].thumbprint` whose certificate cannot be chained to the current bundle (require the PEM at registration, derive the thumbprint server-side, never accept a bare hash). Add the negative test: "pinned thumbprint whose issuer is not in the bundle → TLS handshake failure, not 401". Document the `verify_certificate_hash` trap next to D2.

### B2. S2 "uniform 401 for every rejection" is impossible by construction, and §9.3/§9.4 assert tests that cannot pass

**What's wrong.** §8 S2: "unknown CA, expired, wrong SAN, not-allowlisted all return the **same** 401 body. Otherwise the trust store is enumerable." §9.3 lists "Expired / not-yet-valid → 401", "untrusted CA → 401", "Self-signed → 401", "Chain deeper than `max_verify_depth` → 401". §9.4: "Response body and **timing** for 'unknown CA' vs 'known CA, unknown thumbprint' are indistinguishable."

But §2.7 itself expects — and Envoy source confirms (B1) — that an invalid presented certificate is rejected **at the handshake**. Those clients receive a TLS alert and no HTTP response. Only "valid chain, not in allowlist / SAN mismatch" reaches the policy and gets a 401. Unknown-CA vs unknown-thumbprint are therefore *always* distinguishable: one is a TLS alert, the other an HTTP 401. Research §4.6 (D-A bullet 4) already made this point: "TLS-layer rejection produces no HTTP body … there is nothing to unify." The spec dropped it.

**Why it matters.** Half of §9.3's rejection matrix and the §9.4 enumeration test are unwritable as specified; an implementer will either "fix" them by moving to `ACCEPT_UNTRUSTED` (see B1's consequences) or quietly delete them.

**Fix.** Split S2 into two layers: (i) *handshake-layer* rejections (chain, expiry, depth) — TLS alert, no body, and accept that CA membership is observable at the TLS layer (it is also advertised in the TLS 1.2 `CertificateRequest` CA list; Envoy has a suppress-client-CA-list option — visible as `suppressClientCaList()` in the same source file — consider enabling it); (ii) *policy-layer* rejections (not allowlisted, SAN mismatch, no cert presented) — one uniform 401. Rewrite §9.3 and §9.4 accordingly; the trust-store-enumeration test becomes "known-CA/unknown-thumbprint vs known-CA/wrong-SAN are indistinguishable".

### B3. CA mode has a cross-org identity-confusion hole: the trust bundle is listener-wide, the policy only sees the leaf, and issuer-DN matching is spoofable by any other CA in the bundle

**What's wrong.** Under D2 there is exactly one client-CA validation context for the listener (`SecretNameDownstreamClientCA`, §3.1(2)), built from *all* rows of `gw_client_ca_certificate` across *all* organisations. An API's `trustedCAs: ["ca-uuid-1"]` (§3.2) therefore cannot be enforced at the handshake — any cert from any uploaded CA passes — and must be re-established in `mtls-auth`. The policy's inputs are `connection.subject_peer_certificate`, `connection.peer_certificate` and the singular SAN attributes. `connection.peer_certificate` is the **leaf only, not the chain** (`context.cc`, `SslExtractorsValues`: `info.pemEncodedPeerCertificate()`). So "was this leaf issued by ca-1?" can only be answered by (a) comparing the leaf's Issuer DN string to ca-1's Subject DN, or (b) `leaf.CheckSignatureFrom(ca1)` — which works only when ca-1 is the *direct* issuer, because the policy has no intermediates.

Option (a) is exactly the collision the spec forbids for subjects ("Never CN alone, never Subject DN string equality", §2.3) but silently permits for issuers. Attack: org B uploads a CA whose Subject DN equals org A's CA Subject DN. Org B issues a leaf; the handshake passes via B's chain; `mtls-auth` on org A's API compares issuer DN → "issued by ca-1" → accepted. The `(issuer, serial)` matcher in D4 has the identical flaw, and serials are only unique *per CA*. S4 ("a certificate widens which rows in the caller's org, never which org") is not met in CA mode, and the §9.4 cross-org test will pass in pinned mode (per-API thumbprints) while the CA-mode variant is never written.

**Fix.** (1) CA-mode enforcement must be a cryptographic check against the *referenced CA certificate*, never a DN comparison: `CheckSignatureFrom` for direct issuers, and for chains with intermediates either forbid (document "referenced CA must be the direct issuer of the leaf") or supply the chain to the policy via the XFCC `Chain` element — which §3.4 already emits with `SANITIZE_SET`, so the policy may read it **only** when `connection.mtls == true` (Envoy overwrote it) and never otherwise. (2) Make `gw_client_ca_certificate` one CA per row (drop `cert_count`), so a row is a verifiable key, not a bundle. (3) Reject an upload whose Subject DN collides with an existing CA row in a different organisation. (4) Add the cross-org CA-mode test explicitly: "CA with identical Subject DN in org B; leaf issued by it presented to org A's CA-mode API → 401".

### B4. D4 thumbprint pinning breaks on every renewal, and the spec has no rotation model — while N2 makes renewals *more* frequent

**What's wrong.** `research.md:134`: leaf pinning "**Breaks on every renewal**; allowlist grows linearly with clients". `research.md:162`: thumbprint "Changes on *every* re-issuance, including renewal." The spec adopts thumbprint as canonical (D4) and says nothing about renewal. Its fallback matcher `(issuer, serial)` also changes on every re-issuance. N2 then replaces CRL with "allowlist-removal plus short certificate lifetimes" — which means *more* renewals, each an outage for a pinned client. The two decisions compound. The `clientIdentities[]` schema (§3.2) is one thumbprint per entry with no overlap window, and neither table in §5 surfaces `not_after` to an operator (research §1.6 cites AWS's exact failure: "doesn't notify you if a previously uploaded certificate expires").

Also incorrect as stated: §2.3 says the thumbprint is "identical to the value RFC 8705 uses". Same digest, different encoding — Envoy's `sha256_peer_certificate_digest` is hex, RFC 8705 `cnf.x5t#S256` is base64url (`research.md:162`). N3 needs a re-encode, not an equality; and the spec must pick *one* canonical storage encoding (the §3.2 example `"sha256:9f86d0..."` is a third format).

**Fix.** Allow multiple thumbprints per application binding (add-new / cut-over / remove-old), or make SPKI the primary pin (survives renewal with key reuse; Envoy exposes `verify_certificate_spki`). Store `not_after` on the binding and warn at a configurable horizon. Define the canonical thumbprint encoding (lowercase hex, no colons, no prefix) and normalise on write. Re-word the RFC 8705 claim.

### B5. G2 is not designed for the platform-connected gateway, and is not delivered at all for CA mode

**What's wrong.** In CP-connected mode, API keys and subscriptions arrive as events from platform-api (`gateway/gateway-controller/pkg/controlplane/events.go:153-170` `APIKeyCreatedEventPayload`, `:294` `SubscriptionCreatedEventPayload`); applications are a CP object (`pkg/models/application.go:25`). The spec puts the cert→application binding inline in the gateway's RestApi definition (`security.mtls.clientIdentities[].applicationId`, §3.2) and never mentions platform-api, the portal, or an event. Research §2.10.7 warned this is "a new resource type on policy-xDS, plus a new table, plus a new management API — not a small increment"; the spec replaced it with policy parameters without saying so or costing the CP side. Result: G2 ("exactly as they do for API-key callers") holds only for standalone gateways where an admin hand-edits the API definition.

Worse, **CA mode has no `applicationId` at all** (§3.2: `trustedCAs` + optional `match`). `subscription-validation` requires `Metadata["x-wso2-application-id"]` (`subscriptionvalidation.go:269-281`) or a `Subscription-Key` header and otherwise returns 403 "no subscription token or application identity provided" (`:284`). So every CA-mode caller is either forbidden or forced onto a header credential — reproducing the §1.3 anti-goal precisely for the CA-trust case. Note also `SubscriptionCreationRequest.applicationId` is optional ("Optional for token-based subscriptions", `management-openapi.yaml:3651`), so even pinned mode only works against subscriptions created *with* an application.

**Fix.** Decide and state the deployment scope of v1 (standalone-only is a legitimate answer, but say it). If CP-connected is in scope, define the platform-api resource and the event (mirroring `APIKeyCreatedEvent`) — and cost it. Give CA mode an application binding (per-`match` → `applicationId`, or an explicit "default application for this CA") or state that CA mode is allowlist-only and does *not* satisfy G2.

### B6. Definition-vs-controller version skew fails **open**: an old controller silently deploys an mTLS API with no mTLS

**What's wrong.** §7 analyses policy-vs-gateway skew (fail-closed — good). It does not analyse definition-vs-controller skew. `BindRequestBody` decodes with `yaml.Unmarshal` / `json.Unmarshal` (`gateway/gateway-controller/pkg/api/handlers/handlerkit/handlerkit.go:61-77`) — unknown fields are dropped, and there is no OpenAPI request validator in the handler chain (no `openapi3filter` usage under `pkg/api`). A RestApi with `security.mtls.enabled: true` POSTed to any controller that predates the feature is accepted and deployed **without** `mtls-auth`, with no error. That is the GO-AUTH-017 failure the spec's own §3.2 says must not happen, one layer up.

**Fix.** Reject unknown fields under `security` (or globally, with a compatibility review), and make the §7 deploy-time capability check cover "this controller understands `security.mtls`" as well as "this gateway populates the certificate". Add the test: "definition with `security.mtls` sent to a controller lacking the feature → 400, never 201".

---

## Significant findings

### S1. The §2.7 "fleet skew" premise appears to rest on dead configuration

The operator deploys the **unified `gateway-runtime` image** (Envoy + policy-engine) via Helm: `kubernetes/gateway-operator/config/gateway_values.yaml:309-312` (`ghcr.io/wso2/api-platform/gateway-runtime`), `kubernetes/gateway-operator/README.md:159,182`. That image is built `FROM envoyproxy/envoy:v1.39.0` (`gateway/gateway-runtime/Dockerfile:24,230`). The `GATEWAY_ROUTER_IMAGE: envoyproxy/envoy:v1.38-latest` key the spec builds on (`config/samples/operator-config.yaml:20`) is **not read by any operator Go code** — the only `Getenv` calls are `WATCH_NAMESPACES`, `GATEWAY_API_GATEWAY_CLASS_NAMES`, `CLUSTER_DOMAIN`, `GATEWAY_API_NODEPORT_ADDRESS_OVERRIDE` (`cmd/main.go:125`, `internal/config/config.go:230-248`). The kompose manifest that names a separate `wso2/gateway-router:latest` container (`internal/controller/resources/api-platform-gateway-k8s-manifests.yaml:266`) is referenced only from `internal/k8sutil/examples/template_usage.go`. UNVERIFIED at runtime (I did not inspect a live cluster), but the evidence says there is one Envoy version in the fleet: v1.39.0.

Consequence: the "hard floor v1.38, avoid v1.39 features" reasoning and the M0-1 → minimum-version coupling are solving a problem that probably does not exist. Keep Q-G as hygiene (delete or pin the stale sample key), but stop letting it shape the design. Avoiding `peer_certificate_valid` is still correct — for the simpler reason that Envoy already rejects invalid certs at the handshake (S2 below), so it is never needed.

### S2. M0-1 is answerable from Envoy source today, and the answer changes M0 from a gate into a confirmation

`default_validator.cc` (v1.39.0): `trusted_ca` non-empty → `verify_mode = SSL_VERIFY_PEER` (request, validate if presented, allow absence); `addClientValidationContext(ctx, require_client_cert)` adds `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` only when `require_client_certificate: true`; `ACCEPT_UNTRUSTED` → `SSL_VERIFY_PEER` with no chain failure. So "request-and-validate" (§2.2) is real and an invalid *presented* cert fails the handshake. The spec's "asserted but not explicitly stated in Envoy's docs" is accurate about the docs (I confirmed the `require_client_certificate` doc says only "If specified, Envoy will reject connections without a valid client certificate") but the source is unambiguous. Keep the empirical spike; cite the source in §2.2; drop the "M0-1 decides the minimum Envoy version" framing. Also record `allow_expired_certificate` (sets `X509_V_FLAG_NO_CHECK_TIME`) as a knob that must stay off.

### S3. Per-upstream trust (G5) has no data model and no SDS shape, so M2 is larger than described

§4.1 `tls.trustedCAs: ["ca-uuid-2"]` references — which table? `gw_client_ca_certificate` is defined as *inbound* trust (§5); `certificates` is one flat bundle with a single secret name (`sds.go:34` `upstream_ca_bundle`; `translator.go:2288-2296` hard-codes `SecretNameUpstreamCA`). Per-upstream trust means N validation-context secrets (`upstream_ca:<id>`), a per-cluster reference replacing the single constant, the snapshot gate generalised to arbitrary names, and a decision on whether a per-upstream CA *replaces* or *extends* the global bundle. None of this is in §5/§4.2 or costed in M1/M2. "M2 is independently shippable" is true relative to the SDK/policy train, but M2 as scoped is roughly double what §10 implies.

### S4. `client_validation.enabled: true` with zero uploaded client CAs takes the whole HTTPS listener down — every API, not just mTLS ones

`SDSSecretManager.GetSecret` returns an error when the bundle is empty (`sds.go:92-95`), so the secret is omitted from the snapshot; a listener whose `validation_context_sds_secret_config` names a secret that never arrives stays **warming** and accepts no connections. If instead an empty `trusted_ca` were pushed, Envoy fails to load it ("Failed to load trusted CA certificates", same source) → NACK → frozen last-known-good. Either way, a fresh deployment that enables client validation before uploading a CA is a full outage of `https_port`. S8 only covers `require: true`. Extend S8 to `enabled: true` + empty bundle → refuse to start (or refuse to enable), and add an IT test for the ordering "enable, then upload CA" vs "upload CA, then enable".

### S5. D8 introduces a new failure mode for *every* HTTPS deployment, mTLS or not

Today the SDS manager exists only when `custom_certs_path` is set (`translator.go:124-141`). Moving the listener key to SDS (D8) makes the HTTPS listener depend on SDS unconditionally: a missing or late `Secret_TlsCertificate` = warming listener = outage, for users who never touched mTLS. §4.4 calls this "small". It is small in code and large in blast radius. M1 needs: SDS unconditional; the snapshot gate including the listener-cert secret unconditionally; a golden test "HTTPS listener serves with no `custom_certs_path` after D8"; and an ordering test (§9.5 mentions "SDS push arrives before the listener referencing it" — invert it too).

### S6. The CRD plan for outbound contradicts D6

§6.3 maps `Gateway.spec.tls.backend.clientCertificateRef` → "outbound identity". That field is **per-Gateway**: one client certificate for every backend — i.e. Option U-B, which D6 explicitly rejects ("presents the same identity to every backend"). Per-upstream identity in Gateway API would live on `BackendTLSPolicy` (GEP-1897), which in the vendored v1.5.1 has no client-certificate field (UNVERIFIED — check `apis/v1alpha3/backendtlspolicy_types.go`). Either scope the CRD surface for M2 to "not in v1" or define a `UpstreamDefinition`-level CRD field; do not present the GEP-91 backend field as U-A.

### S7. Revocation and rotation are policy-time decisions, but the spec never says the policy re-validates per request

Enforcement lives in `mtls-auth`, so removing a thumbprint takes effect on the next request (good — a real advantage of D-B). But: a CA removed from the bundle does not drop live connections (SDS affects new handshakes; research §4.7 item 12), and with `idle_timeout` 1h (`config.go:719`) a certificate from a revoked CA, or one that expired mid-connection (Q-E), keeps its connection-level identity. The policy has the leaf PEM and can check `notAfter` and (per B3) the issuer per request. State that it must, decide Q-E as "policy re-checks validity per request", and bound `max_connection_duration` on the listener when client validation is enabled.

### S8. §7 capability negotiation may be over-scoped for this feature

Because the controller *generates* the `mtls-auth` attachment (§3.2) and the runtime image ships policy-engine + controller in lockstep (`README.md:182`: "Keep gateway-controller and gateway-runtime on the same version"), the dangerous "new policy + old gateway" row arises only if an operator pulls a newer `mtls-auth` into an older `gateway-builder` build — a build-time act, not a deploy-time one. A far cheaper v1 mitigation is: `mtls-auth` declares a minimum `sdk/core` that the kernel *also* stamps into `SharedContext` (or a build-time check in `gateway-builder` that the kernel version ≥ the policy's requirement), plus the existing fail-closed behaviour and a loud, rate-limited kernel log. Generic capability negotiation can remain a platform item (Q-C). The spec should present this option and cost both.

### S9. Composition (G3) is under-specified where it matters: ordering and metadata ownership

§3.3 says "`mtls-auth` runs before `jwt-auth`" as if free. Ordering of a controller-generated attachment relative to user-attached API-level policies is not defined anywhere in the spec (prepend? fixed slot?). And `Metadata["x-wso2-application-id"]` has two producers once `api-key-auth` and `mtls-auth` are both attached — last writer wins, and `subscription-validation` reads the `Subscription-Key` header *before* metadata (`subscriptionvalidation.go:227-233`), so a valid-cert caller sending a stale header is refused on the header path. Define: generated auth attachments are prepended; two application-id producers on one chain is a deploy-time error; document the header precedence.

### S10. Multi-org on one listener is assumed but never stated

Both tables carry `organization_id` (§5) and S4 is written in org terms, yet the listener validation context is one bundle for all orgs (B3) and `clientIdentities` are per-API. The spec should say plainly whether one gateway serves multiple organisations on the data plane and, if so, which of its controls are org-partitioned (thumbprint allowlists: yes, by construction; CA trust: no, until B3 is fixed).

---

## Minor findings / nits

- §1 bullet 3: "restated in §5.1 here" — there is no §5.1; D6 is §2.5. N1 and §3.4 point to "§9.6 for the deny test"; §9.6 is Performance, the XFCC tests are in §9.4. Open questions run Q-A…Q-E, Q-G, Q-F.
- §9.2 lists "`PeerCertValid: false` → deny" as a required unit test; §3.1(5) says "deliberately no PeerCertValid field". One of them is wrong.
- §2.4 / research #16 say `"x-wso2-application-id"` is duplicated in "two" modules. It is in six: `api-key-auth/apikey.go:38`, `subscription-validation/subscriptionvalidation.go:20`, `semantic-cache/semanticcache.go:50`, `llm-cost-based-ratelimit/llm_cost_based_ratelimit.go:613`, `token-based-ratelimit/token_based_ratelimit.go:286` (all in gateway-controllers) and `gateway/system-policies/analytics/analytics.go:30`. The constant promotion must cover all six. Separately — and out of scope but worth a ticket — `analytics.go:187` reads the application id from a request **header**, not metadata, so a client can label its own analytics; mTLS attribution (G2 "analytics") must go through metadata.
- §3.1(4): "`ExtProcOverrides.request_attributes` is marked `[#not-implemented-hide:]`" — UNVERIFIED; the v1.39.0 ext_proc docs simply show no such field, which is consistent. The practical point stands: attributes are filter-wide.
- §9.6: `connection.peer_certificate` is the full leaf PEM on every request from any cert-presenting client on the listener, including non-mTLS APIs, and is forwarded again to the Python bridge (`bridge_execution.go:57,80`). Since the knob is filter-wide, decide up front whether the PEM is requested at all in v1 (B3's signature check needs it; pinned mode does not).
- S3 constant-time comparison: a thumbprint is not a secret (the certificate is public; possession of the key is what is proven), and a map lookup keyed by thumbprint is not constant-time anyway. Harmless, but do not let it drive the data structure; the meaningful S3 content is "canonicalise, never substring/DN-string-compare".
- §9.5 "Renegotiation / post-handshake auth attempt over h2 → rejected (RFC 8740)": not testable with standard clients and true by construction in BoringSSL; mark as such or drop.
- §9.5 "Connection coalescing" test: under the shipped single-listener design there is nothing to bypass; the test only proves N4 was a good call. Fine to keep, but say that.
- §5 `gw_client_ca_certificate.certificate` "PEM bundle … `cert_count`": conflicts with B3's need for one verifiable CA per row.
- §6.1 TOML example uses `require  = false` (two spaces) — cosmetic.
- §2.1 table header "In v1.38?" while the prose says "verified against the v1.39.0 attribute reference". I checked both: every listed attribute is on the v1.38.0 page except `peer_certificate_valid`, which is v1.39.0-only. The table is correct; the header is just confusing.

---

## What the spec gets right

These are verified and can stop being re-examined:

- **D6 / §2.5 asymmetry is sound.** There is no `ext_proc` hook on upstream connection establishment; the client certificate is a property of the pooled connection and lives on the cluster `transport_socket` (`translator.go:583-596`, `:2540-2558`). The one refinement: Envoy can select a `TransportSocketMatch` per **route** via route metadata (not only per endpoint), so "per-route identity" is expressible — but still by the controller choosing a match, never by a policy. The spec's "only by selecting a different cluster" is a hair too narrow but the conclusion holds.
- **D1 / D-B and rejecting D-A and D-C2 (N4).** RFC 8740 + `h2` ALPN (`translator.go:2448`) does make negotiation coarse; the coalescing argument against SNI chains is correct.
- **The Envoy attribute table (§2.1)** is exact against the v1.38.0 and v1.39.0 attribute references, including the singular-SAN caveat (`context.cc`: `uriSanPeerCertificate()[0]`, `dnsSansPeerCertificate()[0]`) and the v1.39-only `peer_certificate_valid`.
- **The code-level bites are real:** snapshot gate scans clusters only (`translator.go:2368-2393`); ext_proc requests only `xds.route_name` (`translator.go:3204`, read at `extproc.go:774-790`); listener key inlined in LDS (`translator.go:2403-2420`); cert-store fail-open (`translator.go:133-140`); SDS serves one secret (`sds.go:34,97-110`); no `ForwardClientCertDetails` anywhere in the translator; `DownstreamContext` has one field (`context.go:37-39`; proto `python_executor.proto:209-211`); the accessor fallback posture is documented as deliberate non-fail-closed (`context_accessors.go:43-49`) — the spec's inversion for certificates is exactly right.
- **The api-key → application → subscription chain (D5)** works as described: `apikey.go:244-257` sets `AuthContext` + `Metadata[applicationIDMetadataKey]`; `subscriptionvalidation.go:269-281` reads it and `:374-390` validates by `(apiID, appID)`. Reuse holds for pinned mode in standalone deployments (B5 covers where it does not).
- **D7 new tables, D8 key-to-SDS, §4.5 fail-closed** are the right calls and correctly grounded in `db-schema-changes.md` and `go-control-plane-xds-security.md`.
- **Fail-closed nil accessor, structural enforcement (§3.2), `SANITIZE_SET` (§3.4), forged-XFCC test from day one** — all correct and correctly tied to GO-AUTH-001/017.
- **Test PKI as a prerequisite** is right, and feasible: the IT suite already drives HTTPS on 8443 with a custom transport (`gateway/it/state.go:143`, `setup.go:458`), so client-cert steps are an incremental addition.

---

## Questions the spec doesn't answer

1. Is v1 standalone-only, or must a cert→application binding exist in platform-api and flow by event? (B5)
2. Does one gateway serve multiple organisations on the data plane, and if so which mTLS controls are org-partitioned? (B3, S10)
3. In pinned mode, what must the listener bundle contain for a self-signed partner leaf — the leaf itself? Who uploads it, and does onboarding a client trigger a listener SDS push? (B1)
4. What is the canonical thumbprint encoding, and are multiple thumbprints per binding allowed? (B4)
5. What does CA mode bind to for subscriptions/quotas when no `applicationId` exists? (B5)
6. Where in the chain is the generated `mtls-auth` attachment placed relative to user-attached policies, and what happens when two policies write `x-wso2-application-id`? (S9)
7. Does a per-upstream `trustedCAs` replace or extend the global upstream bundle, and which table holds it? (S3)
8. Is `connection.peer_certificate` requested at all in v1, given it is filter-wide and per-request? (B3 vs §9.6)
9. Does the policy re-validate `notAfter`/issuer per request, or only at handshake? (S7, Q-E)
10. After D8, what is the startup behaviour of a plain HTTPS deployment if the listener-cert secret is late or missing? (S5)
