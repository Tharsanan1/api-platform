# Feature Spec: Mutual TLS (mTLS) for the API Platform Gateway

**Status:** Ready for team review — all decisions recorded (D1–D10); one open question (Q-M, §10) with its own options paper
**Branch:** `mtls`
**Scope:** Data-plane mTLS in both directions — client → gateway (inbound) and gateway → backend (outbound)
**Background:** [`research.md`](./research.md) holds the protocol and option analysis this spec draws on; it is not required reading.

---

## 1. Summary

The gateway has no data-plane mTLS in either direction today; its control-plane channels (xDS,
policy-xDS, ext_proc) already use mTLS, so the config vocabulary and identity helpers exist.

This spec covers both directions. They are **not symmetric**:

- **Inbound is part transport, part policy.** Envoy negotiates and validates the certificate;
  a policy decides, per API, whether that identity is acceptable — and records it as an
  `AuthContext`, nothing more (D5).
- **Outbound is 100% transport, 0% policy.** A backend client certificate is presented during
  connection establishment on a pooled connection. `ext_proc` has no hook there and no handle on
  Envoy's upstream TLS context. It cannot be a policy, and `upstream.auth.type` must not gain an
  `mtls` value (D6).

### 1.1 Goals

- G1. A client can authenticate to the gateway with an X.509 certificate, enforced **per API**.
- G2. mTLS is **authentication, and only authentication**. `mtls-auth` establishes *who* is calling
  and records it in `AuthContext`. It does not decide what they may call, how much, or on whose
  account — those are `subscription-validation`'s job, done by its own means (the `Subscription-Key`
  header) exactly as for a JWT-protected API. Passing mTLS contributes nothing toward any other
  policy's check; an API that attaches both requires both, independently.
- G3. mTLS **composes** with existing auth — an API can require a certificate *and* a JWT.
- G4. The gateway can present a **per-upstream** client certificate to a backend that requires one.
- G5. Per-upstream backend **trust** (a private CA for one backend) ships with G4.
- G6. Certificates and keys rotate without restarting the gateway or dropping in-flight requests.

### 1.2 Non-goals (this increment)

- N1. **Trusting a certificate forwarded in a header from an upstream proxy.** This is a real and
  common topology (ALB/CDN terminates TLS), but a single code path that accepts "cert from
  handshake OR from header" is the canonical way this feature becomes an auth bypass. It will be a
  *separate policy* with its own hop-authentication design — a later increment — so that no code
  path in `mtls-auth` can ever read a header. See §8.7 for the deny test that must exist from day one.
- N2. **CRL (Certificate Revocation List) based revocation.** Envoy accepts a CRL as supplied data but will not fetch or refresh
  it; making that work is control-plane machinery (fetch, validate `nextUpdate`, push via SDS).
  Revocation in v1 is allowlist-removal plus short certificate lifetimes. Reassess in v2.
- N3. **RFC 8705 certificate-bound access tokens** (`cnf.x5t#S256`). Cheap *once* inbound lands
  (the thumbprint is already computed) — but it is a distinct feature with its own IdP dependency.
  The inbound design below deliberately makes it a small follow-on, not a rewrite.
- N4. **Per-SNI filter chains.** HTTP/2 connection coalescing lets a client
  open a connection under hostname A and send `:authority: B`, bypassing the chain selected at
  connection time. GEP-91 declares per-route client validation a non-goal for exactly this reason.
  We do not build it.

---

## 2. Decisions

Each decision states what was chosen and why.

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | Inbound shape | **Listener requests, policy enforces per API** | Per-listener all-or-nothing; per-SNI filter chains |
| D2 | Inbound negotiation mode | **Request, do not require** — validate if presented, accept the connection when absent | Always `require` |
| D3 | Optional dedicated mTLS port | **Yes, M4** — for deployments that can't tolerate browser cert prompts | Mandatory second port |
| D4 | Client identity | An `accept` entry: **issuing authority** (cryptographically verified), optionally narrowed by **SAN** and/or **SHA-256 thumbprint**. Both narrowings ship in v1 | Subject DN or CN as primary; `(issuer, serial)` |
| D5 | Cert → what? | **An `AuthContext`, nothing else.** No application, no subscription, no metadata another policy consumes | Binding to an application |
| D6 | Outbound shape | **Per-upstream keypair via SDS**, on a new `Upstream.tls` block | `upstream.auth.type: mtls`; a single gateway-wide identity |
| D7 | Trust/key storage | **New tables**, not the frozen `certificates` table and not the `secrets` store | `usage` column on `certificates`; identities as `{{ secret }}` values |
| D8 | Listener private key | **Move to SDS** as part of this work | Leave inlined in LDS |
| D9 | Invalid client certificate | **Envoy validates and drops at the handshake** — the policy only ever sees "no certificate" or "valid certificate" (§3.1.1) | Forward the verdict to the policy via `ACCEPT_UNTRUSTED` + `connection.peer_certificate_valid` |
| D10 | Propagation of changes | **The policy re-evaluates `accept` and `notAfter` on every request**; pool changes reach new handshakes only. No connection-duration bound is added (§3.1.2) | A new `max_connection_duration` listener setting |

The rationale for each decision, including what was rejected and why, is in Appendix A.

---

## 3. Implementation

Both directions, in dependency order, then the observability that spans them. Inbound (§3.1) is
part transport, part policy; outbound (§3.2) is transport only (D6). Each ends with the response its
own component returns to the caller. §3.3 names the metrics, traces, access-log fields and analytics
the feature emits, almost all through rails that already exist.

### 3.1 Inbound (client → gateway)

#### 3.1.1 What Envoy gives the policy, and what the policy must establish itself

**Negotiation is coarse; enforcement is fine (D1).** Envoy asks every connection on the listener for
a certificate and validates whatever is presented; the policy decides, per API, whether that identity
is acceptable.

`ext_proc`'s `request_attributes` draws from Envoy's general attribute set, and Envoy v1.39.0
(`gateway-runtime/Dockerfile:24`, see §6) exposes the full `connection.*` peer-certificate family:

| Attribute | Type | Note |
|---|---|---|
| `connection.mtls` | bool | TLS applied **and** peer cert presented |
| `connection.peer_certificate` | string | PEM-encoded peer certificate (leaf only) |
| `connection.sha256_peer_certificate_digest` | string | compared against an entry's `thumbprints` (D4) |
| `connection.subject_peer_certificate` | string | Subject field |
| `connection.uri_san_peer_certificate` | string | **first URI SAN only**, not a list |
| `connection.dns_san_peer_certificate` | string | **first DNS SAN only**, not a list |
| `connection.tls_version` | string | |
| `connection.requested_server_name` | string | |
| `connection.peer_certificate_valid` | bool | v1.39+. Always `true` when a certificate is present under D9; requested as defence in depth only |

The SAN attributes are **singular** — Envoy documents them as "the first URI/DNS entry in the SAN
field". Any logic needing the full SAN set must parse `connection.peer_certificate` instead.

The certificate therefore reaches the policy engine as an **Envoy-asserted attribute on the
connection**, not as a request header. A client cannot forge it, and there is no
header-sanitization trust boundary to get wrong.

**An invalid certificate never reaches the policy (D9).** Envoy verifies the chain at the handshake.
A presented certificate that **fails** that verification — untrusted authority, expired, not yet valid, depth
exceeded, wrong key usage — fails the handshake with a TLS alert and never reaches the policy. The
policy therefore only ever sees "no certificate" or "valid certificate", and decides only whether
that valid identity is acceptable to this API. `TrustChainVerification` stays at Envoy's default.
Self-signed pooled leaves rely on `X509_V_FLAG_PARTIAL_CHAIN` — verify in M0.

Consequences, all deliberate:

- No X.509 chain code in a policy. Junk dies at the handshake at no downstream cost.
- **Handshake-layer rejections produce no HTTP response, no analytics event and no access-log
  entry.** This is inherent to the choice and is why S2a/S2b are separate requirements (§7), why
  §8.15 distinguishes "TLS fail" from `401`, and why `GET /tls/handshake-failures` exists (§8.9).
- Per-API trust is re-established in the policy after the handshake (below), because the listener's
  trust bundle is the union of the pool.

`connection.peer_certificate_valid` is still requested and carried (§3.1.3) as defence in depth: a
policy denies on an explicit `false` even though, under this decision, it should never see one.

**Authority verification: the trust bundle is listener-wide.**

Under D2 there is **one** client-CA validation context for the whole listener, built from every
row of `gw_client_ca_certificate` on this gateway. An API's `accept: [{ca: partner-bank-root}]`
therefore **cannot** be enforced at the handshake — any certificate from any uploaded CA passes it
— and must be re-established inside `mtls-auth`.

The policy sees only the **leaf** (`connection.peer_certificate` is `pemEncodedPeerCertificate()`,
the leaf, not the chain). So "was this issued by ca-1?" must be answered cryptographically:

- `leaf.CheckSignatureFrom(ca1)` where the referenced CA is the **direct** issuer, **or**
- build a path from the leaf to the entry's authority with `x509.Verify`: **roots** = the named
  entry's certificate(s); **intermediates** = the client chain from the XFCC `Chain` element
  (§3.1.6) **plus every certificate in the pool** (any entry — they are all trusted anchors at the
  handshake already, so using them as path material widens nothing); `KeyUsages` =
  `ExtKeyUsageAny` (Go's default is `ServerAuth`, which would reject every client certificate). The
  XFCC value is read **only** when `connection.mtls == true`, i.e. when Envoy itself overwrote the
  header under `SANITIZE_SET`. Never otherwise.

This is the shape Envoy's XFCC `Chain` key and Google's `client_cert_chain` header exist for: the
component that validated the chain is not the component that decides, so it forwards the chain.
Requiring every intermediate to be uploaded to the pool instead was rejected because a partner
rotating an intermediate would then 401 every client until an admin acted, even though the
handshake still succeeds.

**Never by comparing the leaf's Issuer DN to the CA's Subject DN.** That is the same collision
class D4 forbids for subjects: a second pooled authority whose Subject DN equals `partner-bank-root`'s
issues a leaf, passes the handshake on its own chain, and a string compare would let `mtls-auth`
accept it on an API that named only `partner-bank-root`. The signature check makes the DN irrelevant,
so a DN collision in the pool is harmless and is not rejected.

Two consequences, both in v1:

- `gw_client_ca_certificate` stores **one authority per row**, so a row is a verifiable key rather
  than an opaque bundle. The row's identity is the certificate that actually issues client
  certificates. Its root is **optional**: an intermediate alone is a complete anchor (the same
  partial-chain reliance as a pooled leaf, M0) and trusts only what that intermediate signed —
  the tightest choice. Adding the root widens trust to every intermediate the root has signed and
  buys zero-touch intermediate rotation. Root-only, with no intermediate, is the shape that fails
  when clients omit their intermediate from the handshake.
- The same-DN-different-authority test in §8.7 is mandatory, not optional.

**Scope is the gateway.** The controller has no organisation concept — every table is keyed by
`gateway_id`, and a gateway belongs to one organisation in the control plane. Pool entry and identity
names are unique per gateway; every admin on the gateway shares one pool, which is safe because pool
membership grants nothing (S16).

#### 3.1.2 The identity model: `accept` entries and the `AuthContext` they produce

An identity is always anchored to an **issuing authority in the pool**, verified
cryptographically — a signature or path check back to the entry named by `ca:`, never a DN
comparison (§3.1.1). Two optional narrowings sit on top of that anchor, and an entry may use either,
both, or neither:

| Narrowing | Compares | Use when |
|---|---|---|
| `match.uriSANs` / `match.dnsSANs` | lists of exact SANs, parsed from the leaf (not Envoy's first-entry attribute, §3.1.1); any listed value matches | the partner runs a PKI and issues many certificates |
| `thumbprints` | list of SHA-256 digests of the DER leaf, lowercase hex, against `connection.sha256_peer_certificate_digest`; any listed value matches | you want *these exact certificates* and nothing else |

An entry with neither accepts any certificate the authority ever issues — a deliberate, documented
choice, and the controller warns when the pool holds more than one authority (§3.1.4).

**`match` semantics.** `uriSANs` and `dnsSANs` are lists of at least one value each; a list matches
when **any** of the certificate's SANs of that type equals **any** listed value (OR within a list).
Both lists in one entry are **AND** — the certificate must satisfy each list present; two entries
express OR. Exact string comparison only — no wildcards, patterns or prefixes (the CORS-rule failure
class). Comparison is against the SAN set parsed from `connection.peer_certificate`, never against
Envoy's first-entry-only attributes. A list is the shape because the revocation lever is then "remove
one value", exactly as for `thumbprints` (§8.4).

**The leaf must chain to the pool — and a self-signed leaf is its own authority.** A validation
context with a non-empty `trusted_ca` makes Envoy set `SSL_VERIFY_PEER`, so a presented certificate
that fails chain verification fails the **handshake** and never reaches `mtls-auth`. Consequences:

- A self-signed client certificate goes into the pool as an authority entry and is named by `ca:`.
  Envoy validates it as a trust anchor (relying on `X509_V_FLAG_PARTIAL_CHAIN` — verify in M0), the
  signature check passes trivially, and removing the pool entry revokes exactly that client.
- Do **not** reach for Envoy's `verify_certificate_hash` / `verify_certificate_spki` to implement
  `thumbprints`. Those fields force `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`, silently making a client
  certificate **mandatory** on the whole listener regardless of `require_client_certificate: false`
  — breaking D2 for every other API. Thumbprint checks belong in the policy.

**Thumbprint mechanics.** Envoy emits hex; RFC 8705's `cnf.x5t#S256` is base64url of the same
digest. Canonical form is lowercase hex, no colons, no prefix, normalised on read of the API
definition so that any of the common spellings compare equal. `thumbprints` is always a list
(minimum one element) because a renewed certificate has a new thumbprint: the entry lists
`[old, new]` for the cut-over window and drops `old` afterwards, so one partner stays one entry.
Because this is configuration rather than a data store, rotation is an edit and a redeploy, not a
registration workflow. `notAfter` of pooled authorities and identities is surfaced 30 days ahead (§5.2.2).

**Two propagation speeds (D10).** `accept` is policy configuration and is evaluated on **every
request**, and the policy re-checks the leaf's `notAfter` against the current time on every request
too — so removing an entry, narrowing a `match`, dropping a thumbprint, or a certificate expiring
mid-connection all take effect on the caller's next request, even over a connection opened before
the change. Pool membership is handshake configuration delivered over SDS and reaches **new
handshakes only**; an open connection keeps its handshake-time trust until the client closes it or
it idles out (`idle_timeout`, default 1h). No `max_connection_duration` is introduced for this. The
operational consequence: to cut off one client *now*, edit `accept`; removing a pool authority is
the slower lever and is documented as such.

**Policy output (D5).** `mtls-auth` writes exactly what `jwt-auth` writes — an `AuthContext` — and,
like `jwt-auth`, nothing that any other policy consumes as a signal:

| Field | Value |
|---|---|
| `Authenticated` | `true` |
| `AuthType` | `"mtls"` |
| `Subject` | the matched URI SAN if the entry has `match.uriSANs`; else the matched DNS SAN; else first URI SAN; else first DNS SAN; else subject DN |
| `Issuer` | the pool entry's name (`partner-bank-root`), not the issuer DN |
| `CredentialID` | the leaf thumbprint, canonical lowercase hex |
| `Properties` | subject DN, issuer DN, serial, `notAfter`, matched entry index |

#### 3.1.3 Component walk

Six components, in dependency order. Steps 3–5 are the cross-repo critical path (§6).

**(1) Controller — listener config, derived.** There is no configuration switch (§3.1.4, §5.3).
`createDownstreamTLSContext` (`translator.go:2396`) gains a client-validation branch that the
translator takes **when at least one deployed API attaches `mtls-auth`**, and not otherwise:

```go
// Pseudocode — shape only. clientValidationNeeded is computed from the deployed APIs,
// not read from routerConfig.
if clientValidationNeeded {
    ctx.CommonTlsContext.ValidationContextType =
        &tlsv3.CommonTlsContext_ValidationContextSdsSecretConfig{
            ValidationContextSdsSecretConfig: &tlsv3.SdsSecretConfig{
                Name:      SecretNameDownstreamClientCA,   // NEW, distinct from upstream_ca_bundle
                SdsConfig: adsConfigSource(),
            },
        }
    ctx.RequireClientCertificate = wrapperspb.Bool(false)   // D2: request, never require
    // D9: TrustChainVerification stays at its default — an invalid cert fails the handshake.
}
```

When the last `mtls-auth` attachment is removed, the branch is no longer taken and the listener
returns to one-way TLS on the next snapshot.

**(2) Controller — SDS.** `sds.go` today serves exactly one secret. It gains:
- `SecretNameDownstreamClientCA` — a second `Secret_ValidationContext`, built from
  `gw_client_ca_certificate` **only**. It must not share a bundle with `upstream_ca_bundle`.
- `Secret_TlsCertificate` support, for §3.2 and for D8.

**(3) Controller — the snapshot-inclusion gate (easy to miss, silent when wrong).**
`ClusterResourcesReferenceUpstreamCASecret` (`translator.go:2368-2393`) scans **clusters** only.
A secret referenced by a **listener** will never be included in the snapshot; Envoy then logs
`Ignoring unwatched type URL … Secret` and the listener sits broken with no validation context.
Generalize it to "is this secret referenced by any accepted resource (cluster *or* listener)".

**(4) Controller — ext_proc attributes.** `translator.go:3204` currently requests only
`xds.route_name`. Add the peer-certificate attributes from §3.1.1. Note
`ExtProcOverrides.request_attributes` is marked `[#not-implemented-hide:]` upstream, so this is
filter-wide, not per-route — which is fine: we always send them, and the policy decides.

**(5) Policy engine + SDK + proto — carry the identity.** Additive only:

```go
// sdk/core/policy/v1alpha2/context.go — additive
type DownstreamContext struct {
    Request *DownstreamRequest
    TLS     *DownstreamTLS   // NEW — nil when the gateway did not populate it
}

type DownstreamTLS struct {
    MTLS               bool   // connection.mtls — TLS applied AND a peer cert was presented
    SHA256Thumbprint   string // connection.sha256_peer_certificate_digest — canonical identity
    SubjectDN          string // connection.subject_peer_certificate
    FirstURISAN        string // connection.uri_san_peer_certificate — FIRST entry only (§3.1.1)
    FirstDNSSAN        string // connection.dns_san_peer_certificate — FIRST entry only (§3.1.1)
    PeerCertificatePEM string // connection.peer_certificate — parse this for the full SAN set
    TLSVersion         string
    PeerCertValid      *bool  // connection.peer_certificate_valid — defence in depth (D9).
                              // Envoy drops invalid certs at the handshake, so this is true
                              // whenever MTLS is true; a policy still denies on explicit false.
                              // nil means the attribute was not populated.
}
```

Mirror the same field into `python_executor.proto` (`DownstreamContext`, line 209) or every
`pipPackage` policy is blind to it. Note the proto already lags the Go SDK — `SharedContext` has
no `resolved_operation`/`resolution_attributes` — so do not assume parity elsewhere.

**Accessor — and the one place a house convention must be inverted.** The SDK's existing
`downstreamSnapshot` pattern (`context_accessors.go:20-54`) falls back to live request data when
the snapshot is absent. For a certificate that fallback posture is an **auth bypass**. The
accessor must therefore be shaped like the others but fail closed, and say so loudly:

```go
// PeerCertificate returns the Envoy-asserted client certificate for this connection.
//
// UNLIKE DownstreamRequest(), this does NOT fall back to live/header data when the
// snapshot is absent. A nil return means "this gateway did not assert a certificate"
// and callers MUST treat it as authentication failure, never as "no cert required".
// The IDENTITY (the leaf) never comes from a request header. The only header the
// policy reads is X-Forwarded-Client-Cert's Chain element, and only when MTLS is true
// (Envoy wrote it under SANITIZE_SET); its contents are untrusted path material that
// x509.Verify must chain to the named pool entry — never an identity in themselves.
func (c *RequestHeaderContext) PeerCertificate() *DownstreamTLS { ... }
```

**(6) `gateway-controllers` — the `mtls-auth` policy.** Reads `PeerCertificate()`, fails closed on
nil, evaluates the `accept` entries in order per D4, and on the first match writes an `AuthContext`
per D5's table — `AuthType: "mtls"`, `Subject`, `Issuer` (the pool entry name), `CredentialID` (the
thumbprint). It writes **no** shared metadata: no application id, nothing another policy consumes.
On no match, a uniform `401` (S2a).

#### 3.1.4 The user-facing surface: a pool, and a policy that selects from it

Two tiers, governed differently. This split is the design, not an implementation detail.

**The gateway administrator curates a pool.** `POST /client-ca-certificates` adds an authority
that may sign client certificates. The pool is the **handshake boundary** — a presented certificate
must chain to something in it or the connection is dropped before any request exists. Writes are
`admin`; `GET` is `admin, developer`, matching the roles the existing `/certificates` endpoints
already use, and the read matters because a developer cannot reference a pool entry by name
without being able to list it.

**The API developer selects from it.** Attaching `mtls-auth` is the whole action:

```yaml
policies:
  - name: mtls-auth
    version: v1
    params:
      accept:               # OPTIONAL — omitted means every authority in the pool
        - ca: partner-bank-root
```

That selection is the **authorization-to-authenticate boundary**: of the certificates that cleared
the handshake, which ones this API treats as authenticated. It says nothing about subscriptions or
quotas — those belong to `subscription-validation`, which runs independently (D5). The consequence
worth stating plainly is that **adding an authority to the pool never grants access to any API** —
it only makes a certificate eligible to be considered.

**`accept` defaults to the whole pool**, resolved by the controller at deploy time and kept current
as the administrator adds or removes entries. The deploy response echoes the resolved list so the
developer can see what they got. An entry with no `match` and no `thumbprints` accepts anything its
authority ever issued; the controller warns when `accept` is omitted or unnarrowed while the pool
holds more than one authority, because that is the one shape where "whoever the admin trusts" and
"whoever this API accepts" silently become the same set.

**Each entry is one authority plus optional narrowings.** There is no `mode` parameter; the shape
of the entry says what it is:

```yaml
      accept:
        - ca: partner-bank-root                          # anyone this authority issues to,
          match: { uriSANs: ["urn:partner-bank:payments"] } # carrying one of these SANs

        - ca: partner-bank-root                          # these exact certificates from that
          thumbprints: ["9f86d081…"]                     #   authority, and nothing else

        - ca: acme-selfsigned                            # a self-signed leaf, pooled as its
                                                         #   own authority (§3.1.2)
```

Evaluated in order, first match wins. `ca` is always required — the handshake already proved the
chain, but the entry is what says *this* API accepts *that* chain.

**Per-operation enforcement is supported.** The policy attaches wherever any policy attaches — at API
level or under a single operation in `operations[].policies`, the mechanism `dynamic-endpoint`
already uses (`dynamic-endpoint.feature:50-57`). Attached under one operation, only that operation
requires an acceptable certificate; its siblings do not. What cannot be narrowed is the *asking*:
callers on that port are requested for a certificate on every connection (§3.1.1), because
negotiation happens before any request exists. Enforcement is per request; negotiation is per
connection. **One attachment per route.** The controller builds each route's chain by appending
operation-level policies after API-level ones with no de-duplication (`transform/restapi.go`
`buildPolicyChain`), so `mtls-auth` at both levels would run twice and AND the two `accept` lists —
a route no certificate can pass. The controller therefore refuses a deployment whose merged chain
for any route contains `mtls-auth` more than once. To vary `accept` per operation, attach only at
operation level.

**No `security:` block, and no gateway-level switch.** Both are deliberately absent:

- A dedicated `security.mtls` field would duplicate what the policy attachment already says and
  create a state that can disagree with the chain. GO-AUTH-017 is satisfied by the policy configuration
  itself — a policy attached to an API's routes *is* a structural match against the router/policy
  config. An API without the policy is an API without mTLS, which is a valid configuration, not a
  silent failure.
- The listener's validation context is **derived** from deployed APIs, not configured. When any API
  attaches `mtls-auth`, the controller adds the validation context and the union of the pool's
  authorities; when the last such API goes away, it stops. Nothing to switch on, nothing to drift.

**The dependency that does need checking.** `mtls-auth` is the only client-auth policy that needs
something from the transport. The controller must refuse the deployment, with a clear message, when:

| Condition | Why |
|---|---|
| The pool is empty | Nothing could ever validate; the API would deny everything |
| `accept` names an authority not in the pool | Dangling reference — silently denies that partner |
| `router.https_enabled` is false | No TLS listener, so no certificate can ever be presented; every request would 401. The same check runs at **startup**: a controller with `https_enabled: false` and persisted APIs attaching `mtls-auth` refuses to start (GO-AUTH-011) |
| ~~The running gateway does not populate the certificate attribute~~ | Deferred (§6). Interim: fail-closed plus a rate-limited kernel error. |

Each of those is an outage that presents as a misconfiguration, so it is caught at deploy time.

#### 3.1.5 Composition with other auth

`AuthContext.Previous` already models multi-layer auth, so "certificate AND token" needs no new
machinery — attach both policies.

**Chain order is preserved as written.** Policy order is the general contract in this product and
the gateway does not silently rearrange it. `mtls-auth` first is recommended and should be warned
about if reversed, for four reasons: a thumbprint lookup is far cheaper than a signature
verification, so junk traffic is rejected before any asymmetric crypto; RFC 8705 token binding is
only expressible with the certificate established first; `Previous` then reads in the order events
actually occurred; and certificate failures are the harder ones for a caller to self-diagnose.

**Nothing to reconcile between them.** Because `mtls-auth` writes only an `AuthContext` and never
`x-wso2-application-id`, there is no shared metadata for two auth policies to fight over. Each
decides independently; the request must satisfy every one attached.

#### 3.1.6 Forwarding identity to the backend

Set `ForwardClientCertDetails: SANITIZE_SET` on the HCM plus `set_current_client_cert_details`
with `subject`, `uri`, `dns`, `cert` and **`chain: true`** — the chain is what §3.1.1's path
verification consumes. **`SANITIZE_SET`, never `APPEND_FORWARD`** — Envoy overwrites the header, so a
client-supplied XFCC value can never survive. The header is a few kilobytes on connections that
carry a client certificate and absent otherwise; the backend receives the same header (§8.10
measures it). Today the HCM uses Envoy's default (`SANITIZE`) and there are zero
XFCC references repo-wide, so this is net-new and must ship with the forged-header test (§8.7).

#### 3.1.7 The `401` the policy returns

**Identical to `jwt-auth` and `api-key-auth`.** The policy exposes the same three parameters those
policies already have, with the same defaults, and renders the body with the same switch:

| Param | Default | Effect |
|---|---|---|
| `onFailureStatusCode` | `401` | status of every policy-layer rejection |
| `errorMessageFormat` | `json` | `json` → JSON body below with `content-type: application/json`; `plain` → `<errorMessage>` as `text/plain`; `minimal` → the literal `Unauthorized` |
| `errorMessage` | `Authentication failed` | the message text |

Default body, byte for byte:

```json
{"error":"Unauthorized","message":"Authentication failed"}
```

It is the same for **every** cause — no certificate presented, authority not in `accept`, SAN
mismatch, fingerprint mismatch, `notAfter` passed, attribute absent, `PeerCertValid == false` — which
is what S2a requires and §8.15 asserts. No `WWW-Authenticate` header is set: there is no IANA
authentication scheme for client certificates and the sibling policies set none. This follows the
platform's existing wording rather than the literal example in `error-handling.md` d.4; the rule's
requirement is uniformity across causes, which holds.

A handshake-layer rejection (D9) produces **no HTTP response at all** — the client sees a TLS alert
and a closed connection. That is not a body to specify; it is recorded here so nobody looks for one.

---

### 3.2 Outbound (gateway → backend)

#### 3.2.1 Config surface

A new `tls` block on the upstream — **not** a new `upstream.auth.type` value (D6):

```yaml
upstreamDefinitions:
  - name: partner-billing
    upstreams:
      - url: https://billing.partner.example.com
    tls:
      identity: partner-billing-id       # a gateway identity, by name -> gw_gateway_identity
      trustedCAs: [partner-billing-ca]   # per-upstream trust (G5), by name -> /certificates
      verifyHostName: true
```

`tls` belongs to the **definition** and is shared by every target under its `upstreams`. Multiple
targets in one definition are replicas of one backend and therefore one trust relationship; two
targets needing *different* identities are two definitions. References are by name, not UUID — a
human edits this file. The block is valid **only** on an `upstreamDefinitions` entry; on an inline
`upstream.main.url` it is a `400` (§5.2.1), because an inline upstream is one target for one API
while `tls` describes a trust relationship with a backend.

**Fields.** Every field is optional, so `tls: {}` equals omitting the block.

| Field | Type | Default when absent | References | Constraint |
|---|---|---|---|---|
| `identity` | string | no client certificate presented | a `/gateway-identities` entry, by `name` | must exist on this gateway (S18); its certificate is what the gateway presents to this backend |
| `trustedCAs` | list of strings, ≥1 | the gateway-wide backend trust bundle | `/certificates` entries, by `name` | every name must exist (S18); an empty list is `400`; **replaces** the gateway bundle for this upstream, does not extend it |
| `verifyHostName` | boolean | `true` | — | `false` deploys with warning `TLS_VERIFY_HOSTNAME_DISABLED` |

With `tls` present, every target under `upstreams` must be `https://`; a plaintext target is a `400`
naming it, because the translator builds an upstream TLS context only for HTTPS and the block would
otherwise be silently unused (§8.12).

**How a definition is used.** Declaring a definition sends no traffic to it. An API routes to a
definition either by making it the default (`upstream.main.ref`) or per operation with the
existing `dynamic-endpoint` policy (`targetUpstream: <name>`). Once an API has any definitions the
controller switches its routes to cluster-header routing, so every definition is a live cluster and
the choice is made per request (`transform/restapi.go`). Three complete definitions cover the
patterns:

*Whole API behind one mTLS backend — the definition is the default via `ref`:*

```yaml
kind: http/rest
version: 0.1.0
spec:
  displayName: Partner-Billing-API
  version: v1.0
  context: /billing/$version
  upstreamDefinitions:
    - name: partner-billing
      upstreams:
        - url: https://billing.partner.example.com
      tls:
        identity: partner-billing-id
        trustedCAs: [partner-billing-ca]
  upstream:
    main:
      ref: partner-billing
  operations:
    - method: GET
      path: /invoices
    - method: POST
      path: /invoices
```

*Mostly internal, one operation to a partner over mTLS — inline default, one definition, one
`dynamic-endpoint`:*

```yaml
kind: http/rest
version: 0.1.0
spec:
  displayName: Orders-API
  version: v1.0
  context: /orders/$version
  upstreamDefinitions:
    - name: partner-payments
      basePath: /v2
      upstreams:
        - url: https://payments.partner.example.com
      tls:
        identity: partner-payments-id
        trustedCAs: [partner-payments-ca]
  upstream:
    main:
      url: http://orders-service:8080          # internal, default for every operation
  operations:
    - method: GET
      path: /orders
    - method: POST
      path: /orders/{id}/pay
      policies:
        - name: dynamic-endpoint
          version: v1
          params:
            targetUpstream: partner-payments     # only this operation reaches the partner
```

`POST /orders/{id}/pay` reaches `https://payments.partner.example.com/v2/orders/{id}/pay` with the
gateway's certificate presented; `GET /orders` never touches that cluster.

*Two partners, two certificates — two definitions, each its own cluster and connection pool:*

```yaml
kind: http/rest
version: 0.1.0
spec:
  displayName: Settlement-Router-API
  version: v1.0
  context: /settle/$version
  upstreamDefinitions:
    - name: bank-a
      upstreams:
        - url: https://settle.bank-a.example
      tls:
        identity: bank-a-id                  # issued to the gateway by bank A's CA
        trustedCAs: [bank-a-ca]
    - name: bank-b
      upstreams:
        - url: https://settle.bank-b.example
      tls:
        identity: bank-b-id                  # a different certificate, issued by bank B's CA
        trustedCAs: [bank-b-ca]
  upstream:
    main:
      ref: bank-a
  operations:
    - method: POST
      path: /bank-a/transfers                # default
    - method: POST
      path: /bank-b/transfers
      policies:
        - name: dynamic-endpoint
          version: v1
          params:
            targetUpstream: bank-b
```

Bank B's backend only ever sees `bank-b-id`, because the two definitions are separate Envoy clusters
with separate connection pools — the property §8.5 tests.

#### 3.2.2 Translator

`createUpstreamTLSContext` (`translator.go:2234`) gains
`CommonTlsContext.TlsCertificateSdsSecretConfigs` referencing `client_cert:<id>`, attached per
endpoint through the existing `Cluster_TransportSocketMatch` machinery (`translator.go:583`,
`translator.go:2540`) — that machinery already exists for per-endpoint SNI and is the correct
place for per-upstream identity.

Per-upstream **trust** (G5) ships in the same increment deliberately. Shipping per-upstream
identity against a single global trust bundle is half a feature, and the workaround users reach
for is `disable_ssl_verification` — trading an mTLS feature for a downgrade in transport security.

#### 3.2.3 Private key handling

The key never appears in an xDS resource as `inline_bytes`
(`go-control-plane-xds-security.md` directive 3) — it is delivered as an SDS
`Secret_TlsCertificate` only. It is never returned by any read API, never in a config dump, never
logged (GO-AUTH-003), and at rest it is encrypted with the existing `pkg/encryption` machinery.

#### 3.2.4 D8 — fix the existing violation while we are here

`createDownstreamTLSContext` currently reads the listener key and ships the bytes as
`DataSource_InlineBytes` (`translator.go:2403-2420`), so **the listener's private key travels in
LDS today**. That is a standing directive-3 violation. This work adds `Secret_TlsCertificate`
support to SDS anyway, so moving the listener key onto it is small **in code** — but large in
blast radius, and §9 must cost it that way. Today the SDS manager exists only when
`custom_certs_path` is set (`translator.go:124-141`); after D8 the HTTPS listener depends on SDS
**unconditionally**, so a missing or late listener-certificate secret is a warming listener — an
outage for deployments that never touched mTLS. M1 therefore owes: SDS unconditional, the snapshot
gate covering the listener-cert secret unconditionally, a golden test "HTTPS listener serves with
no `custom_certs_path`", and secret-vs-listener arrival-ordering tests in both directions.
Extending that function while leaving the violation in place is not acceptable under
`go-control-plane-xds-security.md` directive 7 (no deferring behind a comment).

#### 3.2.5 Fix the fail-open in the cert-store path

`translator.go:133-140`: if `certstore.LoadCertificates` fails, the store is set to `nil` with a
`Warn` and SDS is silently disabled — leaving Envoy with **no validation context at all**, i.e.
no upstream verification. That is an existing fail-open. Once inbound *client* trust also flows
through this path it becomes considerably more dangerous. Per GO-AUTH-011 it must become a
startup failure that refuses to serve, and it must be fixed in this increment.

#### 3.2.6 A sterile body for backend TLS failures

Today a failed upstream connection returns Envoy's default local reply, whose body reads
`upstream connect error or disconnect/reset before headers. reset reason: …, transport failure
reason: …` — Envoy internals and TLS error text, which `error-handling.md` d.1 forbids. This work
adds a `LocalReplyConfig` mapper on the HCM for `503` responses carrying the `UF` (upstream
connection failure) response flag, replacing the body with:

```json
{"error":"Service Unavailable","message":"The upstream service could not be reached."}
```

with `content-type: application/json`. The original reason stays in the access log
(`%UPSTREAM_TRANSPORT_FAILURE_REASON%`) and in the tls-test (§5.2.4). **This changes the body of an
existing failure class for every API, mTLS or not**; the status code is unchanged. Recorded as a
compatibility note in §6.

### 3.3 Observability

Cross-cutting, so stated once. The feature rides the platform's existing rails wherever one exists;
new signals are limited to two gauges, one counter, five access-log fields and one set of span
attributes. Every item below has a test in §8.9.

**Metrics — policy engine (no change).** `mtls-auth` is a policy, so it is already counted by
`policy_executions_total{policy_name, policy_version, api, route, status}` and timed by
`policy_duration_seconds` (`policy-engine/internal/metrics/metrics.go:142-155`). No `mtls-auth`-specific
request counter is added, matching `jwt-auth` and `api-key-auth`. A deny is `status="denied"` with the
same labels every other policy uses.

**Metrics — controller (new).** Three additions to `pkg/metrics/metrics.go`, shaped like their
neighbours:

| Metric | Type | Labels | Set from |
|---|---|---|---|
| `client_ca_certificates_total` | gauge | — | pool row count, on every write (mirrors `certificates_total`) |
| `gateway_identities_total` | gauge | — | identity row count, on every write |
| `tls_handshake_failures_total` | counter | `reason` (closed enum, §5.2.3) | the same listener-access-log stream that feeds the ring buffer (§5.2.3); incremented once per entry |
| `certificate_expiry_seconds` | gauge (exists, unset) | `cert_id`, `cert_name` | `notAfter` of every pooled authority, identity **and** existing `/certificates` entry (§5.2.2) |

Envoy's own per-listener TLS counters (`ssl.handshake`, `ssl.fail_verify_error`,
`ssl.fail_verify_no_cert`, `ssl.connection_error`) exist regardless and are the cross-check for
`tls_handshake_failures_total` wherever Envoy stats are scraped; the spec adds nothing there.

**Traces.** Both tracers already exist: Envoy's HCM tracing with custom tags (`translator.go:2920`)
and the policy engine's tracer (`policy-engine/internal/tracing`). Envoy custom tags cannot read
connection-level TLS attributes, so the feature adds nothing to the Envoy span. On the **`mtls-auth`
policy span** the policy sets the OpenTelemetry TLS semantic-convention attributes when a
certificate is present, and the decision always:

| Attribute | Value |
|---|---|
| `tls.client.subject` | subject DN |
| `tls.client.issuer` | the **pool entry name**, not the issuer DN (matches `AuthContext.Issuer`) |
| `tls.client.hash.sha256` | canonical thumbprint |
| `tls.client.not_after` | RFC 3339 |
| `tls.protocol.version` | from `connection.tls_version` |
| `enduser.id` | `AuthContext.Subject` |
| `mtls_auth.result` | `allow` or `deny` |
| `mtls_auth.reason` | on deny, one of: `no_certificate`, `authority_not_accepted`, `san_mismatch`, `thumbprint_mismatch`, `expired`, `attribute_absent` |
| `mtls_auth.matched_entry` | index into `accept` on allow |

The reason attribute is for operators; the caller's `401` body never varies (§3.1.7). No private
material and no full certificate is ever a span attribute.

**Access log.** The default **JSON** format (`config.go:1228-1252`) has no TLS field today. Five are
added — additive, so existing consumers keep working:

| Field | Operator | Why |
|---|---|---|
| `sni` | `%REQUESTED_SERVER_NAME%` | which hostname the client asked for (Q-M relies on it) |
| `tlsVer` | `%DOWNSTREAM_TLS_VERSION%` | protocol negotiated |
| `peerSubj` | `%DOWNSTREAM_PEER_SUBJECT%` | which client certificate reached this request; empty when none |
| `peerFp` | `%DOWNSTREAM_PEER_FINGERPRINT_256%` | joins the log line to an `accept` entry and to analytics |
| `upTlsFail` | `%UPSTREAM_TRANSPORT_FAILURE_REASON%` | the reason the sterile `503` (§3.2.6) hides from the caller |

The positional **text** format is left unchanged; adding columns there would shift every existing
parser. Operators on the text format get the new fields by switching to JSON. Recorded as a
compatibility note in §6.

**Analytics (no change).** The analytics system policy already reads `AuthContext` generically and
stamps `x-wso2-auth-type` and the subject as the user id for any authenticated layer
(`system-policies/analytics/analytics.go:221-240`). Because `mtls-auth` writes an `AuthContext` (D5),
every analytics record for a request it authenticated carries `authType = "mtls"` and
`userId = <Subject>` with **zero** mTLS-specific code, and no application is attributed because none
is resolved. A policy-layer deny produces the same analytics record any `401` produces. A
handshake-layer deny produces none (§5.2.3 is the only record).

**Logs.** `mtls-auth` logs a deny at `DEBUG` with `reason`, `subject`, `issuerEntry` and `api` —
the volume posture of the sibling policies — and at `WARN` only for a runtime inconsistency that
should be impossible after deploy-time validation: an `accept` entry naming a pool authority the
policy cannot find. Controller warnings are covered in §5.2.2. Nothing logs a private key, a full
certificate, or an XFCC header value (S6).

---

## 4. Data model

Two new tables (D7). The repo's schema rule (`db-schema-changes.md`, R0-FROZEN) freezes every table
already shipped to customers because there is no migration framework; a **new** table has no
customer data, so the freeze does not apply and it needs only a guarded
`CREATE TABLE IF NOT EXISTS` in each of `gateway-controller-db.sql`, `.postgres.sql` and
`.sqlserver.sql` — **no `ALTER` path required**, since a guarded `CREATE` is correct against both
fresh and already-provisioned databases. Apply R1–R10 via the `designing-db-schemas` skill before
writing the DDL; the shapes below are indicative, not final.

**`gw_client_ca_certificate`** — inbound trust anchors.

| Column | Notes |
|---|---|
| `uuid` | PK, UUIDv7, matching `StoredCertificate` convention |
| `gateway_id` | scoping, as every existing table; PK is `(gateway_id, uuid)`, `UNIQUE(gateway_id, name)` |
| `name` | operator-facing label |
| `certificate` | PEM — **one authority**, optionally with the intermediates needed to build a path to it (§3.1.1). Never several unrelated authorities in one row |
| `subject`, `issuer`, `not_before`, `not_after` | parsed metadata of the issuing certificate |
| `created_at`, `updated_at` | audit |

**`gw_gateway_identity`** — outbound keypairs.

| Column | Notes |
|---|---|
| `uuid` | PK, UUIDv7 |
| `gateway_id` | scoping; PK `(gateway_id, uuid)`, `UNIQUE(gateway_id, name)` |
| `name` | operator-facing label |
| `certificate_chain` | PEM, leaf first |
| `private_key_ciphertext` | **encrypted at rest** via `pkg/encryption`; never returned by any API |
| `key_algorithm`, `subject`, `issuer`, `not_before`, `not_after` | parsed metadata |
| `created_at`, `updated_at` | audit |

Note the PQC sizing rule (`post-quantum-cryptography.md` d.4): these are `BLOB`/`BYTEA`/`TEXT`,
never `VARCHAR(512)`. An ML-DSA-65 signature is 3309 B and chains are unbounded in practice.

**Validation at write time, not first request.** A cert/key mismatch or an already-expired
certificate must be rejected at upload with a clear error, not surfaced later as an opaque Envoy
503. Parse the chain, confirm the key matches the leaf, confirm `notAfter` is in the
future, and confirm the PEM contains what the field claims.

---

## 5. Interfaces

Everything a person touches from outside the gateway: the management API that admins and developers
call (§5.1, §5.2), and the deployment configuration an operator sets before traffic flows (§5.3–§5.5).
The API-definition additions themselves — the `mtls-auth` parameters and the upstream `tls` block — are
specified where their behaviour is, in §3.1 and §3.2.

### 5.1 Management API

Roles follow the pattern the existing `/certificates` endpoints already set — admin writes,
developer reads:

| Endpoint | Roles | Purpose |
|---|---|---|
| `POST /client-ca-certificates` | `admin` | Add an authority that may sign client certificates |
| `GET /client-ca-certificates` | `admin, developer` | List the pool — developers read it to select |
| `DELETE /client-ca-certificates/{id}` | `admin` | Remove an authority |
| `POST /gateway-identities` | `admin` | Add a certificate + key the gateway presents to backends |
| `PUT /gateway-identities/{id}` | `admin` | Rotate one |
| `GET /gateway-identities` | `admin, developer` | List — **never returns `privateKey`, for any role** |
| `DELETE /gateway-identities/{id}` | `admin` | Remove one |
| `GET /tls/handshake-failures` | `admin` | Rejections that never became HTTP requests |
| `POST /rest-apis/{handle}/upstreams/{name}/tls-test` | `admin, developer` | Verify an upstream definition's TLS end to end. Scoped to the API because definition names are unique per API, not per gateway |

Response bodies for every success, warning and failure are fixed in §5.2.

The existing `/certificates` endpoints are **unchanged** and are not listed above; the feature depends
on them because an upstream's `tls.trustedCAs` names entries created there (§3.2.1).
`/client-ca-certificates` and `/certificates` are opposite directions — who may call us, and who we
may call. They are separate resources precisely so that adding a client authority cannot widen
which backends the gateway trusts.

**Deliberately absent:** any endpoint binding a certificate to an application. `mtls-auth` produces
an `AuthContext` and nothing else (D5); the gateway has no `/applications` endpoints and this design
adds none. Subscriptions for an mTLS-protected API are created and enforced exactly as for a
JWT-protected one, through the existing `/subscriptions` endpoints and `subscription-validation`.

### 5.2 Response contracts

Every status code in §8.11–§8.15 resolves to one of the shapes below. Nothing is left to the
implementer; where the platform already has a convention, it is used unchanged. Two audiences: the admin or developer calling the management API (§5.2.1, §5.2.2) and the operator
diagnosing a failure (§5.2.3, §5.2.4). What the **data plane** returns is specified with the behaviour
that produces it: the policy's `401` in §3.1.7 and the sterile backend-failure `503` in §3.2.6.

#### 5.2.1 Management API — errors

**Shape: the existing `ErrorResponse`, nothing new.** Every `400`, `409` and `413` from the new
endpoints uses the schema every existing endpoint uses (`management-openapi.yaml` `ErrorResponse`):

```json
{
  "status": "error",
  "message": "API definition is invalid",
  "errors": [
    { "field": "spec.policies[0].params.accept[1].ca",
      "message": "no client-CA authority named 'partner-bnk-root' exists on this gateway" },
    { "field": "spec.upstreamDefinitions[0].tls.trustedCAs",
      "message": "omit trustedCAs to use the gateway trust bundle, or list at least one certificate" }
  ]
}
```

Rules:

- `message` is one human sentence, never a Go error string.
- Each offending input is one `errors[]` entry. `field` is the full JSON path in the request body.
  Several problems in one request return **all** of them in one `400`, not the first.
- No `message` contains a file path, stack trace, Go type, SQL, Envoy text, or any part of an
  uploaded certificate or key beyond its subject DN and name.
- `401` (unauthenticated) and `403` (wrong role) come from the existing basic-auth middleware,
  byte-identical to today's `/certificates` responses. `413` is the existing generic body-too-large
  response and never states the limit.

**`400` on `POST`/`PUT /rest-apis`.** `field` is the path to the offending line in the YAML the
caller sent, so they can go straight to it. Bracketed numbers are list positions in that document:

```yaml
spec:
  policies:                      # spec.policies
    - name: jwt-auth             # spec.policies[0]
    - name: mtls-auth            # spec.policies[1]
      params:
        accept:                  # spec.policies[1].params.accept
          - ca: partner-a        # spec.policies[1].params.accept[0]
          - ca: partner-bnk      # spec.policies[1].params.accept[1]  <- typo: 400 names THIS path
```

The table below cannot know a caller's positions, so it writes them as letters: `i` a policy, `j` an
`accept` entry, `k` a list item inside an entry, `d` an upstream definition, `u` a target inside it,
`n` an operation. `spec.policies[i].params.accept[j].ca` therefore reads "the `ca` of entry `j` of
policy `i`", and the real response carries the actual numbers.

| Input | `field` | `message` |
|---|---|---|
| `accept: []` | `spec.policies[i].params.accept` | omit `accept` to inherit every pooled authority, or list at least one entry |
| entry without `ca` | `spec.policies[i].params.accept[j].ca` | `ca` is required and must name an authority in this gateway's client-CA pool |
| `ca` not in pool | `spec.policies[i].params.accept[j].ca` | no client-CA authority named `<name>` exists on this gateway |
| pool empty | `spec.policies[i]` | `mtls-auth` requires at least one client-CA authority; add one with `POST /client-ca-certificates` |
| `match.uriSANs: []`, or an empty string in `uriSANs`/`dnsSANs` | `spec.policies[i].params.accept[j].match.uriSANs` (or `…[k]` for the empty element) | list at least one non-empty SAN, or remove `match` to accept any certificate from this authority |
| `thumbprints: []` | `spec.policies[i].params.accept[j].thumbprints` | list at least one fingerprint, or remove `thumbprints` to accept any certificate from this authority |
| malformed fingerprint | `spec.policies[i].params.accept[j].thumbprints[k]` | a fingerprint is the SHA-256 of the certificate as 64 hex characters (colons and a `sha256:` prefix are accepted) |
| unknown param (`thumbprint`, `mode`, …) | `spec.policies[i].params.thumbprint` | unknown parameter `thumbprint`; the field is `thumbprints` |
| `mtls-auth` twice at one scope | `spec.policies[k]` | `mtls-auth` may appear once per scope; use several `accept` entries instead |
| `mtls-auth` at API and operation level | `spec.operations[n].policies[k]` | `mtls-auth` is already attached at API level; attach it at one level only |
| `router.https_enabled: false` | `spec.policies[i]` | `mtls-auth` requires the HTTPS listener, which is disabled on this gateway |
| `trustedCAs: []` | `spec.upstreamDefinitions[d].tls.trustedCAs` | omit `trustedCAs` to use the gateway trust bundle, or list at least one certificate |
| identity missing | `spec.upstreamDefinitions[d].tls.identity` | no gateway identity named `<name>` exists on this gateway |
| trusted CA missing | `spec.upstreamDefinitions[d].tls.trustedCAs[k]` | no certificate named `<name>` exists on this gateway |
| `tls` on an `http://` target | `spec.upstreamDefinitions[d].upstreams[u].url` | `tls` is configured but this target is `http://`; every target of a definition with `tls` must be `https://` |
| `tls` on an inline upstream | `spec.upstream.main.tls` | `tls` is not supported on an inline upstream; move it to `upstreamDefinitions` and reference it |

**`400` on `POST /client-ca-certificates` and `POST`/`PUT /gateway-identities`** — `field` is a
top-level request property.

| Input | `field` | `message` |
|---|---|---|
| two unrelated CAs in one PEM | `certificate` | this PEM contains more than one unrelated authority; upload each as its own entry |
| private key in a CA upload | `certificate` | the upload contains a private key; a client-CA entry accepts certificates only |
| expired certificate | `certificate` | the certificate expired on `<notAfter>` |
| non-PEM or malformed | `certificate` | the value is not a PEM-encoded certificate |
| cert/key mismatch | `privateKey` | the private key does not match the certificate |
| encrypted private key | `privateKey` | passphrase-protected private keys are not supported; upload an unencrypted key (it is encrypted at rest by the gateway) |
| certificate or key absent (identity) | `certificate` / `privateKey` | both `certificate` and `privateKey` are required |
| invalid `name` | `name` | `name` may contain only letters, digits, `.`, `_` and `-` |

**`409`** — `message` states the conflict and the remedy. When the conflict is a reference, each
referencing API is one `errors[]` entry whose `field` is the path **in that API** that holds the
reference and whose `message` names the API:

```json
{
  "status": "error",
  "message": "client-CA authority 'partner-bank-root' is named by 2 deployed APIs; remove those references first",
  "errors": [
    { "field": "spec.policies[0].params.accept[0].ca", "message": "referenced by API 'partner-payments-v1.0'" },
    { "field": "spec.policies[0].params.accept[1].ca", "message": "referenced by API 'partner-reports-v1.0'" }
  ]
}
```

| Conflict | `message` | `errors[]` |
|---|---|---|
| duplicate `name` | a client-CA authority named `<name>` already exists (or: a gateway identity named …) | none |
| authority named in an API's `accept` (S19) | as in the example | one per API, `field` = the `accept[j].ca` path |
| identity named by an upstream (S19) | gateway identity `<name>` is named by N deployed APIs; remove those references first | one per API, `field` = `spec.upstreamDefinitions[d].tls.identity` |
| last authority while mTLS APIs exist (S8) | cannot remove the last client-CA authority while N deployed APIs attach `mtls-auth`; add a replacement first or remove those APIs | one per API, `field` = `spec.policies[i]` |

#### 5.2.2 Management API — warnings

**Shape: one new optional field.** Every resource response already carries a `status` object with
`id`, `state` and timestamps; its OpenAPI schema is named `ResourceStatus`. That object gains
`warnings`, an optional read-only array of `{code, field, message}` — in the example below it is
`status.warnings`. It is present only when non-empty and absent otherwise (§8.16). The
`POST /client-ca-certificates` and `POST`/`PUT /gateway-identities` responses have no `status` object,
so on those the same `warnings` array sits at the top level. Every warning is also written to the
controller log at `WARN` with the same `code`.

```json
{
  "apiVersion": "gateway.api-platform.wso2.com/v1",
  "kind": "RestApi",
  "metadata": { "name": "partner-payments-v1.0" },
  "spec": { "…": "the deployed definition, with accept echoed as resolved" },
  "status": {
    "id": "partner-payments-v1.0",
    "state": "deployed",
    "warnings": [
      { "code": "MTLS_ACCEPT_INHERITS_POOL",
        "field": "spec.policies[0].params.accept",
        "message": "accept is omitted and the pool holds 3 authorities; this API accepts certificates from all of them" }
    ]
  }
}
```

Codes are a closed set; a test asserting a warning matches on `code`, never on `message`.

**Expiry visibility.** Expiry is the one condition an operator must learn about without having done
anything, so it is surfaced on three channels. The horizon is a **constant 30 days** — not a
configuration key, consistent with §5.3 — and applies to every pooled authority and gateway identity:

| Channel | Mechanism | Who sees it |
|---|---|---|
| Pull | `CERT_EXPIRES_SOON` in `warnings[]` on `GET /client-ca-certificates`, `GET /gateway-identities`, and on the deploy response of any API that names the entry | whoever lists or deploys |
| Log | one `WARN` line per entry per day while inside the horizon, carrying the code, the entry name and `notAfter` | whoever reads controller logs |
| Metric | the existing gauge `certificate_expiry_seconds{cert_id, cert_name}` (`pkg/metrics/metrics.go:305`, declared today but never set) is set to the entry's `notAfter` for every pooled authority and identity, alongside the `/certificates` entries it was declared for | operators alerting in Prometheus, e.g. `certificate_expiry_seconds - time() < 30*86400` |

The metric is the channel that reaches an operator who never opens the management API, and it
needs no gateway-side notification machinery.

| `code` | Raised when | `field` |
|---|---|---|
| `MTLS_ACCEPT_INHERITS_POOL` | `accept` omitted while the pool holds >1 authority | `spec.policies[i].params.accept` |
| `MTLS_ACCEPT_UNNARROWED` | an entry has neither `match` nor `thumbprints` while the pool holds >1 authority | `spec.policies[i].params.accept[j]` |
| `MTLS_AUTH_NOT_FIRST` | an auth policy precedes `mtls-auth` in the chain (§3.1.5) | `spec.policies[k]` |
| `MTLS_THUMBPRINT_NORMALISED` | a fingerprint was rewritten to canonical form; `message` carries the canonical value | `spec.policies[i].params.accept[j].thumbprints[k]` |
| `TLS_IDENTITY_EXPIRED` | `tls.identity` names an identity whose certificate has expired since upload | `spec.upstreamDefinitions[d].tls.identity` |
| `TLS_VERIFY_HOSTNAME_DISABLED` | `verifyHostName: false` | `spec.upstreamDefinitions[d].tls.verifyHostName` |
| `CLIENT_CA_NOT_YET_VALID` | uploaded authority's `notBefore` is in the future | `certificate` |
| `CLIENT_CA_IS_LEAF` | uploaded certificate lacks `CA:TRUE` (self-signed client, §3.1.2) | `certificate` |
| `IDENTITY_NO_CLIENTAUTH_EKU` | identity certificate has an EKU extension without `clientAuth` | `certificate` |
| `CERT_EXPIRES_SOON` | a pooled authority or identity expires within **30 days**; on `GET` listings and on deploy responses that reference it | `notAfter` |

#### 5.2.3 Diagnostics — `GET /tls/handshake-failures`

Handshake failures never become HTTP requests, so the source is Envoy's **listener access log**
(`Listener.access_log`), emitted for connections that close before a filter chain completes,
delivered over the ALS transport the collector already runs and kept by the controller in a bounded
in-memory ring of the most recent 1,000 entries per gateway. Not persisted; a controller restart
empties it. Format operators used: `%START_TIME%`, `%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%`,
`%REQUESTED_SERVER_NAME%`, `%DOWNSTREAM_TLS_VERSION%`, `%DOWNSTREAM_TRANSPORT_FAILURE_REASON%`, and
when a certificate was presented `%DOWNSTREAM_PEER_SUBJECT%`, `%DOWNSTREAM_PEER_ISSUER%`,
`%DOWNSTREAM_PEER_FINGERPRINT_256%`, `%DOWNSTREAM_PEER_CERT_V_END%`.

Query: `?since=<duration|RFC3339>` (default `1h`), `?reason=<code>`. Role: `admin`.

```json
{
  "since": "2026-09-21T13:22:00Z",
  "totalCount": 2,
  "failures": [
    {
      "time": "2026-09-21T14:22:07Z",
      "remoteAddress": "203.0.113.7",
      "sni": "api.example.com",
      "tlsVersion": "TLSv1.3",
      "reason": "UNTRUSTED_CA",
      "detail": "unable to get local issuer certificate",
      "peer": { "subject": "CN=client-7,O=Partner", "issuer": "CN=Some Other CA",
                "fingerprint": "3ba9…", "notAfter": "2027-01-01T00:00:00Z" }
    }
  ]
}
```

`reason` is a closed enum mapped from the BoringSSL verify string, which is kept verbatim in `detail`
— the only free text in the response. `peer` is absent when no certificate was presented.

| `reason` | BoringSSL text (`detail`) |
|---|---|
| `UNTRUSTED_CA` | `unable to get local issuer certificate`, `self signed certificate`, `self-signed certificate in certificate chain` |
| `EXPIRED` | `certificate has expired` |
| `NOT_YET_VALID` | `certificate is not yet valid` |
| `CHAIN_TOO_LONG` | `certificate chain too long` |
| `BAD_KEY_USAGE` | `unsupported certificate purpose`, `key usage does not include certificate signing`, `invalid CA certificate` (issuer lacks `CA:TRUE`) |
| `BAD_SIGNATURE` | `certificate signature failure` |
| `TLS_ALERT` | any TLS-level failure before certificate verification (protocol version, cipher, malformed `ClientHello`) |
| `OTHER` | anything else; `detail` carries the string |

#### 5.2.4 Diagnostics — `POST /rest-apis/{handle}/upstreams/{name}/tls-test`

Roles: `admin`, `developer`. The controller dials the named upstream definition's first target
**once**, with that definition's `tls` settings — presenting the identity, verifying against
`trustedCAs` or the gateway bundle, checking the hostname if `verifyHostName` is on — completes the
handshake, closes, and returns `200` regardless of outcome. No HTTP request is sent. The target
comes from the deployed definition, never from the request body, and the dial goes through the
controller's safe dialer (`ssrf-prevention.md`).

```json
{
  "upstream": "partner-billing",
  "target": "https://billing.partner.example.com",
  "identityPresented": "partner-billing-id",
  "backend": {
    "subject": "CN=billing.partner.example.com",
    "issuer": "CN=Partner Billing CA",
    "notAfter": "2027-03-01T00:00:00Z",
    "trustedBy": "partner-billing-ca",
    "hostnameMatches": true
  },
  "result": "OK",
  "detail": null
}
```

| `result` | Meaning | Whose problem |
|---|---|---|
| `OK` | handshake completed both ways | nobody's |
| `UNTRUSTED_BACKEND` | the backend's certificate does not chain to `trustedCAs` | our trust config, or the backend rotated its CA |
| `HOSTNAME_MISMATCH` | chain fine; the certificate's SANs do not cover the target host | the backend's certificate, or the URL |
| `BACKEND_REJECTED_IDENTITY` | the backend sent a TLS alert after we presented our certificate | their trust store lacks the authority that issued our identity |
| `CONNECT_FAILED` | no TLS at all: DNS, TCP, timeout | network |

`detail` is the raw TLS error string. It is shown here only because the caller is an authenticated
admin or developer diagnosing their own upstream; it is never surfaced to API callers (§3.2.6).

---

### 5.3 TOML — nothing new

There is deliberately **no** `client_validation` block and no enable flag. The listener's client
validation is derived from deployed APIs (§3.1.4), so adding configuration for it would create a
second source of truth that can disagree with the first.

The existing `[router.downstream_tls]` and `[router.upstream.tls]` blocks are unchanged, except
that `verify_host_name` gains a per-upstream override (§3.2.1) while remaining the gateway-wide
default.

### 5.4 CRDs — consume what is already vendored

`sigs.k8s.io/gateway-api v1.5.1` is already a direct dependency
(`kubernetes/gateway-operator/go.mod:22`), and GEP-91 is Standard. The types we need exist on disk
already:

- `Gateway.spec.tls.frontend.default.validation.caCertificateRefs` → inbound trust
- `Gateway.spec.tls.backend.clientCertificateRef` → **not used in v1.** It is *per-Gateway* — one
  client certificate for every backend, i.e. exactly the gateway-wide identity D6 rejects. Per-upstream
  identity would belong on `BackendTLSPolicy` (GEP-1897), which in the vendored v1.5.1 has no
  client-certificate field in either `apis/v1alpha3` or `apis/v1` (verified).
  Outbound identity is configured through `UpstreamDefinition.tls` (§3.2.1) only.

The operator simply does not read them. Consuming the vendored standard beats inventing a
parallel CRD surface. Note `AllowInsecureFallback` (GEP-91) must be **off by default** and, if
ever supported, must surface `GatewayConditionInsecureFrontendValidationMode` loudly (GO-AUTH-007).

Caveat to check: the operator's Helm-overlay path states per-listener SNI certificate selection is
unsupported (`gateway_listeners_overlay.go:189-191`). That constrains D3, not D1/D2.

### 5.5 Helm

No client-validation values — there is nothing to switch on (§5.3). Helm changes are limited to
mounts/secret refs for gateway identities and backend authorities where operators prefer files to
the management API. Follow the existing `downstream_tls` templating in `gateway-config.yaml:205`.

## 6. Cross-repo delivery and compatibility

Three repos on independent release cadences. **The shipping order is forced:**

```
(A) sdk/core  →  (B) gateway (controller + policy-engine + proto)  →  (C) mtls-auth policy
```

`gateway-builder` compiles every selected policy into the policy-engine binary in one Go build,
so Go's minimal-version-selection takes the **maximum** `sdk/core` across all modules. The
consequences:

| Combination | Result |
|---|---|
| New policy + new gateway | ✅ Nominal |
| Old policy + new gateway | ✅ Additive change, compiles unchanged, ignores the cert field |
| **New policy + old gateway** | ❌ **Compiles, then denies every request** — MVS satisfies the build, but the old kernel never populates the field, so it is always nil, and fail-closed (correctly) rejects everything |
| Go policy only, Python path not updated | ⚠️ Every `pipPackage` policy is blind to the certificate |

The third row is the dangerous one: a silent 403 storm at runtime that looks like a
misconfiguration. Two mitigations — the first required, the second deferred by decision:

1. **The `sdk/core` change must be purely additive** — a new struct field plus a nil-safe
   accessor. Adding a method to `Policy` or any interface a policy implements breaks all ~60
   policies at once.
2. **Deploy-time capability validation — deferred by decision (M4, §9).** `policy-definition.yaml`
   has no "minimum gateway capability" field and no negotiation exists, so the third row cannot be
   caught at deploy time in v1. The interim position is the fail-closed behaviour itself plus a
   rate-limited kernel error naming the missing attribute. Note that the skew is only reachable
   when an operator pulls a newer `mtls-auth` into an older `gateway-builder` build — a build-time
   act — and the policy-engine and controller ship in lockstep. Revisit before the first
   `mtls-auth` major bump.

**Access-log JSON fields (§3.3).** Five TLS fields are added to the default JSON access-log format.
Additive for JSON consumers; the positional text format is unchanged. Call it out in the release notes
alongside the `503` body change below.

**Sterile upstream-failure body (§3.2.6).** The `LocalReplyConfig` that replaces Envoy's default
`503` text applies to every API on the gateway, not only mTLS upstreams. Status code and response
flags are unchanged; only the body text is. Call it out in the release notes.

**Minimum Envoy version.** Floor: **Envoy v1.39.0**. The single Dockerfile that sets `ENVOY_VERSION` pins it
(`gateway-runtime/Dockerfile:24`), and the operator's default router image
(`internal/k8sutil/template_data.go:89`) is built from it. Every deployment path runs v1.39. How a
deployment pins or caches that image is deployment hygiene outside this feature.

The **Go bindings are not a constraint.** `go-control-plane/envoy v1.37.0`
(`gateway-controller/go.mod:7`) already carries every typed field this design needs —
`RequireClientCertificate`, `CommonTlsContext_ValidationContextSdsSecretConfig`,
`TlsCertificateSdsSecretConfigs`. Attribute names are plain strings and are not bounded. No
binding bump is required.

**NACK risk:** `request_attributes` is a repeated string of CEL names, so an unknown name is simply
not populated — it does not NACK the snapshot. NACK risk applies to *typed* config fields (a new
`DownstreamTlsContext` member, a `FilterChainMatch`), not to the attribute list.

---

## 7. Security requirements

Each maps to a project rule. These are requirements, not suggestions; §8 has the test that proves
each one.

| # | Requirement | Rule |
|---|---|---|
| S1 | Absent/invalid certificate → **deny**. The nil accessor must never mean "not required". | GO-AUTH-001 |
| S2a | **Policy-layer** rejections — not allowlisted, SAN/issuer mismatch, no certificate presented — return one uniform 401 body, fixed in §3.1.7. | error-handling d.4/d.5 |
| S2b | **Handshake-layer** rejections — bad chain, expired, depth exceeded — are TLS alerts with **no HTTP response**. This is inherent, not a gap: CA membership is observable at the TLS layer regardless (the TLS 1.2 `CertificateRequest` advertises the accepted-CA list). Enable Envoy's suppress-client-CA-list option to reduce that disclosure. Do not write requirements or tests that assume a 401 here. | inherent |
| S3 | Identity comparison is **constant-time** (`subtle.ConstantTimeCompare`, as `basic-auth` does) and canonicalized. Never substring, never case-folded DN equality. | go-cors-validation d.1 (same class) |
| S4 | A certificate widens *which pool entries an API accepts*, never which gateway's pool or which API. Identity is decided only from Envoy-asserted connection attributes, never from request headers or body. | GO-AUTH-005 (gateway scope) |
| S5 | Whether a route requires a certificate is decided by **which policy chain the controller assigned to that route** — a structural match against the router/policy configuration — never by a request-shape heuristic. A route whose chain includes `mtls-auth` but cannot be resolved at request time is **denied**, not passed through. | GO-AUTH-017 |
| S6 | Private keys: never in xDS `inline_bytes`, never returned by a read API, never in a config dump, never logged, encrypted at rest, file perms hard-fail if permissive. | xds-security d.3, GO-AUTH-003, GO-AUTH-018 |
| S7 | Client-CA trust is a **separate bundle** from upstream trust. Uploading a client CA must not widen backend trust. | trust-boundary |
| S8 | A deployed API attaching `mtls-auth` while the client-CA pool is **empty** must be refused at deploy time, and a snapshot must never reference an empty bundle: `GetSecret` errors on an empty bundle (`sds.go:92-95`), the secret is omitted from the snapshot, and a listener referencing a never-arriving secret stays **warming** — an outage of `https_port` for *every* API, mTLS or not. Validate the effective outcome, as `ValidateXDSServerTLS` does. | GO-AUTH-011 |
| S9 | Cert-store load failure is a **startup failure**, not a warn-and-continue (fixes the existing fail-open). | GO-AUTH-011 |
| S10 | XFCC is `SANITIZE_SET`. A client-supplied XFCC header can never survive to the backend or be read as identity. | N1 |
| S11 | Every new admin endpoint has its own explicit scope check in the handler. | GO-AUTH-007 |
| S12 | No finding from any of the above is resolved with a `// TODO`/`FIXME` comment. | GO-AUTH-019 |
| S13 | New TLS config defaults follow the existing `ecdh_curves` posture (hybrid PQC first, classical after) and inherit the documented NACK warning. | post-quantum d.3 |
| S14 | **Old-controller skew fails closed.** `policy_validator.go:196` refuses any policy "not found in loaded policy definitions", so an old build rejects `mtls-auth` outright rather than deploying an unprotected API. **Residual:** `BindRequestBody` drops unknown fields (`handlerkit.go:61-77`), so unknown *params* on a known `mtls-auth` version must be rejected by the policy's own schema (`additionalProperties: false`), never ignored. | GO-AUTH-017 |
| S15 | Authority verification is a **cryptographic** signature/path check against the pool entry named by `ca:`, never an issuer-DN string comparison (§3.1.1). | S4 |
| S16 | **Pool membership is not authorization.** Adding an authority to the pool must not grant access to any existing API. Every API either names its authorities or inherits the pool by an explicit documented default, and an entry's `match`/`thumbprints` narrowing still governs. | GO-AUTH-007 |
| S17 | A private key is never returned by any read operation **for any role**, including `admin`. Write-only, as `upstreamAuth.value` already is. | GO-AUTH-003 |
| S18 | A dangling reference — `accept` naming an authority absent from the pool, or `tls.identity` naming a missing identity — is refused at deploy time. Silently denying one partner is worse than refusing the change. | GO-AUTH-017 |
| S19 | Removing a pool authority or an identity that a deployed API **names** (`accept[].ca` or `tls.identity`) is **refused with `409`** listing the referencing APIs — the delete-time mirror of S18. APIs that merely inherit the pool are not references. No existing delete endpoint checks references; this one must. | GO-AUTH-001 |

---

## 8. Testing

Organised by the user stories in §3.1.4 and §3.2.1, because the failure modes that matter are
behavioural rather than unit-level. §8.1 is a prerequisite for everything else.

### 8.1 Test PKI fixtures

`gateway/it/features/` has no client-certificate vocabulary today; `certificates.feature` covers
management CRUD only. This is a real slice of work and lands first.

| Fixture | Purpose |
|---|---|
| `ca-a`, `ca-b` | two independent authorities |
| `ca-a-intermediate` | issuing CA under `ca-a`, for chain tests |
| `ca-a-intermediate-2` | a **rotated** issuing CA under `ca-a` — the partner replaced its intermediate |
| `ca-a-other-intermediate` | a **sibling** issuing CA under `ca-a` for an unrelated system — proves root-level trust is wider than intermediate-level |
| `client-via-intermediate-2`, `client-via-other-intermediate` | leaves under the two intermediates above |
| `client-selfsigned-b` | a second self-signed client, never pooled |
| `client-selfsigned-renewed` | `client-selfsigned` re-issued: same subject, new certificate |
| `client-signed-by-leaf` | a certificate whose issuer is `client-selfsigned` (`CA:FALSE`) — a non-CA must not be able to act as one |
| `ca-b-same-dn` | **Subject DN identical to `ca-a`** — the collision attack |
| `client-valid` | happy path, signed by `ca-a` |
| `client-via-intermediate` | signed by the intermediate, not the root |
| `client-expired`, `client-not-yet-valid` | time-window failures |
| `client-wrong-ca` | signed by `ca-b` when only `ca-a` is pooled |
| `client-same-cn-ca-b` | same CN as `client-valid`, different authority |
| `client-no-san` | CN only |
| `client-multi-san` | several URI and DNS SANs — proves first-entry-only handling |
| `client-serverauth-only` | wrong extended key usage |
| `client-chain-depth-5` | exceeds `max_verify_depth` |
| `client-selfsigned` | no chain to anything |
| `client-renewed` | same subject, **different thumbprint** |
| `backend-*`, `gw-identity-a/b` | mirror set for outbound |
| `key-mismatch` | cert and key that do not correspond |

New godog steps: *"I send a request with client certificate X"*, *"...with client certificate X
and chain Y"* (the client sends its intermediates), *"...with client certificate X only"* (leaf
alone), *"...with no client certificate"*, *"...with a forged XFCC header"*, *"the TLS handshake
should fail with reason R"*, *"the pool contains entry X holding certificates Y"*.

### 8.2 Story: the administrator curates a pool

- Add an authority → appears in `GET`, `referencedByApis` is 0.
- Add several → all present; listener trust becomes their union once any mTLS API is deployed.
- **Adding an authority grants no access (S16)** — an API deployed with `accept: [ca-a]` still
  rejects a `ca-b` certificate after `ca-b` joins the pool. *The single most important test in this
  section.*
- Remove an authority nothing references → succeeds.
- **Remove an authority an API names in `accept` (S19)** → `409` listing those APIs; nothing
  changes. Remove the reference from each API first, then delete.
- Upload a chain (intermediate + root) as one entry → a leaf signed by the intermediate validates.
  Every pool-entry shape × client-presentation combination is in §8.17.
- Upload a leaf that is not a CA → `201` flagged `isLeaf: true` (a pooled leaf trusts exactly that
  certificate, §3.1.2); a leaf from another authority does **not** validate against it.
- **Same-DN second authority (S15)** — uploading `ca-b-same-dn` while `ca-a` is pooled succeeds; a leaf from it is `401` on an API accepting only `ca-a` (§8.7).
- Role enforcement: `developer` `GET` succeeds, `developer` `POST`/`DELETE` → `403`.

### 8.3 Story: the developer selects from the pool

- `accept` omitted → deploy response echoes every pooled authority, and a certificate from any of
  them authenticates.
- **Pool changes propagate to an inheriting API without redeploy** — add an authority, a
  certificate from it is accepted; remove it, it is not.
- `accept: [ca-a]` → a `ca-b` certificate reaches the policy and gets `401`, even though its
  handshake succeeded.
- `accept` naming an absent authority → **deploy refused (S18)**, not silently denying.
- Empty pool + `mtls-auth` attached → deploy refused.
- Two entries for two partners → each caller's `AuthContext.Issuer` names its own authority; a
  certificate from partner A never matches partner B's entry and vice versa.
- **Independence from `subscription-validation`**: an API with both attached — a valid certificate
  and no `Subscription-Key` → `403` from `subscription-validation`; a valid `Subscription-Key` and no
  certificate → `401` from `mtls-auth`. Neither check satisfies the other.
- First-match-wins ordering with two entries that both match.
- Omitting `accept`, or an unnarrowed entry, with >1 pooled authority → deploy warns.
- Two APIs on one gateway, different `accept` lists → a certificate valid for one gets `401` on the
  other.

### 8.4 Story: onboarding, renewal, revocation

Every lever is a configuration change — an edit to the pool or to an API's `accept` list — so each
test states its blast radius and its propagation time.

**Authority-anchored entries (`ca` + optional `match`)**
- Onboarding is zero-touch: a partner obtains a certificate from a pooled authority carrying the
  agreed SAN → authenticates with no gateway action.
- Renewal is invisible: `client-renewed` (same authority, same SAN, new thumbprint) authenticates
  without any change.
- Revoke by removing a SAN from the list: `uriSANs: [srv-1, srv-2, srv-3]` → `[srv-1, srv-2]` → `srv-3`
  gets `401` on the **next request**; `srv-1` and `srv-2` unaffected — the same lever as removing a
  fingerprint. Test both the per-instance-SAN convention followed and ignored, the latter showing the
  lever does not exist when all instances share a SAN.
- Revoke by removing an entry: partner B's entry removed → `401` next request; partner A untouched.

**Thumbprint entries (`ca` + `thumbprints`)**
- Exactly that leaf authenticates; a different leaf from the **same** authority → `401`.
- Renewal is a cut-over within one entry: `thumbprints: [old, new]` → both authenticate; remove `old` → only `new`.
- `client-renewed` against a single-thumbprint entry → `401` until the entry is updated. *The
  behaviour most likely to surprise an operator; the deploy response should call it out.*
- Any of the common thumbprint spellings (upper/lower hex, colons, `sha256:` prefix) in the API
  definition compares equal after normalisation.

**Self-signed leaf pooled as its own authority**
- Authenticates when named by `ca:`; removing the pool entry cuts off that one client and no other.

**Pool-level**
- Removing an authority affects **new handshakes only** — an established connection keeps working
  until it closes or idles out (D10); APIs inheriting the pool stop accepting it silently; APIs
  naming it in `accept` hit S19. Assert all three.
- Expiry surfaced: `notAfter` of pooled authorities in listings; `CERT_EXPIRES_SOON` 30 days ahead; the
  `certificate_expiry_seconds` gauge carries `notAfter` for every entry (§5.2.2).

### 8.5 Story: presenting a certificate to a backend

- Backend requiring mTLS + `tls.identity` → `200`; identity removed → sterile failure, no Envoy
  internals in the response.
- **Two upstream definitions, two identities** → each backend receives its own certificate.
  Assert the partner backend never sees the internal identity. *This is the test that proves
  per-upstream identity works and connection pooling is not crossing them.*
- Several targets under **one** definition → all present that definition's identity.
- Per-upstream `trustedCAs` → a backend trusted for that upstream only; the same certificate is
  rejected for a different upstream.
- `tls.identity` naming a missing identity → **deploy refused (S18)**.
- `verifyHostName: true` with a certificate whose SAN does not match the URL → connection refused.
- `verifyHostName: false` → documented behaviour, and a test asserting it is not the default.
- Identity rotated → new connections use the new certificate; pooled ones continue on the old until
  they close.

### 8.6 Unit tests

**Translator**
- Client validation emitted only when at least one deployed API attaches `mtls-auth`; absent
  otherwise (the derived-config contract).
- Listener trust is the union of pooled authorities; `accept` narrowing happens in the policy, not
  the listener.
- Per-upstream `TlsCertificateSdsSecretConfigs` emitted only when `tls.identity` is set.
- **Golden test: no `PRIVATE KEY` PEM header anywhere in a serialized LDS or CDS snapshot.** Cheap,
  and the regression guard for D8/S6.
- Snapshot-inclusion gate includes a listener-referenced secret (the silent-failure case).
- Client-CA and upstream-CA bundles are disjoint (S7).
- Empty pool + client validation → startup/deploy error, never a warming listener (S8).
- Cert-store load failure → startup failure, not warn (S9).

**SDK**
- `PeerCertificate()` returns nil when the gateway did not populate it; a populated struct with
  `MTLS == false` (no certificate presented) is distinguishable from nil (attribute absent).

**`mtls-auth` policy**
- Nil peer certificate → deny. *The most important unit test in the feature.*
- `PeerCertValid == false` → deny, identical response to every other policy-layer failure (S2a);
  defence in depth, since D9 means it should never be observed.
- Signature verifies against the entry's authority + narrowings match → `AuthContext` populated per
  D5's table; **no `x-wso2-application-id` written**, asserted explicitly.
- **Same CN under a different authority → deny**; **identical Subject DN under a different
  authority → deny** (S15) — the signature check, not a DN compare, is what makes these pass.
- Multi-SAN certificate: matching uses the parsed certificate, not the first-entry-only attribute.
- Thumbprint entry: exact leaf → accept; sibling leaf from the same authority → deny; spelling
  variants normalise to the same value.
- First-match-wins across entries; an unnarrowed entry accepts any certificate from its authority.
- `notAfter` re-checked per request (D10).

**Store**
- Key encrypted at rest; plaintext never round-trips through any read path, at any role (S17).
- Cert/key mismatch and already-expired certificates rejected at upload.
- Non-`CERTIFICATE` PEM blocks in an identity upload are **rejected**, not silently skipped as
  `certstore.go:269` does for trust bundles — silently dropping a key means "your key vanished".

### 8.7 Security and abuse

The tests that would catch a regression into a vulnerability. Not optional.

- **Forged XFCC header** claiming a trusted identity, with no client certificate → `401`, and the
  header does not reach the backend. Must exist from day one precisely *because* header-cert trust
  is a non-goal.
- Forged XFCC **alongside** a valid but different certificate → the handshake identity wins.
- Header injection into the backend-facing XFCC — a client-supplied value never survives.
- **Authority DN collision (S15)**: `ca-b-same-dn` pooled alongside `ca-a`; a leaf it issued, presented to an
  API accepting only `ca-a` → `401`. This is the test that proves verification is cryptographic, not a
  DN compare.
- **Trust-store enumeration**: within the policy layer, "known authority / unknown thumbprint" and
  "known authority / wrong SAN" are indistinguishable in body **and timing**. Unknown-authority is
  not comparable — it fails at TLS by design.
- **Key disclosure sweep**: the private key appears in none of `GET /gateway-identities` (admin or
  developer), the config dump, controller logs at debug level, the xDS snapshot, or analytics.
- **Privilege**: `developer` cannot create, modify or delete pool entries or identities; cannot read
  a private key; **can** read enough to select.
- **Old-gateway skew** (fail-closed): `mtls-auth` on a gateway that does not populate the attribute
  denies everything **and** logs a rate-limited kernel error naming the missing attribute (§6). There
  is no deploy-time detection in v1 — assert the deny and the log line.
- **Old-controller skew** (fail-**open**, more dangerous): an API definition carrying `mtls-auth`
  params the controller does not understand must not deploy as an unprotected API (S14).
- `disable_ssl_verification` must not silently disable client-certificate *presentation* or mask a
  backend trust failure as success.

### 8.8 Edge cases

- **HTTP/2 connection reuse**: request 1 to an mTLS API and request 2 to a non-mTLS API over the
  same connection, and the reverse. Identity attributed correctly per request, never leaking across.
- **Coexistence**: a non-mTLS API on the same listener still serves a caller presenting no
  certificate; a caller presenting one to a non-mTLS API is neither rejected nor treated as
  authenticated.
- Connection coalescing across two hostnames on one certificate — asserts N4's reasoning holds.
- Certificate valid at connection time, expiring mid-connection → per-request re-check rejects it.
- Pool emptied while connections are live (only reachable when no mTLS API is deployed, §8.13) →
  listener returns to one-way TLS on the next snapshot; live connections unaffected.
- Very large pool → the TLS 1.2 accepted-CA list stays within sane bounds; consider suppressing it.
- Same authority uploaded twice under two names → `issuedBy` is deterministic; `accept` on either
  name behaves identically.
- `accept` listing the same authority twice → accepted, no double-evaluation.
- Certificate with no SAN against an entry with a SAN matcher → deny, never fall back to CN.
- Unicode and comma/`+`-containing DNs → canonicalisation does not mis-parse.
- SDS secret arriving before the listener that references it, and after.
- **Envoy NACK** on a rejected snapshot → surfaced by the controller. There is no NACK-surfacing
  mechanism today; without one a rejected listener update is a silent config freeze.

### 8.9 Operability

Under D9 the two-layer split (S2a/S2b, §7) means ordinary observability misses handshake-layer
failures entirely; these tests exist to make them visible.

- A handshake rejection appears in `GET /tls/handshake-failures` with a usable reason, and in **no**
  access log or analytics record — assert both, because "absent from the logs" is the diagnosis.
- A policy rejection appears in analytics with the correct API and `AuthType: mtls`; no application
  is attributed, because none is resolved (D5).
- Expiry warnings fire 30 days ahead on all three channels of §5.2.2: `CERT_EXPIRES_SOON` in the
  listing, one `WARN` log line per day, and the `certificate_expiry_seconds` gauge set for the entry.
- `POST /rest-apis/{handle}/upstreams/{name}/tls-test` reports presented identity, verified backend and hostname match.
- **Metrics (§3.3):** a policy deny increments `policy_executions_total{policy_name="mtls-auth", status="denied"}`
  and nothing `mtls-auth`-specific; a handshake failure increments `tls_handshake_failures_total{reason}`
  with the same reason the ring buffer records; `client_ca_certificates_total` and
  `gateway_identities_total` track pool and identity writes; `certificate_expiry_seconds` is set for
  every pooled authority, identity and `/certificates` entry.
- **Traces (§3.3):** the `mtls-auth` span carries `tls.client.subject`, `tls.client.issuer` (entry
  name), `tls.client.hash.sha256`, `enduser.id`, `mtls_auth.result` and, on deny, `mtls_auth.reason`;
  never a full certificate or key. Under `errorMessageFormat: json` the `401` body is unchanged
  regardless of `mtls_auth.reason`.
- **Access log (§3.3):** a request with a client certificate logs `peerSubj`, `peerFp`, `tlsVer`, `sni`
  in JSON format; a request without one logs them empty; a backend TLS failure logs `upTlsFail` while
  the caller sees the sterile `503`. The text format line is byte-identical to today's.
- **Analytics (§3.3):** a request authenticated by `mtls-auth` produces a record with `authType = mtls`
  and `userId` equal to the certificate subject, with no application id — asserted against the same
  analytics sink the JWT tests use.

### 8.10 Performance

- Handshake cost with client-certificate requests enabled on a listener where most APIs do not use
  mTLS — measure before making any of this a default.
- ext_proc payload growth from `connection.peer_certificate` (a full PEM on every request to that
  listener). It is required in v1: the authority signature check and full-SAN matching both need it.
- XFCC header size with `chain: true` (§3.1.6) on requests carrying a client certificate, as seen by
  both the policy engine and the backend.
- `accept` evaluation and signature verification at realistic pool sizes and entry counts, not toy.

### 8.11 Input matrix — `mtls-auth` policy parameters

Every shape a developer can put in the API YAML, and what the controller does with it. **Deploy-time**
means the `POST /rest-apis` response; **request-time** means what a caller sees.

| Input | Deploy-time | Request-time |
|---|---|---|
| `accept` omitted, pool has 1 authority | `201`, response echoes that authority | any cert from it authenticates |
| `accept` omitted, pool has >1 authority | `201` **with warning** (unnarrowed inheritance) | any cert from any pooled authority authenticates |
| `accept` omitted, pool **empty** | **`400`** — nothing could validate (S8) | — |
| `accept: []` | **`400`** — ambiguous between inherit and deny-all; "omit to inherit, or list ≥1 entry" | — |
| `- ca: X` only, X in pool | `201` | any cert issued by X |
| `- ca: X` only, pool has >1 authority | `201` with warning (unnarrowed entry) | as above |
| `- ca: X`, X **not** in pool | **`400`** naming X (S18) | — |
| entry missing `ca` | **`400`** — `ca` required | — |
| `match.uriSANs: [A]` | `201` | cert from X carrying URI SAN A |
| `match.uriSANs: [A, B]` | `201` | cert from X carrying A **or** B (OR within the list) |
| `match.dnsSANs: [D]` | `201` | cert from X carrying DNS SAN D |
| `match` with both lists | `201` | cert must satisfy **both** lists (AND across lists) |
| `match.uriSANs: []`, or an empty string in either list | **`400`** — empty matcher; "list at least one non-empty SAN, or remove `match`" | — |
| `match.uriSAN:` (singular) | **`400`** — unknown key; the field is `uriSANs` | — |
| `match` with unknown key (`emailSAN`) | **`400`** — schema | — |
| `thumbprints: ["9f86…"]` (lowercase hex) | `201` | exactly that leaf, issued by X |
| `thumbprints: [a, b]` | `201` | either leaf |
| `thumbprints: []` | **`400`** — minimum one element; "remove `thumbprints` to accept any certificate from this authority" | — |
| `thumbprint:` (singular) | **`400`** — unknown key; the field is `thumbprints` | — |
| value uppercase / colons / `sha256:` prefix | `201`, normalised; response echoes canonical form | identical behaviour |
| value wrong length or non-hex | **`400`** — malformed | — |
| duplicate values in one list | `201`, de-duplicated | as one value |
| `match` **and** `thumbprints` on one entry | `201` | cert must satisfy both (AND) |
| two identical entries | `201` (idempotent; no double evaluation) | as one entry |
| two entries, same `ca`, different `match` | `201` | either name (OR across entries) |
| unknown param key (`mode`, `applicationId`, anything) | **`400`** — `additionalProperties: false` in the policy schema (S14 residual) | — |
| `version: v2` when only v1 loaded | **`400`** — existing `policy_validator.go:196` behaviour | — |
| `mtls-auth` attached **twice** at one scope | **`400`** — "`mtls-auth` may appear once per scope; use several `accept` entries instead". Enforced by the policy's own validation, not a general duplicate-policy rule (the controller has none today and other policies may legitimately repeat) | — |
| `mtls-auth` at API level **and** on an operation | **`400`** naming the route — the merged chain would contain it twice and AND the two `accept` lists (§3.1.4); attach at one level only | — |
| `mtls-auth` on an operation only | `201` | only that operation requires a cert; siblings do not |
| `mtls-auth` on a gateway with `router.https_enabled: false` | **`400`** — "`mtls-auth` requires the HTTPS listener"; a certificate cannot be requested over plaintext | — |
| `mtls-auth` API called over the plaintext `listener_port` (HTTPS enabled) | `201` (nothing to refuse) | `401` — no certificate can exist on that connection; fail-closed, not an error condition |
| `jwt-auth` listed **before** `mtls-auth` | `201` **with warning** (§3.1.5) | both enforced, in listed order |

### 8.12 Input matrix — upstream `tls` block

| Input | Deploy-time | Connection-time |
|---|---|---|
| `tls` omitted | `201` | one-way TLS exactly as today |
| `tls: {}` | `201`, no-op — every field is optional with a default, so an empty block equals omitting it | as today |
| `identity: I`, I exists | `201` | gateway presents I |
| `identity: I`, I **missing** | **`400`** naming I (S18) | — |
| `identity` whose cert has **expired since upload** | `201` **with warning** (it will fail at connect) | backend rejects; sterile 503 |
| `trustedCAs: [C]`, C exists | `201` | backend must chain to C |
| `trustedCAs: [C]`, C missing | **`400`** (S18) | — |
| `trustedCAs: []` | **`400`** — "omit to use the gateway bundle, or list ≥1". Never reaches the translator: an empty `trusted_ca` on an Envoy validation context means *no verification*, so this guard is what keeps two brackets from becoming `disable_ssl_verification` | — |
| `trustedCAs` omitted | `201` | gateway-wide backend bundle applies |
| `verifyHostName: false` | `201` **with warning** | chain checked, hostname not |
| `verifyHostName` omitted | `201` | `true` |
| `tls` on a definition whose `url` is `http://` | **`400`** — "`tls` is configured but the upstream URL is `http://`"; the translator builds an upstream TLS context only for `https://`, so the block would be silently unused and the developer would believe mTLS is in force | — |
| `tls` on a definition mixing `http://` and `https://` targets | **`400`** naming the plaintext target — with `tls` set, every target must be `https://` | — |
| `tls` on inline `upstream.main.url` (not a definition) | **`400`** — "`tls` is not supported on an inline upstream; move it to `upstreamDefinitions` and reference it". **Implementation note:** `BindRequestBody` (`handlerkit.go:61-77`) is plain `json`/`yaml.Unmarshal` with no strict mode, so an unknown key is dropped before validation and the API would deploy with a 201 and one-way TLS. To make this 400 fire, `tls` must be declared on the inline `Upstream` struct and rejected by the API validator when present. Strict binding for the whole API document is the better long-term fix, but changes existing behaviour and is a separate decision | — |
| `tls` on a definition with several `upstreams` targets | `201` | every target presents the same identity |
| unknown key under `tls` | **`400`** | — |
| `identity` referenced by two definitions | `201` | both present the same cert (allowed) |

### 8.13 Input matrix — management endpoints

**`POST /client-ca-certificates`** (admin)

| Payload | Result |
|---|---|
| one CA certificate (`CA:TRUE`) | `201`, metadata returned |
| issuing CA + its root in one PEM | `201`; `subject` is the issuing certificate |
| a **leaf** (no `CA:TRUE`) | `201` — legitimate for self-signed clients (§3.1.2); response flags `isLeaf: true` |
| **two unrelated** CAs in one PEM | **`400`** — "this PEM contains more than one unrelated authority; upload each as its own entry" (§3.1.1). Test: every certificate in the body must sign or be signed by another in the same body; the entry's identity is the one no other certificate in the body is signed by. A chain (issuing + root) passes; two roots do not |
| PEM containing a `PRIVATE KEY` block | **`400`** — "the upload contains a private key; a client-CA entry accepts certificates only". Never silently strip it (contrast `certstore.go:269`, which does for trust bundles): the admin must learn a secret left its home. The rejected body is neither persisted nor logged |
| non-PEM / malformed | `400` |
| expired | **`400`** — nothing it signed can validate |
| not-yet-valid | `201` with warning |
| duplicate `name` | `409` |
| same certificate under a **second name** | `201`; both names usable; `issuedBy` reports the first |
| `name` failing `^[a-zA-Z0-9._-]+$` | `400` |
| Subject DN identical to an existing pooled authority | `201` — harmless under S15; listing shows both |
| body over the size limit | `413`, generic |
| caller is `developer` | **`403`** |
| unauthenticated | `401` |

**`GET /client-ca-certificates`** — `admin` and `developer` succeed; `referencedByApis` reflects only
APIs that name the entry in `accept` (inheriting APIs are not counted); private material never
present (there is none).

**`DELETE /client-ca-certificates/{id}`** (admin)

| State | Result |
|---|---|
| referenced by no API | `204`; listener bundle shrinks on next snapshot |
| referenced only by APIs **inheriting** the pool | `204`; those APIs stop accepting it, silently — the documented default |
| named in some API's `accept` (S19) | **`409`** listing the referencing APIs; edit their `accept` first |
| it is the **last** authority and mTLS APIs exist | **`409`** — "cannot remove the last client authority while APIs attach `mtls-auth`", naming them. An empty pool would leave the listener referencing an empty bundle (S8): either a warming `https_port` for every API, or a silent deny-all across every mTLS API. Add a replacement first, or remove the APIs. Applies even when no API names it, unlike S19 |
| unknown id | `404` |
| `developer` | `403` |

**`POST /gateway-identities`** (admin)

| Payload | Result |
|---|---|
| cert + matching key | `201`; response has metadata, **no key** |
| cert chain (leaf + intermediates) + key | `201` |
| cert and key **mismatch** | `400` |
| cert only / key only | `400` |
| **encrypted** private key (`ENCRYPTED PRIVATE KEY` or `Proc-Type: 4,ENCRYPTED`) | **`400`** — "passphrase-protected private keys are not supported; upload an unencrypted key (it is encrypted at rest by the gateway)". Detected by PEM header so the message is specific, not a generic parse failure. PFX/PKCS#12 likewise unsupported in v1 |
| cert **expired** | `400` |
| cert has an EKU extension **without** `clientAuth` | `201` **with warning** — "certificate does not assert the clientAuth extended key usage; some backends will reject it". Shown in the response and in `GET`. The gateway presents it regardless; the check is the backend's. No EKU extension at all → no warning (RFC 5280: absent means unrestricted) |
| duplicate `name` | `409` |
| `developer` | `403` |

**`GET /gateway-identities`** — `admin` and `developer`; **`privateKey` absent for every role** (S17);
assert by schema, not by inspection.

**`PUT /gateway-identities/{id}`** — same payload rules; `200` includes
`pooledConnectionsUsingPrevious`; referencing upstreams continue on old material until connections
close.

**`DELETE /gateway-identities/{id}`** — unreferenced → `204`; named by any deployed upstream's
`tls.identity` → `409` listing the APIs (S19).

### 8.14 Ordering scenarios — sequences where order changes the outcome

Each scenario is one integration test. **Given** is the state before the sequence starts, each step
names who acts and what the gateway returns, and **Why** points at the decision or requirement the
scenario proves. Fixtures are from §8.1; `ca-a`/`ca-b` are pooled authorities, `I` is a gateway
identity.

**Group 1 — naming an authority versus inheriting the pool (S16, S18, D10)**

| # | Given | Sequence | Why |
|---|---|---|---|
| O1 | pool is **empty** | 1. developer deploys an API with `accept: [ca-a]` → **`400`**, `errors[0].field = …accept[0].ca`, "no client-CA authority named `ca-a` exists on this gateway" 2. admin adds `ca-a` → `201` 3. developer redeploys the same YAML → **`201`**; `ca-a` certificates authenticate | S18: a name that resolves to nothing is refused when written, never stored as a silent deny. Nothing re-resolves it later, so the redeploy is required. |
| O2 | pool is empty | 1. admin adds `ca-a` → `201` 2. developer deploys `accept: [ca-a]` → `201`; `ca-a` certificates authenticate | The intended order: admin curates, developer selects (§3.1.4). |
| O2a | pool is **empty** | 1. developer deploys an API with `mtls-auth` and **`accept` omitted** → **`400`**, `field = spec.policies[0]`, "`mtls-auth` requires at least one client-CA authority; add one with `POST /client-ca-certificates`" 2. admin adds `ca-a` → `201` 3. developer redeploys → `201`; the API inherits `{ca-a}` and follows the pool from then on (O3) | S8: inheriting an empty pool would deploy an API that denies every caller. Together with O7 (the last authority cannot be removed while mTLS APIs exist) this makes "mTLS API on an empty pool" an unreachable state, so no request-time behaviour needs defining for it. |
| O3 | pool = `{ca-a}` | 1. developer deploys with **`accept` omitted** → `201`, response echoes `accept: [ca-a]` 2. admin adds `ca-b` → `201` 3. a `ca-b` certificate calls the API → **`200`, no redeploy** 4. `GET /rest-apis/{handle}` → resolved `accept` shows `[ca-a, ca-b]`; the stored definition still has no `accept` key | Omitted `accept` is a standing instruction, re-resolved on every pool change and pushed in the next policy snapshot. The `GET` proves the read model tracks the pool, not the deploy-time echo. |
| O4 | pool = `{ca-a}` | 1. developer deploys `accept: [ca-a]` → `201` 2. admin adds `ca-b` → `201` 3. a `ca-b` certificate calls the API → handshake **succeeds** (the pool trusts `ca-b`), policy returns **`401`** | S16: pool membership is not authorization. Contrast with O3 — the only difference is whether `accept` was written. |
| O5 | pool = `{ca-a, ca-b}`, API deployed with `accept` omitted | 1. admin removes `ca-a` → `204` 2. a `ca-a` certificate opens a **new** connection → TLS fail 3. an **already-open** `ca-a` connection keeps working until it closes or idles out | D10: pool changes reach new handshakes only. Inheriting APIs are not references, so nothing is refused and nothing is surfaced — the documented default. |
| O6 | pool = `{ca-a, ca-b}`, API deployed with `accept: [ca-a]` | 1. admin removes `ca-a` → **`409`**, `errors[]` lists the API and the referencing path 2. the API keeps working unchanged | S19: a named dependency cannot be deleted from under a running API. The admin edits the API's `accept` first. |
| O7 | pool = `{ca-a}` only, one API attaches `mtls-auth` (with or without `accept`) | 1. admin removes `ca-a` → **`409`**, "cannot remove the last client-CA authority while 1 deployed API attaches `mtls-auth`" | S8: an empty pool with mTLS APIs would leave the listener referencing an empty bundle — a warming `https_port` or a silent deny-all. Applies even when no API names `ca-a`. |

**Group 2 — the listener follows the deployed APIs (D1, D2, §3.1.4 derived config)**

| # | Given | Sequence | Why |
|---|---|---|---|
| O8 | pool = `{ca-a}`, **no** API attaches `mtls-auth`, clients connected to public APIs | 1. developer deploys the **first** mTLS API → `201` 2. next snapshot: listener gains the validation context 3. **existing** connections to public APIs are unaffected 4. **new** connections on `https_port` are asked for a certificate (and may decline) | The validation context is derived, not switched on. Adding it must not drain existing connections (SDS, §3.1.3). |
| O9 | one mTLS API deployed | 1. developer removes that API (or redeploys it without `mtls-auth`) 2. next snapshot: validation context removed 3. new connections are no longer asked; nothing else changes | The mirror of O8: the last attachment leaving turns asking off. |
| O10 | two mTLS APIs deployed | 1. developer redeploys **one** of them without `mtls-auth` → `201` 2. that API serves callers with no certificate 3. the listener **still asks** every new connection, because the other API still attaches the policy | Enforcement is per API; asking is per listener (§3.1.1). |
| O11 | API deployed with `thumbprints: ["old"]`, a client holding `new` is connected and getting `401` | 1. developer redeploys with `thumbprints: ["old", "new"]` → `201` 2. the client's **next request on the already-open connection** → `200` | D10: `accept` is evaluated per request, so an edit takes effect without a reconnect. |
| O17 | pool = `{ca-a, ca-b}` | 1. deploy API-1 with `accept: [ca-a]` and API-2 with `accept: [ca-b]`, in either order 2. a `ca-a` certificate → `200` on API-1, `401` on API-2; a `ca-b` certificate → the reverse | Per-API selection is independent; deploy order is irrelevant. |
| O21 | API attaches `mtls-auth` **and** `subscription-validation`; caller has a valid certificate but no subscription | 1. call → **`403`** from `subscription-validation` 2. subscription created 3. same connection, next call → `200` | D5: the two policies are independent; a certificate never satisfies the subscription check and vice versa. |
| O22 | API deployed with `mtls-auth` at API level | 1. developer redeploys adding `mtls-auth` on one operation as well → **`400`** naming that route 2. the previous deployment stays in force | §3.1.4 one-attachment-per-route: both would run and AND their `accept` lists. |

**Group 3 — outbound identities (S18, S19, D6)**

| # | Given | Sequence | Why |
|---|---|---|---|
| O12 | no identity named `I` | 1. developer deploys an upstream definition with `tls.identity: I` → **`400`**, `field = spec.upstreamDefinitions[0].tls.identity` 2. admin adds `I` → `201` 3. developer redeploys → `201` | S18 on the outbound side, same rule as O1. |
| O13 | identity `I` exists, upstream deployed with `tls.identity: I`, backend connections pooled | 1. admin `PUT /gateway-identities/I` with a renewed cert and key → `200`, `pooledConnectionsUsingPrevious: N` 2. **new** backend connections present the new certificate 3. pooled connections finish on the old one and are not dropped | G6: rotation without dropping in-flight requests. |
| O14 | upstream deployed with `tls.identity: I` | 1. admin `DELETE /gateway-identities/I` → **`409`**, `errors[]` lists the API and `field = spec.upstreamDefinitions[0].tls.identity` | S19 on the outbound side, same rule as O6. |
| O23 | as O13 | 1. admin rotates `I` twice before the pool drains 2. connections may be holding any of the three certificates; every one stays valid for its lifetime; no connection is dropped | Each SDS secret version is independent; Envoy never tears down a pool on a secret update. |

**Group 4 — restart, resync and concurrency (S8, §3.2.4, GO-AUTH-011)**

| # | Given | Sequence | Why |
|---|---|---|---|
| O15 | mTLS APIs deployed, controller restarts | 1. controller restarts 2. listener is re-derived from persisted APIs and pool **identically** 3. there is **no window** in which the listener lacks its validation context while APIs attach `mtls-auth` | Derived config must be reproducible from storage alone; a gap would either drop mTLS callers or, worse, serve without asking. |
| O15a | mTLS APIs deployed, operator sets `router.https_enabled: false`, controller restarts | 1. startup **refused**, log names the APIs 2. nothing is served | GO-AUTH-011: the effective outcome (mTLS APIs with no TLS listener) is invalid; fail closed at startup rather than serve 401s forever (§3.1.4). |
| O16 | Envoy reconnects to the controller (restart, network blip) | 1. snapshot re-sync 2. SDS secrets (`listener_cert`, `downstream_client_ca`, identities) arrive **before or with** the listener 3. the listener is never left **warming** | §3.2.4 / S8: a listener referencing a secret that has not arrived does not serve; the snapshot gate must include listener-referenced secrets. |
| O18 | pool is empty | 1. admin's `POST /client-ca-certificates` for `ca-a` and developer's deploy with `accept: [ca-a]` arrive **near-simultaneously** 2. if the CA commit landed first, the deploy → `201`; otherwise → `400` 3. the deploy must read **committed** pool state, never a stale cache | A spurious S18 from a cache would look like a bug to the developer; correctness requires read-after-commit. |
| O19 | pool = `{ca-a}`, `ca-a`'s `notAfter` passes while APIs name it | 1. new handshakes with `ca-a` certificates fail (Envoy validates the chain, including the authority's own dates) 2. `GET /client-ca-certificates` shows it expired; `CERT_EXPIRES_SOON` warned 30 days beforehand 3. a deploy naming it → `201` with a warning | Expiry is surfaced, never silent. Deploy is not refused because the admin may be mid-rotation. |
| O20 | gateway A has `ca-a` in its pool, gateway B does not | 1. the same API YAML with `accept: [ca-a]` is deployed to both 2. A → `201`; B → **`400`** | Pools are per gateway (§3.1.1 scope). The same definition is not portable until each gateway's pool is prepared. |

### 8.15 Request-time matrix — client × API

`API-M` has `mtls-auth` with `accept: [{ca: ca-a, match: {uriSANs: [U]}}]`. `API-P` is public. `API-T`
has a thumbprint entry for `client-valid`. "TLS fail" is a handshake alert with no HTTP response (D9).

| Client presents | API-M | API-P | API-T |
|---|---|---|---|
| nothing | `401` | `200` | `401` |
| `client-valid` (ca-a, SAN U) | `200` | `200` (cert ignored) | `200` |
| `client-valid` with extra SANs, one is U | `200` | `200` | `200` |
| ca-a cert, SAN ≠ U | `401` | `200` | `401` |
| ca-a cert, **no** SAN | `401` | `200` | `401` |
| ca-a cert, sibling of `client-valid` | `401` (SAN) | `200` | `401` (thumbprint) |
| `client-renewed` (same subject, new thumbprint, SAN U) | `200` | `200` | `401` until entry updated |
| cert from `ca-b` (pooled, not in `accept`) | `401` | `200` | `401` |
| cert from `ca-b`, **same CN** as `client-valid` | `401` | `200` | `401` |
| cert from `ca-b-same-dn` (DN collision) | `401` | `200` | `401` |
| self-signed, pooled as authority, named in `accept` | `200` | `200` | n/a |
| self-signed, **not** pooled | TLS fail | TLS fail | TLS fail |
| expired / not-yet-valid | TLS fail | TLS fail | TLS fail |
| untrusted authority | TLS fail | TLS fail | TLS fail |
| chain depth > max | TLS fail | TLS fail | TLS fail |
| `serverAuth`-only EKU | TLS fail | TLS fail | TLS fail |
| leaf **without** intermediate; pool has root only | TLS fail | TLS fail | TLS fail |
| leaf without intermediate; pool has root+intermediate | `200` | `200` | per entry |
| valid cert + **forged XFCC** for another identity | identity from handshake; header stripped | `200` | as handshake |
| **no** cert + forged XFCC | `401` | `200`, header stripped | `401` |
| HTTP/1.1 client, valid cert | `200` | `200` | `200` |
| TLS 1.2 client, valid cert | `200` | `200` | `200` |
| one HTTP/2 connection: API-M then API-P then API-M | `200`, `200`, `200` — identity attributed per request | | |

**Combination with other auth**, on an API with `mtls-auth` then `jwt-auth`:

| cert | token | Result |
|---|---|---|
| valid | valid | `200` |
| valid | absent/invalid | `401` from `jwt-auth` |
| absent | valid | `401` from `mtls-auth` — token does not help |
| absent | absent | `401` from `mtls-auth` (first in chain) |

Same shape for `mtls-auth` + `subscription-validation`: valid cert + no `Subscription-Key` → `403`;
key + no cert → `401`. **Every `401` body in this section is byte-identical** (S2a).

### 8.16 Response-contract checks

- Every deploy `201` for an API with `mtls-auth` echoes the **resolved** `accept` list.
- Every `400`/`409` matches the `ErrorResponse` shape and the canonical `field`/`message` texts in
  §5.2; none leaks a file path, stack trace, or Envoy internal (`error-handling.md` d.1).
- Every warning carries a `code` from the closed set in §5.2; an unknown code fails the test.
- A backend TLS failure returns the sterile `503` body of §3.2.6, never Envoy's default text.
- Every deploy-time **warning** listed above is present as `status.warnings[]` in the response body
  and in the controller log, and the array is absent when no condition holds.
- No response, at any role, on any endpoint, contains a private key — asserted against the schema.

### 8.17 Trust-anchor matrix — pool entry shape × what the client presents

The pool accepts four shapes of entry (§3.1.1, §3.1.2): a root alone, a root with its issuing
intermediate, an issuing intermediate alone, and a self-signed leaf. Clients differ in what they
send: the leaf alone, or the leaf with its intermediate(s). Every combination below is one
integration scenario. The API under test names the entry in `accept` with no narrowing. "TLS fail"
is a handshake alert recorded in `/tls/handshake-failures` with the reason shown; "200" means the
handshake completed **and** `mtls-auth` built a path to the named entry. Expected results follow
BoringSSL semantics with `X509_V_FLAG_PARTIAL_CHAIN` (the M0 item); a row marked ★ is the one that
depends on it.

**Entry A — root only (`ca-a`)**

| Client presents | Expected | Why |
|---|---|---|
| `client-valid` (signed by the root directly) | `200` | one-step path |
| `client-via-intermediate`, **leaf only** | **TLS fail `UNTRUSTED_CA`** | nothing links leaf to root — the documented failure that "include intermediates" prevents |
| `client-via-intermediate` **+ `ca-a-intermediate`** | `200` | Envoy completes the path from the sent intermediate; the policy uses the XFCC chain |
| `client-via-intermediate-2` + `ca-a-intermediate-2` (rotated) | `200` | zero-touch rotation: any intermediate under the root works if the client sends it |
| `client-via-other-intermediate` + `ca-a-other-intermediate` (sibling) | `200` | **root-level trust is wide**: every intermediate the root signed is accepted — the reason intermediate-only exists |
| `client-wrong-ca` (under `ca-b`) | TLS fail `UNTRUSTED_CA` | different root |

**Entry B — root + issuing intermediate in one entry (`ca-a` + `ca-a-intermediate`)**

| Client presents | Expected | Why |
|---|---|---|
| `client-via-intermediate`, leaf only | `200` | the entry supplies the intermediate; path built from pool material |
| `client-via-intermediate` + intermediate | `200` | same |
| `client-via-intermediate-2` + `ca-a-intermediate-2` (rotated, sent) | `200` | chains to the root in the entry |
| `client-via-intermediate-2`, leaf only (rotated, **not** sent) | **TLS fail `UNTRUSTED_CA`** | the entry holds the old intermediate; nothing links leaf to root — update the entry or have clients send the new intermediate |
| `client-via-other-intermediate` + sibling | `200` | root in the entry → wide trust, as Entry A |
| `AuthContext.Issuer` for any `200` above | the **entry name** | not the issuing intermediate's DN |

**Entry C — issuing intermediate only (`ca-a-intermediate`)**

| Client presents | Expected | Why |
|---|---|---|
| `client-via-intermediate`, leaf only | `200` ★ | the intermediate is the anchor; one-step path via partial chain |
| `client-via-intermediate` + intermediate | `200` ★ | the sent intermediate matches the anchor |
| `client-via-intermediate` + intermediate + `ca-a` root | `200` ★ | extra certificates the client sends are ignored |
| `client-via-intermediate-2` + `ca-a-intermediate-2` (rotated) | **TLS fail `UNTRUSTED_CA`** | the rotation cost of intermediate-only: the new intermediate is a new anchor and must be uploaded |
| `client-via-other-intermediate` + sibling | **TLS fail `UNTRUSTED_CA`** | **the tightest trust**: a sibling intermediate under the same root is not accepted — the point of this shape |
| `client-valid` (signed by the root directly) | TLS fail `UNTRUSTED_CA` | the root is not in the pool |

**Entry D — self-signed leaf (`client-selfsigned`)**

| Client presents | Expected | Why |
|---|---|---|
| `client-selfsigned` itself | `200` ★ | the presented certificate **is** the anchor; signature check against its own key |
| `client-selfsigned-b` (another self-signed) | TLS fail `UNTRUSTED_CA` | never pooled |
| `client-selfsigned-renewed` | TLS fail `UNTRUSTED_CA` until uploaded as a new entry | a renewed self-signed certificate is a new anchor (§3.1.2) |
| `client-signed-by-leaf` (+ `client-selfsigned` as "intermediate") | **TLS fail `BAD_KEY_USAGE`** | a `CA:FALSE` certificate cannot act as an issuer; BoringSSL reports `invalid CA certificate` |
| upload of `client-selfsigned` | `201`, `isLeaf: true`, warning `CLIENT_CA_IS_LEAF` | §5.2.2 |

**Cross-entry cases**

| Pool | API `accept` | Client presents | Expected | Why |
|---|---|---|---|---|
| `ca-a` and `ca-a-intermediate` as **two separate entries** | `[ca: ca-a-intermediate]` | `client-via-intermediate`, leaf only | `200` ★ | the intermediate entry is the anchor |
| same | `[ca: ca-a]` | `client-via-intermediate`, leaf only | `200` | handshake passes (the intermediate is in the bundle); the policy builds leaf → intermediate → root using **the other pool entry** as path material (§3.1.1) |
| same | `[ca: ca-a]` | `client-via-other-intermediate` + sibling | `200` | root named → wide |
| same | `[ca: ca-a-intermediate]` | `client-via-other-intermediate` + sibling | **`401`**, handshake **OK** | the bundle trusts the root, so the handshake passes; the named entry is the intermediate, so the policy finds no path — S16 in chain form |
| `ca-a-intermediate` uploaded twice under two names | `[ca: <either name>]` | `client-via-intermediate` | `200`; `Issuer` = the named entry | duplicate anchors are harmless (§8.8) |
| two unrelated roots in one PEM | — | upload | `400` | §5.2.1 |

**Unit tests the matrix implies (`mtls-auth`)**

- `x509.Verify` is called with `Roots` = the named entry's certificates, `Intermediates` = XFCC chain
  ∪ all pool certificates, `KeyUsages` = `[ExtKeyUsageAny]`, `CurrentTime` = now. A test that
  removes `KeyUsages` must fail on every client certificate carrying only `clientAuth`.
- The XFCC `Chain` element is parsed only when `connection.mtls == true`; with it `false` the same
  header content is ignored and the path is built from pool material alone.
- The policy never adds a certificate from the XFCC chain to `Roots`; a chain whose final
  certificate is an untrusted root must fail even though it is self-consistent.

---

## 9. Phasing

**M0 — Spike (blocking, ~days).** Confirm request-and-validate end to end on Envoy v1.39.0: a
listener with `require_client_certificate: false` and a validation context accepts a connection with
no certificate, drops one with an invalid certificate, and exposes the `connection.*` attributes to
ext_proc for a valid one. Verify the `X509_V_FLAG_PARTIAL_CHAIN` reliance for self-signed pooled
leaves (§3.1.2).

**M1 — Foundations.** SDS `Secret_TlsCertificate` and a second validation context; generalize the
snapshot-inclusion gate; move the listener key to SDS (D8); fix the cert-store fail-open (§3.2.5);
test PKI fixtures and godog steps (§8.1). *Ships no user-visible feature and carries most of the
risk — see §3.2.4 on D8's blast radius.*

**M2 and M3 run in parallel after M1.**

**M2 — Outbound.** `gw_gateway_identity`, `Upstream.tls`, per-upstream trust, management API.
No SDK, proto or policy-repo coupling. Larger than it looks: per-upstream *trust* has no data model
today — `SecretNameUpstreamCA` is a single hard-coded constant serving one flat bundle — so G5 needs
N validation-context secrets, a per-cluster reference replacing that constant, and the snapshot
gate generalized to arbitrary names. A per-upstream `trustedCAs` **replaces** the global bundle for that
upstream (it does not extend it), as §8.5 and §8.12 already test.

**M3 — Inbound.** ext_proc attributes, SDK field and accessor, proto, policy-engine population,
`mtls-auth` policy, the CA pool endpoints, `accept` resolution and deploy-time validation. Both
identity forms — authority+SAN and thumbprint — ship here. Carries the three-repo release ordering
of §6.

Running these in parallel means M1 is a hard bottleneck for both, and the two teams share the
snapshot-inclusion gate and SDS work. Sequence M1 deliberately rather than splitting it.

**M4 — Follow-ons.** Dedicated mTLS port (D3); RFC 8705 bound tokens (N3); header-cert-auth as a separate policy (N1); CRL (N2);
capability negotiation (§6, deferred).

## 10. Open questions

1. **Q-M — SNI-scoped certificate requests on the shared listener.** Under D2 the shared HTTPS
   listener asks *every* connection for a certificate while any mTLS API exists, and D3's dedicated
   port (M4) is the only relief the spec offers. Kong and Envoy Gateway instead ask only on the
   hostnames of mTLS routes, on one port. Because enforcement here is per request in the policy
   (D1), a coalesced connection yields a `401` rather than the bypass that made GEP-91 reject the
   shape, so it is available to us as a derived second filter chain when every mTLS API has its
   own `vhosts.main`. Options, preconditions, verified platform facts, example API YAML and the
   target Envoy configuration are in [`sni-scoped-asking.md`](./sni-scoped-asking.md). Decide
   whether to adopt it, and if so in M3 or M4. Nothing in M1–M3 as specified depends on the answer.

---

## Appendix A — Decision rationale

One entry per decision in §2: why the chosen option beat the alternatives. Nothing here is needed to
implement the feature; it is here so the decisions are not re-litigated.

### A.1 D1 — Inbound is policy-enforced

The decisive constraint is RFC 8740: an HTTP/2 server **MUST NOT** send a post-handshake
`CertificateRequest`, and our listener negotiates `h2` (`translator.go:2448`). So "ask for a
certificate only on the routes that need it" is not achievable at the transport layer, on any
design. **Negotiation must be coarse; enforcement must be fine.**

Pure per-listener transport enforcement was rejected because it makes every API behind `https_port`
require a certificate — an availability incident dressed as a security improvement — and because
it rejects at the TLS layer, producing no HTTP body, no uniform 401, and no analytics event.

### A.2 D2 — Default to `request`, not `require`

`RequireClientCertificate: false` **with** a validation context means: ask for a certificate,
validate it if one is presented, do not terminate the connection if it is absent. That is what
lets one shared listener serve both mTLS and non-mTLS APIs, which is what makes per-API
enforcement possible at all.

Cost, stated plainly: **every** client on that listener is *asked* for a certificate, so browsers
will show a certificate-selection prompt on APIs that don't use mTLS. D3 is the escape hatch.

Request-and-validate is confirmed from Envoy source (`default_validator.cc`: a non-empty
`trusted_ca` sets `SSL_VERIFY_PEER`; `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` is added only when
`require_client_certificate: true`). An *invalid* presented certificate is dropped at the handshake
(D9, §3.1.1).

### A.3 D3 — Optional dedicated mTLS port

**The problem.** Asking for a certificate happens once per connection, before the first request, and
HTTP/2 forbids asking again (A.1). So on the shared listener the choice is binary: ask every connection
or none. While any mTLS API is deployed the listener asks, and a browser with client certificates
installed may show a selection dialog on public APIs — including the public *operations* of an API
whose other operations use `mtls-auth`. No product can narrow this at the transport: all operations of
one API share one hostname, so Kong's SNI map cannot separate them either.

**The shape.** A second listener on its own port with `require_client_certificate: true`. The
dedicated listener is a property of the **connection**, not of the API: every deployed API is reachable
on both listeners and the policy still decides per operation. Only the handshake differs — the shared
port stops asking altogether, the dedicated port always requires. A browser calls the public
operations on the shared port and never sees a prompt; a partner calls the mTLS operations on the
dedicated port with its certificate. An mTLS operation reached over the shared port answers `401`,
because no certificate can exist on that connection and the policy fails closed (§8.11). The operator
publishes one base URL per listener.

**Alternative for the M4 design.** Kong and Envoy Gateway split by *hostname* on one port instead —
an SNI-matched filter chain that asks only on the mTLS hostname. We rejected per-SNI chains in N4
because HTTP/2 connection coalescing lets a browser reuse a connection across hostnames, but coalescing
only occurs when one server certificate covers both names. With a separate certificate per hostname it
is safe, and it is what those products rely on. The M4 design may offer both shapes; the port is
airtight without operator discipline, the hostname needs the certificate rule.

**Why optional, why M4.** Most gateway traffic is machine-to-machine and never sees the prompt.
Nothing in M1–M3 depends on the second listener, and the operator's Helm overlay states per-listener
certificate selection is unsupported today (§5.4), so it needs operator work of its own.

### A.4 D4 — Identity is an `accept` entry

`tlsauth.PeerIdentity` (`peer_identity.go:41-46`) picked "first URI SAN, else CN" for
control-plane peers. We **deliberately diverge** for data-plane clients: two different CAs issuing
the same CN produce the same identity under that rule, and external client certificates are not
issued by an infrastructure we control.

### A.5 D5 — The output is an `AuthContext`, and nothing else

It does **not** write `x-wso2-application-id`. That key is produced by `api-key-auth` because an API
key is an application credential; a certificate is not, and neither is a JWT — `jwt-auth` writes no
such key either. `subscription-validation` therefore treats an mTLS-protected API exactly as it
treats a JWT-protected one: it looks for its `Subscription-Key` header and decides on its own.

Two things follow, and both are simplifications:

- **No coordination between the two policies.** Each does its job; a caller must satisfy both.
  Order matters only for cost (§3.1.5), not for correctness.
- **No control-plane dependency.** Nothing here needs a platform-api resource, an event, or a
  gateway-side credential store, which is what lets both identity forms ship in v1.

### A.6 D6 — Outbound is transport config, never a policy

Every existing `upstream.auth.type` value resolves to an attached L7 policy that sets a header.
Backend mTLS cannot work that way because:

1. The certificate is presented during TLS handshake, before any HTTP request is framed.
2. Envoy **pools** upstream connections and reuses them across requests and across different
   downstream callers — the certificate is a property of the pooled connection, not the request.
3. It is configured on the cluster transport socket (CDS), which no HTTP filter can reach.
4. `ext_proc` has no "about to dial an upstream" message type.

Therefore backend mTLS goes on a new **`Upstream.tls` block**, alongside trust settings. Anything
request-scoped can influence it only by selecting a *different cluster* — never by changing an
existing connection's certificate.

### A.7 D7 — New tables, not the frozen `certificates` table

`certificates` is a shipped table and therefore frozen under the repo's schema rule
(`db-schema-changes.md` R0-FROZEN: no retyping, renaming or constraint changes on customer data). More importantly,
every row in it feeds **one flat bundle** used for upstream verification (`certstore.go:73-130`).
Adding client-CA certificates to that bundle — even with a `usage` tag — risks a change that
silently widens which backends the gateway trusts. That is a trust-boundary violation introduced
by a storage convenience.

Two **new** tables instead. New tables need only a guarded `CREATE TABLE IF NOT EXISTS` per
dialect and no `ALTER` path (R0-UPGRADE-PATH), so this is both safer and *less* migration work:

- `gw_client_ca_certificate` — inbound trust anchors (CA bundle for validating client certs).
- `gw_gateway_identity` — outbound keypairs (cert chain + encrypted private key). Named for what
  it holds — *our* identity — so it is not mistaken for a sibling of `gw_client_ca_certificate`.

The existing `certificates` table and `/certificates` API are left untouched, and keep meaning
exactly what they mean today: upstream trust.

Gateway identities also do **not** ride the existing `secrets` store. A secret is an opaque string
(≤10240 characters) consumed by rendering `{{ secret "handle" }}` into the API definition at deploy
time — which would place a private key inside stored API configuration, the opposite of S6's
"SDS only" rule. An opaque string also cannot be validated at write (cert/key match, expiry,
metadata for listings), and the size cap already excludes an RSA-4096 chain and every PQC
certificate. An identity is a typed object with its own endpoint, delivered to Envoy directly over
SDS, and never rendered into a definition.

### A.8 D8 — Listener private key moves to SDS

The listener key travels inline in LDS today, a standing `go-control-plane-xds-security.md` directive-3
violation. This work adds `Secret_TlsCertificate` support to SDS regardless, so leaving the violation in
place while extending the same function is not acceptable under directive 7. The blast radius and what
M1 owes for it are in §3.2.4.

### A.9 D9 — An invalid certificate is stopped at the handshake

**Rejected:** `trust_chain_verification: ACCEPT_UNTRUSTED` with the verdict forwarded as
`connection.peer_certificate_valid`, so every rejection becomes a uniform 401. It would unify the
error contract, but every garbage certificate would cost an ext_proc round trip, the policy would
receive a boolean without a reason, and the shape is unproven for us. Also rejected: accepting
untrusted and rebuilding the chain inside the policy, which reimplements path validation.

### A.10 D10 — Per-request re-evaluation, no connection-duration bound

A `max_connection_duration` listener setting would bound how long a removed pool authority stays
trusted on an open connection, but it is a new, gateway-wide behaviour change for a narrow gain: the
fast lever for cutting a client off is editing `accept`, which is per request. Deferred; `idle_timeout`
bounds the idle case today (§3.1.2).
