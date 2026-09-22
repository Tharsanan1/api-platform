# Research: Mutual TLS (mTLS) for the API Platform Gateway

**Feature**: mTLS — client→gateway authentication and gateway→backend client certificates
**Branch**: `mtls`
**Research Date**: 2026-09-15
**Phase**: 0 — Research only. This document deliberately does **not** pick a design; it
establishes protocol facts, the current state of this codebase, prior art, and the open
questions a subsequent spec must answer.

## Reading guide

- Phase 1 — mTLS fundamentals (protocol-level, product-neutral)
- Phase 2 — This codebase: what exists today, cited to `file:line`
- Phase 3 — Competitive / prior-art analysis
- Phase 4 — Synthesis: capability matrix, candidate designs, open questions, pitfalls

Claims about this repo cite `file:line`. Claims about external products cite a URL.
Anything not directly confirmed from a primary source is marked **UNVERIFIED**.

---

# Phase 1 — mTLS fundamentals

## 1.1 What mTLS is

Ordinary TLS authenticates only the server: the client validates the server's certificate
chain against a trust store. **Mutual TLS** adds the reverse leg — the server asks the
client for an X.509 certificate and validates it, so both peers are authenticated by the
transport before any application bytes flow.

The critical property for an API gateway: mTLS authenticates a **TLS connection**, not a
request. On HTTP/1.1 with keep-alive and especially on HTTP/2, many requests — potentially
from different logical callers if a shared proxy sits in front — ride one authenticated
connection. Every design decision below flows from that mismatch between connection-scoped
authentication and request-scoped authorization.

## 1.2 Handshake flow: TLS 1.2 vs TLS 1.3

### TLS 1.2 (RFC 5246)

```
Client                                        Server
ClientHello                 ────────────────▶
                            ◀──────────────── ServerHello
                                              Certificate
                                              ServerKeyExchange
                                              CertificateRequest      ← client auth negotiated HERE
                            ◀──────────────── ServerHelloDone
Certificate                 ────────────────▶ ← client's cert, sent in the CLEAR
ClientKeyExchange
CertificateVerify           ────────────────▶ ← proves possession of the private key
ChangeCipherSpec / Finished ────────────────▶
                            ◀──────────────── ChangeCipherSpec / Finished
```

Key points:

- `CertificateRequest` carries `certificate_types`, `supported_signature_algorithms`, and
  `certificate_authorities` (a list of acceptable CA distinguished names). That DN list is
  what lets a browser/client pick which client cert to offer — and it is also why a very
  large trust bundle inflates every handshake (Kong exposes this as `send_ca_dn`).
- The client's `Certificate` message is **not encrypted** in TLS 1.2. A passive observer
  sees the client's identity.
- If the client has no suitable certificate it sends an empty `Certificate` message; the
  server then chooses to fail or continue (this is the "optional client cert" mode).
- `CertificateVerify` is a signature over the handshake transcript with the client's
  private key. Without it, presenting a certificate proves nothing — it is public data.

### TLS 1.3 (RFC 8446)

```
Client                                        Server
ClientHello                 ────────────────▶
                            ◀──────────────── ServerHello
                                              {EncryptedExtensions}
                                              {CertificateRequest}    ← client auth negotiated HERE
                                              {Certificate}
                                              {CertificateVerify}
                                              {Finished}
{Certificate}               ────────────────▶ ← ENCRYPTED
{CertificateVerify}         ────────────────▶
{Finished}                  ────────────────▶
```

Braces `{}` denote handshake-encrypted records. Differences that matter:

- The client certificate is **encrypted** under the handshake traffic key. This removes the
  historical reason for doing client auth via renegotiation (privacy of the client identity)
  — see RFC 8740 below.
- `CertificateRequest` in 1.3 no longer carries a `certificate_authorities` list by default;
  it is an optional extension (`certificate_authorities`, RFC 8446 §4.2.4).
- Client auth is still negotiated **once, at the start of the connection**, before any
  application data.

### Post-handshake client authentication (RFC 8446 §4.6.2)

TLS 1.3 removed renegotiation and replaced it with *post-handshake authentication*: if the
client advertised the `post_handshake_auth` extension in its ClientHello, the server may
send a `CertificateRequest` at any later point, and the client answers with
`Certificate` / `CertificateVerify` / `Finished`.

This is the mechanism you would want for "only ask for a certificate when the request hits
a protected route". **It is effectively unusable over HTTP/2**, and this is normative, not
a limitation of any particular implementation:

> RFC 8740 ("Using TLS 1.3 with HTTP/2", Feb 2020) updates RFC 7540 to forbid TLS 1.3
> post-handshake authentication in HTTP/2. "HTTP/2 servers **MUST NOT** send post-handshake
> TLS 1.3 CertificateRequest messages. HTTP/2 clients **MUST** treat such messages as a
> connection error of type PROTOCOL_ERROR."
> — https://www.rfc-editor.org/rfc/rfc8740.html

The reason is multiplexing: many streams share one connection, so the client cannot
correlate a certificate request with the request that triggered it, and the server cannot
attribute the resulting identity to only the stream that needed it. This is the exact analog
of the TLS 1.2 renegotiation prohibition in RFC 7540 §9.2.1.

**Consequence for this product**: any design that says "turn on mTLS only for the APIs that
need it, on a shared HTTPS listener that negotiates h2" cannot do so by deferring the
certificate request. The certificate must be requested at connection setup — which means
either (a) a separate listener/port, (b) SNI-based filter-chain selection, or (c) request it
from everyone and enforce per-route in the application layer. All three appear in Phase 4.

Azure API Management documents the practical fallout of the TLS 1.2 renegotiation path:
requesting the certificate lazily via `context.Request.Certificate` "might freeze requests"
or return 403 for POST/PUT bodies over ~60 KB, and the recommended fix is to enable
`negotiateClientCertificate` on the hostname — i.e. request it up front.
(https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates-for-clients)

## 1.3 Trust models

| Model | How it works | Pros | Cons |
|---|---|---|---|
| **CA bundle / PKI** | Trust a CA; accept anything it signs. Chain validated to a root in the bundle. | Scales to many clients; rotation is a client-side concern; standard tooling. | "Trusted CA" grants access to **every** certificate that CA will ever sign. A public CA in the bundle is catastrophic. Needs a second authorization step. |
| **Certificate pinning (leaf)** | Compare the presented cert's SHA-256 fingerprint to an allowlist. | Exact identity; no CA trust needed; works with self-signed. | Breaks on every renewal; allowlist grows linearly with clients; no revocation semantics beyond deletion. |
| **SPKI pinning** | Pin the SHA-256 of the SubjectPublicKeyInfo, not the whole cert. | Survives certificate renewal **if the key is reused**; still exact. | Key reuse across renewals is itself a weaker posture; still O(clients). |
| **SPIFFE / SVID** | X.509 SVID whose URI SAN is `spiffe://<trust-domain>/<path>`; short-lived (minutes-hours), auto-rotated by a workload API. | Identity is a structured, comparable URI; rotation solves revocation; designed for service-to-service. | Requires a SPIFFE issuer (SPIRE, Istio citadel); not what an external B2B partner will have. |
| **Self-signed + explicit allowlist** | Client generates a self-signed cert, uploads it; server matches by fingerprint (or trusts it as its own root). | No PKI needed; per-client revocation is "delete the row". | Same O(clients) problem; rotation is a coordinated ceremony. RFC 8705 blesses this shape via `self_signed_tls_client_auth`. |

Envoy supports the first three directly on `CertificateValidationContext`: `trusted_ca`,
`verify_certificate_hash` (hex SHA-256 of the DER cert), `verify_certificate_spki` (base64
SHA-256 of the SPKI), and `match_typed_subject_alt_names`.
(https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto)

A note that is easy to get wrong: Envoy performs **no** peer verification unless a validation
context with trust anchors is present — "Certificate verification of both upstream and
downstream connections is not enabled unless the validation context specifies one or more
trusted authority certificates", and specifying only `trusted_ca` "verifies the certificate
chain but not its subject name, hash, etc."
(https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl)

## 1.4 Certificate identity extraction

| Field | Stability | Forgeable if misused | Canonicalization hazards |
|---|---|---|---|
| **Subject DN** | Stable per issuance policy; changes on re-issuance if the CA changes attribute order/encoding. | Only within what the CA will sign. If two CAs are trusted, DNs collide across issuers — bind DN **to issuer**. | Severe. RFC 4514 string form vs OpenSSL `oneline` vs Envoy's format all differ. Attribute ordering (`CN=a,O=b` vs `O=b,CN=a`), spacing after commas, escaping of `,`/`+`/`"`/`\`, `PrintableString` vs `UTF8String` encoding, and case-insensitivity of some attribute types (per X.520 matching rules) all produce byte-different strings for the same DN. Never compare DNs as raw strings across producers. |
| **CN** (a component of the Subject DN) | Deprecated for identity since RFC 6125; many CAs still populate it. | Same as DN. | Same, plus: a CN is not required to be unique, and an attacker-chosen CN under a trusted CA impersonates trivially. |
| **SAN dNSName** | Stable. | Constrained by CA name constraints if present; otherwise the CA can issue any name. | Case-insensitive ASCII compare; watch IDN/punycode; trailing dot. |
| **SAN URI** | Stable; the SPIFFE convention. | Same. | Exact-match a normalized URI; beware trailing slash, case of scheme/authority. |
| **SAN IP** | Stable. | Same. | Compare as parsed bytes, not text — `::ffff:10.0.0.1` vs `10.0.0.1`, IPv6 zero-compression. |
| **SAN rfc822Name (email)** | Stable. | Same. | Local-part is case-sensitive in theory; domain is not. |
| **serialNumber + issuer** | The only pair guaranteed unique by X.509 within a CA. | Not forgeable without the CA. | Serial is a positive integer that can exceed 64 bits — store as a big-int or hex string, never `int64`. Leading-zero and sign-byte handling differs between encoders. |
| **Thumbprint / fingerprint** (SHA-256 of DER) | Changes on *every* re-issuance, including renewal. | Not forgeable. | Case of hex; base64 vs base64url vs hex — RFC 8705 uses **base64url** of the raw SHA-256; Azure uses uppercase hex; Envoy `verify_certificate_hash` uses hex. |

Practical rule: for authorization, prefer **(issuer, serial)** or **SAN URI** or
**SHA-256 thumbprint**. If you must use a DN, canonicalize it yourself from the parsed
`pkix.Name` rather than accepting whatever string a proxy handed you.

## 1.5 Revocation

- **CRL** — a signed list of revoked serials published by the CA. Envoy supports it on
  `CertificateValidationContext.crl`, plus `only_verify_leaf_cert_crl` to skip CRL checks on
  intermediates. The operational cost is real: CRLs must be fetched, refreshed before
  `nextUpdate`, and they grow unboundedly. Envoy does **not** fetch CRLs itself — the CRL is
  a data source you supply (file or inline), so refresh is the control plane's job.
- **OCSP** — an online query to the CA per certificate. Adds a synchronous dependency in the
  handshake path and leaks which certificates you see to the CA.
- **OCSP stapling** — the *server* attaches a recent OCSP response for **its own**
  certificate. This does nothing for client certificates: the client would have to staple its
  own status, which requires the client to support it and the server to demand it
  (`status_request_v2`/`post_handshake` variants are essentially not deployed). Envoy's
  `DownstreamTlsContext.ocsp_staple_policy` (`LENIENT_STAPLING` default, `STRICT_STAPLING`,
  `MUST_STAPLE`) governs the **server** certificate only, and Envoy explicitly states "OCSP
  responses are ignored for UpstreamTlsContexts".
  (https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto,
  https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl)
- **Short-lived certificates** — the practical modern answer. If a certificate lives hours,
  revocation is "stop re-issuing". This is the SPIFFE/SVID model and increasingly the ACME
  model. It moves the problem to automated issuance.
- **Application-layer allowlist/denylist** — what most API gateways actually ship: the
  gateway keeps a table of accepted identities; revocation = delete the row. AWS explicitly
  pushes revocation into a Lambda authorizer because API Gateway "doesn't verify if a
  certificate has been revoked"
  (https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html).

**What Envoy supports, summarized**: CRL yes (supplied, not fetched); OCSP for client certs
no; SPKI/hash pinning yes; SAN matching yes; `allow_expired_certificate` and
`trust_chain_verification` (including `ACCEPT_UNTRUSTED`) as escape hatches; `max_verify_depth`
for chain depth.

## 1.6 Chain validation, depth, cross-signing, rotation

- **Depth**: the number of intermediates between leaf and trust anchor. Envoy exposes
  `max_verify_depth`; NGINX exposes `ssl_verify_depth` (ingress-nginx annotation
  `auth-tls-verify-depth`, default 1 — and note the community-reported gotcha that with
  OpenSSL ≥1.1.0 the effective depth is one more than configured,
  https://github.com/kubernetes/ingress-nginx/issues/110). AWS API Gateway caps the chain at
  4 and requires the *complete* chain in the truststore.
- **Intermediates**: the client is expected to send leaf + intermediates; the server supplies
  only the root. If a client omits an intermediate, validation fails with a confusing
  "unknown CA". Some gateways offer `allow_partial_chain` (Kong) to tolerate trusting an
  intermediate directly as an anchor — convenient and a real trust narrowing, but it changes
  what "trusted" means.
- **Cross-signed chains**: the same public key may be reachable via two different chains
  (the classic Let's Encrypt DST Root / ISRG Root X1 situation). A validator that builds only
  one path can fail where another succeeds. Pinning the SPKI is immune; pinning the leaf hash
  is immune; trusting a CA is not.
- **Expiry/rotation**: client certificates expire, and there is no in-band renewal signal.
  The gateway should surface `notAfter` and warn. AWS's model is a cautionary tale: "API
  Gateway produces certificate warnings only when you update your domain name. API Gateway
  doesn't notify you if a previously uploaded certificate expires."
- **What "trusted CA" really grants**: everything that CA will ever sign, for as long as it is
  in the bundle. If the CA is a public/commercial CA, that is the entire public internet.
  This is *the* recurring mTLS misconfiguration, and it is why every mature product pairs CA
  trust with a second, identity-level check (Kong consumer lookup, Azure
  `validate-client-certificate` identity matching, RFC 8705 expected-DN/SAN metadata).

## 1.7 The termination-topology problem

In most real deployments the gateway is not the TLS terminator. A cloud LB, ingress, or CDN
terminates and re-originates. The client identity then has to be *conveyed*, and every
conveyance mechanism is a header — i.e. attacker-controllable unless the hop is trusted.

### X-Forwarded-Client-Cert (XFCC), Envoy's format

Semicolon-separated `key=value` pairs; multiple proxies append comma-separated elements.
Keys are case-insensitive, values case-sensitive. Values containing `,`, `;` or `=` must be
double-quoted, with inner quotes escaped as `\"`.
(https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert)

| Key | Meaning |
|---|---|
| `By` | URI SAN of the **current proxy's** certificate |
| `Hash` | SHA-256 digest of the current client certificate |
| `Cert` | Whole client certificate, URL-encoded PEM |
| `Chain` | Whole client chain, URL-encoded PEM (the chain **as presented**, not the validated path) |
| `Subject` | Subject DN of the client cert, always double-quoted |
| `URI` | URI SAN(s) |
| `DNS` | dNSName SAN(s) |
| `Issuer` | Issuer DN, always double-quoted |

A JSON variant exists in which `by`/`uri`/`dns`/`chain` are arrays. Envoy's
`forward_client_cert_details` enum governs behaviour: `SANITIZE` (**default** — strip the
header), `FORWARD_ONLY`, `APPEND_FORWARD`, `SANITIZE_SET`, `ALWAYS_FORWARD_ONLY`;
`set_current_client_cert_details` selects which subfields Envoy writes.

The default being `SANITIZE` is the correct default and worth preserving: an unconfigured
Envoy strips any client-supplied XFCC.

### Other conveyances

- **AWS ALB** — with mTLS in "verify" mode ALB adds `X-Amzn-Mtls-Clientcert` (URL-encoded
  PEM) plus `-Leaf`, `-Subject`, `-Issuer`, `-Serial-Number`, `-Validity` variants.
  **UNVERIFIED** in exact header spelling — not fetched from AWS primary docs in this pass.
  **NLB** operates at L4 and does *not* terminate TLS in passthrough mode, so the gateway can
  do real mTLS behind an NLB — this is the topology that preserves the handshake.
- **AWS API Gateway** — terminates and exposes the cert to integrations/authorizers via the
  request context (`$context.identity.clientCert.*`: `clientCertPem`, `subjectDN`,
  `issuerDN`, `serialNumber`, `validity.notBefore/notAfter`). **UNVERIFIED** on exact
  variable names — the fetched HTTP-API page documents forwarding "to Lambda authorizers and
  to backend integrations" without enumerating the variables.
- **NGINX** — `$ssl_client_escaped_cert` (URL-encoded PEM), `$ssl_client_s_dn`,
  `$ssl_client_verify`. ingress-nginx sets `proxy_set_header ssl-client-cert
  $ssl_client_escaped_cert` only when `auth-tls-pass-certificate-to-upstream: "true"`.
- **Azure Application Gateway** — does not forward the client certificate to APIM; Microsoft
  documents this explicitly and points at "Mutual Authentication Server Variables" rewriting
  as the workaround
  (https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates-for-clients).
- **WSO2 APIM / APK heritage** — `X-WSO2-CLIENT-CERTIFICATE`, configurable via
  `[apimgt.mutual_ssl] certificate_header`.

### Why trusting such a header from an untrusted hop is a critical auth bypass

If the gateway accepts `X-Forwarded-Client-Cert` (or `X-WSO2-CLIENT-CERTIFICATE`) from any
peer, **any client can assert any identity** by setting the header. This is a complete
authentication bypass, not a hardening gap. The mitigations, all of which are required
together:

1. Only accept the header when the connection arrives from an explicitly configured trusted
   hop (source IP/CIDR allowlist, or better, the gateway itself terminates mTLS *from the
   proxy* so the hop is cryptographically identified).
2. **Always strip** the header on ingress from untrusted peers before any policy reads it
   (Envoy's `SANITIZE` default does this; anything that re-enables forwarding must
   re-establish the trust boundary).
3. Make the "trust a forwarded cert header" mode an explicit, off-by-default configuration
   with a named trusted-hop list — never a fallback that engages when no TLS peer cert is
   present.

This maps directly onto this repo's `authentication_authorization.md` GO-AUTH-001
(fail-closed) and GO-AUTH-011 (fail-closed startup validation on the *effective* config).

## 1.8 RFC 8705 — OAuth 2.0 mTLS client auth and certificate-bound tokens

Directly relevant because this gateway already does OAuth2/JWT auth
(`jwt-auth`, `opaque-token-auth` policies).

**Two client authentication methods** at the token endpoint:

- `tls_client_auth` — PKI-based. The client registers **exactly one** expected subject value
  via client metadata: `tls_client_auth_subject_dn` (RFC 4514 string),
  `tls_client_auth_san_dns`, `tls_client_auth_san_uri`, `tls_client_auth_san_ip`,
  `tls_client_auth_san_email`.
- `self_signed_tls_client_auth` — the client registers its certificate(s) via `jwks`/
  `jwks_uri` using the JWK `x5c` member; no PKI validation, exact match instead.

**Certificate-bound access tokens**: the AS puts the base64url SHA-256 thumbprint of the
client's DER certificate into the token's confirmation claim:

```json
{ "cnf": { "x5t#S256": "<base64url SHA-256 of DER cert>" } }
```

A resource server (here: **the gateway**) must obtain the client certificate from its TLS
layer, compute the same thumbprint, and reject with `401 invalid_token` on mismatch. The
same `cnf` object appears as a top-level member of an RFC 7662 introspection response, so an
opaque-token path can also be bound.

`mtls_endpoint_aliases` lets the AS publish separate mTLS-enabled endpoint URLs so that
turning on client-cert negotiation does not affect conventional clients — the same
"separate listener for mTLS" pattern that Phase 4 proposes for this gateway.

**Security consideration called out by the RFC itself**, and highly relevant here: when a TLS-
terminating proxy fronts the resource server, "how the client certificate metadata is securely
communicated between the intermediary and the application server ... is out of scope" — i.e.
RFC 8705 hands the §1.7 problem straight back to the implementer.

WSO2 APIM 4.x already implements the validation half of this: `enable_certificate_bound_access_token`
in `deployment.toml`, thumbprint compared against the cert from `X-WSO2-CLIENT-CERTIFICATE`,
with the documented limitation that "WSO2 API-M supports certificate bound JWT (access token)
validation only" — the IdP must mint the bound token.
(https://apim.docs.wso2.com/en/4.4.0/design/api-security/api-authentication/securing-apis-using-certificate-bound-access-tokens/)

## 1.9 Key and secret handling

- **Private key at rest** — a client key (for backend mTLS) or a server key (for the listener)
  is the highest-value secret in the system. It must be encrypted at rest, never returned by
  any read API, never logged, and never serialized into a config dump.
- **Rotation** — needs to be doable without a restart and without dropping in-flight
  connections. TLS certificates are bound at *connection* setup, so a rotated certificate
  affects only new connections; existing connections keep the old one until they close. That
  is usually acceptable, but it means "rotation is complete" is a function of connection
  lifetime, not of the config push.
- **Hot reload** — Envoy's mechanism is SDS: the control plane pushes a `Secret` resource and
  Envoy swaps it in for new connections. Envoy also supports filesystem-watched rotation via
  `watched_directory` on the validation context. Envoy's own docs say rotation "is supported
  for static resources by sourcing SDS configuration from the filesystem or by pushing
  updates from the SDS server" but do not state whether existing connections drain —
  **UNVERIFIED** whether an SDS certificate rotation closes established downstream
  connections in current Envoy.
- **HSM/KMS** — Envoy supports private-key providers (`custom_tls_certificate_selector`,
  private key provider extensions) for keeping keys in an HSM; out of scope for a first
  implementation but relevant to whether keys are modelled as opaque handles or as PEM bytes.
- **SDS** — the right shape: keys never sit in the LDS/CDS resources, and the control plane
  can rotate independently of route config. This repo's own
  `go-control-plane-xds-security.md` directive 3 forbids `inline_bytes` private keys in xDS
  resources for exactly this reason.

---

# Phase 2 — Our gateway context

All paths below are relative to the repository root unless otherwise noted.

## 2.0 Executive summary of the current state

**There is no mTLS anywhere on the data path today — in either direction.** Specifically:

- The HTTPS listener is server-auth only. `createDownstreamTLSContext`
  (`gateway/gateway-controller/pkg/xds/translator.go:2396`) builds a `DownstreamTlsContext`
  with `TlsCertificates` + `TlsParams` + `AlpnProtocols` and **no**
  `RequireClientCertificate` and **no** `ValidationContextType`
  (`translator.go:2435-2450`). There is no config field to ask for one:
  `DownstreamTLS` (`pkg/config/config.go:674-689`) has only `CertPath`, `KeyPath`,
  min/max version, `Ciphers`, `EcdhCurves`.
- The gateway never presents a client certificate to a backend.
  `createUpstreamTLSContext` (`translator.go:2234`) never sets
  `CommonTlsContext.TlsCertificates` — it only ever configures a **validation** context
  (`translator.go:2288-2324`).
- `grep -rni "x-forwarded-client-cert|forward_client_cert|ForwardClientCertDetails|xfcc"`
  across the whole repo returns **zero hits**. The HCM built at
  `translator.go:1322-1358` does not set `ForwardClientCertDetails`, so Envoy's default
  `SANITIZE` applies — a client-supplied XFCC header is stripped today. That is the safe
  default and should be preserved.
- The certificate store has **no private-key support at all** — `StoredCertificate`
  (`pkg/models/certificate.go:24-35`) has a `Certificate []byte` field and metadata, no key
  field; `certstore.validateCertificateData` (`pkg/certstore/certstore.go:257-290`)
  explicitly skips every PEM block whose type is not `CERTIFICATE`.
- SDS serves exactly **one** secret, and it is a **validation context**, not a keypair —
  `SecretNameUpstreamCA = "upstream_ca_bundle"` (`pkg/xds/sds.go:34`), built in
  `SDSSecretManager.GetSecret` (`sds.go:85-111`) as
  `Secret_ValidationContext{ValidationContext{TrustedCa: InlineBytes(combined)}}`.

mTLS **does** exist, but only on control-plane channels (xDS, policy-xDS, policy-engine
ext_proc) — and those patterns are the most directly reusable prior art in the codebase.

## 2.1 Config flow: TOML → controller config → xDS → Envoy

1. `gateway/configs/config-template.toml` is the shipped template. Router TLS lives at
   `[router.downstream_tls]` (line 409) and `[router.upstream.tls]` (line 423).
2. Koanf-tagged structs in `gateway/gateway-controller/pkg/config/config.go` parse it.
   `RouterConfig` is at `config.go:613-630`; it holds `DownstreamTLS`
   (`config.go:624`, type at `674-689`), `Upstream RouterUpstream` (`config.go:622`, type at
   `632-636`, whose `TLS UpstreamTLS` is at `639-655`), `PolicyEngine PolicyEngineConfig`
   (`config.go:723-730`) and `HTTPListener HTTPListenerConfig` (`config.go:705-712`).
3. `Config.Validate` checks TLS versions/ciphers (`config.go:1670-1706`, `1856+`).
4. `pkg/xds/translator.go` turns config + stored API configs into Envoy resources;
   `pkg/xds/snapshot.go` versions them; `pkg/xds/server.go` serves ADS/SDS.
5. Envoy (gateway-runtime/router) bootstraps from
   `gateway/gateway-runtime/router/config/envoy-bootstrap.yaml` +
   `config-override.yaml`, using ADS against `xds_cluster`.

### The listener shape — and why per-API mTLS is hard here

`createListener` (`translator.go:1288`) builds **one filter chain** per listener:

```go
filterChain := &listener.FilterChain{ Filters: []*listener.Filter{{ Name: wellknown.HTTPConnectionManager, ... }} }
// translator.go:1408-1425
if isHTTPS {
    tlsContext, err := t.createDownstreamTLSContext()
    ...
    filterChain.TransportSocket = &core.TransportSocket{ Name: "envoy.transport_sockets.tls", ... }
}
// translator.go:1441
FilterChains: []*listener.FilterChain{filterChain},
```

and every API shares **one** route configuration — `SharedRouteConfigName`, delivered via RDS
(`translator.go:1327-1341`, `createRouteConfiguration` at `translator.go:1448-1454`). There is
exactly one HTTP listener (`router.listener_port`) and one HTTPS listener
(`router.https_port`, gated on `HTTPSEnabled`, `translator.go:889-891`).

The consequence is structural: **TLS parameters today are per-listener, not per-API**, and
the listener has no `FilterChainMatch` at all, so there is no existing mechanism to select
different TLS behaviour by SNI. Any per-API mTLS design must either introduce filter-chain
matching (new machinery, plus the TLS-inspector listener filter), add listeners/ports, or
push enforcement up into the policy layer.

ALPN is hardcoded to `h2, http/1.1` (`translator.go:2448`, constants at
`pkg/constants/constants.go:49-50`) — so h2 is negotiated, and §1.2's post-handshake-auth
prohibition applies.

## 2.2 Upstream (backend) TLS: what exists

`createUpstreamTLSContext(certificate []byte, address string)` — `translator.go:2234-2358`:

- Sets `TlsParams` from `router.upstream.tls` (versions, ciphers, ECDH curves)
  (`translator.go:2238-2247`).
- Sets `Sni` to the address when it is a hostname, not an IP (`translator.go:2252-2255`).
- Unless `DisableSslVerification`, picks a validation context by priority
  (`translator.go:2258-2324`):
  1. **SDS** if a cert store exists — `CombinedValidationContext` with
     `ValidationContextSdsSecretConfig{Name: SecretNameUpstreamCA, SdsConfig: ADS}`
     (`translator.go:2288-2298`). The comment at `translator.go:2266-2280` explains the
     design: SDS rides the existing ADS stream so the controller never needs to know
     runtime-local file paths.
  2. per-upstream `certificate` bytes inline (`translator.go:2302-2312`) — the parameter is
     passed `nil` from the RDC path.
  3. `router.upstream.tls.trusted_cert_path` as a filename (`translator.go:2313-2323`).
  4. otherwise Envoy's default (which, per §1.3, means **no verification**).
- Optional SAN hostname verification when `verify_host_name` is true
  (`translator.go:2327-2354`).

**There is no `TlsCertificates` assignment anywhere in this function** — the gateway cannot
present a client certificate to a backend. That is the whole of the gateway→backend mTLS gap.

### Where a backend client cert would attach

Envoy already gets a **per-endpoint** transport socket, which is the natural attachment point:

- Single-endpoint path: `processEndpoint` (`translator.go:2485-2563`) builds one
  `Cluster_TransportSocketMatch` named `ts0` keyed on the endpoint's `lb_id` metadata
  (`translator.go:2540-2559`), with `setEndpointTransportSocketMatchID` stamping the endpoint
  (`translator.go:3120-3135`).
- Weighted/multi-endpoint path: `translator.go:568-600` does the same per endpoint, indexing
  `matchID` by position, "certs are nil here, same as the single-endpoint RDC path"
  (`translator.go:571-575`).

So a per-upstream client certificate would flow as: model field → `UpstreamCluster.TLS` →
`createUpstreamTLSContext` → `CommonTlsContext.TlsCertificates` (ideally as
`TlsCertificateSdsSecretConfigs`, per `go-control-plane-xds-security.md` directive 3).

### The upstream data model is currently a single boolean

`pkg/models/runtime_deploy_config.go`:

```go
// :167-174
type UpstreamCluster struct {
    Name           string
    BasePath       string
    Endpoints      []Endpoint
    TLS            *UpstreamTLS
    ConnectTimeout *time.Duration
}
// :182-185
type UpstreamTLS struct {
    Enabled bool
}
```

`UpstreamTLS` has exactly one field. Anything richer (client cert ref, per-upstream CA,
SNI override, SAN expectations, `insecureSkipVerify`) is new surface.

The management API mirrors this: `UpstreamDefinition`
(`gateway/gateway-controller/api/management-openapi.yaml:3019-3059`) and `Upstream`
(`:3090-3116`) carry only `url`, `weight`, `basePath`, `timeout`, `ref`, `hostRewrite`.
No TLS block.

## 2.3 The certificate store

`gateway/gateway-controller/pkg/certstore/certstore.go`:

```go
// :49-56
type CertStore struct {
    logger         *slog.Logger
    certsDir       string
    systemCertPath string
    combinedCerts  []byte
    db             storage.Storage
    mu             sync.RWMutex
}
```

- Constructed only when `router.upstream.tls.custom_certs_path` is non-empty
  (`translator.go:122-147`); on load failure the store is set to `nil`
  (`translator.go:133-140`), which silently disables SDS entirely.
- `LoadCertificates` (`certstore.go:73-130`) bootstraps PEM files from `certsDir` into the DB
  (`bootstrapCertificatesFromFilesystem`, `certstore.go:314-422`), then concatenates all DB
  certificates with the system bundle into **one flat `[]byte`**.
- `GetCombinedCertificates` (`certstore.go:294-304`) returns a copy of that single blob.
- `Reload` (`certstore.go:475-479`) re-runs the load.
- Only `CERTIFICATE` PEM blocks are accepted; anything else is skipped with a debug log
  (`certstore.go:269-274`). A `PRIVATE KEY` block is silently dropped.

**Capabilities today**: one global, unnamed, append-only trust bundle for *upstream*
verification.
**Cannot do**: per-API or per-upstream trust scoping; keypairs; distinguishing "CA I trust to
sign client certs" from "CA I trust to sign backend server certs"; leaf pinning; any notion of
what a certificate is *for*.

### Persistence

`gateway/gateway-controller/pkg/storage/gateway-controller-db.sql:76-105`:

```sql
CREATE TABLE IF NOT EXISTS certificates (
    uuid TEXT NOT NULL,
    gateway_id TEXT NOT NULL,
    name TEXT NOT NULL,
    certificate BLOB NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    cert_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (gateway_id, uuid),
    UNIQUE(gateway_id, name)
);
```

Mirrored in `gateway-controller-db.postgres.sql` and `gateway-controller-db.sqlserver.sql`.
`PRAGMA user_version = 4` at the end of the SQLite file.

**This is a shipped table and therefore frozen** under `.claude/rules/db-schema-changes.md`
Directive 1 (R0-FROZEN): only additive changes — a new nullable/defaulted column, a new
index, or a new table. Adding a `usage`/`kind` discriminator column is permissible **and must
ship a per-dialect `ALTER TABLE`** (Directive 3), because `CREATE TABLE IF NOT EXISTS` is a
no-op on an already-provisioned database. Adding `NOT NULL`, a new `UNIQUE`, or retyping
`certificate` is **not** permitted without a migration plan.

A separate `secrets` table exists (`gateway-controller-db.sql:270-280`) with an encrypted
`ciphertext BLOB` — that is where a private key would plausibly live:

```sql
CREATE TABLE IF NOT EXISTS secrets (
    gateway_id TEXT NOT NULL, handle TEXT NOT NULL, display_name TEXT NOT NULL,
    description TEXT, ciphertext BLOB NOT NULL, created_at ..., updated_at ...,
    PRIMARY KEY (gateway_id, handle)
);
```

Note the management API caps a secret value at 10240 chars
(`management-openapi.yaml:4989-4995`) — a PEM keypair + chain can approach that.
Note also that `platform-api`'s own secret model already has a `type: [GENERIC, CERTIFICATE]`
enum (`platform-api/resources/openapi.yaml:8830`, `:8912`) that the gateway's secret schema
does **not** have — worth reconciling.

## 2.4 The `/certificates` management API

`gateway/gateway-controller/api/management-openapi.yaml:854-990`, handlers in
`gateway/gateway-controller/pkg/api/handlers/certificates.go`:

| Method | Path | Handler | Notes |
|---|---|---|---|
| GET | `/certificates` | `ListCertificates` (`:202`) | |
| POST | `/certificates` | `UploadCertificate` (`:65`) | `{name, certificate}` only |
| DELETE | `/certificates/{id}` | `DeleteCertificate` (`:244`) | |
| POST | `/certificates/reload` | `ReloadCertificates` (`:313`) | |

Schemas: `CertificateUploadRequest` (`:5063-5084`) = `{name, certificate}`;
`CertificateResponse` (`:5085-5121`) = `{id, name, subject, issuer, notAfter, count, message,
status}`. The API description says outright: "These certificates are used for verifying HTTPS
upstream connections" (`:858-859`). Tag description at `:5278-5279` repeats it.

Write path, e.g. `UploadCertificate` → `certificates.go:165` `certStore.Reload()` →
`certificates.go:174` `s.snapshotManager.UpdateSnapshot(...)`. So a certificate change
triggers a full xDS snapshot regeneration. That is the existing hot-reload path and it works
— but it regenerates *everything*, not just the secret.

## 2.5 SDS plumbing — exactly what it can and cannot do

`gateway/gateway-controller/pkg/xds/sds.go`:

```go
const SecretNameUpstreamCA = "upstream_ca_bundle"   // :34

func (sm *SDSSecretManager) GetSecret() (types.Resource, error) {   // :85
    combinedCerts := sm.certStore.GetCombinedCertificates()
    ...
    secret := &tlsv3.Secret{
        Name: SecretNameUpstreamCA,
        Type: &tlsv3.Secret_ValidationContext{
            ValidationContext: &tlsv3.CertificateValidationContext{
                TrustedCa: &core.DataSource{Specifier: &core.DataSource_InlineBytes{InlineBytes: combinedCerts}},
            },
        },
    }
    return secret, nil
}
```

Limits, precisely:

- **One** secret, one hardcoded name, `Secret_ValidationContext` only. Serving a keypair
  requires `Secret_TlsCertificate` — a different oneof arm that does not exist here.
- `UpdateSecrets` (`sds.go:63-82`) is a no-op validity check; the real delivery is via the
  main snapshot.
- The secret is only included in a snapshot when a cluster actually references it:
  `snapshot.go:145-151` gates on `ClusterResourcesReferenceUpstreamCASecret`
  (`translator.go:2368-2393`), which walks each cluster's transport-socket matches looking for
  a `CombinedValidationContext` whose SDS name is `upstream_ca_bundle`. The comment at
  `translator.go:2362-2367` explains why: Envoy doesn't watch the Secret type URL until an
  accepted Cluster references it, otherwise it logs "Ignoring unwatched type URL … Secret".
  **Any new secret name must extend this gate or it will never be delivered.**
- SDS is registered on the same gRPC server and snapshot cache as ADS
  (`pkg/xds/server.go:140-143`), initialized in `cmd/controller/main.go:363-383`.

## 2.6 Existing mTLS on control-plane channels — the reusable patterns

This is the most valuable prior art in the repo, because it is already rule-compliant.

### `XDSServerTLSConfig` — `pkg/config/xds_tls.go:44-94`

```go
type XDSServerTLSConfig struct {
    Enabled                 bool     `koanf:"enabled"`
    CertFile                string   `koanf:"cert_file"`
    KeyFile                 string   `koanf:"key_file"`
    ClientCAFile            string   `koanf:"client_ca_file"`
    AllowedClientIdentities []string `koanf:"allowed_client_identities"`
    MinimumProtocolVersion  string   `koanf:"minimum_protocol_version"`
    MaximumProtocolVersion  string   `koanf:"maximum_protocol_version"`
    Ciphers                 string   `koanf:"ciphers"`
    EcdhCurves              string   `koanf:"ecdh_curves"`
}
```

Used for both `server.xds_tls` (Envoy-facing) and `policy_server.tls`
(policy-engine-facing) — `config.go:315-319`, `config.go:424`, validated at
`config.go:1698-1706`.

Three properties worth copying verbatim into a data-plane mTLS design:

1. **No server-only mode.** `ValidateXDSServerTLS` (`xds_tls.go:99-130`) hard-requires
   `ClientCAFile` **and** at least one non-blank `AllowedClientIdentities` entry when
   `Enabled` — "this can't be silently left as a no-op allowlist"
   (`xds_tls.go:66-70`, error text at `:110` and `:113`).
2. **CA trust is not authorization.** `BuildXDSServerTLSConfig` (`xds_tls.go:144-184`) sets
   `ClientAuth: tls.RequireAndVerifyClientCert` and explicitly documents that the identity
   check is a *separate* step (`xds_tls.go:133-140`).
3. **The identity check is a real accept/reject, on every stream.**

### `pkg/tlsauth/peer_identity.go` — the identity extraction convention

```go
// :41-46
func PeerIdentity(cert *x509.Certificate) string {
    if len(cert.URIs) > 0 { return cert.URIs[0].String() }   // SPIFFE ID if present
    return cert.Subject.CommonName                            // else CN
}

// :64-78
func VerifyStreamPeer(ctx context.Context, allowed map[string]bool) error {
    p, ok := peer.FromContext(ctx); if !ok { return status.Error(codes.Unauthenticated, "no peer information") }
    tlsInfo, isTLS := p.AuthInfo.(credentials.TLSInfo)
    if !isTLS || len(tlsInfo.State.PeerCertificates) == 0 { return status.Error(codes.Unauthenticated, "no client certificate presented") }
    identity := PeerIdentity(tlsInfo.State.PeerCertificates[0])
    if !allowed[identity] { return status.Error(codes.PermissionDenied, "peer identity not authorized for this xDS snapshot") }
    return nil
}
```

Called from `xds.serverCallbacks.OnStreamOpen` (`pkg/xds/server.go:202-208`) and the
equivalent in `pkg/policyxds/server.go`. Both gRPC servers set
`MaxRecvMsgSize`/`MaxSendMsgSize`/`MaxConcurrentStreams` (`xds/server.go:113-115`,
`policyxds/server.go:138-140`) per `go-network-service-hardening.md` directive 2.

**Note the limitation to carry forward**: `PeerIdentity` is "first URI SAN, else CN". That is
adequate for a handful of known infrastructure peers; it is *not* adequate as the identity
model for arbitrary external API clients (no issuer binding, no DNS/IP SAN, no serial, CN
collision across CAs — see §1.4). A data-plane design should treat this as a *pattern* to
follow, not a function to reuse as-is.

### Policy-engine channel — `PolicyEngineTLS`, `config.go:733-740`

```go
type PolicyEngineTLS struct {
    Enabled bool; CertPath, KeyPath, CAPath, ServerName string; SkipVerify bool
}
```

This is the **gateway-as-mTLS-client** shape already present in config (Envoy dialing the
policy engine over TCP with a client cert). Template at `config-template.toml:474-478`.
Note `SkipVerify` — an insecure escape hatch that a data-plane design should not copy
uncritically.

### httpkit client — `config.go:833-847`

`HTTPClientTLSConfig` has `ClientCertFile`/`ClientKeyFile` ("mTLS to the origin; both cert and
key must be set together", `config.go:839`). This is the controller's *own* outbound HTTP
client, not Envoy's data path, but it is the existing vocabulary for outbound client certs.

### Envoy↔controller bootstrap

`gateway/gateway-runtime/router/config/config-override.yaml:42-49` shows how the runtime
opts into xDS mTLS: `transport_socket: ${XDS_CLUSTER_TRANSPORT_SOCKET}`, substituted by
`docker-entrypoint.sh` to a flow-style `UpstreamTlsContext` when `XDS_TLS_ENABLED=true`, or
to `null` otherwise. The admin interface is deliberately absent from
`envoy-bootstrap.yaml` (`:19-24`), injected only on `ROUTER_ADMIN_ENABLED`.

## 2.7 The policy engine: what a policy can and cannot see

### ext_proc wiring

`createExtProcFilter` (`translator.go:3184-3235`) builds the `ExternalProcessor`:

```go
FailureModeAllow: false,                  // :3199 — always fail closed
RouteCacheAction: extproc.ExternalProcessor_DEFAULT,
AllowModeOverride: true,
RequestAttributes: []string{constants.ExtProcRequestAttributeRouteName},   // :3204
ProcessingMode: &extproc.ProcessingMode{ RequestHeaderMode: extproc.ProcessingMode_SEND },
MessageTimeout: durationpb.New(...),
MetadataOptions: { Receiving/Forwarding Namespaces: ExtProcMetadataNamespace },
```

`ExtProcRequestAttributeRouteName = "xds.route_name"`
(`pkg/constants/constants.go:103`). **That is the only Envoy attribute requested.** The
policy engine reads exactly that one and nothing else —
`ExternalProcessorServer.extractRouteKey`
(`gateway/gateway-runtime/policy-engine/internal/kernel/extproc.go:776-790`) pulls
`req.Attributes[ExtProcFilter].Fields["xds.route_name"]`.

Envoy exposes connection-level TLS attributes to ext_proc via the same `request_attributes`
mechanism — `connection.subject_peer_certificate`, `connection.uri_san_peer_certificate`,
`connection.dns_san_peer_certificate`, `connection.sha256_peer_certificate_digest`,
`connection.mtls`, etc. **UNVERIFIED** as to which of these are available in the Envoy
version pinned here and whether the ext_proc `request_attributes` list accepts the
`connection.*` namespace (Envoy's attribute docs list them under CEL attributes; the
ext_proc filter documents `request_attributes` as CEL attribute paths). Confirming this is a
**high-priority spike** because it decides whether a cert-aware policy is cheap or expensive.

### The policy SDK context — no place for a certificate

`sdk/core/policy/v1alpha2/context.go`:

```go
// :37-41
type DownstreamContext struct {
    Request *DownstreamRequest
}

// :45-51
type DownstreamRequest struct {
    Headers   *Headers
    Path      string
    Method    string
    Authority string
    Scheme    string
}
```

`DownstreamContext` carries **only** the request snapshot. There is no connection struct, no
peer certificate, no source address, no TLS metadata of any kind. `RequestHeaderContext`
(`context.go:159-177`) embeds `*SharedContext` and adds `Headers/Path/Method/Authority/
Scheme/Vhost`, `Downstream`, `Upstream`. `SharedContext` (`context.go:78-153`) carries
project/API/operation identity, `ResolutionAttributes`, and `AuthContext`.

So **a policy today has no way whatsoever to see a client certificate**, except by reading a
header — which is precisely the untrusted-header problem of §1.7.

`AuthContext` (`sdk/core/policy/v1alpha2/auth_context.go:23-70`) is the structured result an
auth policy writes: `Authenticated`, `Authorized`, `AuthType`, `Subject`, `Issuer`,
`Audience`, `Scopes`, `CredentialID`, `Properties`, `TypedProperties`, `TokenId`, and
`Previous` for multi-layer auth chains. A client-cert auth policy maps onto this cleanly
(`AuthType: "mtls"`, `Subject: <chosen identity>`, `CredentialID: <cert id / app id>`), and
`Previous` is exactly the field that makes "mTLS **and** OAuth2" composable.

### Policy shape

Policies are external Go modules — `gateway/build.yaml` lists ~55 of them as
`github.com/wso2/gateway-controllers/policies/<name>@<major>`. Auth-relevant ones:
`api-key-auth`, `basic-auth`, `jwt-auth`, `opaque-token-auth`, `mcp-auth`, `mcp-authz`,
`subscription-validation`, `oauth2-generator`.

Each carries a `policy-definition.yaml` — see the in-tree examples
`gateway/sample-policies/slugify-body/policy-definition.yaml` and
`gateway/system-policies/analytics/policy-definition.yaml`: `name`, `version` (`vX.Y.Z`),
`displayName`, `description`, `parameters` (JSON Schema draft-7, validated by the controller
*before* the policy runs), `systemParameters`.

The Go contract is `sdk/core/policy/v1alpha2/interface.go`: `Policy{ Mode() ProcessingMode }`
plus phase sub-interfaces `RequestHeaderPolicy.OnRequestHeaders`, `RequestPolicy.OnRequestBody`,
`ResponseHeaderPolicy`, `ResponsePolicy`, and the streaming variants (`interface.go:110-170`).
A factory `GetPolicy(metadata PolicyMetadata, params map[string]interface{}) (Policy, error)`
(`interface.go:40-41`) is the entry point; `PolicyMetadata` (`interface.go:44-59`) carries
`RouteName`, `APIId`, `APIName`, `APIVersion`, `AttachedTo` (`LevelAPI` / `LevelRoute`).

§2.10 expands all of this against the policy hub repo itself.

## 2.8 CRDs and Helm

### `Certificate` CRD — `kubernetes/gateway-operator/api/v1/certificate_types.go:31-40`

```go
type CertificateSpec struct {
    DisplayName string            `json:"displayName"`
    Certificate SecretValueSource `json:"certificate"`
}
```

`SecretValueSource` (`kubernetes/gateway-operator/api/v1/common_types.go:31-41`) is
`{value | valueFrom: corev1.SecretKeySelector}` with a CEL XValidation enforcing exactly one.
The controller PUT/DELETEs `/certificates/{status.id}` using the UUID persisted into
`.status.id` (`certificate_types.go:28-30`, `common_types.go:57-60`).

This CRD is a thin mirror of the management API, so it inherits the same
"CA-bundle-for-upstream-verification, no key" limitation.

### `RestApi` CRD — `kubernetes/gateway-operator/api/v1/restapi_types.go`

`APIConfigData` (`:58`), `UpstreamConfig` (`:104`), `Upstream` (`:270`),
`UpstreamDefinition` (`:303`), `Policy` (`:246`). No TLS/cert fields on any of them — the CRD
mirrors `management-openapi.yaml`.

### Gateway API — already vendored, and it already has the fields

`kubernetes/gateway-operator/go.mod:22` pins `sigs.k8s.io/gateway-api v1.5.1`, which
**already contains GEP-91's client-certificate validation** and the backend client-cert ref:

```go
// gateway_types.go:624-642
type GatewayTLSConfig struct {
    Backend  *GatewayBackendTLS  `json:"backend,omitempty"`   // Support: Core
    Frontend *FrontendTLSConfig  `json:"frontend,omitempty"`  // Support: Core
}
// :644-668
type FrontendTLSConfig struct {
    Default TLSConfig        `json:"default"`            // +required
    PerPort []TLSPortConfig  `json:"perPort,omitempty"`  // per-port override
}
// :690-702
type TLSConfig struct { Validation *FrontendTLSValidation `json:"validation,omitempty"` }
// :726-798
type FrontendTLSValidation struct {
    CACertificateRefs []ObjectReference          `json:"caCertificateRefs"`
    Mode              FrontendValidationModeType `json:"mode,omitempty"` // AllowValidOnly (default) | AllowInsecureFallback
}
// :526-556
type GatewayBackendTLS struct { ClientCertificateRef *SecretObjectReference `json:"clientCertificateRef,omitempty"` }
```

So the *standard* CRD surface for both directions is already on disk in this repo. What is
missing is the operator consuming it.

Today the operator only reads listener `certificateRefs` for the **server** certificate:
`listenerTLSSecretFromGateway` + `applyListenerTLSOverlayToValues`
(`kubernetes/gateway-operator/internal/controller/gateway_listeners_overlay.go:203-250`),
which overlays Helm values:

```yaml
gateway:
  controller:
    tls: { enabled: true, certificateProvider: secret, secret: { name: <ref>, certKey: tls.crt, keyKey: tls.key } }
```

with the documented caveat at `gateway_listeners_overlay.go:189-191`: "all HTTPS listeners
are served with this single certificate; per-listener (SNI-based) certificate selection is
not yet supported."

### Helm

`kubernetes/helm/gateway-helm-chart/values.yaml`:

- `gateway.controller.config.router.downstream_tls` (`:333-347`) — cert/key paths, versions,
  ciphers. No client-validation keys.
- `gateway.controller.config.router.upstream.tls` (`:351-360`) — `trusted_cert_path`,
  `custom_certs_path: ./certificates`, `verify_host_name`, `disable_ssl_verification`.
- `gateway.controller.tls` (`:667-709`) — `certificateProvider: cert-manager|secret|none`,
  cert-manager issuer/dnsNames/duration/renewBefore, or an existing Secret with
  `certKey`/`keyKey`.
- `gateway.controller.upstreamCerts` (`:710-718`) — `enabled`, `secretName`, `configMapName`
  for mounting CA bundles into `custom_certs_path`.

So the chart already knows how to mount a CA bundle (for upstream) and a keypair (for the
listener). A **client** CA bundle and a **backend client** keypair would be new value blocks
plus new mounts.

## 2.9 Integration-test conventions

`gateway/it/` is a godog/BDD suite. Feature files live in `gateway/it/features/*.feature`;
step definitions in `gateway/it/steps_*.go`; compose files `docker-compose.test*.yaml`;
config `test-config.toml`.

Conventions visible in `features/jwt-auth.feature:19-45`: Apache licence header, a `@tag`,
`Feature:`/`As a`/`I want`/`So that`, a `Background:` (`Given the gateway services are
running`), then scenarios that `Given I authenticate using basic auth as "admin"` and
`When I deploy this API configuration:` with an inline `RestApi` YAML docstring.

`features/certificates.feature` covers only the management-API CRUD surface (list/upload
validation/delete/reload) — no traffic-level assertions, because there is no mTLS traffic to
assert.

**Gap to note for a spec**: there is no existing step vocabulary for "make an HTTPS request
presenting client certificate X", and no test PKI fixture. Both would be new. A realistic
test matrix needs: valid cert, cert from an untrusted CA, expired cert, revoked cert (if CRL
lands), no cert presented, cert with the wrong SAN, and — critically — a *forged*
`X-Forwarded-Client-Cert`/`X-WSO2-CLIENT-CERTIFICATE` header from an untrusted client.

## 2.10 The policy layer (`github.com/wso2/gateway-controllers`)

A client-certificate auth policy would live in the **policy hub repo**, not in api-platform.
Reference clone read for this section: `/Users/tharsanan/Documents/wso2/github/gateway-controllers`
(read-only; nothing modified). Paths in this subsection are relative to that repo unless they
start with `sdk/` or `gateway/`, which are in the api-platform worktree.

### 2.10.1 Repo shape and versioning

`README.md:29` states the model: "Each policy in this repository is versioned independently.
When a new version is published, older versions remain available so existing deployments are
not affected."

- One Go module **per policy**, flat — `policies/<name>/{go.mod, <name>.go, policy-definition.yaml, *_test.go}`.
  There are **no** version subdirectories in the source tree (contrary to the aspirational
  layout in `gateway/gateway-runtime/policy-engine/Spec.md:2419-2445`); versions are Go module
  tags plus the `version:` field in `policy-definition.yaml`.
- `docs/<policy>/vX.Y/` holds per-minor documentation — e.g. `docs/jwt-auth/` contains
  `v0.1 v0.2 v0.3 v0.8 v0.9 v1.0 v1.2 v1.3`. Docs are versioned per **minor**; the module is
  tagged per patch.
- `gateway/build.yaml` in api-platform references **major only**:
  `gomodule: github.com/wso2/gateway-controllers/policies/jwt-auth@v1`. Current actual
  versions: `jwt-auth v1.3.1`, `api-key-auth v1.2.1`, `basic-auth v1.0.3`,
  `subscription-validation v1.0.3`, `oauth2-generator v0.9.0`.
- `gateway-builder` resolves and pins at build time: `UpdateGoMod`
  (`gateway/gateway-builder/internal/policyengine/gomod.go:61-100`) runs
  `go get <GoModulePath>@<GoModuleVersion>` into the policy-engine source dir, then the
  generated plugin registry keys policies by `name:major`
  (`gateway/gateway-builder/internal/policyengine/generator.go:249-250` for the Python
  variant; `templates/plugin_registry.go.tmpl` for Go).
- A local policy under `gateway/dev-policies/` can be wired via `filePath` instead, which
  emits a `replace` directive (`gomod.go:62`). That is the loop for prototyping a
  `client-cert-auth` policy without publishing to the hub.

### 2.10.2 `policy-definition.yaml` anatomy

Confirmed shape across `basic-auth`, `api-key-auth`, `jwt-auth`, `subscription-validation`:

```yaml
name: api-key-auth              # kebab-case, unique across the gateway
version: v1.2.1                 # semver, 'v'-prefixed
description: |                  # rendered as docs in the management console
  ...
parameters:                     # JSON Schema draft-7 object; validated by the CONTROLLER
  type: object                  # before the policy code ever runs
  additionalProperties: false
  properties:
    key:
      type: string
      x-wso2-policy-advanced-param: false   # UI hint: basic vs "Advanced" section
      description: |
        ...
      default: API-Key
      validation:               # NOTE: api-key-auth nests minLength/maxLength under
        minLength: 1            # `validation:` rather than at the property level;
        maxLength: 128          # basic-auth/jwt-auth put them at the property level.
  required: [key, in]           # An inconsistency worth not copying.
systemParameters:               # injected by the gateway runtime, NOT by the API deployer
  type: object
  properties:
    issuer:
      type: string
      default: ""
      "wso2/defaultValue": "${config.api_key.issuer}"   # resolved from config.toml at startup
```

Two vendor extensions matter for a new policy:

- `x-wso2-policy-advanced-param: true|false` — per-property UI placement
  (`basic-auth/policy-definition.yaml:12,18,24,31`).
- `x-wso2-policy-deprecated-param: true` — e.g. `jwt-auth`'s `requiredScopes`
  (`jwt-auth/policy-definition.yaml:32`), superseded by `scopes`.
- `"wso2/defaultValue": "${config.<toml path>}"` on a `systemParameter` is the mechanism by
  which **gateway-level configuration reaches a policy**
  (`api-key-auth/policy-definition.yaml`, `issuer`). This is directly relevant: a
  client-cert policy's "which CA bundle / which trusted-hop list" could arrive this way
  rather than being duplicated into every API's policy params.

### 2.10.3 The Go contract, phase by phase

Every policy imports `policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"`.

```go
// basic-auth/basicauth.go:41-47 — the factory the builder-generated registry calls
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error)

// basic-auth/basicauth.go:49-57 — declares buffering/ext_proc modes at chain-build time
func (p *BasicAuthPolicy) Mode() policy.ProcessingMode {
    return policy.ProcessingMode{
        RequestHeaderMode:  policy.HeaderModeProcess,
        RequestBodyMode:    policy.BodyModeSkip,
        ResponseHeaderMode: policy.HeaderModeSkip,
        ResponseBodyMode:   policy.BodyModeSkip,
    }
}

// basic-auth/basicauth.go:59 — the only phase an auth policy needs
func (p *BasicAuthPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext,
    params map[string]interface{}) policy.RequestHeaderAction
```

Phase interfaces (`sdk/core/policy/v1alpha2/interface.go:110-170`):
`RequestHeaderPolicy.OnRequestHeaders`, `RequestPolicy.OnRequestBody`,
`ResponseHeaderPolicy.OnResponseHeaders`, `ResponsePolicy.OnResponseBody`, plus
`StreamingRequestPolicy`/`StreamingResponsePolicy`. Auth policies use **request headers only** —
which is exactly the phase at which a client certificate would be available, since it is a
connection property known before the first byte of body.

Actions (`sdk/core/policy/v1alpha2/action.go`): `UpstreamRequestHeaderModifications` (`:54`)
to continue, `ImmediateResponse` (`:31`) to short-circuit — `ImmediateResponse.StopExecution()
returns true` (`action.go:152`), `UpstreamRequestModifications.StopExecution() returns false`
(`action.go:147`).

### 2.10.4 How an auth policy signals success/failure (`AuthContext`)

`basic-auth/basicauth.go:132-141` on success:

```go
reqCtx.SharedContext.AuthContext = &policy.AuthContext{
    Authenticated: true,
    AuthType:      AuthType,            // "basic"
    Subject:       providedUsername,
    Previous:      reqCtx.SharedContext.AuthContext,   // ← chains, never overwrites
    TokenId:       providedUsername,
}
return policy.UpstreamRequestHeaderModifications{}
```

and `basic-auth/basicauth.go:143-170` on failure:

```go
shared.AuthContext = &policy.AuthContext{Authenticated: false, AuthType: AuthType, Previous: shared.AuthContext}
if allowUnauthenticated { return policy.UpstreamRequestHeaderModifications{} }   // ← note
return policy.ImmediateResponse{StatusCode: 401, ...}
```

Four observations that bear directly on a cert policy:

1. **`Previous` is the composition mechanism.** "mTLS AND OAuth2" — the APIM heritage
   requirement — is expressible today: two auth policies in a chain, the second linking to the
   first. No new machinery needed.
2. **`allowUnauthenticated` is an established, off-by-default escape hatch**
   (`basic-auth/policy-definition.yaml:23-29`, default `false`). It is the natural spelling of
   mTLS "optional" mode — but note it sets `Authenticated: false` and *still forwards*, so
   anything downstream must actually read `AuthContext.Authenticated`. Under GO-AUTH-007 a
   cert policy offering this must not let it become a silent bypass.
3. **`basic-auth` does constant-time credential comparison** (`basicauth.go:127-128`,
   `subtle.ConstantTimeCompare`). A thumbprint/DN comparison in a cert policy should do the
   same.
4. Error bodies are sterile and uniform — `{"error":"Unauthorized","message":"Authentication
   required"}` for every failure cause (`basicauth.go:158-161`), matching
   `error-handling.md` directive 4. `api-key-auth` goes further: the *reason* string
   (`"invalid API key"` vs `"missing or malformed API key"`) is passed to `failAuth` for
   **logging only** and never reaches the body (`api-key-auth/apikey.go:259-270`).

### 2.10.5 The SDK context — confirmed: a policy cannot see a client certificate

Re-confirming §2.7 against the SDK source, since this is the load-bearing fact for the whole
policy-vs-transport design fork:

```go
// sdk/core/policy/v1alpha2/context.go:37-41
type DownstreamContext struct {
    Request *DownstreamRequest
}

// sdk/core/policy/v1alpha2/context.go:45-51
type DownstreamRequest struct {
    Headers   *Headers
    Path      string
    Method    string
    Authority string
    Scheme    string
}
```

`DownstreamContext` has **exactly one field**. There is no `Connection`, no `TLS`, no
`PeerCertificate`, no `SourceAddress`. `RequestHeaderContext` (`context.go:159-177`) adds only
`Headers/Path/Method/Authority/Scheme/Vhost` + `Downstream` + `Upstream`, over an embedded
`*SharedContext` (`context.go:78-153`). The wire proto agrees:
`gateway/gateway-runtime/api/proto/python_executor.proto:197-211` defines
`DownstreamRequest{headers, path, method, authority, scheme}` and
`DownstreamContext{request}` and nothing else.

**Therefore: today, the only way a policy can learn anything about a client certificate is by
reading a request header** — i.e. the untrusted-header problem of §1.7, with no way for the
policy to verify the hop that set it. A policy-based mTLS design is not merely inconvenient
today; it is *unimplementable securely* until the SDK carries a trustworthy cert field.

### 2.10.6 The mandatory nil-safe accessor convention

Any new field must follow the pattern already established for snapshots in
`sdk/core/policy/v1alpha2/context_accessors.go`. The file header (`:20-54`) spells out the
contract, and it is unusually explicit — worth quoting because a cert field must decide the
same question:

> "When the gateway does NOT provide the snapshot (gateways released before the snapshot
> feature …), the accessor falls back to the live values. … The fallback is deliberate
> compatibility behaviour and **does NOT fail closed**: on a gateway that never populates the
> snapshot, live is the only data that exists, and refusing to return it would break every
> such deployment."

Implementation shape (`context_accessors.go:56-62`):

```go
func downstreamSnapshot(ds *DownstreamContext) *DownstreamRequest {
    if ds != nil && ds.Request != nil { return ds.Request }
    return nil
}
```

The proto mirrors the convention in comments — `python_executor.proto:205-208`: "Absent on
older gateways — new policies must treat an unset field as 'not available' and fall back to
legacy validation against the mutable headers."

**Critical divergence for a certificate field.** The snapshot accessor's fallback is *safe*
because the fallback data (live headers) is at worst stale. For a peer certificate there is
**no safe fallback**: "absent" must mean "this gateway cannot tell me, so I must deny", not
"fall back to the header". A cert-carrying field must therefore follow the *structural*
convention (nil-safe accessor, absent on older gateways) while **inverting the failure
posture** — fail closed, per GO-AUTH-001/GO-AUTH-007. This needs to be stated loudly in the
SDK doc comment or a policy author will copy the wrong half of the pattern.

### 2.10.7 How `api-key-auth` + `subscription-validation` bind a credential to an application

This is the existing "credential → application → subscription" chain, and it is the obvious
template for "client certificate → application".

**Step 1 — `api-key-auth` resolves the key to an application.**
`api-key-auth/apikey.go:232` calls `resolveValidatedAPIKey` (`:67-74`), which delegates to
`store.GetAPIkeyStoreInstance().ResolveValidatedAPIKey(apiId, apiOperation, operationMethod,
apiKey, issuer)` from `github.com/wso2/api-platform/common/apikey`.

In `common/apikey/store.go:198-238`:

```go
hash := ComputeAPIKeyHash(providedAPIKey)            // :206  — hash the presented secret
targetAPIKey, exists := aks.apiKeysByAPI[apiId][hash]  // :214 — O(1) lookup, scoped to THIS api
if !exists { return nil, ErrNotFound }
if clonedAPIKey.APIId != apiId { return nil, nil }   // :224 — re-check binding
if len(issuer) > 0 && issuer[0] != "" {              // :229 — issuer must match if configured
    if clonedAPIKey.Issuer == nil || *clonedAPIKey.Issuer != issuer[0] { return nil, nil }
}
if clonedAPIKey.Status != Active { return nil, nil }  // :236 — revocation is a status field
```

`common/apikey/store.go:31-51` — the resolved record carries `ID`, `Name`, `DisplayName`,
`APIKey` (hash), `APIId`, **`ApplicationID`**, **`ApplicationName`**, `Operations`, `Status`,
`CreatedAt`. The store is an in-process cache in the policy engine, populated over policy-xDS
(`gateway/gateway-controller/pkg/apikeyxds`, consumed via
`sdk/core/policyengine/api_key_xds.go`).

**Step 2 — the policy publishes the application id into shared metadata.**
`api-key-auth/apikey.go:246-257`:

```go
shared.AuthContext = &policy.AuthContext{
    Authenticated: true, AuthType: AuthType, Previous: shared.AuthContext,
    Properties: map[string]string{"ApplicationName": resolvedKey.ApplicationName,
                                  "ApplicationID":   resolvedKey.ApplicationID},
    TokenId: generateTokenID(providedKey),
}
shared.Metadata[applicationIDMetadataKey] = resolvedKey.ApplicationID   // "x-wso2-application-id"
```

**Step 3 — `subscription-validation` consumes it.**
`subscription-validation/subscriptionvalidation.go:20` declares the *same* literal
`applicationIDMetadataKey = "x-wso2-application-id"` (it is duplicated, not shared). Lookup
order in `OnRequestHeaders` (`:207-284`):

1. `Subscription-Key` header → `validateByToken(apiID, token)`
2. configured cookie → `validateByToken`
3. **fallback**: `Metadata["x-wso2-application-id"]` → `validateByApplication(apiID, appID)`
   (`:269-281`), which calls `p.store.IsActiveByApplication(apiID, appID)` (`:375`).
4. otherwise `403 forbidden`, "no subscription token or application identity provided"
   (`:284`).

On success it strips the credential header before forwarding (`:236`, `HeadersToRemove`) and
writes plan/billing metadata (`writeSubscriptionMetadata`, `:395`).

**Assessment for mTLS reuse.** The chain is generic over "some credential resolved to an
ApplicationID". A `client-cert-auth` policy could slot in at step 1-2 unchanged: resolve the
presented certificate (by thumbprint, or by (issuer, serial), or by SAN) to an
`ApplicationID`, set `AuthContext` + `Metadata["x-wso2-application-id"]`, and
`subscription-validation` would then work with **zero changes**. That is a genuinely strong
argument for the policy-shaped design of the client→gateway direction.

Two caveats:
- The api-key store is keyed `apiKeysByAPI[apiId][hash]` — per-API. A certificate→application
  mapping would need an equivalent xDS-delivered store, scoped the same way (or org-scoped,
  see GO-AUTH-005). That is a new resource type on policy-xDS, plus a new table, plus a new
  management API — not a small increment.
- The magic string `"x-wso2-application-id"` is duplicated across two independently-versioned
  modules. A third producer makes that a three-way coupling with no compile-time check.
  Worth promoting into `sdk/core` before adding one.

### 2.10.8 `oauth2-generator` — the upstream/backend-auth direction

`oauth2-generator` (v0.9.0, `sdk/core v0.3.5`, plus `github.com/redis/go-redis/v9`) is the
policy that `upstream.auth.type: oauth2` attaches by default
(`gateway/gateway-controller/api/management-openapi.yaml:4418-4496`). It acquires a token and
sets an outbound header. `set-headers` plays the same role for `type: api-key`.

This establishes the existing shape for **backend authentication**: it is always an L7 header
mutation performed by an ext_proc policy. §4.5 explains why mTLS to the backend cannot follow
that shape at all.

### 2.10.9 Cross-repo compatibility matrix

Three moving parts must line up, and they ship on independent cadences:

| # | Component | Repo | What a cert field needs from it |
|---|---|---|---|
| A | `sdk/core` module (`sdk/core/policy/v1alpha2`) | api-platform | New type(s) + nil-safe accessor; released as a new `sdk/core vX.Y.Z` tag |
| B | Gateway build: controller/translator (request the Envoy attribute or XFCC), policy-engine kernel (parse it, populate the context), `python_executor.proto` + generated code (for Python policies) | api-platform | Must *populate* the field; a gateway that doesn't leaves it nil |
| C | The policy itself | gateway-controllers | `go.mod` must require an `sdk/core` ≥ the version that defines the field |

Version facts observed: `policy-engine/go.mod:19` requires `sdk/core v0.4.0`; `jwt-auth`,
`api-key-auth`, `basic-auth`, `subscription-validation` require `v0.3.4`; `oauth2-generator`
requires `v0.3.5`. Because `gateway-builder` compiles every selected policy **into the
policy-engine binary** (one Go build, `gomod.go:61-100`), Go's minimal-version-selection takes
the **maximum** required `sdk/core` across the main module and all policy modules. A policy
pinning an older SDK is therefore *compiled against the newer one*.

That gives the following matrix:

| Combination | Result | Why |
|---|---|---|
| New policy (needs cert field) + **new** gateway (populates it) | ✅ Works | Nominal case. |
| New policy + **old** gateway binary (kernel does not populate the field) | ❌ **Compiles, then denies everything** | MVS bumps `sdk/core` to the policy's requirement so the build succeeds, but the old image's policy-engine kernel has no code to populate the field, so it is always nil. Per §2.10.6 the policy must then **fail closed** and reject every request. Effectively the policy is unusable on that gateway, and this needs to surface as a loud build- or deploy-time error, not a silent 403 storm at runtime. |
| **Old** policy (SDK v0.3.4) + new gateway | ✅ Works | MVS resolves `sdk/core` to the max (v0.4.x); the old policy compiles unchanged because the change is **additive** (a new struct field + a new accessor). It simply ignores the cert. |
| Policy built against an SDK **older than** the one exposing the field | ✅ Compiles, ignores the field | Same as above — additive changes are source-compatible. |
| New policy + new gateway, but the **Python** executor path | ⚠️ Needs `python_executor.proto` extended too | The proto already lags the Go SDK: `SharedContext` in `python_executor.proto:162-173` has no `resolved_operation` / `resolution_attributes`, which `sdk/.../context.go:116-148` does have. A cert field added only to the Go SDK would be invisible to every `pipPackage` policy. |
| Any policy + gateway where mTLS is off / cert absent | Field nil | The only correct behaviour is deny (fail closed), *not* the snapshot accessors' fall-back-to-live posture. |

**Hard constraints this implies for a spec:**

- The change to `sdk/core` **must be purely additive** — a new field on `DownstreamContext`
  (or a new `Connection`/`PeerCertificate` struct hung off it) plus a nil-safe accessor. Adding
  a method to `Policy`, `RequestHeaderPolicy`, or any interface a policy implements would break
  **every one of the ~60 policies** at once.
- Shipping order is forced: (A) SDK release → (B) gateway populates → (C) policy published
  requiring the new SDK. A policy published before the gateway populates the field is a
  guaranteed fail-closed outage on any older gateway that picks it up.
- The gateway needs a way to tell an operator "this policy requires a capability this gateway
  doesn't have" at **deploy/validation time**, not at request time. No such capability-negotiation
  mechanism exists today — **this is an open question for the spec** (§4.4).
- Because `policy-definition.yaml` parameters are validated by the *controller*
  (`gateway/gateway-controller/pkg/config/policy_validator.go`) against the definition shipped
  in the gateway image, a policy's schema and the running gateway are already coupled through
  the image build; the cert field adds a *runtime* coupling that the image build does not check.

---

## 2.11 Project security rules that constrain any mTLS design

From `.claude/rules/`:

| Rule | Constraint it imposes on mTLS |
|---|---|
| `authentication_authorization.md` **GO-AUTH-001** | Every cert-validation failure path must `return` immediately. No "log and continue". |
| **GO-AUTH-005** | If a cert maps to an application/subscription, the tenant/org scoping must come from verified context, never from request input. |
| **GO-AUTH-007** | Deny by default. A valid certificate chaining to a trusted CA is *authentication*, never authorization — a second, explicit check is mandatory. This is the single most important rule for this feature. |
| **GO-AUTH-011** | Startup must validate the **effective** result: "mTLS enabled" with an empty trust bundle, or with an empty identity allowlist, must refuse to start — exactly as `ValidateXDSServerTLS` (`xds_tls.go:99-130`) already does. |
| **GO-AUTH-016** | A peer-asserted value must be compared to local expectation, and a mismatch degrades the connection — never `os.Exit`. |
| **GO-AUTH-017** | Whether mTLS applies must be a **structural** route/policy match, not a heuristic on path/method. A request in a protected namespace that fails to resolve must be **denied**, not passed through. |
| **GO-AUTH-018** | A private-key file with permissive permissions must hard-fail, not warn. Socket/file modes set at creation time. |
| **GO-AUTH-019 / -003** | No deferring behind `// TODO`. Never log a raw certificate or key; mask. |
| `go-control-plane-xds-security.md` **directive 3** | **Never** embed private key material as `inline_bytes` in an xDS resource — use `TlsCertificateSdsSecretConfig`. Note: `createDownstreamTLSContext` (`translator.go:2409-2420`) **currently violates this** — it inlines the listener's private key bytes. Any mTLS work touching that function should fix it rather than extend it. |
| **directive 6** | Generated HCMs must keep `NormalizePath`/`MergeSlashes`/`PathWithEscapedSlashesAction` (already set, `translator.go:1354-1357`). |
| `go-network-service-hardening.md` **d.1, d.2** | Explicit timeouts, body caps, and gRPC message/stream ceilings on anything new. |
| `error-handling.md` **d.1, d.4, d.5** | A rejected certificate must produce one sterile response. Do **not** tell the caller *why* (unknown CA vs expired vs wrong SAN vs not-allowlisted) — that is an enumeration oracle over the trust store. Do not echo the certificate or its handle. Log the specific reason internally with a hashed/masked identifier. |
| `post-quantum-cryptography.md` **d.1, d.3** | New TLS configuration must expose a PQC/hybrid option (`X25519MLKEM768` first in `ecdh_curves`, classical after) rather than being classical-only, but must not hard-fail against classical peers. Note the existing warning on `UpstreamTLS.EcdhCurves` (`config.go:643-650`) and `DownstreamTLS.EcdhCurves` (`config.go:681-688`) that an Envoy build which doesn't know a curve name will **NACK the whole xDS update** and freeze that instance. |
| `db-schema-changes.md` **D1, D3** | `certificates` is shipped/frozen: additive columns only, each with a per-dialect `ALTER TABLE` across `gateway-controller-db.sql`, `.postgres.sql`, `.sqlserver.sql`. |
| `file-access.md` **d.5, d.6** | An uploaded PEM must be size-bounded via a config-sourced `io.LimitReader` and content-validated, not trusted by extension. |

---

# Phase 3 — Competitive / prior-art analysis

Each subsection covers both directions where the product supports them:
**↓ client→gateway** (inbound client cert) and **↑ gateway→backend** (outbound client cert).

A recurring axis, called out per product because it maps onto our own design fork:
**is client-cert auth a pluggable policy/plugin, or native listener config?**

## 3.1 WSO2 API Manager 4.x (classic) — the product's own heritage

**Mechanism: native transport config + a header, with per-API enablement in the API's
runtime configuration.** Not a plugin.

### ↓ Client → gateway

- Enabled per API: **Develop → API Configurations → Runtime → Mutual SSL**. Client
  certificates are uploaded in `.crt`/`.cer` with an **alias**, a **key type**
  (Production/Sandbox), and a **throttling tier** per certificate.
- "From APIM 4.0.0 onwards, when using Mutual SSL to invoke APIs, it is a must to use HTTPS
  as the transport, and HTTP transport will be disabled for an API if it has Mutual SSL
  enabled."
- The gateway reads the certificate from a **header**, not the handshake:
  `X-WSO2-CLIENT-CERTIFICATE` by default, configurable:

  ```toml
  [apimgt.mutual_ssl]
  certificate_header = "SSL-CLIENT-CERT"
  enable_client_validation = false
  client_certificate_encode = false
  enable_certificate_chain_validation = false
  ```

- Mutual SSL **can be combined with OAuth2**; when both are mandatory, the cert presence is
  verified and authentication still runs via OAuth2.
- Certificate-bound access tokens (RFC 8705) are supported on the validation side —
  `[apim.oauth_config] enable_certificate_bound_access_token = true`, `cnf`/`x5t#S256`
  compared against the cert from the same header, with the documented limitation "WSO2 API-M
  supports certificate bound JWT (access token) validation only".

**Documented limitations for Mutual-SSL-only APIs** (this is the list that sets user
expectations, and it is a *long* list of things that stop working):

- Application subscription is **not permitted**; subscription- and application-level
  throttling do not apply.
- Resource-level throttling does not apply.
- Resource-level security and scope-level security do not apply.

That is a significant admission: in classic APIM, the certificate→application binding exists
only as a *per-certificate tier*, not as a real application/subscription. Anyone migrating
from APIM will expect mutual SSL to work; the ones who used it will *also* remember that it
degraded everything else.

### ↑ Gateway → backend

- Endpoint certificates uploaded per API in **Publisher → Endpoints → General Endpoint
  Configuration → Add Certificate**, with an alias and an endpoint association.
- Backing store is `client-truststore.jks`, dynamically reloaded (default every 10 min, via
  `[transport.passthru_https.sender.ssl_profile] interval`), no restart needed.
- Certificates are **bound to the backend domain**, and shared: "if you deploy another API
  with the same backend domain, the certificate will be picked from the previously uploaded
  API." Per-API isolation of backend trust is therefore *not* real.
- **The uploaded endpoint certificate is a trust anchor, not a client identity.** Presenting a
  client cert to the backend requires `[[keystore.ssl_profile.custom]]` entries per endpoint
  hostname in `deployment.toml` — i.e. a static, node-local, per-hostname keystore, and in a
  cluster `sslprofiles.xml` and `client-truststore.jks` must be synchronized across nodes.
- Format limits: keystore `.jks`, certificate `.crt` only.

Sources:
https://apim.docs.wso2.com/en/4.4.0/design/api-security/api-authentication/secure-apis-using-mutual-ssl/,
https://apim.docs.wso2.com/en/4.5.0/manage-apis/design/endpoints/certificates/,
https://apim.docs.wso2.com/en/4.4.0/design/api-security/api-authentication/securing-apis-using-certificate-bound-access-tokens/

**UNVERIFIED**: the exact Publisher REST API paths/schemas for `/apis/{apiId}/client-certificates`
and `/endpoint-certificates` (alias, tier, certificate multipart fields). The docs pages
fetched describe the UI flow; the REST resource shapes were not retrieved in this pass.

## 3.2 WSO2 APK (and the Choreo Connect lineage)

**Mechanism: a policy-ish CRD (`Authentication`) that targets an API — so, per-API, declarative,
but still reading the cert from a header.**

```yaml
apiVersion: "dp.wso2.com/v1alpha2"
kind: "Authentication"
spec:
  default:
    mtls:
      required: mandatory        # or: optional
      configMapRefs:   [{ name: <configmap>, key: <cert-key> }]
      secretRefs:      [{ name: <secret>,    key: <cert-key> }]
      certificatesInline:
        - |
          -----BEGIN CERTIFICATE-----
          ...
  targetRef:
    group: "gateway.networking.k8s.io"
    kind: "API"
    name: "<api-name>"
```

- Three certificate sources: `configMapRefs`, `secretRefs`, `certificatesInline`.
- `required: mandatory|optional` — the optional mode is "validate if presented".
- **Per-API** granularity via `targetRef` — notably better than APIM classic or AWS.
- Composable with OAuth2: the same `Authentication` CR can carry `authType: OAuth2` alongside
  `authType: mTLS`.
- Still retrieves the client certificate from `X-WSO2-CLIENT-CERTIFICATE` by default —
  inheriting the trusted-hop problem of §1.7.
- The docs do not detail identity extraction/binding beyond "validate the cert" —
  **UNVERIFIED** whether APK binds a certificate to an application/subscription at all.

Source: https://apk.docs.wso2.com/en/latest/develop-and-deploy-api/security/authentication/enable-api-security/mtls/

For the backend direction, APK models upstreams with a `Backend` CR carrying `tls` — with
`certificateInline`/`secretRef`/`configMapRef` for the **trust** side. **UNVERIFIED** whether
`Backend` supports a client keypair for backend mTLS.

**Correction after reading the `support-1.3.0.x-full` source (2026-09-21).** The per-API half of
APK's mTLS appears **not to be wired** in the 1.3 Go enforcer. The listener half works: with
`MTLSAPIsEnabled`, every HTTPS listener gets a validation context (`listener.go:121-140`,
`RequireClientCertificate: false`, Envoy default `VERIFY_TRUST_CHAIN`, so an invalid certificate is
dropped at the handshake). The `Authentication` CRD's `mtls: {disabled, required, clientCertificates}`
is parsed and delivered to the enforcer. But: `getExtAuthzHTTPFilter()` — the only code carrying
`IncludePeerCertificate: true` — has no live caller (`http_filters.go:61` comments it out; zero
`.java` files remain, so no Java enforcer uses it); the `ext_proc` filter requests only
`xds.route_metadata`, `request.method`, `request.id` (`http_filters.go:358`) and no `connection.*`
attribute; no `ForwardClientCertDetails` is set anywhere in the adapter; the Go enforcer reads no
XFCC or `X-WSO2-CLIENT-CERTIFICATE` header; and the stored `MutualSSL` field
(`api_store.go:72`, `requestconfig/api.go:44`) is never read by any evaluation path. The one
`PeerCertificates` reference (`jwt_transformer.go:574`) verifies an *outbound* JWKS connection.
Net: per-API `mandatory`/`optional` and `clientCertificates` are configured but not enforced;
what is enforced is gateway-wide listener trust only. A second translator
(`gateway-api/translator/extauth.go:125`) does set `IncludePeerCertificate`, but its wiring into
the synchronizer was not found — **UNVERIFIED** whether that path is reachable. This should be
confirmed against a live cluster before being relied on either way. It is also a precise picture of
the gap the API Platform design closes: APK has the listener half and the per-API config half and
no channel between them — that channel is the `connection.*` attribute list on `ext_proc`.

## 3.3 Kong Gateway — `mtls-auth`

**Mechanism: a plugin.** This is the purest example of the policy-shaped design, and it shows
both what that buys and what it costs.

Config fields (`config.*`): `ca_certificates` (list of CA certificate entity UUIDs),
`skip_consumer_lookup`, `allow_partial_chain`, `authenticated_group_by`,
`revocation_check_mode`, `http_timeout`, `cert_cache_ttl`, `cache_ttl`, `send_ca_dn`,
`default_consumer`, `consumer_by`, `anonymous`.

**Consumer binding — the most developed model of any product surveyed.** Match order:

1. Manual `mtls_auth_credentials` mapping with matching SAN/CN **and** a specific
   `ca_certificate` (disambiguates the same DN issued by two CAs — exactly the §1.4 hazard).
2. Manual mapping with matching SAN/CN and **any** CA.
3. Automatic Consumer lookup by `username`/`id` when `consumer_by` is configured.
4. `anonymous` Consumer fallback.

`skip_consumer_lookup: false` is the **default** — no matching consumer ⇒ request denied.
Setting it `true` means "any client with a valid certificate gets in", which is precisely the
"trusted CA ≠ authorization" trap; Kong at least makes the safe behaviour the default.
Subject names are taken from SAN, "CN is only used if the SAN extension does not exist".

**Upstream headers**: normal flow sets `X-Consumer-ID`, `X-Consumer-Custom-ID`,
`X-Consumer-Username`, `X-Credential-Identifier`, `X-Anonymous-Consumer`. With
`skip_consumer_lookup` it instead sets `X-Client-Cert-Dn` and `X-Client-Cert-San`.

**Handshake mechanics — the granularity tax, stated plainly by Kong.** Because the client
certificate must be requested during `ssl_certificate_by_lua`, Kong builds an in-memory SNI
map of Routes that need client certs. Routes **must have SNI attributes configured**;
"missing SNIs force certificate requests on every handshake", and "expression-based routes
always trigger certificate requests regardless of SNI configuration". This is §1.2's
constraint surfacing as a product limitation: even a plugin-shaped design has to decide, at
connection time, whether to ask.

**Revocation**: **supported (Kong Enterprise/Konnect; the plugin is enterprise-tier).** Verified against
the plugin reference: `revocation_check_mode` ∈ {`SKIP`, `IGNORE_CA_ERROR` (default), `STRICT`}. In
`IGNORE_CA_ERROR` Kong checks OCSP or the CRL when a URL is present but does not fail on network
errors; `STRICT` treats the certificate as valid only when revocation status could be verified.
Supporting fields: `http_timeout` (OCSP/CRL fetch, default 30000 ms), `cert_cache_ttl` (revocation
status cache), `ssl_verify` (verify the OCSP responder / CRL distribution point's own certificate),
and HTTP(S) proxy settings for the fetch. Kong therefore ships exactly the control-plane machinery
our N2 defers — fetch, cache, and a configurable stale/failure policy — and notably chose
*fail-open on network error* as the default. An earlier version of this note said "no CRL/OCSP
support"; that was wrong.

Kong also ships **`header-cert-auth`** as a *separate* plugin for the terminated-upstream
topology — an explicit acknowledgement that "cert from the handshake" and "cert from a header"
are different trust problems and should not be the same code path. That separation is a good
idea worth stealing.

↑ Backend direction: a `Certificate` entity assigned to `Service.client_certificate`, plus
`Service.ca_certificates` / `tls_verify` for trust. Per-Service, i.e. per-upstream.
`tls-handshake-modifier` is a companion plugin that forces the handshake to request a client
cert so other plugins can see it.

Sources: https://developer.konghq.com/plugins/mtls-auth/, https://developer.konghq.com/plugins/header-cert-auth/

## 3.4 Apigee (X / Edge)

**Mechanism: native infrastructure config (keystores/truststores + virtual host), not a policy.**

- **Keystore**: holds a certificate + private key (the identity you present).
  **Truststore**: holds CA/peer certs you trust. Both are first-class, environment-scoped
  resources with aliases.
- ↓ Client→gateway: enabled on the **virtual host** — `clientAuthEnabled: true` plus a
  `TrustStore` reference. Granularity is therefore **per virtual host / per host alias**, not
  per API proxy. Per-proxy differentiation is done in the proxy flow by inspecting client-cert
  flow variables and rejecting.
- ↑ Gateway→backend: `TargetEndpoint`/`TargetServer` `<SSLInfo>` with
  `<Enabled>`, `<Enforce>`, `<ClientAuthEnabled>true</ClientAuthEnabled>`, `<KeyStore>`,
  `<KeyAlias>`, `<TrustStore>`. This is the cleanest backend-mTLS model in the survey: an
  explicit keystore+alias per target.
- References (indirection objects) may point at keystores/truststores so certs can be rotated
  without editing the proxy; "you can only use a reference to the keystore and truststore; you
  cannot use a reference to the alias", and on rotation the alias name must stay the same.
- Apigee requires the **`clientAuth` EKU** in client certificates for mTLS, in both
  directions. A certificate lacking that EKU fails — a very common real-world footgun.
- Flow variables expose the client cert to policies (`tls.client.*` family).
  **UNVERIFIED** — exact variable names not retrieved from a primary source in this pass.

Sources: https://docs.apigee.com/api-platform/system-administration/creating-keystores-and-truststore-cloud-using-edge-ui,
https://docs.apigee.com/api-platform/fundamentals/configuring-virtual-hosts-cloud,
https://docs.cloud.google.com/apigee/docs/api-platform/reference/api-proxy-configuration-reference

## 3.5 AWS API Gateway

**Mechanism: entirely native, and bluntly coarse — per custom domain name.** No policy, no
per-route control.

- `aws apigatewayv2 create-domain-name --mutual-tls-authentication TruststoreUri=s3://bucket/key`
  (+ `TruststoreVersion` from S3 object versioning). A regional custom domain, TLS ≥ 1.2. Not
  supported for private APIs.
- The truststore is a single `.pem` with the **complete** chain from issuing CA to root.
  "API Gateway accepts client certificates issued by **any** CA present in the chain of trust."
  Max chain length **4**. SHA-256+, RSA-2048+, ECDSA-256+.
- API Gateway validates: X.509 syntax, integrity, validity period, name/key chaining. That's it.
- **"API Gateway doesn't verify if a certificate has been revoked."** The sanctioned workaround
  is a Lambda authorizer doing your own CRL check — AWS published a whole Security Blog post
  on doing this "at scale".
- Certificates are forwarded "to Lambda authorizers and to backend integrations" via the
  request context (`$context.identity.clientCert.*`: `clientCertPem`, `subjectDN`, `issuerDN`,
  `serialNumber`, `validity.notBefore/notAfter` — **UNVERIFIED**, names not confirmed from the
  fetched page).
- **Granularity**: per domain name only. Every route under that domain gets the same policy.
  The documented mitigation for "clients must use the mTLS domain" is to *disable the default
  `execute-api` endpoint* — otherwise the API is reachable without a certificate at all. That
  is a real and frequently-missed bypass.
- Operational sharp edges users hit: "For each subject in the certificate, there can only be
  one issuer in API Gateway for mutual TLS domains"; certificate warnings are produced **only**
  when you update the domain name, never on later expiry; an imported/Private-CA server cert
  additionally needs an `ownershipVerificationCertificate` whose expiry **locks all updates to
  the domain name** if it lapses.

↑ Backend direction: no first-class backend-mTLS. HTTP integrations go over the public
network or a VPC link; presenting a client certificate to the backend is not a configuration
of the integration.

Sources: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html,
https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mutual-tls.html,
https://aws.amazon.com/blogs/security/how-to-implement-client-certificate-revocation-list-checks-at-scale-with-api-gateway/

## 3.6 Azure API Management

**Mechanism: a hybrid — native negotiation toggle on the hostname + a *policy* that does the
validation.** The closest analogue to a policy-shaped design in a major product, and the
clearest evidence for it working.

- **Negotiation is native and per-hostname**: Developer/Basic/Standard/Premium set
  **Negotiate client certificate** on the custom domain (REST:
  `hostnameConfiguration.negotiateClientCertificate: true`, default **false**);
  Consumption/v2 tiers set **Request client certificate**.
- **Validation is a policy**: `validate-client-certificate`, with attributes
  `validate-revocation`, `validate-trust`, `validate-not-before`, `validate-not-after`, and
  `match-in-identities` containing `<identity>` elements matched on `thumbprint`,
  `serial-number`, `common-name`, `subject`, `dns-name`, `issuer-subject`,
  `issuer-thumbprint`, `issuer-certificate-id`. **UNVERIFIED** in exact attribute spelling —
  the `validate-client-certificate` reference page was not fetched; the list comes from the
  overview page's pointer plus prior knowledge.
- **Or raw expressions**: `context.Request.Certificate` (a `X509Certificate2`) with
  `.Verify()`, `.VerifyNoRevocation()`, `.Thumbprint`, `.Issuer`, `.SubjectName.Name`, and
  `context.Deployment.Certificates` to compare against the APIM certificate store.
- Certificate store: upload a `.pfx`/`.cer` directly, **or** reference an Azure Key Vault
  certificate — Key Vault certificates "are automatically rotated in API Management … within 4
  hours". That is the best rotation story in the survey.
- CA certificates for validating self-signed client certs must be uploaded separately, and are
  **not supported in the Consumption tier**.
- Documented sharp edges, all of which we would inherit in a similar design:
  - Since May 2021 `context.Request.Certificate` only requests the certificate when
    `negotiateClientCertificate` is true — i.e. the lazy path was withdrawn.
  - "If TLS renegotiation is disabled in your client, you might see TLS errors"; "Certificate
    renegotiation isn't supported in the API Management v2 tiers."
  - The client-certificate **deadlock**: requests freeze, or 403 after timeout, or
    `context.Request.Certificate` is null — "usually affects POST and PUT requests with content
    length of approximately 60KB or larger". Fix: negotiate up front.
  - **Application Gateway in front breaks it entirely**: "The certificate attached by the
    client in the initial HTTP request isn't forwarded to APIM" — workaround is header rewriting
    with mutual-authentication server variables. A textbook §1.7 failure.

↑ Backend: `authentication-certificate` policy (`thumbprint` or `certificate-id` referencing
the APIM certificate store) sets the client certificate on the backend call. So Azure also does
**backend mTLS as a policy** — but note that Azure's "policy" is inside its own proxy runtime
and can influence the outbound TLS handshake, which an out-of-process ext_proc policy cannot
(see §4.5).

Source: https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates-for-clients

## 3.7 Envoy Gateway + Gateway API (the standard this repo already vendors)

**Mechanism: native, policy-attachment-shaped CRDs targeting a Gateway (not a route).**

### Envoy Gateway `ClientTrafficPolicy`

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: ClientTrafficPolicy
metadata: { name: enable-mtls, namespace: default }
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: eg
  tls:
    clientValidation:
      caCertificateRefs:
        - kind: Secret
          group: ""
          name: example-ca-cert
```

`targetRefs` points at a **Gateway**; the docs demonstrate Gateway-level enforcement, not
per-route. `BackendTLSPolicy` handles the trust side of gateway→backend.
(https://gateway.envoyproxy.io/docs/tasks/security/mutual-tls/,
https://gateway.envoyproxy.io/docs/api/gateway_api/backendtlspolicy/)

### Gateway API GEP-91 — and it is already on our disk

GEP-91 ("Client Certificate Validation for TLS terminating at the Gateway") has reached
**Standard**. Its API is in `sigs.k8s.io/gateway-api` **v1.5.1**, which
`kubernetes/gateway-operator/go.mod:22` already pins:

- `Gateway.spec.tls` → `GatewayTLSConfig{ Frontend *FrontendTLSConfig, Backend *GatewayBackendTLS }`
  (`gateway_types.go:624-642`)
- `FrontendTLSConfig{ Default TLSConfig (required), PerPort []TLSPortConfig }` (`:644-668`)
- `TLSConfig{ Validation *FrontendTLSValidation }` (`:690-702`)
- `FrontendTLSValidation{ CACertificateRefs []ObjectReference (required), Mode
  FrontendValidationModeType }` (`:726-798`), with `AllowValidOnly` (default, Core) and
  `AllowInsecureFallback` (Extended) — the latter documented as delegating authorization to the
  backend and introducing "a significant security risk".
- `GatewayBackendTLS{ ClientCertificateRef *SecretObjectReference }` (`:526-556`) — the
  gateway's **own** client certificate for backend connections, Core support for a
  `kubernetes.io/tls` Secret.
- A `GatewayConditionInsecureFrontendValidationMode` condition (`:1200-1212`) that
  implementations must set while insecure fallback is on.

**Deliberate non-goals of GEP-91**, which tells us where the standard will *not* help:
system CA trust anchors; a `subjectAltNames` field (explicitly deferred as "an Authorization
concern, not Authentication"); chain-depth specification; **per-route client validation**;
CRLs; certificate-hash verification. The `PerPort` design exists specifically to mitigate
HTTP/2 connection coalescing by applying validation at the TCP-connection level.

So the standard's answer to "per-API mTLS" is: **you don't; you do it per port.** That is a
strong signal about which of our candidate designs is swimming with the current.

## 3.8 Others, briefly

**Tyk.** Distinctive for having *two* client models: **static mTLS** (certificate allowlisted
on the API definition — any client with a listed cert gets in) and **dynamic mTLS** (the
certificate is bound to an *auth key/policy*, so the cert **is** the credential and carries the
key's quotas/policies). The dynamic model is the closest thing in the survey to
"certificate == application", which is what the APIM heritage user expects.
↑ Backend: `upstream_certificates` on the API definition as `{"example.com": "<cert-id>"}`,
or globally via `security.certificates.upstream` — **per upstream host, with a default**.
Tyk also supports **certificate pinning** (`pinned_public_keys`, one or more public keys per
domain) for the upstream direction — the only surveyed product to make SPKI pinning a
first-class user-facing feature.
(https://tyk.io/docs/api-management/upstream-authentication/mtls, https://tyk.io/docs/3.1/security/certificate-pinning/)

**NGINX / ingress-nginx.** `ssl_client_certificate` + `ssl_verify_client on|optional` +
`ssl_verify_depth`; identity to the app via `$ssl_client_escaped_cert`, `$ssl_client_s_dn`,
`$ssl_client_verify`. In ingress-nginx: `auth-tls-secret` (a Secret containing `ca.crt`),
`auth-tls-verify-client`, `auth-tls-verify-depth` (default 1), `auth-tls-match-cn`,
`auth-tls-pass-certificate-to-upstream`.
**The limitation worth internalizing**: all Ingresses sharing a hostname render into one
`server` block, so `auth-tls-pass-certificate-to-upstream: "true"` must be set on **every**
Ingress for that host or the `proxy_set_header` line is omitted for all of them
(https://github.com/kubernetes/ingress-nginx/issues/4911). Also: changing `auth-tls-match-cn`
can be ignored until the controller restarts
(https://github.com/kubernetes/ingress-nginx/issues/10915); and with OpenSSL ≥1.1.0 the
effective verify depth is one greater than configured
(https://github.com/kubernetes/ingress-nginx/issues/110). This is *exactly* the per-listener-
config-fighting-per-route-intent problem our shared filter chain would create.

**Istio.** Two orthogonal resources: `PeerAuthentication` (server side — `mtls.mode`
`STRICT`/`PERMISSIVE`/`DISABLE`, mesh/namespace/workload scoped) and `DestinationRule`
(client side — `trafficPolicy.tls.mode: ISTIO_MUTUAL`). Identity is a SPIFFE URI SAN
`spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>`, and authorization is a
**separate** resource: `AuthorizationPolicy` with `source.principals`. Istio is the cleanest
demonstration of the principle our GO-AUTH-007 encodes: *authenticate with mTLS, authorize
separately, never conflate*. `PERMISSIVE` mode (accept both mTLS and plaintext) is the
migration primitive everyone actually needs and few API gateways offer.

**Traefik.** `TLSOption` CRD with `clientAuth.clientAuthType` ∈ {`NoClientCert`,
`RequestClientCert`, `RequireAnyClientCert`, `VerifyClientCertIfGiven`,
`RequireAndVerifyClientCert`} and `clientAuth.secretNames`/`caFiles`. Forwarding to the
backend is a *middleware*: `passTLSClientCert` (`pem: true` and/or structured `info`
sub-fields). Distinctive: five explicit modes rather than a boolean — notably
`VerifyClientCertIfGiven`, a genuinely useful "optional but must be valid if presented" that
most products fold into a vague "optional". Known bug worth noting:
`passTLSClientCert` with `pem: true` can forward the intermediate CA instead of the leaf when
the chain includes an intermediate (https://github.com/traefik/traefik/issues/12183).
`TLSOption` is per-router-via-TLS-config, so granularity is per SNI/host, not per path.

**Solo Gloo.** `VirtualService.sslConfig` with `secretRef` + `sslSecrets`, and a `oneWayTls`
boolean in `VirtualServiceOptions` (with a defaults-level counterpart) to force one-way TLS —
i.e. mTLS is the *implied* behaviour when a validation context is present and `oneWayTls` is
false. Granularity is per VirtualService, which (since a VirtualService owns a set of domains)
is effectively per-SNI. `Upstream.sslConfig` covers the backend direction. Gloo also uses mTLS
for its own control↔data plane with a `certGen` job writing `gloo-mtls-certs` — the same
pattern as our `server.xds_tls`.
(https://docs.solo.io/gloo-edge/latest/guides/security/tls/mtls/,
https://github.com/solo-io/gloo/issues/10169)

**Cloudflare (API Shield).** Edge terminates; `cf.tls_client_auth.cert_presented` and
`cf.tls_client_auth.cert_verified` become **Ruleset Engine fields**, so enforcement is a WAF
rule (`not cf.tls_client_auth.cert_verified` ⇒ Block) rather than a TLS setting. Client
certificates are a managed zone resource — default quota 100 active certs per zone, raised to
100,000 for Enterprise with API Shield. Cloudflare also supports "bring your own CA" for
client-cert validation. Architecturally this is the §1.7 topology made explicit: the edge
verifies, then the *origin* must trust the edge.
(https://developers.cloudflare.com/api-shield/security/mtls/,
https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_verified)

**Akamai.** Mutual TLS at the edge via Edge Certificate / mTLS Edge TrustStore, with client
cert details injected into a forwarded header for the origin. **UNVERIFIED** — no primary
Akamai source retrieved in this pass; do not rely on specifics here.

## 3.9 Comparison table — configuration models

| Product | Client-auth mechanism | Granularity (↓) | Cert store | Identity → consumer binding | Backend mTLS (↑) | Revocation |
|---|---|---|---|---|---|---|
| **WSO2 APIM 4.x** | Native + `X-WSO2-CLIENT-CERTIFICATE` header | **Per API** (but disables HTTP for that API) | DB + `client-truststore.jks` | Cert → alias + **tier**; *no* application/subscription | `[[keystore.ssl_profile.custom]]` per hostname, node-local | Not built in |
| **WSO2 APK** | `Authentication` CRD, `mtls.required` | **Per API** (`targetRef`) | ConfigMap / Secret / inline | UNVERIFIED | `Backend` CR `tls` (trust side); client side UNVERIFIED | UNVERIFIED |
| **Kong** | **Plugin** (`mtls-auth`) | Global / Service / Route (needs SNI on routes) | `ca_certificates` entity | **Consumer** via `mtls_auth_credentials.subject_name` (+ optional CA disambiguation), or `consumer_by`, or anonymous | `Service.client_certificate` | No CRL/OCSP in plugin |
| **Apigee** | Native, virtual host `clientAuthEnabled` | **Per virtual host** | Keystore / Truststore (env-scoped, aliased, referenceable) | Flow variables → proxy logic | `TargetEndpoint <SSLInfo>` KeyStore+KeyAlias | UNVERIFIED |
| **AWS API GW** | Native, custom domain `TruststoreUri` | **Per domain name** | S3 `.pem` (versioned) | None — do it in a Lambda authorizer | Not supported | **Explicitly none** |
| **Azure APIM** | Native negotiation + **policy** validation | Negotiation per hostname; validation **per API/operation** (policy scope) | APIM cert store or **Key Vault** (auto-rotate ≤4h) | Policy expressions / `match-in-identities` | `authentication-certificate` policy | `validate-revocation` / `.Verify()` (CRL) |
| **Envoy Gateway** | Native `ClientTrafficPolicy` | **Per Gateway** | Secret/ConfigMap refs | None built in | `BackendTLSPolicy` (trust) | Not in the CRD |
| **Gateway API (GEP-91)** | Native `Gateway.spec.tls.frontend` | **Per Gateway, or per port** | `caCertificateRefs` | Explicit non-goal | `tls.backend.clientCertificateRef` | Explicit non-goal |
| **Tyk** | Native, API definition | **Per API** | Cert store (cert IDs) | **Dynamic mTLS: cert ↔ auth key/policy** | `upstream_certificates` per host + global default | **Pinning** (`pinned_public_keys`) |
| **NGINX / ingress-nginx** | Native `ssl_verify_client` / annotations | Per `server` block (**per hostname**) | Secret with `ca.crt` | None — `$ssl_client_*` to the app | `proxy_ssl_certificate` | CRL via `ssl_crl` |
| **Istio** | `PeerAuthentication` (STRICT/PERMISSIVE/DISABLE) | Mesh / namespace / workload | SPIRE-style, auto-rotated | `AuthorizationPolicy.source.principals` (SPIFFE) | `DestinationRule` `ISTIO_MUTUAL` | Short-lived certs |
| **Traefik** | `TLSOption.clientAuth` (5 modes) | Per TLS option → per SNI/router | Secret `secretNames` | None — `passTLSClientCert` middleware | `serversTransport` | UNVERIFIED |
| **Gloo** | `VirtualService.sslConfig` + `oneWayTls` | Per VirtualService (≈ per SNI) | `secretRef` | None built in | `Upstream.sslConfig` | UNVERIFIED |
| **Cloudflare** | Edge terminates; **WAF rule** on `cf.tls_client_auth.*` | Per hostname/rule expression | Zone-managed (100 → 100k certs) | Rule expressions | N/A (origin's problem) | Cert revoke in the zone API |

## 3.10 Patterns that recur across products

1. **Negotiation is coarse; enforcement is fine.** Almost every product decides *whether to ask
   for a certificate* at the listener/hostname/SNI level, and then does the interesting
   per-API/per-route work above the transport. Azure is the clearest: a hostname toggle plus a
   per-operation policy. This is a direct consequence of §1.2, not a coincidence.
2. **"Optional / permissive" mode is universally needed** and inconsistently spelled:
   Istio `PERMISSIVE`, Traefik `VerifyClientCertIfGiven` / `RequestClientCert`, APK
   `required: optional`, Gateway API `AllowInsecureFallback`, Envoy `require_client_certificate:
   false` + a validation context, Kong `anonymous`. It exists because nobody can flip an entire
   listener to mandatory mTLS in one step.
3. **CA trust is never sufficient, and every mature product says so.** Kong's
   `skip_consumer_lookup: false` default, Azure's `match-in-identities`, RFC 8705's
   expected-subject metadata, Istio's separate `AuthorizationPolicy`. The products that *don't*
   have a second check (AWS) tell users to write a Lambda.
4. **Two distinct trust problems, deserving two distinct configurations**: "cert from my own
   handshake" vs "cert asserted by an upstream hop". Kong splits them into two plugins
   (`mtls-auth` vs `header-cert-auth`). WSO2 APIM/APK collapse them into one header-based path —
   which is why the `certificate_header` setting is a security-critical config in those products.
5. **The certificate store is a first-class, aliased resource** everywhere (Apigee keystores,
   Kong `ca_certificates`, Azure certificates/Key Vault, Tyk cert IDs, AWS S3 truststore).
   Nobody makes it a flat file path.
6. **Revocation is punted.** AWS: none. Kong: none in-plugin. Gateway API: explicit non-goal.
   Azure alone does CRL by default. The practical answer everywhere is an
   allowlist/denylist the operator controls, plus expiry.
7. **The backend direction is always keystore-shaped, never policy-shaped at the wire level**
   — even Azure's `authentication-certificate` policy is only *selecting* a certificate that the
   proxy's own TLS stack then uses. Nobody implements backend mTLS by mutating headers, because
   it is not possible (see §4.5).

## 3.11 Mistakes and limitations users actually complain about

- **AWS: no revocation.** The single loudest complaint; it spawned an AWS Security Blog post
  and multiple third-party write-ups on bolting CRL checks onto a Lambda authorizer.
  Secondary: silent expiry (warnings only on domain update), the one-issuer-per-subject
  constraint, and forgetting to disable the `execute-api` endpoint — which leaves the API
  reachable with no certificate at all.
- **AWS/Azure: granularity.** "mTLS is per domain / per hostname" forces teams to stand up a
  separate domain per trust boundary.
- **Azure: the >60 KB POST/PUT deadlock** and `context.Request.Certificate == null`. Also
  Application Gateway silently dropping the client certificate before APIM.
- **ingress-nginx: annotations that only take effect if set on every Ingress sharing a
  hostname** (#4911), and annotation changes ignored until controller restart (#10915).
  Shared-listener config leaking across tenants is the same class of bug our shared filter
  chain would invite.
- **Traefik: `RequireAndVerifyClientCert` "not requesting client certificate"** — repeated
  community threads; usually a TLSOption not actually bound to the router. Plus the
  intermediate-instead-of-leaf `passTLSClientCert` bug (#12183).
- **Kong: browsers prompting for certificates** on routes that don't need them, because the
  certificate request is per-handshake and the SNI map is incomplete. Kong documents this.
- **Apigee: missing `clientAuth` EKU** breaking handshakes in both directions, with an
  unhelpful error.
- **WSO2 APIM: mutual-SSL-only APIs losing subscriptions, scopes, and resource-level
  throttling.** This is documented, not folklore — and it is the expectation gap a new WSO2
  product should close rather than reproduce.

---

# Phase 4 — Synthesis

## 4.1 Capability matrix — competitors vs us today

Legend: ✅ full · ◐ partial · ❌ absent · n/a not applicable

| Capability | APIM 4.x | APK | Kong | Apigee | AWS | Azure | Envoy GW / GEP-91 | Tyk | Istio | **Us today** |
|---|---|---|---|---|---|---|---|---|---|---|
| Require client cert on the listener | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ (`DownstreamTlsContext` has no `RequireClientCertificate`, `translator.go:2435`) |
| Optional / permissive client cert | ◐ | ✅ | ✅ | ◐ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Per-API (not per-listener) client-cert enforcement | ✅ | ◐ (see §3.2 note) | ◐ | ❌ | ❌ | ✅ | ❌ | ✅ | ◐ | ❌ (one filter chain, one shared RouteConfiguration) |
| CA-bundle trust for client certs | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ (cert store is upstream-trust only, `sds.go:34`) |
| Leaf / SPKI pinning for client certs | ◐ | ? | ❌ | ❌ | ❌ | ✅ (thumbprint) | ❌ | ✅ | ❌ | ❌ |
| SAN / DN / issuer identity matching | ◐ | ? | ✅ | ◐ | ❌ | ✅ | ❌ | ◐ | ✅ | ❌ (only `tlsauth.PeerIdentity` on control-plane channels) |
| Cert → application / consumer binding | ◐ (tier only) | ? | ✅ | ❌ | ❌ | ◐ | ❌ | ✅ | ✅ (SPIFFE) | ❌ |
| Cert → subscription / quota | ❌ (explicitly unsupported) | ? | ✅ (consumer plugins) | ❌ | ❌ | ◐ | ❌ | ✅ | n/a | ❌ |
| Combine mTLS with OAuth2/JWT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ (but `AuthContext.Previous` makes it trivial once a cert policy exists) |
| RFC 8705 certificate-bound tokens | ✅ (validate only) | ? | ❌ | ❌ | ❌ | ◐ | ❌ | ❌ | ❌ | ❌ |
| Forward client identity to backend (XFCC/header) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ (zero XFCC references repo-wide; HCM default `SANITIZE`) |
| Trust a forwarded cert header from a proxy | ✅ (it's the primary path) | ✅ | ✅ (`header-cert-auth`) | ◐ | n/a | ◐ (workaround) | ❌ | ◐ | ❌ | ❌ |
| CRL / revocation | ❌ | ❌ | ✅ (Enterprise: CRL + OCSP, `revocation_check_mode`) | ? | ❌ | ✅ | ❌ | ❌ | (short-lived) | ❌ |
| Client-cert expiry visibility / warning | ◐ | ? | ◐ | ◐ | ❌ | ✅ | ❌ | ◐ | n/a | ◐ (`notAfter` stored + returned, `models/certificate.go:31`) |
| **Gateway presents client cert to backend** | ◐ (node-local keystore) | ? | ✅ | ✅ | ❌ | ✅ | ✅ (GEP-91 `clientCertificateRef`) | ✅ | ✅ | ❌ (`createUpstreamTLSContext` never sets `TlsCertificates`) |
| Per-upstream backend client cert | ◐ (per hostname) | ? | ✅ (per Service) | ✅ (per TargetEndpoint) | ❌ | ✅ | ◐ (per Gateway) | ✅ (per host) | ✅ | ❌ (`UpstreamTLS{Enabled bool}` only) |
| Per-upstream backend trust (not global) | ◐ | ✅ | ✅ | ✅ | n/a | ✅ | ✅ | ✅ | ✅ | ❌ (one global `upstream_ca_bundle`) |
| Backend cert pinning | ❌ | ? | ❌ | ❌ | n/a | ❌ | ❌ | ✅ | ❌ | ❌ |
| Hot cert rotation without restart | ✅ (10 min poll) | ✅ | ✅ | ✅ | ◐ | ✅ (≤4h) | ✅ | ✅ | ✅ | ◐ (SDS + `/certificates/reload`, `certificates.go:165-183`) |
| Key material in a secret store / KMS | ◐ | ✅ | ◐ | ✅ | n/a | ✅ (Key Vault) | ✅ | ◐ | ✅ | ◐ (`secrets` table w/ encrypted ciphertext exists, unused for certs) |
| **Control-plane mTLS (xDS / ext_proc)** | n/a | ✅ | n/a | n/a | n/a | n/a | ✅ | n/a | ✅ | ✅ (`xds_tls.go`, `tlsauth`, `PolicyEngineTLS`) |

Read the last row together with the rest: **we are ahead of most of the field on control-plane
mTLS and at zero on data-plane mTLS.**

## 4.2 Candidate designs — direction ↓ (client → gateway)

Three genuinely different shapes. Not ranked.

### Option D-A — "Transport-native, per-listener"

Add client validation to the existing HTTPS listener. Config-only, no per-API notion.

- `router.downstream_tls` gains `client_validation.{enabled, trusted_ca_source, require,
  match_typed_san[], verify_certificate_hash[], verify_certificate_spki[], crl, max_verify_depth}`.
- `createDownstreamTLSContext` sets `RequireClientCertificate` and a
  `CommonTlsContext_ValidationContextSdsSecretConfig` pointing at a **new** SDS secret
  (e.g. `downstream_client_ca_bundle`) — which requires extending the
  `ClusterResourcesReferenceUpstreamCASecret` gate (`translator.go:2368`) into a general
  "is this secret referenced by any accepted resource" check, since the current gate only
  scans **clusters**, and this secret is referenced by a **listener**.
- Optionally set `ForwardClientCertDetails: SANITIZE_SET` + `set_current_client_cert_details`
  so backends and the policy engine see a trustworthy XFCC.
- CRD: consume `Gateway.spec.tls.frontend.default.validation.caCertificateRefs` (GEP-91,
  already vendored) in the operator's existing overlay path
  (`gateway_listeners_overlay.go:203`).

**Trade-offs.** + Smallest change; matches where the Gateway API standard is going; no SDK or
policy-repo changes; no cross-repo version matrix. + Envoy does all validation, so it is fast
and correct. − All-or-nothing per listener: every API behind `https_port` must present a
certificate. − No cert→application binding, no subscription integration — reproduces the APIM
"mutual-SSL-only APIs lose everything" complaint. − Rejects at the TLS layer, so there is no
useful HTTP error body and no analytics event for the rejection.

### Option D-B — "Listener requests, policy enforces" (hybrid — the Azure shape)

Envoy requests a certificate but does **not** require it
(`RequireClientCertificate: false` **with** a validation context ⇒ request, validate if
presented, do not reject when absent). A new `client-cert-auth` policy then enforces per API.

Mechanically this needs, in order:
1. Envoy: validation context on the listener, `require_client_certificate: false`.
2. Controller: add `connection.*` TLS attributes to the ext_proc `RequestAttributes` list
   (`translator.go:3204`) — **spike required**, see §4.4 Q1.
3. Policy engine kernel: read those attributes and populate a new SDK field.
4. `sdk/core`: additive `DownstreamContext.Connection *ConnectionContext` (or similar) +
   nil-safe accessor (§2.10.6), released as a new `sdk/core` tag.
5. `python_executor.proto`: same field, for Python policies.
6. `gateway-controllers`: a new `client-cert-auth` policy resolving the certificate to an
   identity and writing `AuthContext` (+ `Metadata["x-wso2-application-id"]` to reuse
   `subscription-validation` unchanged, §2.10.7).

**Trade-offs.** + True **per-API** enforcement, on the existing shared listener — this is what
the APIM heritage user expects and what D-A cannot give. + Sterile HTTP 401/403 with a body,
analytics, and `AuthContext.Previous` composition with `jwt-auth` for free. + The
cert→application→subscription chain reuses existing machinery end to end. − Every client on
that listener is *asked* for a certificate, which makes browsers prompt (Kong documents this
exact complaint) and adds handshake bytes. − Six-component change spanning three release
trains with the compatibility matrix of §2.10.9. − An API **not** carrying the policy is
silently unprotected — GO-AUTH-017 demands the "is mTLS required here" decision be a
structural route match, and the default must be deny for any route in a protected namespace
that fails to resolve.

### Option D-C — "Dedicated mTLS listener / port (or SNI-selected filter chain)"

Stand up a second HTTPS listener (`router.mtls_port`) whose filter chain requires client
certs, sharing the same RDS route config. APIs opt in by being published on that vhost/port.

- Variant D-C1: separate port. Simple; no `FilterChainMatch` needed; mirrors RFC 8705's
  `mtls_endpoint_aliases` and AWS/Azure's per-domain model.
- Variant D-C2: same port, multiple filter chains selected by `FilterChainMatch.server_names`
  (SNI), requiring the TLS-inspector listener filter. Gives per-hostname mTLS on one port.

**Trade-offs.** + Clients that don't do mTLS are never prompted. + Clean, cryptographically
unambiguous boundary — the strongest posture of the three. + Composes with D-B: the mTLS port
can also be the one that populates the policy context. − Clients must use a different
port/hostname (a real migration cost, and the AWS "forgot to disable the default endpoint"
bypass is the same hazard: the API is still reachable on the ordinary HTTPS port unless
routing forbids it). − D-C2 inherits Envoy filter-chain-match subtleties and, per GEP-91's own
reasoning, HTTP/2 **connection coalescing**: a client may reuse a connection established for
hostname A to send requests for hostname B when both resolve to the same IP and the
certificate covers both — so the mTLS filter chain can be bypassed by SNI choice. GEP-91
mitigates this with **per-port**, not per-listener, config. D-C1 does not have this problem.
− More listeners = more places the `downstream_tls` config must stay consistent.

### Cross-cutting sub-decision: where does trust material live?

Independent of A/B/C:

- **T1 — extend the existing cert store** with a usage discriminator (`usage`/`kind` column:
  `upstream_ca` | `downstream_client_ca` | `client_leaf`). Additive column + per-dialect
  `ALTER TABLE` (`db-schema-changes.md` D1/D3). Reuses `/certificates`, the `Certificate` CRD,
  and the Helm mounts. Requires a **second SDS secret** and extending the secret-inclusion gate.
- **T2 — a separate resource** (`/client-ca-certificates`, `ClientCACertificate` CRD). Cleaner
  semantics, no risk of silently widening upstream trust, but duplicates a lot of surface.
- **T3 — Kubernetes-native only**: CA refs come from `Gateway.spec.tls.frontend` Secrets/
  ConfigMaps, no management-API resource. Standard-aligned but leaves the Docker-compose /
  standalone deployment without a story.

A hard note on T1: today every certificate uploaded to `/certificates` lands in **one** flat
bundle used for upstream verification (`certstore.go:73-130`). If client-CA certs land in the
same bundle without a discriminator, uploading a client CA silently widens the set of backends
the gateway will trust — a trust-boundary violation introduced by a "reuse the existing store"
decision. **Any T1 design must partition the bundle, not just tag it.**

## 4.3 Candidate designs — direction ↑ (gateway → backend)

### Option U-A — "Per-upstream client certificate via SDS"

Extend `models.UpstreamTLS` (`runtime_deploy_config.go:182-185`) and the management API
`Upstream`/`UpstreamDefinition` with a `tls` block referencing a stored keypair; the translator
attaches `CommonTlsContext.TlsCertificateSdsSecretConfigs` in `createUpstreamTLSContext`, per
endpoint via the existing `Cluster_TransportSocketMatch` machinery (`translator.go:2540`,
`translator.go:583`).

- Needs: a keypair-capable store (new table or `secrets` reuse), a **second SDS secret type**
  (`Secret_TlsCertificate`), a per-secret name scheme (e.g. `client_cert:<id>`), and the
  secret-inclusion gate generalized.
- Matches Apigee's `KeyStore`+`KeyAlias`, Kong's `Service.client_certificate`, Tyk's
  `upstream_certificates`, and GEP-91's `clientCertificateRef`.
- **Trade-offs.** + Right granularity (per upstream definition), right mechanism, and it fixes
  the `go-control-plane-xds-security.md` directive-3 problem by construction (keys never in
  LDS/CDS). − Largest new surface: store, API, CRD, translator, SDS, Helm. − Per-upstream
  trust (a private CA for *this* backend only) is a natural companion ask that the current
  single global bundle cannot express; doing one without the other is half a feature.

### Option U-B — "Gateway-wide client identity"

One client certificate for the whole gateway, configured in `router.upstream.tls`
(`cert_path`/`key_path`, mirroring `PolicyEngineTLS`, `config.go:733-740`), presented to every
HTTPS upstream that asks.

- **Trade-offs.** + Tiny change; no new store, no new API, no CRD; file-mount + Helm value.
  + Matches the common "the gateway is one workload identity" case (SPIFFE-ish). − Presents
  the same identity to **every** backend, including third-party ones — an information leak and
  a blast-radius problem. − Cannot express "backend A needs cert X, backend B needs cert Y",
  which is the actual B2B requirement. − Inlining the key into the xDS `UpstreamTlsContext`
  would violate directive 3, so even this "small" option needs SDS or a file DataSource.

### Option U-C — "Reference a `secrets` entry / external secret"

Keep U-A's per-upstream shape but make the keypair a **reference** into the existing secret
system (`{{ secret "handle" }}` interpolation, `secrets` table with encrypted ciphertext,
`platform-api`'s `type: CERTIFICATE` secret already exists at
`platform-api/resources/openapi.yaml:8830`), rather than a new certificate-with-key resource.

- **Trade-offs.** + Reuses at-rest encryption, redaction (`SensitiveValues`,
  `runtime_deploy_config.go:45`), and the CP's existing `CERTIFICATE` secret type. + One place
  to rotate. − The 10240-char cap on a secret value (`management-openapi.yaml:4989-4995`) is
  tight for a key + chain. − `file-access.md` d.6 and `error-handling.md` d.5 apply: a failed
  secret resolution must never echo the handle. − Two resources (cert + key) or one blob with
  both PEM blocks — a modelling decision with real ergonomic consequences.

## 4.4 Open questions the design must answer

**Protocol / Envoy**

- **Q1 (blocking, spike first).** Does this repo's pinned Envoy expose peer-certificate
  attributes (`connection.subject_peer_certificate`, `connection.uri_san_peer_certificate`,
  `connection.dns_san_peer_certificate`, `connection.sha256_peer_certificate_digest`,
  `connection.mtls`) through **ext_proc `request_attributes`**? Currently only `xds.route_name`
  is requested (`translator.go:3204`, `constants.go:103`). If not, the policy path must fall
  back to `SANITIZE_SET` XFCC + header parsing — which is materially worse (parsing, size,
  and an extra place the trust boundary can be got wrong). **This single answer decides how
  expensive Option D-B is.**
- Q2. Do we require a certificate (`RequireClientCertificate: true`) or request-and-validate
  (`false` + validation context)? The latter is what makes D-B possible; confirm Envoy's exact
  semantics for that combination (docs do not state it explicitly).
- Q3. Do we need CRL? Envoy supports `crl` as a supplied DataSource but will not fetch or
  refresh it — that becomes control-plane work (fetch, validate `nextUpdate`, push via SDS).
  If not CRL, what *is* the revocation story: delete-the-row allowlist, short expiry, or both?
- Q4. Do we accept `AllowInsecureFallback` (GEP-91) at all? It requires surfacing
  `GatewayConditionInsecureFrontendValidationMode`, and under GO-AUTH-007 it must be an
  explicit off-by-default opt-in with a loud signal.

**Identity and authorization**

- Q5. What is *the* identity? Thumbprint, (issuer, serial), SAN URI, SAN DNS, or Subject DN?
  Given §1.4, a single canonical choice plus an optional secondary matcher is much safer than
  "configurable, any of the above". Note `tlsauth.PeerIdentity` (`peer_identity.go:41-46`)
  already picked "first URI SAN, else CN" for control-plane peers — do we align or deliberately
  diverge for data-plane clients?
- Q6. Does a certificate map to an **application** (reusing the api-key-auth →
  `Metadata["x-wso2-application-id"]` → subscription-validation chain, §2.10.7), to a
  **subscription** directly, or to nothing (pure allowlist)? This is the single biggest
  product-level decision and the one where APIM's documented limitation is the clearest
  anti-goal.
- Q7. Is the mapping per-API (like `apiKeysByAPI[apiId][hash]`, `common/apikey/store.go:214`)
  or org/gateway-wide? GO-AUTH-005 requires the org scope come from verified context either way.
- Q8. Do we implement RFC 8705 certificate-bound access tokens (`cnf.x5t#S256`)? If yes it is
  a small addition to `jwt-auth`/`opaque-token-auth` *given* Q1 — and it is the feature APIM
  users on 4.x already have.

**Topology**

- Q9. Do we support "cert arrives in a header from a trusted hop"? If yes: which header
  (`X-Forwarded-Client-Cert` vs the APIM-heritage `X-WSO2-CLIENT-CERTIFICATE`), and how is the
  hop authenticated — source-IP allowlist, or mTLS from the proxy? Kong's split into two
  plugins is the model worth copying; a single "cert from handshake OR header" code path is how
  this becomes an auth bypass.
- Q10. Do we set XFCC outbound to backends? If yes, `SANITIZE_SET` (not `APPEND_FORWARD`) so a
  client-supplied value can never survive, and which `set_current_client_cert_details` subfields.

**Cross-repo mechanics**

- Q11. How does an operator learn that a policy requires a gateway capability the running
  gateway lacks (§2.10.9)? There is no capability negotiation today. Deploy-time validation in
  the controller against a declared capability set is the obvious shape, but it does not exist.
- Q12. Release ordering and support window: `sdk/core` → gateway → policy. What is the minimum
  gateway version a `client-cert-auth@v1` policy declares, and where is that declared —
  `policy-definition.yaml` has no such field today.

**Storage / config**

- Q13. T1 vs T2 vs T3 (§4.2). And if T1: what is the `usage` column's default for the ~N
  existing rows, given the table is frozen and the migration must be nullable/defaulted?
- Q14. Where does a **private key** live — new column on `certificates` (frozen table:
  additive nullable BLOB is legal), the `secrets` table, or a file mount only? `certstore` today
  actively discards non-`CERTIFICATE` PEM blocks (`certstore.go:269-274`), so this is not a
  no-op either way.
- Q15. PQC: `post-quantum-cryptography.md` d.3 wants `X25519MLKEM768` first in `ecdh_curves`
  with classical after. The existing warnings on `UpstreamTLS.EcdhCurves`/`DownstreamTLS.EcdhCurves`
  (`config.go:643-650`, `681-688`) say an Envoy that doesn't know the group **NACKs the whole
  snapshot**. Does a new mTLS listener default to hybrid-first or stay classical-first?

## 4.5 The asymmetry: backend mTLS cannot be a policy

This deserves its own section because it cuts against the instinct built by every existing
upstream-auth feature in this product.

Today, `management-openapi.yaml:4418-4496` defines `UpstreamAuth.auth.type ∈ {api-key, oauth2,
other, none}`, and **every one of them resolves to an attached L7 policy**: `api-key` →
`set-headers`, `oauth2` → `oauth2-generator`, `other` → any named policy. The mental model is
"backend auth = a policy that sets a header".

**mTLS to the backend does not fit that model at all, and cannot be made to.** The reasons are
structural, not incidental:

1. **It is a TLS handshake, not a request.** The client certificate is presented while Envoy
   establishes the TCP+TLS connection to the upstream — before any HTTP request is framed, and
   possibly minutes before the request that triggered the connection (Envoy pools upstream
   connections and reuses them across requests and across *different downstream callers*).
2. **The policy engine is out of process.** ext_proc sees `ProcessingRequest` messages over
   gRPC; it can mutate headers, body, and dynamic metadata. It has **no handle on Envoy's
   upstream TLS context** and no hook in the connection-establishment path. There is no
   ext_proc message type for "about to dial an upstream".
3. **It is configured on the cluster's transport socket**, which lives in CDS, not in any HTTP
   filter: `Cluster.TransportSocketMatches[].TransportSocket` → `UpstreamTlsContext` →
   `CommonTlsContext.TlsCertificates` (`translator.go:2540-2558`, `translator.go:583-596`).
   That is control-plane config, produced by the translator, consumed by Envoy's TLS stack.
4. **Even Azure's "policy" isn't doing it at the wire.** `authentication-certificate` merely
   *selects* which certificate the APIM proxy's own TLS stack will use — it works because the
   policy runs inside the proxy. Our policies do not.
5. **A per-request client identity is not even expressible.** Connection pooling means the
   certificate is a property of the pooled connection. "Use cert X for this request and cert Y
   for the next" would require a separate connection pool per certificate — which is precisely
   what `TransportSocketMatch` + per-endpoint metadata gives you, at *cluster* granularity, not
   request granularity.

**Consequences for the spec:**

- `upstream.auth.type` must **not** gain an `mtls` value. Backend mTLS belongs on the upstream's
  **`tls` block** (a new `Upstream.tls` / `UpstreamDefinition.tls`), alongside trust settings —
  not in the auth-policy dispatch table. Putting it in `auth.type` would promise per-operation
  behaviour the transport cannot deliver.
- The two directions therefore have **structurally different designs**, and a spec that treats
  them symmetrically will be wrong. ↓ client→gateway *can* be part-transport/part-policy
  (Option D-B). ↑ gateway→backend is 100% transport configuration, 0% policy.
- A corollary worth stating for reviewers: anything that varies per *request* (which API, which
  operation, which caller) can influence backend mTLS only by selecting a **different cluster**
  (or a different `TransportSocketMatch` within one), never by changing an existing
  connection's certificate.

## 4.6 Security pitfalls, per candidate

**D-A (per-listener transport-native)**
- Turning it on makes *every* API on `https_port` require a certificate — an availability
  incident dressed as a security improvement. Needs a migration path (D-C or permissive mode).
- The new client-CA SDS secret must not be delivered through the same flat bundle as
  `upstream_ca_bundle`, or uploading a client CA silently widens backend trust (§4.2, T1).
- `RequireClientCertificate: true` with an **empty** trust bundle: Envoy behaviour is to reject
  everything, but the *controller* must refuse to start/deploy in that state per GO-AUTH-011 —
  validate the **effective** outcome, exactly as `ValidateXDSServerTLS` does (`xds_tls.go:109-119`).
- TLS-layer rejection produces no HTTP body and no analytics event — blind spot for operators,
  and for `error-handling.md` d.4's uniform-401 requirement there is nothing to unify.

**D-B (listener requests, policy enforces)**
- **The default must be deny.** An API whose chain lacks the policy is unprotected. GO-AUTH-017
  requires a structural decision ("does this route's binding require mTLS?"), not "did someone
  remember to attach the policy?".
- **Absent cert must fail closed**, inverting the SDK's snapshot-accessor fallback convention
  (§2.10.6). A policy author copying `downstreamSnapshot`'s shape will get this backwards.
- If the cert arrives via XFCC rather than an Envoy attribute, the header must be
  `SANITIZE_SET` (Envoy overwrites), never `APPEND_FORWARD`, and the policy must never read it
  on a connection where Envoy did not itself validate a peer certificate.
- Requesting certificates from every client on a shared listener causes browser prompts (Kong's
  documented complaint) and is itself a mild information disclosure (the CA DN list in TLS 1.2).
- Identity comparison must be constant-time (following `basic-auth`'s
  `subtle.ConstantTimeCompare`, `basicauth.go:127`) and canonicalized (§1.4) — a naive
  `subject == configured` string compare across two DN encoders is a silent deny-everything bug
  at best, and a match-anything bug if someone "fixes" it with substring matching
  (cf. `go-cors-validation.md` directive 1, the same mistake in a different header).
- Rejection responses must be uniform: unknown CA, expired, wrong SAN, and not-allowlisted must
  all produce the same body (`error-handling.md` d.4/d.5), or the trust store becomes
  enumerable.

**D-C (dedicated listener / SNI filter chains)**
- D-C2 only: **HTTP/2 connection coalescing** lets a client establish a connection under
  hostname A (no mTLS chain) and send requests with `:authority: B` (mTLS chain) — the filter
  chain was chosen at connection time by SNI. GEP-91's `PerPort` design exists because of this.
  Any D-C2 design must either pin per port or enforce at the HTTP layer as well.
- D-C1: the ordinary HTTPS port remains a bypass unless routing actively refuses the protected
  APIs there — the AWS `execute-api` mistake, reproduced.
- Two listeners means two `downstream_tls` configurations that can drift (different min TLS
  version, different ciphers). Validate them together.

**U-A / U-C (per-upstream backend client cert)**
- Private key handling is the whole risk. Never `inline_bytes` in CDS
  (`go-control-plane-xds-security.md` d.3); never returned by a read API; never in a config
  dump; never logged (GO-AUTH-003); file permissions hard-fail if too permissive (GO-AUTH-018).
- A per-upstream certificate + a global trust bundle is an asymmetry that invites
  "insecureSkipVerify" as a workaround. Ship per-upstream trust in the same increment or
  explicitly refuse the skip flag.
- Certificate/key mismatch or an expired client cert manifests as an upstream 503 with an
  opaque Envoy reason — needs explicit validation at upload/deploy time, not at first request.

**U-B (gateway-wide client identity)**
- Presents the gateway's identity to third-party backends that never asked for it. If any
  upstream is attacker-controlled (dynamic-endpoint policy, LLM proxy with a user-supplied
  base URL), that is credential disclosure to an untrusted party. Cross-reference
  `ssrf-prevention.md`: any feature that lets a request influence the upstream host becomes a
  vector for harvesting the gateway's client certificate handshake. **UNVERIFIED** whether the
  `dynamic-endpoint` policy can currently point at an arbitrary host — worth checking before
  choosing U-B.

## 4.7 Things that will bite us (grounded in this codebase)

1. **SDS serves exactly one secret, and it is a validation context.** `sds.go:34,85-111`. A
   keypair needs `Secret_TlsCertificate`; a client-CA bundle needs a second
   `Secret_ValidationContext` with a different name. Both need the snapshot-inclusion gate
   generalized — `ClusterResourcesReferenceUpstreamCASecret` (`translator.go:2368-2393`) only
   scans **clusters** for `CombinedValidationContext`, so a secret referenced by a **listener**
   will never be included in the snapshot and Envoy will warn "Ignoring unwatched type URL …
   Secret" while the listener sits broken. This is a silent, non-obvious failure mode.
2. **The cert store has no private-key support, and actively drops keys.**
   `certstore.go:269-274` skips every non-`CERTIFICATE` PEM block; `StoredCertificate`
   (`models/certificate.go:24-35`) has no key field. Anyone uploading a combined cert+key PEM
   today gets the key silently discarded.
3. **The cert store is one flat bundle with no notion of purpose.** `certstore.go:73-130`
   concatenates every DB certificate plus the system bundle. Adding client CAs here widens
   backend trust as a side effect.
4. **`certificates` is a shipped, frozen table.** `db-schema-changes.md` D1. Additive nullable/
   defaulted columns only, each with per-dialect `ALTER TABLE` across
   `gateway-controller-db.sql` / `.postgres.sql` / `.sqlserver.sql`. No new `UNIQUE`, no
   retyping, no `NOT NULL` on an existing column.
5. **`createDownstreamTLSContext` already violates `go-control-plane-xds-security.md`
   directive 3** — it reads the key file and puts the bytes in `DataSource_InlineBytes`
   (`translator.go:2403-2420`), so the listener's private key travels in LDS. Touching that
   function to add client validation means either fixing it (move to SDS) or knowingly extending
   a rule violation. The former is the right call and should be scoped in.
6. **One filter chain, one shared RouteConfiguration.** `translator.go:1428-1441`,
   `SharedRouteConfigName` at `translator.go:1337`/`1448-1454`. There is no `FilterChainMatch`
   anywhere today, so per-API TLS behaviour has no existing hook. This is the ingress-nginx
   `auth-tls-pass-certificate-to-upstream` problem (#4911) waiting to happen: shared listener
   config that cannot express per-route intent.
7. **HTTP/2 is negotiated (`h2, http/1.1`, `translator.go:2448`)**, so post-handshake client
   auth is forbidden by RFC 8740 and connection coalescing applies to any SNI-based scheme.
   "Ask for the cert only when the route needs it" is not achievable.
8. **ext_proc requests exactly one attribute.** `translator.go:3204`,
   `constants.go:103`, and the policy engine reads only `xds.route_name`
   (`extproc.go:776-790`). Whether `connection.*` attributes can be added is unproven —
   §4.4 Q1.
9. **`DownstreamContext` has one field.** `sdk/core/policy/v1alpha2/context.go:37-41` and
   `python_executor.proto:209-211`. Every policy-based option needs an additive SDK change,
   a proto change, a gateway change, and a policy release, in that order (§2.10.9).
10. **The SDK's established "absent on older gateways" convention falls back rather than failing
    closed** (`context_accessors.go:20-54`). For a certificate the correct behaviour is the
    opposite. A policy author following the house pattern will write an auth bypass.
11. **Envoy NACK risk on unknown config.** The `EcdhCurves` comments (`config.go:643-650`,
    `681-688`) document it: an Envoy build that doesn't recognize a value NACKs the update and
    **keeps serving its last-known-good config**, silently freezing that instance out of all
    future changes. Any new `DownstreamTlsContext`/`UpstreamTlsContext` field (or a
    `FilterChainMatch`, or the TLS-inspector listener filter) carries this risk against mixed-
    version fleets. There is no NACK-surfacing mechanism in the controller today —
    **UNVERIFIED** whether `OnStreamResponse`/`OnFetchResponse` callbacks log NACKs at all.
12. **Certificate rotation without dropping connections.** SDS swaps material for *new*
    connections; established connections keep the old certificate until they close. With HTTP/2
    keep-alive and a generous `idle_timeout` (default 1h, `config.go:719`), "rotation complete"
    can be an hour after the push. Revocation-by-rotation is therefore not immediate. Envoy's
    exact drain behaviour on SDS rotation is **UNVERIFIED**.
13. **A cert change regenerates the entire xDS snapshot.** `certificates.go:174` calls
    `snapshotManager.UpdateSnapshot`. Fine today; with per-upstream certificates and a large API
    catalogue this becomes a full re-translation on every certificate upload.
14. **The SDS manager only exists if `custom_certs_path` is set.** `translator.go:122-147` —
    and if `LoadCertificates` fails the store is set to `nil` with only a `Warn`, which silently
    disables SDS for the whole gateway (`translator.go:133-140`), falling back to "no validation
    context" ⇒ **no upstream verification at all** (§1.3). That is an existing fail-open and it
    will become much more dangerous once client trust also flows through this store. Under
    GO-AUTH-011 this should become a startup failure.
15. **`tlsauth.PeerIdentity` is "first URI SAN, else CN"** (`peer_identity.go:41-46`) with no
    issuer binding. Reusing it for external clients would mean two different CAs issuing the
    same CN produce the same identity — the exact collision Kong's per-CA credential
    disambiguation exists to prevent.
16. **The `"x-wso2-application-id"` metadata key is duplicated across two independently-versioned
    policy modules** (`api-key-auth/apikey.go:38`, `subscription-validation/subscriptionvalidation.go:20`)
    with no shared constant. A third producer makes it a three-way coupling with no compile-time
    check.
17. **No test PKI and no client-cert step vocabulary in the IT suite.** `gateway/it/features/`
    has no step for "request with client certificate"; `certificates.feature` tests only
    management CRUD. Fixtures (a test CA, leaf, expired leaf, wrong-CA leaf, CRL) and new godog
    steps are a non-trivial slice of the work — and the forged-`XFCC`-header case must be in
    that suite from day one.
18. **The operator's Helm-overlay path is single-certificate by design.**
    `gateway_listeners_overlay.go:189-191` states per-listener SNI certificate selection is not
    supported. Any D-C2 design collides with this directly.
19. **`platform-api` and the gateway disagree about secrets.** `platform-api` already has
    `type: [GENERIC, CERTIFICATE]` (`platform-api/resources/openapi.yaml:8830`); the gateway's
    `SecretConfigData` (`management-openapi.yaml:4969-4998`) has no `type` at all and caps the
    value at 10240 chars. If keys ride the secret system, these need reconciling.

---

## Appendix A — Primary sources

**RFCs / specifications**
- RFC 8446 (TLS 1.3), §4.4.2 Certificate, §4.4.3 CertificateVerify, §4.6.2 Post-Handshake Authentication
- RFC 8740, Using TLS 1.3 with HTTP/2 — https://www.rfc-editor.org/rfc/rfc8740.html
- RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens — https://datatracker.ietf.org/doc/html/rfc8705
- RFC 5280 / RFC 4514 (DN string representation) / RFC 6125 (identity in certs)

**Envoy**
- XFCC header — https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
- TLS common.proto (CertificateValidationContext) — https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto
- TLS tls.proto (DownstreamTlsContext / CommonTlsContext) — https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto
- TLS architecture overview — https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl
- SNI / filter chain match FAQ — https://www.envoyproxy.io/docs/envoy/latest/faq/configuration/sni

**Gateway API / Envoy Gateway**
- GEP-91 — https://gateway-api.sigs.k8s.io/geps/gep-91/
- GEP-1897 (BackendTLSPolicy) — https://gateway-api.sigs.k8s.io/geps/gep-1897/
- Envoy Gateway mutual TLS task — https://gateway.envoyproxy.io/docs/tasks/security/mutual-tls/
- Envoy Gateway BackendTLSPolicy — https://gateway.envoyproxy.io/docs/api/gateway_api/backendtlspolicy/
- Vendored source: `~/go/pkg/mod/sigs.k8s.io/gateway-api@v1.5.1/apis/v1/gateway_types.go`

**WSO2**
- APIM 4.4 Mutual SSL — https://apim.docs.wso2.com/en/4.4.0/design/api-security/api-authentication/secure-apis-using-mutual-ssl/
- APIM 4.5 endpoint certificates — https://apim.docs.wso2.com/en/4.5.0/manage-apis/design/endpoints/certificates/
- APIM 4.4 certificate-bound access tokens — https://apim.docs.wso2.com/en/4.4.0/design/api-security/api-authentication/securing-apis-using-certificate-bound-access-tokens/
- APK mTLS — https://apk.docs.wso2.com/en/latest/develop-and-deploy-api/security/authentication/enable-api-security/mtls/

**Other products**
- Kong `mtls-auth` — https://developer.konghq.com/plugins/mtls-auth/
- Kong `header-cert-auth` — https://developer.konghq.com/plugins/header-cert-auth/
- Apigee keystores/truststores — https://docs.apigee.com/api-platform/system-administration/creating-keystores-and-truststore-cloud-using-edge-ui
- Apigee proxy configuration reference (SSLInfo) — https://docs.cloud.google.com/apigee/docs/api-platform/reference/api-proxy-configuration-reference
- AWS HTTP API mTLS — https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html
- AWS CRL checks at scale — https://aws.amazon.com/blogs/security/how-to-implement-client-certificate-revocation-list-checks-at-scale-with-api-gateway/
- Azure APIM client certificates — https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates-for-clients
- Tyk upstream mTLS — https://tyk.io/docs/api-management/upstream-authentication/mtls
- Tyk certificate pinning — https://tyk.io/docs/3.1/security/certificate-pinning/
- Traefik TLSOption — https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/crd/tls/tlsoption/
- ingress-nginx annotations — https://github.com/kubernetes/ingress-nginx/blob/main/docs/user-guide/nginx-configuration/annotations.md
- Istio PeerAuthentication — https://istio.io/latest/docs/reference/config/security/peer_authentication/
- Gloo mTLS — https://docs.solo.io/gloo-edge/latest/guides/security/tls/mtls/
- Cloudflare API Shield mTLS — https://developers.cloudflare.com/api-shield/security/mtls/

**Reported issues cited**
- ingress-nginx #4911 (pass-certificate shadowed across Ingresses) — https://github.com/kubernetes/ingress-nginx/issues/4911
- ingress-nginx #110 (verify depth) — https://github.com/kubernetes/ingress-nginx/issues/110
- ingress-nginx #10915 (`auth-tls-match-cn` needs restart) — https://github.com/kubernetes/ingress-nginx/issues/10915
- traefik #12183 (`passTLSClientCert` forwards intermediate) — https://github.com/traefik/traefik/issues/12183
- solo-io/gloo #10169 (`oneWayTls`) — https://github.com/solo-io/gloo/issues/10169

## Appendix B — UNVERIFIED claims

Listed so a spec author knows what still needs confirming:

1. Whether this repo's pinned Envoy exposes `connection.*` peer-certificate attributes to
   **ext_proc `request_attributes`** (§4.4 Q1). **Highest priority.**
2. Envoy's exact semantics for `require_client_certificate: false` **with** a validation
   context (request-and-validate-if-present). Not stated in the API docs.
3. Whether an SDS certificate rotation drains/closes established downstream connections.
4. Whether the controller logs or surfaces Envoy **NACKs** today.
5. AWS ALB `X-Amzn-Mtls-*` header spellings.
6. AWS API Gateway `$context.identity.clientCert.*` variable names.
7. Azure `validate-client-certificate` policy's exact attribute/element spelling.
8. Apigee `tls.client.*` flow-variable names.
9. Kong `revocation_check_mode` accepted values and edition availability.
10. WSO2 APIM Publisher REST API shapes for `/apis/{id}/client-certificates` and
    `/endpoint-certificates`.
11. Whether WSO2 APK binds a client certificate to an application/subscription at all, and
    whether APK's `Backend` CR supports a client keypair for backend mTLS.
12. Akamai mTLS specifics (no primary source retrieved).
13. Whether the in-tree `dynamic-endpoint` policy can direct traffic to an arbitrary,
    request-influenced upstream host (relevant to Option U-B's credential-disclosure risk).
