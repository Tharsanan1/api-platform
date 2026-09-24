# [Proposal] Mutual TLS for the gateway — client → gateway and gateway → backend

## Problem

The gateway has no data-plane mTLS in either direction today. This proposes mTLS in both directions:

1. **Inbound** — a client authenticates to an API with an X.509 certificate, enforced **per API**,
   including when a load balancer terminates TLS in front of the gateway and relays the certificate
   in a header.
2. **Outbound** — the gateway presents a **per-upstream** client certificate to a backend that
   requires one, with per-upstream trust.

The two are not symmetric. Inbound is part transport, part policy: Envoy negotiates and validates,
a policy decides per API. Outbound is pure transport: a client certificate is presented on a pooled
connection before any request exists, so no policy can touch it, and `upstream.auth.type` does not
gain an `mtls` value.

mTLS is **authentication only**. The new `mtls-auth` policy writes an `AuthContext` and nothing
else — no application id, nothing `subscription-validation` consumes. An API that needs both
attaches both, exactly as for a JWT-protected API today.

## Inbound

### Listener

The shared HTTPS listener gains a client-CA validation context **derived** from deployed APIs: when
any API attaches `mtls-auth` the listener requests a certificate; when the last one is removed it
stops. `require_client_certificate: false`, so callers of non-mTLS APIs are unaffected. There is no
gateway-level switch.

Envoy validates every presented certificate but is configured with
`trust_chain_verification: ACCEPT_UNTRUSTED`, so it **never drops** the connection over a bad
certificate. The verdict reaches the policy engine as `connection.peer_certificate_valid` alongside
the certificate. Every certificate outcome is therefore an HTTP outcome: an invalid certificate gets
the same uniform 401, analytics record and access-log line as a certificate from the wrong
authority. Only pre-certificate TLS failures (protocol or cipher mismatch) still die at the
handshake, and those are unrelated to mTLS.

### The pool, and the policy that selects from it

Two tiers. The **admin** curates a pool of client authorities through the existing certificates
endpoint, told where the certificate lands:

```
POST /api/management/v1/certificates
{ "name": "partner-bank-root", "usage": "client", "certificate": "-----BEGIN CERTIFICATE----- …" }
```

`usage` is `upstream` (default — backend trust, as today), `client` (a client authority) or
`identity` (a certificate the gateway presents, see Outbound). A self-signed client certificate goes
into the pool as its own one-member authority.

The **developer** selects from the pool by attaching the policy. Nothing else changes in the API:

```yaml
policies:
  - name: mtls-auth
    version: v1
    params:
      accept:                                  # optional — omitted means the whole pool
        - ca: partner-bank-root                # anyone this authority issued to …
          match: { uriSANs: ["urn:partner-bank:payments"] }   # … carrying one of these SANs
        - ca: partner-bank-root                # or exactly these certificates
          thumbprints: ["9f86d081…"]
        - ca: acme-selfsigned                  # a self-signed leaf, pooled as its own authority
```

Entries are tried in order, first match wins. `ca` is always required and is verified
**cryptographically** — a signature and path check back to the named pool entry, never an
issuer-DN compare, because the handshake proved only that the certificate chains to *something* in
the pool. Adding an authority to the pool grants no access to any API; only an `accept` list does.
Every parameter must have its declared shape: a narrowing given as a scalar, an empty `match`, or an
entry that is not an object is refused at deploy, never read as "no narrowing".

Output: `AuthContext{Authenticated: true, AuthType: "mtls", Subject: <matched SAN or DN>,
Issuer: <pool entry name>, CredentialID: <thumbprint>}`. `accept` and `notAfter` are re-evaluated
on **every request**, so removing an entry, a SAN or a thumbprint takes effect on the caller's next
request; pool changes reach new handshakes only.

### Behind a load balancer: the certificate arrives in a header

When a proxy terminates TLS, the client certificate reaches the gateway only as a header the proxy
sets. The **same policy** handles it; the API YAML does not change. What changes is how the header
is trusted, because a header is text anyone can send:

| How the header is believed | Setting | Default |
|---|---|---|
| The connection's own certificate chains to a pool entry marked as a **relay** — i.e. it is the load balancer. The entry may be narrowed with `match` so that only the proxy's own certificate under a shared authority can relay | `POST /certificates { "usage": "client", "role": "relay", "match": {…}, … }` | no relay entries |
| Trusted network: believe the header from any connection that presented no certificate | `trust_any = true` in `config.toml` | `false`, warns at startup and on every deploy while on |

```toml
[router.downstream_tls.client_certificate_header]
name               = "X-WSO2-CLIENT-CERTIFICATE"   # header name is configurable
trust_any          = false
forward_to_backend = false                          # a believed header may be forwarded; an ignored one never is
```

Header mode is on when a relay entry exists or `trust_any` is true, and off otherwise — there is no
`enabled` key. On a route with `mtls-auth` the policy decides in this order:

1. The connection's own certificate is judged first. If it passes an `accept` entry, the caller is
   authenticated as the connection and the header is ignored. An API that accepts the load
   balancer's authority therefore authenticates the load balancer; an API that accepts only partner
   authorities never does.
2. Otherwise, if a header is present, the certificate inside it is judged against `accept` — but
   only when the connection chains to a relay entry, or under `trust_any`. The policy parses,
   date-checks and chains the relayed certificate to the pool itself, since no handshake the
   gateway saw validated it.
3. A connection that presented a certificate Envoy rejected is denied outright. No header and no
   setting rescues it: a caller who identified itself with a bad certificate does not get a second
   chance through a header.

A partner connecting directly who sends a header is therefore authenticated as **themselves**; the
header is ignored. A relay entry cannot itself be named in an `accept`; to accept the load balancer
as a caller, its authority is pooled a second time as an ordinary client entry. The header is
deleted before every backend unless forwarding is enabled and the header was believed.

## Outbound

A `tls` block on an `upstreamDefinitions` entry — never on an inline `upstream.main.url`, and not a
new `upstream.auth.type`:

```yaml
upstreamDefinitions:
  - name: partner-billing
    upstreams:
      - url: https://billing.partner.example.com
    tls:
      identity: partner-billing-id        # what we present  → /certificates (usage: identity)
      trustedCAs: [partner-billing-ca]    # who we accept    → /certificates (usage: upstream), replaces the gateway bundle
      verifyHostName: true                # default
upstream:
  main:
    ref: partner-billing
```

Every field is optional. `tls` belongs to the definition and is shared by its targets; two backends
needing different identities are two definitions, and `dynamic-endpoint` selects between them per
operation. Identities are uploaded once by the admin, stored encrypted, delivered to Envoy over SDS
as `Secret_TlsCertificate`, rotated in place with `PUT`, and never returned by any read:

```
POST /api/management/v1/certificates
{ "name": "partner-billing-id", "usage": "identity", "certificate": "…", "privateKey": "…" }
```

A backend TLS failure returns one sterile 503 body; the reason goes to the access log only. A
`tls-test` endpoint performs one handshake to the backend with the definition's settings and
reports the outcome as a closed enum, so an operator can check a definition before traffic does.

Two existing weaknesses are fixed on the way: the listener's private key used to travel inline in
the listener resource and now moves to SDS; and the certificate store, which backs every SDS
secret, is always present — a load failure is a startup failure rather than a silent loss of
verification.

## Observability

Nothing new is invented; the feature rides the existing rails. The JSON access log gains the TLS
fields (`sni`, `tlsVer`, `peerSubj`, `peerFp`, `upTlsFail`). The `mtls-auth` policy span carries the
result, the reason on a deny, the matched entry, whether the certificate came from the handshake or
a relay, and the standard `tls.client.*` attributes — never certificate material. A deny counts on
the generic `policy_executions_total{status="denied"}`; the controller exposes certificate counts per
usage and each certificate's expiry, and warns thirty days ahead of expiry in the listing, the
log and the gauge.

## Interfaces

| Endpoint | Roles | New or extended |
|---|---|---|
| `POST/GET/DELETE /certificates` | admin write, developer read | **extended**: `usage`, `role`, `match`, `?usage=`; omit the new fields and behaviour is unchanged |
| `POST /certificates` with `usage: identity`, `PUT /certificates/{id}` | admin write, developer read | **extended**: identities are certificate rows with an encrypted key; `PUT` rotates an identity; no read ever returns the key |
| `POST /rest-apis/{handle}/upstreams/{name}/tls-test` | admin, developer | new; one handshake to the backend with the definition's `tls`, result as a closed enum |

Data model: additive, defaulted or nullable columns on the shipped `certificates` table (`usage`,
`role`, `match_json`, `private_key_ciphertext`, `key_algorithm`), all with a guarded per-dialect
`ALTER`; no new table. No other TOML besides the header block above.

## Guarantees the tests defend

- Absent, invalid, unpopulated or unmatched certificate → deny. `nil` never means "not required".
- Every certificate rejection returns one uniform 401 body; the cause goes to telemetry only.
- A header is believed only after the connection itself proved it may relay, or under the explicit
  `trust_any` posture; a connection whose certificate was rejected is never rescued by a header.
- Client-CA trust and upstream trust are built from separate `usage` filters and asserted disjoint.
- `X-Forwarded-Client-Cert` reaches a backend only on routes whose chain has `mtls-auth`; every other
  route strips it, and an API can opt out with `forwardCertificate: false` on the policy. The
  relayed-certificate header follows the same rule.
- A dangling reference (`accept` naming a missing, relay or `upstream` entry; `tls.identity`
  missing) is refused at deploy. Deleting an entry an API names is refused with 409.
- Malformed input fails closed: a narrowing in the wrong shape, an unknown field on a relay upload,
  or a private key pasted into a certificate field is refused, never ignored.
- Private keys: never in xDS `inline_bytes`, never in a read response, config dump or log.
