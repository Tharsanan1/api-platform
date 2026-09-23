[Proposal] Mutual TLS for the gateway — client → gateway and gateway → backend

## What

The gateway has no data-plane mTLS in either direction today. Every control-plane channel already
uses it (xDS, policy-xDS, ext_proc), so the config vocabulary and identity helpers exist; they have
never been pointed at API traffic. This proposes both directions:

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
authority. Only pre-certificate TLS failures (protocol/cipher mismatch) still die at the handshake.

### The pool, and the policy that selects from it

Two tiers. The **admin** curates a pool of client authorities through the existing certificates
endpoint, told where the certificate lands:

```
POST /api/management/v1/certificates
{ "name": "partner-bank-root", "usage": "client", "certificate": "-----BEGIN CERTIFICATE----- …" }
```

`usage` is `upstream` (default — backend trust, as today) or `client`. A self-signed client
certificate goes into the pool as its own one-member authority.

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
**cryptographically** — a signature/path check back to the named pool entry, never an issuer-DN
compare, because the handshake proved only that the certificate chains to *something* in the pool.
Adding an authority to the pool grants no access to any API; only an `accept` list does.

Output: `AuthContext{Authenticated: true, AuthType: "mtls", Subject: <matched SAN or DN>,
Issuer: <pool entry name>, CredentialID: <thumbprint>}`. `accept` and `notAfter` are re-evaluated
on **every request**, so removing an entry, a SAN or a fingerprint takes effect on the caller's next
request; pool changes reach new handshakes only.

### Behind a load balancer: the certificate arrives in a header

When a proxy terminates TLS, the client certificate reaches the gateway only as a header the proxy
sets. The **same policy** handles it; the API YAML does not change. What changes is how the header
is trusted, because a header is text anyone can send:

| How the header is believed | Setting | Default |
|---|---|---|
| The connection's own certificate chains to a pool entry marked as a **relay** — i.e. it is the load balancer | `POST /certificates { "usage": "client", "role": "relay", … }` | no relay entries |
| Trusted network: believe the header from any connection | `trust_any = true` in `config.toml` | `false`, warns at startup and on every deploy while on |

```toml
[router.downstream_tls.client_certificate_header]
name               = "X-WSO2-CLIENT-CERTIFICATE"   # ALB / nginx names configurable
trust_any          = false
forward_to_backend = false                          # a believed header may be forwarded; an ignored one never is
```

Header mode is on when a relay entry exists or `trust_any` is true, and off otherwise — there is no
`enabled` key. A partner connecting directly who sends the header is authenticated as **themselves**;
the header is ignored. The policy parses, date-checks and chains the relayed certificate to the
pool itself, since no handshake the gateway saw validated it. The header is deleted before every
backend unless forwarding is enabled and the header was believed.

APIM does this in one authenticator with `enable_client_validation` (default true): the header is
honoured if the connection's certificate exists in the truststore — which also holds every client
certificate, so any client can relay another's identity. Kong's separate `header-cert-auth` plugin
gates on `trusted_ips`. The relay mark is APIM's approach with that gap closed; trusted IPs are
deferred and can be added between the two options later.

## Outbound

A `tls` block on an `upstreamDefinitions` entry — never on an inline `upstream.main.url`, and not a
new `upstream.auth.type`:

```yaml
upstreamDefinitions:
  - name: partner-billing
    upstreams:
      - url: https://billing.partner.example.com
    tls:
      identity: partner-billing-id        # what we present  → /gateway-identities
      trustedCAs: [partner-billing-ca]    # who we accept    → /certificates (usage: upstream), replaces the gateway bundle
      verifyHostName: true                # default
upstream:
  main:
    ref: partner-billing
```

Every field is optional. `tls` belongs to the definition and is shared by its targets; two backends
needing different identities are two definitions, and `dynamic-endpoint` selects between them per
operation. Identities are uploaded once by the admin, stored encrypted, delivered to Envoy over SDS
as `Secret_TlsCertificate`, and never returned by any read:

```
POST /api/management/v1/gateway-identities
{ "name": "partner-billing-id", "certificate": "…", "privateKey": "…" }
```

Two existing violations are fixed on the way: the listener's private key currently travels inline
in LDS and moves to SDS; a cert-store load failure currently warns and disables verification and
becomes a startup failure.

## Interfaces

| Endpoint | Roles | New or extended |
|---|---|---|
| `POST/GET/DELETE /certificates` | admin write, developer read | **extended**: `usage`, `role`, `?usage=`; omit both and behaviour is unchanged |
| `POST/PUT/GET/DELETE /gateway-identities` | admin write, developer read | new; `GET` never returns the key |
| `GET /tls/handshake-failures` | admin | new; pre-certificate TLS failures, which never become requests |
| `POST /rest-apis/{handle}/upstreams/{name}/tls-test` | admin, developer | new; one handshake to the backend with the definition's `tls`, result as a closed enum |

Data model: two additive defaulted columns on the shipped `certificates` table (`usage`, `role`)
with a guarded per-dialect `ALTER`; one new table `gw_gateway_identity`. No other TOML besides the
header block above.

## Guarantees the tests defend

- Absent, invalid, unpopulated or unmatched certificate → deny. `nil` never means "not required".
- Every certificate rejection returns one uniform 401 body; the cause goes to telemetry only.
- Client-CA trust and upstream trust are built from separate `usage` filters and asserted disjoint.
- `X-Forwarded-Client-Cert` reaches a backend only on routes whose chain has `mtls-auth`; every other
  route strips it. The relayed-certificate header follows the same rule.
- A dangling reference (`accept` naming a missing or relay or `upstream` entry; `tls.identity`
  missing) is refused at deploy. Deleting an entry an API names is refused with 409.
- Private keys: never in xDS `inline_bytes`, never in a read response, config dump or log.

Full spec: `gateway/spec/impls/4-mtls/spec.md` on branch `mtls`.
