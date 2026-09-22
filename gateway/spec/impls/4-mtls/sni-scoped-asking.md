# SNI-scoped certificate requests on the shared listener

**Status:** Options paper for open question Q-M in [`spec.md`](./spec.md) §10. Nothing here is decided.
**Scope:** How to stop the shared HTTPS listener asking *every* connection for a client certificate once one mTLS API exists, without a second port.

---

## 1. The problem

Under D2 the shared HTTPS listener requests a client certificate on every connection while any deployed
API attaches `mtls-auth`. Asking happens once per connection, in the TLS handshake, before any HTTP
request exists, and HTTP/2 forbids asking again later (RFC 8740). So on one listener the choice is
binary: ask everyone or ask nobody.

The cost lands on browser users of **non-mTLS** APIs. A browser that has any client certificate
installed may show a "select a certificate" dialog when the server asks. The user can dismiss it and
the public API still works, but it is confusing and looks like a bug.

The spec's answer today is D3: an optional **dedicated port** that always requires a certificate, so
the shared port can stop asking. Scheduled for M4.

This paper describes a second shape that keeps one port: ask **only on the hostnames that belong to
mTLS APIs**, decided from the SNI in the `ClientHello`.

## 2. What other products do

| Product | Mechanism | Shared port? |
|---|---|---|
| Kong `mtls-auth` | Keeps "an in-memory map of SNIs from Routes that require client certificates" and requests a certificate only when the `ClientHello` SNI is in the map. Docs: "SNIs must be set for all Routes that mutual TLS authentication uses"; without them Kong asks on every handshake. | yes |
| Envoy Gateway | `ClientTrafficPolicy.tls.clientValidation` attached to a Gateway or one of its listeners; each listener hostname becomes an SNI-matched Envoy filter chain. `optional: true` gives request-not-require. | yes |
| APK 1.3 | Gateway-wide `mtlsAPIsEnabled` TOML flag; when on, the single listener asks on every handshake. No SNI split, no second port. | yes, asks everyone |
| Kubernetes Gateway API (GEP-91) | Per-**port** client validation. Per-route/per-hostname validation is declared a non-goal because of HTTP/2 connection coalescing. | per port |

Kong and Envoy Gateway split by hostname on one port. GEP-91 refused to, for the reason in §4.

## 3. Why our design can do what GEP-91 could not

GEP-91's concern is HTTP/2 **connection coalescing**: a browser with an open connection to
`api.example.com` may reuse it for `partner.example.com` when the server certificate covers both
names. In a design where the SNI filter chain **enforces** mTLS, that reused connection was never
asked and never validated, yet reaches a route that trusts the transport. That is a bypass.

Our design does not enforce at the transport (D1). `mtls-auth` runs on **every request** and fails
closed on a missing certificate. A coalesced connection reaching an mTLS API therefore gets `401`.
The failure mode is an availability nuisance for a partner's browser, never an open door. That is
the property that makes SNI-scoped *asking* safe here while SNI-scoped *enforcement* stays a
non-goal (N4).

## 4. Preconditions

1. **Each mTLS API needs its own hostname.** The SNI is the only routing key that exists at handshake
   time. If an mTLS API sits on the gateway's default hostname (`router.vhosts.main.default`) next to
   public APIs, their `ClientHello` messages are identical and the controller must fall back to asking
   on the whole listener. The operator sets `vhosts.main` on the API and points DNS at the gateway.
2. **No wildcard covering both kinds of API.** A wildcard `vhosts.main` (`*.example.com`) drags public
   hostnames into the asking chain. A wildcard *server certificate* covering both hostnames is what lets
   browsers coalesce (§3). Our listener has a single server certificate today and the operator overlay
   does not support per-SNI certificate selection (`spec.md` §5.4), so in practice the certificate is
   multi-SAN, and a partner using a **browser** against both hostnames may get a spurious `401`.
   Machine clients do not coalesce across hostnames.
3. **The mixed API is not helped.** One API with a public `GET /reports` and an mTLS `POST /payments`
   has one hostname for both, so it is asked or not as a whole. Only D3's dedicated port separates
   those callers.

Violating 1 or 3 means the listener asks more broadly than ideal, which is today's behaviour.
Violating 2 means a browser may see a `401` and retry. None of them is a security condition.

## 5. How the platform supports it today

Verified against `gateway-controller` on the `mtls` branch:

- APIs default to the shared hostname `router.vhosts.main.default`; startup refuses an empty default.
- An API may override it with `vhosts.main`: one hostname, several separated by `;`, or a wildcard.
  The sentinel `_gateway_default_` means "use the default". (`management-openapi.yaml:2973`)
- The translator groups routes by hostname into Envoy **virtual hosts** — HTTP-level routing on
  `:authority` after the handshake (`translator.go:778-861`). Domain patterns are `host` and `host:*`.
- The HTTPS listener has **one filter chain**, **one server certificate**, and no `tls_inspector`;
  SNI is not consulted anywhere (`translator.go:1399-1441`).
- Every HCM references the routes by name over RDS — `SharedRouteConfigName = "shared_route_config"`
  (`translator.go:1268`, `1328-1338`) — so a second filter chain adds **no** route duplication.

### 5.1 API definition with its own hostname

```yaml
kind: http/rest
version: 0.1.0
spec:
  displayName: Partner-Payments-API
  version: v1.0
  context: /payments/$version

  vhosts:
    main: partner.example.com          # this API answers only on this hostname

  policies:
    - name: mtls-auth
      version: v1
      params:
        accept:
          - ca: partner-bank-root
            match: { uriSAN: "urn:partner-bank:payments" }

  upstream:
    main:
      url: https://payments-backend:8443

  operations:
    - method: POST
      path: /transfers
    - method: GET
      path: /transfers/{id}
```

Outside the YAML the operator needs a DNS record for `partner.example.com` at the gateway address and
a server certificate valid for that name (a SAN on the existing certificate).

### 5.2 Envoy config emitted today for that API

One listener, one chain, SNI ignored; the hostname only affects routing.

```yaml
listeners:
  - name: https_listener
    address: { socket_address: { address: 0.0.0.0, port_value: 8443 } }
    filter_chains:
      - # no filter_chain_match — every connection lands here regardless of SNI
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
            common_tls_context:
              alpn_protocols: [h2, http/1.1]
              tls_certificates:
                - certificate_chain: { inline_bytes: <gateway cert> }
                  private_key:       { inline_bytes: <gateway key> }   # D8 moves this to SDS
              # no validation_context today -> clients are never asked for a certificate
        filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              rds: { route_config_name: shared_route_config, config_source: { ads: {} } }
              http_filters: [ ext_proc -> policy engine, router ]

route_config:
  name: shared_route_config
  virtual_hosts:
    - name: api.wso2.com                      # the gateway default hostname
      domains: ["api.wso2.com", "api.wso2.com:*"]
      routes: [ /weather/v1.0/... -> weather cluster ]
    - name: partner.example.com               # from the API's vhosts.main
      domains: ["partner.example.com", "partner.example.com:*"]
      routes: [ /payments/v1.0/transfers ... -> payments cluster ]
    - name: "*"                               # catch-all, always present
      domains: ["*"]
      routes: [ no-api-found 404, gateway health routes ]
```

## 6. The proposed shape

**Rule.** If **every** API attaching `mtls-auth` has a non-default, non-wildcard `vhosts.main`, the
controller emits two filter chains on the existing HTTPS listener: one matched on those hostnames that
requests a certificate, and a default chain that never asks. Otherwise it emits one asking chain for
the whole listener (today's D2 behaviour) and warns at deploy time naming the offending API. Derived
on every snapshot; collapses back to one chain when the last mTLS API is removed.

### 6.1 Target Envoy config

Three APIs: Weather on the default hostname (no mTLS), Payments on `partner.example.com` and
Settlements on `partner-eu.example.com` (both `mtls-auth`).

```yaml
listeners:
  - name: https_listener
    address: { socket_address: { address: 0.0.0.0, port_value: 8443 } }
    listener_filters:
      - name: envoy.filters.listener.tls_inspector      # NEW: reads SNI from the ClientHello so
        typed_config:                                   # filter_chain_match.server_names can work
          "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector

    filter_chains:

      # ---- chain 1: asks for a certificate. Matched only when the SNI is one of the
      #      hostnames of APIs that attach mtls-auth. Derived; rebuilt on every snapshot.
      - name: mtls_asking_chain
        filter_chain_match:
          server_names: ["partner.example.com", "partner-eu.example.com"]
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
            require_client_certificate: false              # D2: request, do not require
            common_tls_context:
              alpn_protocols: [h2, http/1.1]
              tls_certificate_sds_secret_configs:          # D8: same gateway cert, via SDS
                - name: listener_cert
                  sds_config: { ads: {}, resource_api_version: V3 }
              validation_context_sds_secret_config:        # the pool: partner-bank-root + partner-eu-root
                name: downstream_client_ca
                sds_config: { ads: {}, resource_api_version: V3 }
        filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: https
              rds: { route_config_name: shared_route_config, config_source: { ads: {}, resource_api_version: V3, initial_fetch_timeout: 0s } }
              forward_client_cert_details: SANITIZE_SET  # spec §3.1.6
              set_current_client_cert_details: { subject: true, cert: true, chain: true, uri: true, dns: true }
              http_filters:
                - name: envoy.filters.http.ext_proc
                  typed_config:
                    request_attributes:                    # spec §3.1.1
                      - xds.route_name
                      - connection.mtls
                      - connection.peer_certificate
                      - connection.sha256_peer_certificate_digest
                      - connection.subject_peer_certificate
                      - connection.uri_san_peer_certificate
                      - connection.dns_san_peer_certificate
                      - connection.peer_certificate_valid
                      - connection.tls_version
                - name: envoy.filters.http.router

      # ---- chain 2: default. No server_names, so it catches everything else:
      #      api.wso2.com, any unknown SNI, and a ClientHello with no SNI at all.
      - name: default_chain
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
            common_tls_context:
              alpn_protocols: [h2, http/1.1]
              tls_certificate_sds_secret_configs:
                - name: listener_cert
                  sds_config: { ads: {}, resource_api_version: V3 }
              # no validation_context, no require_client_certificate: never asks
        filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              # identical HCM: same rds name, same SANITIZE_SET, same ext_proc attributes.
              # A connection here carries no certificate, so mtls-auth returns 401 if a
              # request on it ever reaches Payments or Settlements.
              rds: { route_config_name: shared_route_config, config_source: { ads: {} } }
              ...
```

The route configuration is **unchanged** from §5.2 plus one more virtual host for
`partner-eu.example.com`. Both chains name `shared_route_config`; Envoy fetches it once over RDS.

SDS secrets referenced:

| Secret | Contents |
|---|---|
| `listener_cert` | the gateway's server certificate and key, valid for all three hostnames |
| `downstream_client_ca` | the pool — `partner-bank-root` and `partner-eu-root`, the union across all mTLS APIs |

### 6.2 Per-connection behaviour

| Client connects with SNI | Chain | Asked for cert | Then |
|---|---|---|---|
| `api.wso2.com` | default | no | Weather serves; a request to Payments on this connection gets `401` |
| `partner.example.com` | asking | yes | Payments checks its `accept`; Settlements on this connection `401`s unless the cert also matches its entry |
| `partner-eu.example.com` | asking | yes | same, for Settlements |
| none, or an unknown name | default | no | catch-all `404` for unknown paths |

Chain selection decides **whether to ask**. Each API's `accept` list decides **whom to accept**. Both
partners' CAs are in the one validation context; Payments still rejects a Settlements certificate
through its own `accept`.

### 6.3 What changes in the controller

- `createListener` emits a `tls_inspector` listener filter and two filter chains when the rule in §6
  holds; one chain otherwise. `server_names` is the set of `vhosts.main` values (all entries of a
  `;` list) of every API attaching `mtls-auth`.
- Both chains share the HCM builder and reference `shared_route_config`; no route changes.
- Deploy-time warning: an mTLS API on the default hostname or a wildcard vhost forces whole-listener
  asking and is named in the `POST /rest-apis` response.
- The single `listener_cert` must be valid for every mTLS hostname; the controller can check the
  certificate's SANs against the derived `server_names` and warn on a miss.

## 7. Options

| | (a) Dedicated port only — D3 as specified | (b) SNI-scoped asking, derived | (c) Both |
|---|---|---|---|
| Removes the browser prompt for | every deployment, once operators publish a second base URL | deployments where mTLS APIs have their own hostnames | all of the above |
| Mixed API (public + mTLS operations) | yes — same API on both listeners | no | yes |
| Operator work | second port/Service/Ingress, second base URL | `vhosts.main` + DNS + SAN on the server cert | either |
| Coalescing exposure | none | spurious `401` for a partner's browser on a multi-SAN cert; never a bypass | as (b) on the shared port |
| Controller work | second listener; operator overlay work (`spec.md` §5.4) | `tls_inspector` + second filter chain + derivation + warning | both |
| Industry precedent | GEP-91 | Kong, Envoy Gateway | — |
| Milestone fit | M4 | small enough for M3; or M4 | M3 (b) + M4 (a) |

## 8. Tests this would add to `spec.md` §8

- **§8.6 translator:** all mTLS APIs on custom hostnames → two chains, `server_names` equals their
  vhosts; one mTLS API on the default hostname → one chain + warning; last mTLS API removed → one
  chain, no validation context, no `tls_inspector`.
- **§8.8 edge:** an HTTP/2 connection opened with SNI `api.wso2.com` carrying a request for a
  `partner.example.com` route (coalescing) → `401`, never `200`.
- **§8.11 input:** `mtls-auth` on an API whose `vhosts.main` is the default or a wildcard → `201`
  **with warning** "whole-listener certificate request".
- **§8.14 ordering:** SNI-scoped gateway + deploy a default-hostname mTLS API → listener falls back to
  one asking chain on the next snapshot, existing connections unaffected; remove it → two chains again.
- **§8.15 request matrix:** new column "public API on default hostname, SNI-scoped": no
  `CertificateRequest` observed in the handshake.

## 9. Recommendation

Option (c), with (b) in M3 because it is a second filter chain derived from data the controller
already holds, and (a) in M4 as specified. If only one is affordable in the first release, (b)
helps more customers sooner than (a) but leaves the mixed-API case open.
