# Connect to backends with mutual TLS

Some backends accept a connection only from a caller that presents a certificate they trust. This page shows you how to make the gateway present its own certificate to such a backend, choose which certificates the gateway trusts for it, and rotate the gateway's certificate without redeploying.

This page is for the **platform administrator** who uploads the gateway's identity, and the **AI developer** who names it in an API's upstream definition.

## Before you start

You need two things in the certificate pool:

- **A gateway identity** that the backend trusts: the certificate chain and private key the gateway presents. See [Add a gateway identity](manage-certificates.md#add-a-gateway-identity).
- **The authority that issued the backend's certificate,** if it isn't already in the gateway's trust bundle. See [Add an upstream trust certificate](manage-certificates.md#add-an-upstream-trust-certificate).

The examples on this page use an identity named `gateway-billing` and a trust certificate named `billing-ca`.

## Add a tls block to an upstream definition

Mutual TLS to a backend is configured in a `tls` block on an `upstreamDefinitions` entry. The API's upstream then refers to that definition with `ref`:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: billing-api
spec:
  displayName: Billing API
  version: v1.0
  context: /billing/$version
  upstreamDefinitions:
    - name: billing-backend
      upstreams:
        - url: https://billing.internal.example.com:8443
      tls:
        identity: gateway-billing
        trustedCAs: [billing-ca]
  upstream:
    main:
      ref: billing-backend
  operations:
    - method: GET
      path: /invoices
```

The `tls` block takes three fields:

| Field | Type | Default | What it does |
|---|---|---|---|
| `identity` | string | — | Name of a `usage: identity` entry to present on the connection. Omit it to verify the backend without presenting a certificate. |
| `trustedCAs` | array of strings | The gateway trust bundle | Names of `usage: upstream` entries to trust for this backend, in place of the gateway trust bundle. |
| `verifyHostName` | boolean | `true` | Checks that the backend certificate's name matches the target host. |

An `Agent` takes the same `tls` block on its `upstreamDefinitions` entries. See the [agent configuration reference](../reference/agent-configuration.md).

Deploy the API through the management API:

```bash
curl -X POST http://localhost:9090/api/management/v1/rest-apis \
  -u admin:<password> \
  -H "Content-Type: application/yaml" \
  --data-binary "@billing-api.yaml"
```

## What the gateway checks at deploy time

The gateway refuses a `tls` block that could never work, and returns `400` with the field path of each problem. The messages below show the wording, with this page's names filled in:

| Problem | Message |
|---|---|
| `tls` on an inline upstream | `tls is not supported on an inline upstream; move it to upstreamDefinitions and reference it` |
| A target that isn't `https://` | `tls is configured but this target is http://; every target of a definition with tls must be https://` |
| An identity that doesn't exist | `no gateway identity named gateway-billing exists on this gateway` |
| An identity that names another usage | `billing-ca is not a gateway identity (usage: identity)` |
| A trust certificate that doesn't exist | `no certificate named billing-ca exists on this gateway` |
| A client authority in `trustedCAs` | `partner-a is a client authority (usage: client); trustedCAs takes usage: upstream certificates` |
| An identity in `trustedCAs` | `gateway-billing is a gateway identity (usage: identity); trustedCAs takes usage: upstream certificates` |
| An empty `trustedCAs` | `omit trustedCAs to use the gateway trust bundle, or list at least one certificate` |
| A field other than the three above | `unknown parameter mode`, naming the field |

The `tls` block always goes on an `upstreamDefinitions` entry, never on an inline upstream that sets `url` directly. Every target of a definition that carries `tls` must use `https://`.

Two findings don't block the deploy, and come back as warnings instead:

- **`TLS_VERIFY_HOSTNAME_DISABLED`** when `verifyHostName` is `false`.
- **`TLS_IDENTITY_EXPIRED`** when the named identity's certificate has expired, for example `gateway identity gateway-billing expired on 2027-01-31T00:00:00Z`. Rotate it before the backend starts refusing the gateway.

After a successful deploy, the identity and trust certificates it names can't be deleted until no deployed API names them. See [Delete an entry](manage-certificates.md#delete-an-entry).

## Rotate the identity without redeploying

Replace the identity's certificate and key in place with `PUT /certificates/{id}`. The name doesn't change, so every upstream definition that names it keeps working, and new connections to the backend present the new certificate. See [Rotate a gateway identity](manage-certificates.md#rotate-a-gateway-identity).

Upload the new certificate before the old one expires, and make sure the backend already trusts its issuer.

## Choose what to trust

Without `trustedCAs`, the gateway verifies the backend against its trust bundle: the system certificate authorities plus every `usage: upstream` certificate in the pool.

With `trustedCAs`, the listed certificates replace the gateway trust bundle for that backend only. A backend certificate issued by any other authority is refused, even if the gateway bundle trusts it. Use this when a backend's authority is private to that backend, or when you want to be sure a connection reaches that backend and no other.

If the gateway has server certificate verification turned off with `router.upstream.tls.disable_ssl_verification`, a `tls` block that sets `trustedCAs` or `verifyHostName` can't be enforced, and the deploy is refused with `per-upstream trust cannot be enforced while router.upstream.tls.disable_ssl_verification is on`.

## Hostname verification

By default the gateway checks that the backend certificate's SAN matches the host in the target URL, and refuses the connection otherwise. Set `verifyHostName: false` only when the backend's certificate can't carry the name you reach it by, for example an internal address. The chain is still verified, but any certificate the trusted authorities issued is accepted for that backend. The deploy response carries a `TLS_VERIFY_HOSTNAME_DISABLED` warning while it's off.

## Connections to the backend

A definition with a `tls` block gets its own connection pool. Connections that present one identity are never reused for a definition that presents another, or none, so each backend sees only the identity its definition names. That holds even when two APIs call the same backend with different identities.

## When the connection fails

If the TLS handshake with the backend fails, the caller receives an ordinary `503`, the same as for any backend that can't be reached. The response doesn't say why. Common causes are a backend that doesn't trust the gateway's identity, a backend certificate outside `trustedCAs`, and a host name mismatch.

The router's access log records the reason. In the JSON access log format it's in the `upTlsFail` field.

## Related topics

- [Manage certificates](manage-certificates.md) — upload, rotate, and delete the identities and trust certificates this page names.
- [Authenticate clients with certificates](authenticate-clients-with-certificates.md) — the certificates callers present to the gateway, which is a separate concern.
- [Authenticate backends](https://github.com/wso2/docs-api-platform/blob/main/en/docs/ai-gateway/next/authenticate-backends.md) — credentials such as API keys that the gateway sends to a backend inside the request.
