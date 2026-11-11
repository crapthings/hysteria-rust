# ACME DNS providers

[Back to README](../README.md)

These are server-side DNS-01 examples. Configure `acme` instead of static
`tls.cert`/`tls.key`. Replace the example domain, email and credentials.

## Cloudflare

Cloudflare DNS-01 is implemented using the same configuration keys as
[upstream Hysteria](https://hysteria.network/docs/advanced/ACME-DNS-Config/).
A minimal server configuration is:

```yaml
listen: :443
acme:
  domains: [edge.example.com]
  email: admin@example.com
  type: dns
  dns:
    name: cloudflare
    config:
      cloudflare_api_token: YOUR_API_TOKEN
auth:
  type: password
  password: REPLACE_WITH_A_STRONG_PASSWORD
```

Use a Cloudflare API token with **Zone / Zone / Read** and **Zone / DNS / Edit**,
scoped to the required zone(s). Do not use the Global API Key. All configured
certificate domains must be accessible with this token. Wildcards are supported
by DNS-01; quote them in YAML, for example `domains: ["*.example.com"]`.
Protect the server configuration because it contains credentials.

The server discovers the DNS zone via SOA, creates a separate
`_acme-challenge` TXT record, waits up to 120 seconds for it to appear through
the system-configured DNS resolver, then asks the CA to validate it. Cleanup
addresses only the created record ID. Certificate issuance and renewal use the
same solver. This implementation does not follow CNAME challenge delegation.
DNS-01 does not open HTTP/TLS challenge listeners on TCP ports 80/443; outbound
DNS, Cloudflare API and ACME access are still required.

```shell
hysteria check server -c server.yaml
hysteria server -c server.yaml
```

`check` validates configuration offline; it does not test token permissions or
request a certificate. Starting the server performs real DNS writes and ACME
requests. Current automated coverage checks configuration and Cloudflare
response handling with a local mock; real issuance requires a domain/token
and is not covered by that test.

The normal Hysteria server address should use a DNS-only A/AAAA record:
Cloudflare's ordinary HTTP proxy does not relay Hysteria's QUIC connection.

## Other providers

Porkbun DNS-01 certificate validation uses the upstream-compatible configuration:

```yaml
acme:
  domains: [example.com]
  email: admin@example.com
  type: dns
  dns:
    name: porkbun
    config:
      porkbun_api_key: YOUR_API_KEY
      porkbun_api_secret_key: YOUR_SECRET_API_KEY
```

Enable API access for the domain in Porkbun. The solver creates a TXT record
and deletes that record by ID after validation.

For Njalla, replace `acme.dns` in the full example above with the following
`dns` section (keep it nested under `acme`):

```yaml
dns:
  name: njalla
  config:
    njalla_api_token: YOUR_API_TOKEN
```

The token must permit creating and removing the domain's ACME TXT records.
Njalla records are also cleaned up by their individual record IDs.

For Namecheap, replace `acme.dns` the same way:

```yaml
dns:
  name: namecheap
  config:
    namecheap_api_key: YOUR_API_KEY
    namecheap_api_user: YOUR_USERNAME
    namecheap_client_ip: YOUR_WHITELISTED_IPV4
    # Optional sandbox endpoint:
    # namecheap_api_endpoint: https://api.sandbox.namecheap.com/xml.response
```

Enable API access and whitelist the server's public IPv4 address in Namecheap.
Namecheap replaces the full host list on each update. The solver preserves
existing records and serializes its own updates, but external DNS edits during
certificate validation can race with that read/modify/write operation.
