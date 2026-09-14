# Additional ACME DNS providers

[Back to README](../README.md)

These are server-side DNS-01 examples. Configure `acme` instead of static
`tls.cert`/`tls.key`. Replace the example domain, email and credentials.

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
