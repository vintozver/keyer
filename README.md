# keyer
Embedded premises access controller using MIFARE Classic 1K EV1 cards.
The companion [keyer_web](https://github.com/vintozver/keyer_web) service
provides the administration UI and control endpoint for user and card configuration.

## Configuration

Install the package and its dependencies with `python -m pip install .`.
Replace the old INI-style `config.txt` with `config.yaml` in the application's
working directory:

```yaml
title1: "Premises"
title2: "Access control"
validate_sig_mifare_classic_ev1: false
local_storage: false
unit_id: "0123456789abcdef01234567"
kid: "primary"
control:
  endpoint: control.example.com
  certificate: /etc/keyer/unit.crt
  privatekey: /etc/keyer/unit.key
  algorithm: RS256
```

Move the old `DEFAULT` settings to the YAML root; keep the `control` settings
nested under `control`. Use YAML booleans (`true`/`false`), not quoted strings.
Both boolean options default to `false`; `algorithm` defaults to `RS256`.
The endpoint is a hostname; configuration is fetched from `https://<endpoint>/config`.
Certificate and private-key paths refer to PEM files and, when relative, are
resolved from the working directory. The certificate and corresponding private
key are also used for the existing TLS client authentication. Server TLS
certificates must be trusted by the system CA store.

Provision the unit in keyer_web, set `unit_id` to its 24-character hexadecimal
ObjectId, and set `kid` to an id in that unit's keyset. Register the certificate
or its public key there; keep the private key only on this controller with
restricted file permissions. Never commit deployment configuration or private keys.

Outbound requests use PyJWT to sign a fresh bearer token with protected
`unit_id`, `kid`, and timezone-aware ISO 8601 `dt` headers and an empty object
payload. Keep the controller clock synchronized: keyer_web accepts timestamps
within 300 seconds of its clock. The configured algorithm must match the key;
supported algorithms are RS256/384/512, PS256/384/512, ES256/384/512, and EdDSA.
Unsigned and HMAC tokens are not supported. YAML is loaded with PyYAML's safe loader.
