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
control:
  unit_id: "0123456789abcdef01234567"
  kid: "primary"
  endpoint: control.example.com
  certificate: /etc/keyer/unit.crt
  privatekey: /etc/keyer/unit.key
```

Move the old `DEFAULT` settings to the YAML root; keep the `control` settings
nested under `control`. Use YAML booleans (`true`/`false`), not quoted strings.
Both boolean options default to `false`.
The endpoint is a hostname; configuration is fetched from `https://<endpoint>/config`.
Certificate and private-key paths refer to PEM files and, when relative, are
resolved from the working directory. The certificate and corresponding private
key are also used for the existing TLS client authentication. Server TLS
certificates must be trusted by the system CA store.

Provision the unit in keyer_web, set `control.unit_id` to its 24-character hexadecimal
ObjectId, and set `control.kid` to an id in that unit's keyset. Register the certificate
or its public key there; keep the private key only on this controller with
restricted file permissions. Never commit deployment configuration or private keys.

Outbound requests use PyJWT to sign a fresh bearer token with protected
`unit_id`, `kid`, and timezone-aware ISO 8601 `dt` headers and an empty object
payload. Keep the controller clock synchronized: keyer_web accepts timestamps
within 300 seconds of its clock. The signing algorithm is derived from the
certificate's public key, not its issuer's signature algorithm: RSA uses RS256;
EC P-256/P-384/P-521 use ES256/ES384/ES512; Ed25519/Ed448 use EdDSA.
Other public key types and EC curves are rejected. No algorithm setting is needed.
Unsigned and HMAC tokens are not supported. YAML is loaded with PyYAML's safe loader.

## Card-event logging

In remote mode (`local_storage: false`), the unit queues `card_tap`,
`card_personalize`, and `card_format` events in memory and uploads to
`https://<control.endpoint>/log` every five seconds, independently of configuration
refreshes. Taps with a readable card UUID include denied and unknown cards, once
per physical presentation; personalization and formatting are logged only on
success. A tap without a readable, valid UUID is denied and reported locally to
stderr, not uploaded with a fabricated identifier. The controller resolves user
identity from issued/revoked cards; the unit sends no email, user ID, or name.
Remote unlocks and revocations are logged only by the controller.

The request body is a top-level JSON array. Each entry contains exactly `oid`
(event ObjectId), `event` (event type), and `card_id` (card UUID):

```json
[
  {
    "oid": "6aefe9c80000000000000001",
    "event": "card_tap",
    "card_id": "12345678-1234-5678-1234-567812345678"
  }
]
```

Each request uses the same validated HTTPS, client certificate and fresh signed
bearer JWT as `/config`. Batches contain at most 1000 events and 1 MiB of JSON.
Event ObjectIds, types, and card UUIDs never change on retry. Only HTTP 200 with
an exact set of accepted ObjectIds removes a batch; all other responses,
timeouts, or malformed acknowledgements retain it unchanged. Retries back off
from five seconds to at most 60 seconds, even while configuration is unavailable.
HTTP 400/409 errors are printed to stderr for operator investigation; a rejected
prefix blocks later events, rather than discarding or rewriting history.

The queue holds at most 10,000 events. Overflow prints an error and raises
`queue.Full` to the caller (stopping dispatch rather than silently dropping logs).
Shutdown attempts to drain the queue within five seconds, then reports pending
events. **Restart or power loss loses pending events**: this is not durable
storage; disk-backed buffering is a separate reliability improvement.
Local-file mode deliberately does not buffer or upload events: it does not load
controller signing credentials or run an uploader.
Use remote mode for controller log coverage.

Deploy compatible controller and firmware changes together before relying on
card-event coverage. The controller's MongoDB must be a replica set or sharded
cluster to support atomic transactional batches; standalone storage returns 503.

Hardware-independent tests use the standard library:
`python -m unittest discover -s tests -v`.
