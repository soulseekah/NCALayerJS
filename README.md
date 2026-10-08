# NCALayerJS

A local signing server compatible with NCALayer, written in plain
JavaScript. Sites like egov.kz and nca.pki.gov.kz talk to it the same way
they talk to NCALayer: over `wss://127.0.0.1:13579`. Every signature has to
be approved in the terminal.

Supports Kazakh GOST 2015 512 keys in PKCS#12 (`.p12`) files, and the
`kz.gov.pki.knca.basics` `sign` method with the `xml` and `cms` formats.
CMS can include a timestamp from the NCA RK timestamp server.

## Requirements

- Node.js 24
- OpenSSL, to create the local TLS certificate

## Setup

Install the dependencies:

```
npm ci
```

Create the TLS certificate for `127.0.0.1`:

```
scripts/make-local-ca.sh
```

This writes `ca.pem`, `server.pem` and `server.key` to
`~/.config/ncalayerjs/tls`. The CA can only issue certificates for
`127.0.0.1` and `localhost`, and its private key is deleted right after
use. Import `ca.pem` into your browser once:

- Firefox: Settings, Certificates, View Certificates, Authorities, Import.
  Tick "Trust this CA to identify websites" only.
- Chrome on Linux:
  `certutil -d sql:$HOME/.pki/nssdb -A -t 'C,,' -n 'NCALayerJS local CA' -i ~/.config/ncalayerjs/tls/ca.pem`

Run the script again when the certificate expires (after 397 days) and
import the new CA.

## Usage

```
node bin/ncalayerjs.mjs --key /path/to/key.p12
```

Enter the key password. The key stays unlocked until you stop the server
with Ctrl+C. Then log in or sign on the site as you would with NCALayer.
Each request is shown in the terminal and needs a `y` to be signed.

Options:

- `-y`, `--yes`: approve every request without asking. Any site you open
  can then get signatures from your key, so use it with care.
- `--log-requests`: log the structure of each request, with long values
  shortened.
- `--tls <dir>`: TLS files directory, default `~/.config/ncalayerjs/tls`.
- `--port <n>`: port, default `13579`.

Chrome may ask whether a site may "access other apps and services on this
device". Allow it for the sites you want to sign on.

## Command line signing

```
NCA_PASSWORD=... node scripts/sign-cms.mjs key.p12 input.txt output.cms [--detached] [--tsp]
```

## Tests

```
npm test
```

Two tests use a real Kalkan signature as a test vector. It is not
distributed with the code; download it first to run them:

```
test/fixtures/fetch-kalkan-manifest.sh
```

## Not supported yet

- The `raw` format, `digested` CMS and co-signing an existing CMS
- The older `kz.gov.pki.knca.commonUtils` module
- Hardware tokens and ID cards; only `.p12` files
- Certificate chain and revocation checks when verifying
