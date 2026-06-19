# vault-warden-secret-engine

[![CI](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml)
[![Release](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/release.yml/badge.svg)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/kalw/vault-warden-secret-engine?sort=semver&logo=github)](https://github.com/kalw/vault-warden-secret-engine/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/kalw/vault-warden-secret-engine?logo=go)](go.mod)

**Platforms** — cross-compiled in CI:

| OS | amd64 | arm64 |
|---|---|---|
| ![linux](https://img.shields.io/badge/linux-FCC624?logo=linux&logoColor=black) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+linux%2Famd64&label=amd64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+linux%2Farm64&label=arm64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) |
| ![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+darwin%2Famd64&label=amd64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+darwin%2Farm64&label=arm64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) |
| ![FreeBSD](https://img.shields.io/badge/FreeBSD-AB2B28?logo=freebsd&logoColor=white) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+freebsd%2Famd64&label=amd64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+freebsd%2Farm64&label=arm64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) |
| ![OpenBSD](https://img.shields.io/badge/OpenBSD-F2CA30?logo=openbsd&logoColor=black) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+openbsd%2Famd64&label=amd64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) | [![](https://img.shields.io/github/actions/workflow/status/kalw/vault-warden-secret-engine/ci.yml?job=Build+openbsd%2Farm64&label=arm64)](https://github.com/kalw/vault-warden-secret-engine/actions/workflows/ci.yml) |



A HashiCorp Vault secrets engine for [Vaultwarden](https://github.com/dani-garcia/vaultwarden/) and compatible self-hosted password manager servers. It authenticates to your Warden server with an API key, derives the vault encryption keys in-process, and surfaces decrypted vault items through Vault's API — so your applications can pull credentials from Warden using the standard Vault client, ACL policies, and lease model.

> **How the crypto works.** Warden-compatible servers encrypt all item data end-to-end before it reaches the server. To read it, the plugin derives the master key from your email + master password (PBKDF2-SHA256 or Argon2id), expands it with HKDF into a 64-byte user symmetric key, and uses that to AES-256-CBC decrypt each cipher field. Organization items are additionally unwrapped via RSA-OAEP. The master password lives in Vault's sealed storage and never leaves the Vault node.

## Install (pre-built binary)

Each release publishes the bare plugin binary for the common Vault server and
developer architectures (`linux`, `darwin`, `freebsd`, `openbsd` × `amd64`,
`arm64`) plus a `checksums.txt`.

1. Download the asset matching your Vault server from the
   [latest release](https://github.com/kalw/vault-warden-secret-engine/releases/latest),
   e.g. `vault-warden-secret-engine_<version>_linux_amd64`, together with
   `checksums.txt`.

2. Verify and install it into Vault's `plugin_directory` under the plugin's
   command name:

   ```bash
   sha256sum --ignore-missing -c checksums.txt
   install -m 0755 vault-warden-secret-engine_<version>_linux_amd64 \
     /etc/vault/plugins/vault-warden-secret-engine
   ```

3. Register it with the catalog and enable it:

   ```bash
   SHASUM=$(sha256sum /etc/vault/plugins/vault-warden-secret-engine | cut -d ' ' -f1)
   vault write sys/plugins/catalog/vault-warden-secret-engine \
     sha_256="$SHASUM" command="vault-warden-secret-engine"
   vault secrets enable -path="warden" -plugin-name="vault-warden-secret-engine" plugin
   ```

### Setup

1. Register the plugin with the catalog:

   ```text
   $ SHASUM=$(shasum -a 256 vault-warden-secret-engine | cut -d " " -f1)
   $ vault write sys/plugins/catalog/vault-warden-secret-engine \
       sha_256="$SHASUM" command="vault-warden-secret-engine"
   Success! Data written to: sys/plugins/catalog/vault-warden-secret-engine
   ```

2. Enable the secrets engine:

   ```text
   $ vault secrets enable -path="warden" -plugin-name="vault-warden-secret-engine" plugin
   Success! Enabled the vault-warden-secret-engine plugin at: warden/
   ```

3. Configure it with your Warden credentials:

   ```text
   $ vault write warden/config \
       url="https://vault.example.com" \
       client_id="user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
       client_secret="<your-api-key-secret>" \
       email="you@example.com" \
       master_password="<your-master-password>"
   Success! Data written to: warden/config
   ```

   The API key (`client_id` + `client_secret`) is generated in Warden under
   **Account Settings → Security → Keys → API Key**. All sensitive fields are stored
   seal-wrapped and never returned in plaintext by `vault read warden/config`.

   | Field | Description |
   | --- | --- |
   | `url` | Base URL of your Warden instance. No trailing slash. |
   | `client_id` | API key client ID (starts with `user.`). |
   | `client_secret` | API key client secret. |
   | `email` | Account email. Used as the PBKDF2/Argon2id salt for key derivation. |
   | `master_password` | Master password. Used to derive the vault encryption key. |

### Usage

Read an item by **UUID** or case-insensitive **name**:

```text
$ vault read warden/items/my-github-login
Key              Value
---              -----
id               a1b2c3d4-e5f6-7890-abcd-ef1234567890
name             My GitHub Login
type             login
username         alice@example.com
password         supersecret
totp             JBSWY3DPEHPK3PXP
uris             [https://github.com]
notes            2FA backup codes: ...
fields           map[recovery_code:abc123]
organization_id  <empty>
folder_id        <empty>
revision_date    2024-06-01T12:00:00.000Z
creation_date    2024-01-15T09:30:00.000Z
```

```text
$ vault read warden/items/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

List all accessible item names:

```text
$ vault list warden/items/
Keys
----
My GitHub Login
Production DB Password
AWS Root Key
AWS Access Key - prod
Stripe API Key
```

#### Item types

All vault cipher types are supported. The returned fields depend on the item type:

| Type | Returned fields |
| --- | --- |
| `login` | `username`, `password`, `totp`, `uris` |
| `secure_note` | `notes` only |
| `card` | `cardholder_name`, `brand`, `number`, `exp_month`, `exp_year`, `code` |
| `identity` | `title`, `first_name`, `last_name`, `address1`, `city`, `country`, `email`, `phone`, and more |

All types also return `notes` and a `fields` map containing any custom fields.

#### Accessing organization items

Organization items are decrypted transparently — no extra configuration is needed. The plugin unwraps the org's AES key using the account's RSA private key, which is itself derived from the master password. Any item the Warden account can see (personal or org) is accessible.

#### Vault ACL

Because item reads are gated on `warden/items/<name>`, Vault's standard policy system controls which identities may read which items:

```hcl
# Allow reading only the production database credential.
path "warden/items/prod-db" {
  capabilities = ["read"]
}

# Allow listing but not reading.
path "warden/items/" {
  capabilities = ["list"]
}
```

## Local Development

### Build and run

```bash
docker build -t vault-warden-plugin .
docker run --cap-add=IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:1234 \
  -p 1234:1234 \
  vault-warden-plugin
```

To build just the plugin binary for the host platform:

```bash
go build -o vault-warden-secret-engine ./cmd/vault-warden-secret-engine
```

### Configure the local vault

In a second terminal window:

```bash
export VAULT_ADDR='http://0.0.0.0:1234'
vault login myroot

CID=$(docker ps -q --filter ancestor=vault-warden-plugin | head -1)
SHASUM=$(docker exec "$CID" sha256sum /vault/plugins/vault-warden-secret-engine | cut -d ' ' -f1)

vault write sys/plugins/catalog/vault-warden-secret-engine \
  sha_256="$SHASUM" command="vault-warden-secret-engine"
vault secrets enable -path="warden" -plugin-name="vault-warden-secret-engine" plugin

vault write warden/config \
  url="$WARDEN_URL" \
  client_id="$WARDEN_CLIENT_ID" \
  client_secret="$WARDEN_CLIENT_SECRET" \
  email="$WARDEN_EMAIL" \
  master_password="$WARDEN_MASTER_PASSWORD"
```

> Tip: `-dev-plugin-dir=/vault/plugins` on the dev server auto-registers plugins
> and skips the manual `sha_256` step — handy for iterating.

### Tests

Unit tests run with no external dependencies:

```bash
go test ./...
```

There is also an acceptance test that reads real items from a live Warden
instance. It is skipped unless `VAULT_ACC` is set:

```bash
export VAULT_ACC=1
export WARDEN_URL="https://vault.example.com"
export WARDEN_CLIENT_ID="user.xxxx"
export WARDEN_CLIENT_SECRET="xxxx"
export WARDEN_EMAIL="you@example.com"
export WARDEN_MASTER_PASSWORD="xxxx"

go test -run TestAcceptance -v
```

### Releases

Releases are automated. Every push to `main` is analyzed with
[Conventional Commits](https://www.conventionalcommits.org/): the next
[semver](https://semver.org/) is derived from the commit types since the last
tag, the tag is created, and [GoReleaser](https://goreleaser.com) publishes the
cross-compiled binaries and `checksums.txt` to a GitHub Release.

| Commit prefix | Version bump |
| --- | --- |
| `fix:` | patch (`x.y.Z`) |
| `feat:` | minor (`x.Y.0`) |
| `feat!:` / `fix!:` / `BREAKING CHANGE:` footer | major (`X.0.0`) |
| `docs:`, `chore:`, `ci:`, `refactor:`, `test:`, `style:` | no release |

You can also cut a release at any specific version by pushing a `v*` tag
directly (e.g. `git tag v1.0.0 && git push origin v1.0.0`) — that builds and
publishes that exact tag. Use this to seed the first release; subsequent bumps
then follow automatically from commit messages.
