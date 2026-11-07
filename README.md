# terraform-provider-nebula

An OpenTofu/Terraform provider that issues [Nebula](https://github.com/slackhq/nebula) certificates
with a CA private key that **never leaves OpenBao or HashiCorp Vault**.

The CA key is an `ed25519` key in the [transit secrets engine](https://openbao.org/docs/secrets/transit/),
created with `exportable=false`. The provider reads the key's public half, builds certificates with
Nebula's own `cert` package, and asks transit to sign them. It checks every returned signature
against the public key before using it.

Why: with `nebula-cert`, the CA key is a file that someone has to keep somewhere, and every machine
that signs certificates has a copy. Here, signing is an OpenBao/Vault permission. The key cannot be
read or exported, signing is audited, and taking the permission away is enough to stop issuance.

> This project is not affiliated with or endorsed by Slack or Defined Networking.

## Resources

| Name | What it does | Talks to OpenBao |
|---|---|---|
| `nebula_ca` | Self-signed CA certificate for a pinned transit key version | on create |
| `nebula_certificate` | Host certificate signed by that CA | on create |
| `nebula_keypair` | X25519 host key pair, like `nebula-cert keygen` | never |
| `nebula_ca_bundle` (data source) | Checked, de-duplicated CA bundle for `pki.ca` | never |

Certificates are pure state: refresh and destroy never contact OpenBao/Vault. Every input change
replaces a certificate (except `early_renewal_hours`). With `early_renewal_hours`, a certificate is
replaced on the first plan inside the renewal window, the same way `hashicorp/tls` does it.

Both certificate format versions work: `version = 2` (default, needs Nebula 1.10+) and `version = 1`.

See [docs/](docs/) for every attribute.

## Setup in OpenBao/Vault

```sh
bao secrets enable transit
bao write -f transit/keys/nebula-ca type=ed25519 exportable=false
```

The provider needs exactly this policy (adjust mount and key name):

```hcl
# policy.hcl
path "transit/keys/nebula-ca" { capabilities = ["read"] }    # public key
path "transit/sign/nebula-ca" { capabilities = ["update"] }  # signing
```

```sh
bao policy write nebula-signer policy.hcl
export BAO_ADDR=https://bao.example.com:8200
export BAO_TOKEN=$(bao token create -policy=nebula-signer -field=token)
```

The provider reads `BAO_ADDR`, `BAO_TOKEN`, `BAO_NAMESPACE`, `BAO_CACERT` and `BAO_SKIP_VERIFY`, and
falls back to the `VAULT_*` names. Everything can also be set in the provider block.

## Example

A CA, a lighthouse and two nodes, with complete Nebula configs.
The same file is in [examples/complete/main.tf](examples/complete/main.tf).

```hcl
terraform {
  required_providers {
    nebula = {
      source = "awapf/nebula"
    }
  }
}

provider "nebula" {}

locals {
  lighthouse_ip = "10.99.0.1"
  hosts = {
    lighthouse = { ip = "${local.lighthouse_ip}/16", groups = ["lighthouse"] }
    node-a     = { ip = "10.99.0.2/16", groups = ["nodes"] }
    node-b     = { ip = "10.99.0.3/16", groups = ["nodes"] }
  }
}

resource "nebula_ca" "mesh" {
  key_name            = "nebula-ca"
  key_version         = 1
  name                = "example mesh CA"
  groups              = ["lighthouse", "nodes"]
  networks            = ["10.99.0.0/16"]
  duration            = "17520h"
  early_renewal_hours = 1440
}

# Everything every host trusts. During a CA rotation, list both CAs here.
data "nebula_ca_bundle" "trusted" {
  ca_certs_pem = [nebula_ca.mesh.cert_pem]
}

resource "nebula_keypair" "host" {
  for_each = local.hosts
}

resource "nebula_certificate" "host" {
  for_each = local.hosts

  ca_cert_pem    = nebula_ca.mesh.cert_pem
  key_name       = nebula_ca.mesh.key_name
  key_version    = nebula_ca.mesh.key_version
  public_key_pem = nebula_keypair.host[each.key].public_key_pem

  name                = each.key
  networks            = [each.value.ip]
  groups              = each.value.groups
  duration            = "2160h"
  early_renewal_hours = 360
}
```

### Feeding Nebula

Nebula accepts PEM content inline in `pki.ca`, `pki.cert` and `pki.key`, so a whole config can be
rendered in one place:

```hcl
locals {
  nebula_config = {
    for name, h in local.hosts : name => yamlencode({
      pki = {
        ca   = data.nebula_ca_bundle.trusted.bundle_pem
        cert = nebula_certificate.host[name].cert_pem
        key  = nebula_keypair.host[name].private_key_pem
      }
      static_host_map = { (local.lighthouse_ip) = ["lighthouse.example.com:4242"] }
      lighthouse = {
        am_lighthouse = name == "lighthouse"
        hosts         = name == "lighthouse" ? [] : [local.lighthouse_ip]
      }
      listen   = { host = "0.0.0.0", port = 4242 }
      tun      = { dev = "nebula1" }
      firewall = {
        outbound = [{ port = "any", proto = "any", host = "any" }]
        inbound  = [{ port = "any", proto = "icmp", host = "any" }]
      }
    })
  }
}
```

Deliver it however your hosts are configured: a cloud-init `write_files` entry, a Kubernetes Secret for
a Nebula DaemonSet, or a Talos machine config patch. Talos can write files under `/var`, where an
extension service or a DaemonSet can pick them up:

```hcl
locals {
  talos_patch = {
    for name, cfg in local.nebula_config : name => yamlencode({
      machine = {
        files = [{
          path        = "/var/etc/nebula/config.yml"
          permissions = 384 # 0600
          op          = "create"
          content     = cfg
        }]
      }
    })
  }
}
```

Pass `local.talos_patch[name]` to `config_patches` of the Talos provider's machine configuration.

To keep host private keys out of the state entirely, run `nebula-cert keygen` on the host and pass
only the public key to `nebula_certificate.public_key_pem`.

## Security notes

- **Private keys in state.** `nebula_keypair.private_key_pem` is marked sensitive, but it is stored in
  the state in plain text, like every Terraform secret. Encrypt the state (OpenTofu
  [state encryption](https://opentofu.org/docs/language/state/encryption/) or an encrypted backend with
  tight access), or generate keys on the hosts. The CA private key is never in the state.
- **Who can sign.** Anyone with `update` on `transit/sign/<key>` can mint certificates for the mesh, with
  any name, group or address the CA allows. Treat that permission like the CA key. Restrict the CA with
  `groups` and `networks` so that a misuse is bounded.
- **Signatures are verified.** Each transit signature is checked with Ed25519 against the pinned key
  version's public key, and every host certificate is verified against its CA before it is stored.
- **Pinned key versions.** `key_version` is required. A `transit/keys/<key>/rotate` does not change
  anything until you raise `key_version`, and then it creates a new CA. Do not trim old key versions
  (`min_available_version`) while their CA is still trusted and you may need to sign with it.
- **Exportable keys** produce a warning: an exportable key defeats the point of this provider.
- **Validity.** A host certificate never outlives its CA. A `duration` that would is capped to the
  CA's `not_after`, the way `nebula-cert sign` does it; an explicit `not_after` after the CA's is an
  error. Rotate the CA well before it expires, or host certificates will be capped and renewed with it.

## CA rotation

A Nebula host only accepts peers whose certificate is signed by a CA in its `pki.ca`. Rotation therefore
takes three rounds, and every host must have applied a round before the next one starts:

1. **Trust both CAs.** Create the new CA, either from a new transit key or from a new version of the
   same key (`bao write -f transit/keys/nebula-ca/rotate`, then a second `nebula_ca` with `key_version = 2`).
   Add it to the bundle and roll out the configs:

   ```hcl
   data "nebula_ca_bundle" "trusted" {
     ca_certs_pem = [nebula_ca.mesh.cert_pem, nebula_ca.mesh_next.cert_pem]
   }
   ```

2. **Move hosts to the new CA.** Point `nebula_certificate` at `nebula_ca.mesh_next` (`ca_cert_pem`,
   `key_name`, `key_version`). The certificates are replaced; roll out again. Hosts with old and new
   certificates can talk to each other because everyone trusts both CAs.

3. **Drop the old CA.** Remove `nebula_ca.mesh` from the bundle, roll out, then delete the old
   `nebula_ca` resource.

The acceptance test `TestAccCABundle_rotation` walks through these rounds.

## Development

Requirements: Go (see `go.mod`), and for acceptance tests the `bao` binary and `tofu` or `terraform`.

```sh
go build ./...
go vet ./...
go test ./...                          # unit tests

# Acceptance tests start a throwaway `bao server -dev` on 127.0.0.1 and skip
# when `bao` is not on PATH. They never use BAO_ADDR/VAULT_ADDR from your shell.
TF_ACC=1 go test -v ./internal/provider/
TF_ACC=1 TF_ACC_TERRAFORM_PATH=$(command -v tofu) TF_ACC_PROVIDER_HOST=registry.opentofu.org \
  go test -v ./internal/provider/

go generate ./...                      # regenerate docs/ (needs terraform on PATH)
```

## License

MIT, see [LICENSE](LICENSE).
