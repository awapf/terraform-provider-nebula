# A small mesh: one CA in transit, a lighthouse and two nodes.
#
# Prerequisites (once, as an admin):
#   bao secrets enable transit
#   bao write -f transit/keys/nebula-ca type=ed25519 exportable=false
#   bao policy write nebula-signer policy.hcl
#   export BAO_ADDR=... BAO_TOKEN=$(bao token create -policy=nebula-signer -field=token)

terraform {
  required_providers {
    nebula = {
      source = "awapf/nebula"
    }
  }
}

provider "nebula" {}

variable "transit_key" {
  type    = string
  default = "nebula-ca"
}

locals {
  lighthouse_ip = "10.99.0.1"
  hosts = {
    lighthouse = { ip = "${local.lighthouse_ip}/16", groups = ["lighthouse"] }
    node-a     = { ip = "10.99.0.2/16", groups = ["nodes"] }
    node-b     = { ip = "10.99.0.3/16", groups = ["nodes"] }
  }
}

resource "nebula_ca" "mesh" {
  key_name            = var.transit_key
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

# Private keys land in the state. Encrypt it, or generate keys on the hosts
# and pass in only their public keys.
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

# A complete Nebula config per host. Nebula accepts the PEM content inline
# in pki.ca, pki.cert and pki.key.
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
      listen = { host = "0.0.0.0", port = 4242 }
      tun    = { dev = "nebula1" }
      firewall = {
        outbound = [{ port = "any", proto = "any", host = "any" }]
        inbound  = [{ port = "any", proto = "icmp", host = "any" }]
      }
    })
  }
}

# Example: hand the config to a Talos node as a machine config patch. Talos
# can write files under /var; whatever runs Nebula on the node (an extension
# service or a DaemonSet) reads it from there.
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

output "ca_fingerprint" {
  value = nebula_ca.mesh.fingerprint
}

output "nebula_config" {
  value     = local.nebula_config
  sensitive = true
}

output "talos_patch" {
  value     = local.talos_patch
  sensitive = true
}
