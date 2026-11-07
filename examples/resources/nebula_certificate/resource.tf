resource "nebula_certificate" "lighthouse" {
  ca_cert_pem = nebula_ca.mesh.cert_pem
  key_name    = nebula_ca.mesh.key_name
  key_version = nebula_ca.mesh.key_version

  # From nebula_keypair, or from `nebula-cert keygen` run on the host.
  public_key_pem = nebula_keypair.lighthouse.public_key_pem

  name     = "lighthouse-1"
  networks = ["10.99.0.1/16"]
  groups   = ["lighthouse"]
  duration = "720h"

  # Replace the certificate when less than 10 days are left.
  early_renewal_hours = 240
}
