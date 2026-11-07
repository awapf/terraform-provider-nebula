# The transit key must exist: bao write transit/keys/nebula-ca type=ed25519 exportable=false
resource "nebula_ca" "mesh" {
  key_name    = "nebula-ca"
  key_version = 1

  name     = "example mesh CA"
  groups   = ["lighthouse", "servers", "laptops"]
  networks = ["10.99.0.0/16"]
  duration = "17520h" # two years

  # Plan a new CA 60 days before expiry.
  early_renewal_hours = 1440
}
