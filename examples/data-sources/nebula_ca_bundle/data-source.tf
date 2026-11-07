# Trust the current and the next CA while rotating.
data "nebula_ca_bundle" "trusted" {
  ca_certs_pem = [
    nebula_ca.current.cert_pem,
    nebula_ca.next.cert_pem,
  ]
}

# Use data.nebula_ca_bundle.trusted.bundle_pem as Nebula's pki.ca.
