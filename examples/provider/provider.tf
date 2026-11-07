terraform {
  required_providers {
    nebula = {
      source = "awapf/nebula"
    }
  }
}

# Address and token usually come from BAO_ADDR/BAO_TOKEN (or VAULT_ADDR/VAULT_TOKEN).
provider "nebula" {
  address       = "https://bao.example.com:8200"
  transit_mount = "transit"
}
