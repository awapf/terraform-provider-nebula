# The private key ends up in the state: encrypt the state.
resource "nebula_keypair" "lighthouse" {
  # Change a keeper to generate a new key pair.
  keepers = {
    generation = "1"
  }
}
