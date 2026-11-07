package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// rotationConfig has two CAs on two transit keys, a host certificate from
// each, and a bundle of the CAs listed in `bundle`.
func rotationConfig(key1, key2, nodeACA, bundle string) string {
	return fmt.Sprintf(`
resource "nebula_ca" "ca1" {
  key_name    = %[1]q
  key_version = 1
  name        = "CA 1"
  duration    = "48h"
}

resource "nebula_ca" "ca2" {
  key_name    = %[2]q
  key_version = 1
  name        = "CA 2"
  duration    = "96h"
}

locals {
  cas = {
    ca1 = { cert = nebula_ca.ca1.cert_pem, key = nebula_ca.ca1.key_name }
    ca2 = { cert = nebula_ca.ca2.cert_pem, key = nebula_ca.ca2.key_name }
  }
}

resource "nebula_keypair" "a" {}
resource "nebula_keypair" "b" {}

resource "nebula_certificate" "a" {
  ca_cert_pem    = local.cas[%[3]q].cert
  key_name       = local.cas[%[3]q].key
  key_version    = 1
  public_key_pem = nebula_keypair.a.public_key_pem
  name           = "node-a"
  networks       = ["10.99.0.2/24"]
}

resource "nebula_certificate" "b" {
  ca_cert_pem    = nebula_ca.ca2.cert_pem
  key_name       = %[2]q
  key_version    = 1
  public_key_pem = nebula_keypair.b.public_key_pem
  name           = "node-b"
  networks       = ["10.99.0.3/24"]
}

data "nebula_ca_bundle" "all" {
  ca_certs_pem = [%[4]s]
}
`, key1, key2, nodeACA, bundle)
}

func checkBundleCount(n int) func(*terraform.State) error {
	return func(s *terraform.State) error {
		p, err := attr(s, "data.nebula_ca_bundle.all", "bundle_pem")
		if err != nil {
			return err
		}
		if got := strings.Count(p, "-----BEGIN NEBULA CERTIFICATE"); got != n {
			return fmt.Errorf("bundle has %d certificates, want %d", got, n)
		}
		return nil
	}
}

func TestAccCABundle_twoCAs(t *testing.T) {
	key1, key2 := accTransitKey(t), accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// ca1 twice: duplicates are dropped.
			Config: rotationConfig(key1, key2, "ca1", "nebula_ca.ca1.cert_pem, nebula_ca.ca2.cert_pem, nebula_ca.ca1.cert_pem"),
			Check: resource.ComposeAggregateTestCheckFunc(
				checkBundleCount(2),
				resource.TestCheckResourceAttr("data.nebula_ca_bundle.all", "fingerprints.#", "2"),
				resource.TestCheckResourceAttrPair("data.nebula_ca_bundle.all", "fingerprints.0", "nebula_ca.ca1", "fingerprint"),
				resource.TestCheckResourceAttrPair("data.nebula_ca_bundle.all", "fingerprints.1", "nebula_ca.ca2", "fingerprint"),
				checkVerifies("data.nebula_ca_bundle.all", "bundle_pem", "nebula_certificate.a", "nebula_certificate.b"),
				checkVerifies("nebula_ca.ca1", "cert_pem", "nebula_certificate.a"),
				checkNotVerifies("nebula_ca.ca1", "cert_pem", "nebula_certificate.b"),
				checkNotVerifies("nebula_ca.ca2", "cert_pem", "nebula_certificate.a"),
			),
		}},
	})
}

// TestAccCABundle_rotation walks the three rounds from the README: trust
// both CAs, move hosts to the new CA, drop the old CA.
func TestAccCABundle_rotation(t *testing.T) {
	key1, key2 := accTransitKey(t), accTransitKey(t)
	both := "nebula_ca.ca1.cert_pem, nebula_ca.ca2.cert_pem"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: rotationConfig(key1, key2, "ca1", "nebula_ca.ca1.cert_pem"),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkBundleCount(1),
					checkVerifies("data.nebula_ca_bundle.all", "bundle_pem", "nebula_certificate.a"),
				),
			},
			{
				// Round 1: every host trusts both CAs.
				Config: rotationConfig(key1, key2, "ca1", both),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkBundleCount(2),
					checkVerifies("data.nebula_ca_bundle.all", "bundle_pem", "nebula_certificate.a", "nebula_certificate.b"),
				),
			},
			{
				// Round 2: host certificates move to the new CA.
				Config: rotationConfig(key1, key2, "ca2", both),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("nebula_certificate.a", plancheck.ResourceActionReplace),
				}},
				Check: checkVerifies("data.nebula_ca_bundle.all", "bundle_pem", "nebula_certificate.a", "nebula_certificate.b"),
			},
			{
				// Round 3: the old CA leaves the bundle.
				Config: rotationConfig(key1, key2, "ca2", "nebula_ca.ca2.cert_pem"),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkBundleCount(1),
					checkVerifies("data.nebula_ca_bundle.all", "bundle_pem", "nebula_certificate.a", "nebula_certificate.b"),
				),
			},
		},
	})
}

func TestAccCABundle_rejectsHostCert(t *testing.T) {
	key1, key2 := accTransitKey(t), accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      rotationConfig(key1, key2, "ca1", "nebula_ca.ca1.cert_pem, nebula_certificate.a.cert_pem"),
			ExpectError: regexp.MustCompile(`not a CA certificate`),
		}},
	})
}
