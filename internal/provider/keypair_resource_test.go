package provider

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/slackhq/nebula/cert"
)

func checkKeypair(res string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		privPEM, err := attr(s, res, "private_key_pem")
		if err != nil {
			return err
		}
		pubPEM, err := attr(s, res, "public_key_pem")
		if err != nil {
			return err
		}
		priv, _, curve, err := cert.UnmarshalPrivateKeyFromPEM([]byte(privPEM))
		if err != nil || curve != cert.Curve_CURVE25519 {
			return fmt.Errorf("private key: curve %v: %w", curve, err)
		}
		pub, _, curve, err := cert.UnmarshalPublicKeyFromPEM([]byte(pubPEM))
		if err != nil || curve != cert.Curve_CURVE25519 {
			return fmt.Errorf("public key: curve %v: %w", curve, err)
		}
		k, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return err
		}
		if !bytes.Equal(k.PublicKey().Bytes(), pub) {
			return fmt.Errorf("public key does not belong to the private key")
		}
		return nil
	}
}

// The keypair needs no OpenBao at all, so it runs without the dev server
// (TF_ACC is still required by resource.Test).
func TestAccKeypair(t *testing.T) {
	cfg := func(keeper string) string {
		return fmt.Sprintf(`
resource "nebula_keypair" "test" {
  keepers = { rotation = %q }
}`, keeper)
	}
	var first string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("1"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectSensitiveValue("nebula_keypair.test", tfjsonpath.New("private_key_pem")),
				}},
				Check: resource.ComposeTestCheckFunc(
					checkKeypair("nebula_keypair.test"),
					resource.TestCheckResourceAttrWith("nebula_keypair.test", "public_key_pem", func(v string) error { first = v; return nil }),
				),
			},
			{
				Config: cfg("2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("nebula_keypair.test", plancheck.ResourceActionReplace),
				}},
				Check: resource.ComposeTestCheckFunc(
					checkKeypair("nebula_keypair.test"),
					resource.TestCheckResourceAttrWith("nebula_keypair.test", "public_key_pem", func(v string) error {
						if v == first {
							return fmt.Errorf("public key unchanged after keepers change")
						}
						return nil
					}),
				),
			},
		},
	})
}
