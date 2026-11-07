package provider

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/slackhq/nebula/cert"
)

// hostConfig renders a CA, a keypair and a host certificate.
type hostConfig struct {
	Key        string
	KeyVersion int // for the certificate; the CA always uses 1
	CAName     string
	CAVersion  int
	CAExtra    string
	Version    int
	Keeper     string
	Extra      string // extra attributes for nebula_certificate
}

func (c hostConfig) String() string {
	if c.KeyVersion == 0 {
		c.KeyVersion = 1
	}
	if c.CAName == "" {
		c.CAName = "acc CA"
	}
	if c.CAVersion == 0 {
		c.CAVersion = 2
	}
	if c.Version == 0 {
		c.Version = 2
	}
	return fmt.Sprintf(`
resource "nebula_ca" "ca" {
  key_name    = %[1]q
  key_version = 1
  name        = %[3]q
  version     = %[4]d
  groups      = ["lighthouse", "nodes"]
  networks    = ["10.99.0.0/16"]
  duration    = "48h"
  %[5]s
}

resource "nebula_keypair" "host" {
  keepers = { k = %[7]q }
}

resource "nebula_certificate" "host" {
  ca_cert_pem    = nebula_ca.ca.cert_pem
  key_name       = %[1]q
  key_version    = %[2]d
  public_key_pem = nebula_keypair.host.public_key_pem
  name           = "node-a"
  networks       = ["10.99.0.2/24"]
  groups         = ["nodes"]
  version        = %[6]d
  %[8]s
}
`, c.Key, c.KeyVersion, c.CAName, c.CAVersion, c.CAExtra, c.Version, c.Keeper, c.Extra)
}

// checkHost checks the host certificate matches its key pair and inputs.
func checkHost(res, keypairRes string, version cert.Version) func(*terraform.State) error {
	return func(s *terraform.State) error {
		c, err := certFromState(s, res)
		if err != nil {
			return err
		}
		if c.IsCA() || c.Version() != version || c.Name() != "node-a" {
			return fmt.Errorf("unexpected host cert: %s", c)
		}
		pubPEM, err := attr(s, keypairRes, "public_key_pem")
		if err != nil {
			return err
		}
		pub, _, _, err := cert.UnmarshalPublicKeyFromPEM([]byte(pubPEM))
		if err != nil {
			return err
		}
		if !bytes.Equal(pub, c.PublicKey()) {
			return fmt.Errorf("certificate is not for the key pair's public key")
		}
		if n := c.Networks(); len(n) != 1 || n[0].String() != "10.99.0.2/24" {
			return fmt.Errorf("networks %v", n)
		}
		if g := c.Groups(); len(g) != 1 || g[0] != "nodes" {
			return fmt.Errorf("groups %v", g)
		}
		fp, _ := c.Fingerprint()
		for k, want := range map[string]string{
			"fingerprint": fp,
			"id":          fp,
			"not_before":  formatTime(c.NotBefore()),
			"not_after":   formatTime(c.NotAfter()),
		} {
			if got, err := attr(s, res, k); err != nil || got != want {
				return fmt.Errorf("%s = %q, want %q (%w)", k, got, want, err)
			}
		}
		return nil
	}
}

func TestAccCertificate_v2(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: hostConfig{Key: key, Extra: `duration = "24h"`}.String(),
			Check: resource.ComposeAggregateTestCheckFunc(
				checkHost("nebula_certificate.host", "nebula_keypair.host", cert.Version2),
				checkVerifies("nebula_ca.ca", "cert_pem", "nebula_certificate.host"),
				checkLifetime("nebula_certificate.host", 24*time.Hour),
			),
		}},
	})
}

func TestAccCertificate_v1(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: hostConfig{Key: key, CAVersion: 1, Version: 1}.String(),
			Check: resource.ComposeAggregateTestCheckFunc(
				checkHost("nebula_certificate.host", "nebula_keypair.host", cert.Version1),
				checkVerifies("nebula_ca.ca", "cert_pem", "nebula_certificate.host"),
				// No duration: the certificate expires with its CA.
				resource.TestCheckResourceAttrPair("nebula_certificate.host", "not_after", "nebula_ca.ca", "not_after"),
			),
		}},
	})
}

func TestAccCertificate_durationCappedToCA(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: hostConfig{Key: key, Extra: `duration = "1000h"`}.String(),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrPair("nebula_certificate.host", "not_after", "nebula_ca.ca", "not_after"),
				checkVerifies("nebula_ca.ca", "cert_pem", "nebula_certificate.host"),
			),
		}},
	})
}

func TestAccCertificate_explicitNotAfterPastCA(t *testing.T) {
	key := accTransitKey(t)
	notAfter := formatTime(time.Now().Add(1000 * time.Hour).Truncate(time.Second))
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      hostConfig{Key: key, Extra: fmt.Sprintf("not_after = %q", notAfter)}.String(),
			ExpectError: regexp.MustCompile(`after the CA's not_after`),
		}},
	})
}

func TestAccCertificate_keyVersionMismatch(t *testing.T) {
	key := accTransitKey(t)
	accRotateKey(t, key) // v2 exists, but the CA is made with v1
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      hostConfig{Key: key, KeyVersion: 2}.String(),
			ExpectError: regexp.MustCompile(`does not belong to transit key`),
		}},
	})
}

func TestAccCertificate_missingKeyVersion(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      hostConfig{Key: key, KeyVersion: 3}.String(),
			ExpectError: regexp.MustCompile(`has no version 3`),
		}},
	})
}

func TestAccCertificate_outsideCANetworks(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      hostConfig{Key: key, Extra: `unsafe_networks = ["192.168.0.0/24"]`, CAExtra: `unsafe_networks = ["172.16.0.0/12"]`}.String(),
			ExpectError: regexp.MustCompile(`unsafe network assignment outside the limitations`),
		}},
	})
}

func TestAccCertificate_replacedWithCAAndKey(t *testing.T) {
	key := accTransitKey(t)
	replace := resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
		plancheck.ExpectResourceAction("nebula_certificate.host", plancheck.ResourceActionReplace),
	}}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: hostConfig{Key: key}.String()},
			{
				// A new CA (input change) means a new host certificate.
				Config:           hostConfig{Key: key, CAName: "acc CA renamed"}.String(),
				ConfigPlanChecks: replace,
				Check:            checkVerifies("nebula_ca.ca", "cert_pem", "nebula_certificate.host"),
			},
			{
				// A new host key means a new host certificate.
				Config:           hostConfig{Key: key, CAName: "acc CA renamed", Keeper: "2"}.String(),
				ConfigPlanChecks: replace,
				Check:            checkHost("nebula_certificate.host", "nebula_keypair.host", cert.Version2),
			},
			{
				Config:           hostConfig{Key: key, CAName: "acc CA renamed", Keeper: "2", Extra: `duration = "2h"`}.String(),
				ConfigPlanChecks: replace,
				Check:            checkLifetime("nebula_certificate.host", 2*time.Hour),
			},
		},
	})
}

func TestAccCertificate_renewalWindowReplaces(t *testing.T) {
	key := accTransitKey(t)
	cfg := hostConfig{Key: key, Extra: "duration = \"1h\"\n  early_renewal_hours = 2"}.String()
	var first string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             cfg,
				ExpectNonEmptyPlan: true,
				Check:              resource.TestCheckResourceAttrWith("nebula_certificate.host", "fingerprint", func(v string) error { first = v; return nil }),
			},
			{
				PreConfig: func() { time.Sleep(1100 * time.Millisecond) },
				Config:    cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("nebula_certificate.host", plancheck.ResourceActionReplace),
					plancheck.ExpectResourceAction("nebula_ca.ca", plancheck.ResourceActionNoop),
				}},
				ExpectNonEmptyPlan: true,
				Check: resource.TestCheckResourceAttrWith("nebula_certificate.host", "fingerprint", func(v string) error {
					if v == first {
						return fmt.Errorf("fingerprint unchanged after renewal")
					}
					return nil
				}),
			},
		},
	})
}

func checkLifetime(res string, want time.Duration) func(*terraform.State) error {
	return func(s *terraform.State) error {
		c, err := certFromState(s, res)
		if err != nil {
			return err
		}
		if got := c.NotAfter().Sub(c.NotBefore()); got != want {
			return fmt.Errorf("%s lifetime %s, want %s", res, got, want)
		}
		return nil
	}
}
