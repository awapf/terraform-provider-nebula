package provider

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/slackhq/nebula/cert"
)

func TestAccCA_v2(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name    = %q
  key_version = 1
  name        = "acc CA"
  groups      = ["infra", "nodes"]
  networks    = ["10.99.0.0/16"]
  duration    = "48h"
}`, key),
			Check: resource.ComposeAggregateTestCheckFunc(
				checkCA("nebula_ca.test", key, 1, cert.Version2, 48*time.Hour),
				resource.TestCheckResourceAttr("nebula_ca.test", "version", "2"),
				resource.TestCheckResourceAttr("nebula_ca.test", "groups.#", "2"),
				resource.TestCheckResourceAttr("nebula_ca.test", "ready_for_renewal", "false"),
			),
		}},
	})
}

func TestAccCA_v1DefaultDuration(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name    = %q
  key_version = 1
  name        = "acc CA v1"
  version     = 1
}`, key),
			Check: checkCA("nebula_ca.test", key, 1, cert.Version1, defaultCADuration),
		}},
	})
}

func TestAccCA_explicitNotAfter(t *testing.T) {
	key := accTransitKey(t)
	notAfter := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name    = %q
  key_version = 1
  name        = "acc CA"
  not_after   = %q
}`, key, notAfter),
			Check: resource.TestCheckResourceAttr("nebula_ca.test", "not_after", notAfter),
		}},
	})
}

func TestAccCA_missingKeyVersion(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name    = %q
  key_version = 2
  name        = "acc CA"
}`, key),
			ExpectError: regexp.MustCompile(`has no version 2`),
		}},
	})
}

func TestAccCA_inputChangeReplaces(t *testing.T) {
	key := accTransitKey(t)
	cfg := func(name string) string {
		return fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name    = %q
  key_version = 1
  name        = %q
}`, key, name)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg("one")},
			{
				Config: cfg("two"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("nebula_ca.test", plancheck.ResourceActionReplace),
				}},
				Check: resource.TestCheckResourceAttr("nebula_ca.test", "name", "two"),
			},
		},
	})
}

func TestAccCA_renewalWindowReplaces(t *testing.T) {
	key := accTransitKey(t)
	// A 1h CA with a 2h renewal window is due for renewal right away, so
	// the next plan must replace it.
	cfg := fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name            = %q
  key_version         = 1
  name                = "short CA"
  duration            = "1h"
  early_renewal_hours = 2
}`, key)
	var first string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             cfg,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("nebula_ca.test", "ready_for_renewal", "false"),
					resource.TestCheckResourceAttrWith("nebula_ca.test", "fingerprint", func(v string) error { first = v; return nil }),
				),
			},
			{
				// Nebula times have one-second resolution and Ed25519 is
				// deterministic: wait so the renewed certificate differs.
				PreConfig: func() { time.Sleep(1100 * time.Millisecond) },
				Config:    cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("nebula_ca.test", plancheck.ResourceActionReplace),
				}},
				ExpectNonEmptyPlan: true,
				Check: resource.TestCheckResourceAttrWith("nebula_ca.test", "fingerprint", func(v string) error {
					if v == first {
						return fmt.Errorf("fingerprint unchanged after renewal")
					}
					return nil
				}),
			},
		},
	})
}

func TestAccCA_noRenewalOutsideWindow(t *testing.T) {
	key := accTransitKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// The default post-apply plan check fails if the plan is not empty.
			Config: fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name            = %q
  key_version         = 1
  name                = "CA"
  duration            = "48h"
  early_renewal_hours = 24
}`, key),
		}},
	})
}

func TestAccCA_earlyRenewalHoursUpdatesInPlace(t *testing.T) {
	key := accTransitKey(t)
	cfg := func(h int) string {
		return fmt.Sprintf(`
resource "nebula_ca" "test" {
  key_name            = %q
  key_version         = 1
  name                = "CA"
  duration            = "48h"
  early_renewal_hours = %d
}`, key, h)
	}
	var first string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg(0),
				Check:  resource.TestCheckResourceAttrWith("nebula_ca.test", "fingerprint", func(v string) error { first = v; return nil }),
			},
			{
				Config: cfg(1),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("nebula_ca.test", plancheck.ResourceActionUpdate),
				}},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("nebula_ca.test", "early_renewal_hours", "1"),
					resource.TestCheckResourceAttrWith("nebula_ca.test", "fingerprint", func(v string) error {
						if v != first {
							return fmt.Errorf("fingerprint changed on an in-place update")
						}
						return nil
					}),
				),
			},
		},
	})
}
