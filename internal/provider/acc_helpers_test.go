package provider

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/slackhq/nebula/cert"
)

// attr returns a resource attribute from state.
func attr(s *terraform.State, res, key string) (string, error) {
	rs, ok := s.RootModule().Resources[res]
	if !ok {
		return "", fmt.Errorf("resource %s not in state", res)
	}
	v, ok := rs.Primary.Attributes[key]
	if !ok {
		return "", fmt.Errorf("%s has no attribute %s", res, key)
	}
	return v, nil
}

func certFromState(s *terraform.State, res string) (cert.Certificate, error) {
	p, err := attr(s, res, "cert_pem")
	if err != nil {
		return nil, err
	}
	c, _, err := cert.UnmarshalCertificateFromPEM([]byte(p))
	return c, err
}

// transitPublicKey reads a transit key version's public key with the root token.
func transitPublicKey(name string, version int) ([]byte, error) {
	var r struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := baoRootOut(http.MethodGet, "transit/keys/"+name, nil, &r); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(r.Data.Keys[fmt.Sprint(version)].PublicKey)
}

// checkCA verifies the CA in state belongs to the transit key and matches
// the expected version and lifetime.
func checkCA(res, keyName string, keyVersion int, version cert.Version, lifetime time.Duration) func(*terraform.State) error {
	return func(s *terraform.State) error {
		c, err := certFromState(s, res)
		if err != nil {
			return err
		}
		pub, err := transitPublicKey(keyName, keyVersion)
		if err != nil {
			return err
		}
		if !c.IsCA() || c.Version() != version {
			return fmt.Errorf("want CA version %d, got IsCA=%v version %d", version, c.IsCA(), c.Version())
		}
		if !bytes.Equal(c.PublicKey(), pub) || !c.CheckSignature(pub) {
			return fmt.Errorf("CA is not keyed and signed by transit key %s v%d", keyName, keyVersion)
		}
		if got := c.NotAfter().Sub(c.NotBefore()); got != lifetime {
			return fmt.Errorf("CA lifetime %s, want %s", got, lifetime)
		}
		fp, _ := c.Fingerprint()
		for k, want := range map[string]string{
			"fingerprint":    fp,
			"id":             fp,
			"not_before":     c.NotBefore().UTC().Format(time.RFC3339),
			"not_after":      c.NotAfter().UTC().Format(time.RFC3339),
			"public_key_pem": string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_CURVE25519, pub)),
		} {
			got, err := attr(s, res, k)
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		return nil
	}
}

// checkVerifies checks host certificates verify against a pool built from
// the given PEM attribute (a CA cert or a bundle), like `nebula-cert verify`.
func checkVerifies(caRes, caAttr string, hosts ...string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		caPEM, err := attr(s, caRes, caAttr)
		if err != nil {
			return err
		}
		pool, err := cert.NewCAPoolFromPEM([]byte(caPEM))
		if err != nil {
			return err
		}
		for _, h := range hosts {
			c, err := certFromState(s, h)
			if err != nil {
				return err
			}
			if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
				return fmt.Errorf("%s does not verify against %s.%s: %w", h, caRes, caAttr, err)
			}
		}
		return nil
	}
}

// checkNotVerifies is the negative of checkVerifies.
func checkNotVerifies(caRes, caAttr, host string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		if err := checkVerifies(caRes, caAttr, host)(s); err == nil {
			return fmt.Errorf("%s unexpectedly verifies against %s.%s", host, caRes, caAttr)
		}
		return nil
	}
}
