package provider

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/awapf/terraform-provider-nebula/transitsign"
)

const (
	defaultCADuration = transitsign.DefaultCADuration
	defaultVersion    = 2
)

// certSpec holds the user-facing fields shared by CA and host certificates.
type certSpec = transitsign.Spec

func parsePrefixes(in []string) ([]netip.Prefix, error) { return transitsign.ParsePrefixes(in) }

func certVersion(v int64) (cert.Version, error) { return transitsign.CertVersion(v) }

// nowFunc is overridable in tests.
var nowFunc = time.Now

func withClock(spec certSpec) certSpec {
	if spec.Now.IsZero() {
		spec.Now = nowFunc()
	}
	return spec
}

func issueCA(key *transitKey, sign cert.SignerLambda, spec certSpec) (cert.Certificate, error) {
	return transitsign.IssueCA(key, sign, withClock(spec))
}

func parseCA(caPEM string, key *transitKey) (cert.Certificate, error) {
	ca, err := transitsign.ParseCAAt(caPEM, key, nowFunc())
	if err != nil {
		return nil, fmt.Errorf("ca_cert_pem: %w", err)
	}
	return ca, nil
}

func parseHostPublicKey(pubPEM string) ([]byte, error) {
	pub, err := transitsign.ParseHostPublicKey(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("public_key_pem: %w", err)
	}
	return pub, nil
}

func hostValidity(ca cert.Certificate, spec certSpec) (time.Time, time.Time, error) {
	return transitsign.HostValidity(ca, withClock(spec))
}

func issueHost(ca cert.Certificate, key *transitKey, sign cert.SignerLambda, hostPub []byte, spec certSpec) (cert.Certificate, error) {
	return transitsign.IssueHost(ca, key, sign, hostPub, withClock(spec))
}

// ed25519PublicKeyPEM marshals a CA (signing) public key.
func ed25519PublicKeyPEM(pub ed25519.PublicKey) string { return transitsign.SigningPublicKeyPEM(pub) }

// needsRenewal reports whether a certificate expiring at notAfter is within
// earlyRenewal of now (or already expired).
func needsRenewal(notAfter time.Time, earlyRenewal time.Duration) bool {
	return !nowFunc().Before(notAfter.Add(-earlyRenewal))
}
