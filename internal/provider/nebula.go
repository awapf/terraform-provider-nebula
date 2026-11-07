package provider

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

const (
	defaultCADuration = 365 * 24 * time.Hour
	defaultVersion    = 2
)

// certSpec holds the user-facing fields shared by CA and host certificates.
type certSpec struct {
	Version        int64
	Name           string
	Groups         []string
	Networks       []netip.Prefix
	UnsafeNetworks []netip.Prefix
	// Duration is used when NotAfter is zero.
	Duration time.Duration
	// NotAfter, when set, is used as is and never capped.
	NotAfter time.Time
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func certVersion(v int64) (cert.Version, error) {
	switch v {
	case 1:
		return cert.Version1, nil
	case 2:
		return cert.Version2, nil
	default:
		return 0, fmt.Errorf("unsupported certificate version %d: want 1 or 2", v)
	}
}

// nowFunc is overridable in tests.
var nowFunc = time.Now

// issueCA builds a self-signed Nebula CA certificate whose key is the transit
// key, and signs it via transit.
func issueCA(key *transitKey, sign cert.SignerLambda, spec certSpec) (cert.Certificate, error) {
	now := nowFunc().UTC().Truncate(time.Second)
	notAfter := spec.NotAfter
	if notAfter.IsZero() {
		d := spec.Duration
		if d == 0 {
			d = defaultCADuration
		}
		notAfter = now.Add(d)
	}
	if !notAfter.After(now) {
		return nil, fmt.Errorf("not_after %s is not in the future", notAfter.Format(time.RFC3339))
	}
	version, err := certVersion(spec.Version)
	if err != nil {
		return nil, err
	}
	t := &cert.TBSCertificate{
		Version:        version,
		Name:           spec.Name,
		Groups:         spec.Groups,
		Networks:       spec.Networks,
		UnsafeNetworks: spec.UnsafeNetworks,
		IsCA:           true,
		NotBefore:      now,
		NotAfter:       notAfter,
		PublicKey:      key.PublicKey,
		Curve:          cert.Curve_CURVE25519,
	}
	c, err := t.SignWith(nil, cert.Curve_CURVE25519, sign)
	if err != nil {
		return nil, err
	}
	if !c.CheckSignature(key.PublicKey) {
		return nil, errors.New("signed CA certificate does not verify against the transit public key")
	}
	return c, nil
}

// parseCA parses a single Nebula CA certificate and checks it is usable for
// signing with the given transit key.
func parseCA(caPEM string, key *transitKey) (cert.Certificate, error) {
	ca, rest, err := cert.UnmarshalCertificateFromPEM([]byte(caPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing ca_cert_pem: %w", err)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("ca_cert_pem must contain exactly one certificate, not a bundle")
	}
	if !ca.IsCA() {
		return nil, errors.New("ca_cert_pem is not a CA certificate")
	}
	if ca.Curve() != cert.Curve_CURVE25519 {
		return nil, fmt.Errorf("ca_cert_pem uses curve %s; only CURVE25519 (Ed25519) CAs can live in transit", ca.Curve())
	}
	if !ca.CheckSignature(ca.PublicKey()) {
		return nil, errors.New("ca_cert_pem is not correctly self-signed")
	}
	if key != nil && !bytes.Equal(ca.PublicKey(), key.PublicKey) {
		return nil, fmt.Errorf("ca_cert_pem (%s) does not belong to transit key %q version %d: public keys differ", cert.QuoteName(ca.Name()), key.Name, key.Version)
	}
	if ca.Expired(nowFunc()) {
		return nil, fmt.Errorf("CA %s expired at %s", cert.QuoteName(ca.Name()), ca.NotAfter().UTC().Format(time.RFC3339))
	}
	return ca, nil
}

// parseHostPublicKey accepts a Nebula X25519 public key PEM.
func parseHostPublicKey(pubPEM string) ([]byte, error) {
	pub, rest, curve, err := cert.UnmarshalPublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing public_key_pem: %w", err)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("public_key_pem must contain exactly one key")
	}
	if curve != cert.Curve_CURVE25519 {
		return nil, fmt.Errorf("public_key_pem uses curve %s; the CA is CURVE25519, so the host key must be X25519", curve)
	}
	return pub, nil
}

// hostValidity computes the validity window of a host certificate. A
// certificate never starts before the CA does. With an explicit NotAfter that
// exceeds the CA's, it is an error; a duration-derived NotAfter (or no
// duration at all) is capped to the CA's NotAfter, like nebula-cert does.
func hostValidity(ca cert.Certificate, spec certSpec) (time.Time, time.Time, error) {
	now := nowFunc().UTC().Truncate(time.Second)
	notBefore := now
	if caNB := ca.NotBefore().UTC(); notBefore.Before(caNB) {
		notBefore = caNB
	}
	caNA := ca.NotAfter().UTC()
	var notAfter time.Time
	switch {
	case !spec.NotAfter.IsZero():
		notAfter = spec.NotAfter
		if notAfter.After(caNA) {
			return time.Time{}, time.Time{}, fmt.Errorf("not_after %s is after the CA's not_after %s", notAfter.Format(time.RFC3339), caNA.Format(time.RFC3339))
		}
	case spec.Duration > 0:
		notAfter = now.Add(spec.Duration)
		if notAfter.After(caNA) {
			notAfter = caNA
		}
	default:
		notAfter = caNA
	}
	if !notAfter.After(now) {
		return time.Time{}, time.Time{}, fmt.Errorf("not_after %s is not in the future", notAfter.Format(time.RFC3339))
	}
	return notBefore, notAfter, nil
}

// issueHost builds and signs a host certificate for hostPub under ca.
func issueHost(ca cert.Certificate, key *transitKey, sign cert.SignerLambda, hostPub []byte, spec certSpec) (cert.Certificate, error) {
	notBefore, notAfter, err := hostValidity(ca, spec)
	if err != nil {
		return nil, err
	}
	version, err := certVersion(spec.Version)
	if err != nil {
		return nil, err
	}
	t := &cert.TBSCertificate{
		Version:        version,
		Name:           spec.Name,
		Groups:         spec.Groups,
		Networks:       spec.Networks,
		UnsafeNetworks: spec.UnsafeNetworks,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		PublicKey:      hostPub,
		Curve:          cert.Curve_CURVE25519,
	}
	c, err := t.SignWith(ca, cert.Curve_CURVE25519, sign)
	if err != nil {
		return nil, err
	}
	if !c.CheckSignature(key.PublicKey) {
		return nil, errors.New("signed certificate does not verify against the transit public key")
	}
	pool := cert.NewCAPool()
	if err := pool.AddCA(ca); err != nil {
		return nil, err
	}
	if _, err := pool.VerifyCertificate(notBefore, c); err != nil {
		return nil, fmt.Errorf("issued certificate does not verify against its CA: %w", err)
	}
	return c, nil
}

// ed25519PublicKeyPEM marshals a CA (signing) public key.
func ed25519PublicKeyPEM(pub ed25519.PublicKey) string {
	return string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_CURVE25519, pub))
}

// needsRenewal reports whether a certificate expiring at notAfter is within
// earlyRenewal of now (or already expired).
func needsRenewal(notAfter time.Time, earlyRenewal time.Duration) bool {
	return !nowFunc().Before(notAfter.Add(-earlyRenewal))
}
