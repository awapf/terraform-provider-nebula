package transitsign

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

// DefaultCADuration is the CA lifetime used when Spec has neither Duration
// nor NotAfter.
const DefaultCADuration = 365 * 24 * time.Hour

// Spec holds the fields shared by CA and host certificates.
type Spec struct {
	// Version is the Nebula certificate version, 1 or 2.
	Version        int64
	Name           string
	Groups         []string
	Networks       []netip.Prefix
	UnsafeNetworks []netip.Prefix
	// Duration is used when NotAfter is zero.
	Duration time.Duration
	// NotAfter, when set, is used as is and never capped.
	NotAfter time.Time
	// Now, when set, is used instead of the current time.
	Now time.Time
}

func (s Spec) now() time.Time {
	if s.Now.IsZero() {
		return time.Now()
	}
	return s.Now
}

// ParsePrefixes parses CIDR prefixes such as "10.0.0.1/24".
func ParsePrefixes(in []string) ([]netip.Prefix, error) {
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

// CertVersion maps 1 or 2 to the Nebula certificate version.
func CertVersion(v int64) (cert.Version, error) {
	switch v {
	case 1:
		return cert.Version1, nil
	case 2:
		return cert.Version2, nil
	default:
		return 0, fmt.Errorf("unsupported certificate version %d: want 1 or 2", v)
	}
}

// IssueCA builds a self-signed Nebula CA certificate whose key is the transit
// key, and signs it via sign.
func IssueCA(key *Key, sign cert.SignerLambda, spec Spec) (cert.Certificate, error) {
	now := spec.now().UTC().Truncate(time.Second)
	notAfter := spec.NotAfter
	if notAfter.IsZero() {
		d := spec.Duration
		if d == 0 {
			d = DefaultCADuration
		}
		notAfter = now.Add(d)
	}
	if !notAfter.After(now) {
		return nil, fmt.Errorf("not_after %s is not in the future", notAfter.Format(time.RFC3339))
	}
	version, err := CertVersion(spec.Version)
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

// ParseCA parses a single Nebula CA certificate and checks it is self-signed,
// unexpired and, when key is not nil, that it belongs to key.
func ParseCA(caPEM string, key *Key) (cert.Certificate, error) {
	return parseCA(caPEM, key, time.Now())
}

func parseCA(caPEM string, key *Key, now time.Time) (cert.Certificate, error) {
	ca, rest, err := cert.UnmarshalCertificateFromPEM([]byte(caPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("CA certificate PEM must contain exactly one certificate, not a bundle")
	}
	if !ca.IsCA() {
		return nil, errors.New("certificate is not a CA certificate")
	}
	if ca.Curve() != cert.Curve_CURVE25519 {
		return nil, fmt.Errorf("CA certificate uses curve %s; only CURVE25519 (Ed25519) CAs can live in transit", ca.Curve())
	}
	if !ca.CheckSignature(ca.PublicKey()) {
		return nil, errors.New("CA certificate is not correctly self-signed")
	}
	if key != nil && !bytes.Equal(ca.PublicKey(), key.PublicKey) {
		return nil, fmt.Errorf("CA certificate (%s) does not belong to transit key %q version %d: public keys differ", cert.QuoteName(ca.Name()), key.Name, key.Version)
	}
	if ca.Expired(now) {
		return nil, fmt.Errorf("CA %s expired at %s", cert.QuoteName(ca.Name()), ca.NotAfter().UTC().Format(time.RFC3339))
	}
	return ca, nil
}

// ParseCAAt is ParseCA with an explicit current time.
func ParseCAAt(caPEM string, key *Key, now time.Time) (cert.Certificate, error) {
	return parseCA(caPEM, key, now)
}

// ParseHostPublicKey accepts a single Nebula X25519 public key PEM.
func ParseHostPublicKey(pubPEM string) ([]byte, error) {
	pub, rest, curve, err := cert.UnmarshalPublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("public key PEM must contain exactly one key")
	}
	if curve != cert.Curve_CURVE25519 {
		return nil, fmt.Errorf("public key uses curve %s; the CA is CURVE25519, so the host key must be X25519", curve)
	}
	return pub, nil
}

// HostValidity computes the validity window of a host certificate. A
// certificate never starts before the CA does. With an explicit NotAfter that
// exceeds the CA's, it is an error; a duration-derived NotAfter (or no
// duration at all) is capped to the CA's NotAfter, like nebula-cert does.
func HostValidity(ca cert.Certificate, spec Spec) (notBefore, notAfter time.Time, err error) {
	now := spec.now().UTC().Truncate(time.Second)
	notBefore = now
	if caNB := ca.NotBefore().UTC(); notBefore.Before(caNB) {
		notBefore = caNB
	}
	caNA := ca.NotAfter().UTC()
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

// IssueHost builds and signs a host certificate for hostPub under ca, then
// verifies it against both the transit public key and the CA, so a result is
// only returned when it lies inside the CA's group and network constraints.
func IssueHost(ca cert.Certificate, key *Key, sign cert.SignerLambda, hostPub []byte, spec Spec) (cert.Certificate, error) {
	notBefore, notAfter, err := HostValidity(ca, spec)
	if err != nil {
		return nil, err
	}
	version, err := CertVersion(spec.Version)
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

// SigningPublicKeyPEM marshals a CA (signing) public key.
func SigningPublicKeyPEM(pub ed25519.PublicKey) string {
	return string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_CURVE25519, pub))
}
