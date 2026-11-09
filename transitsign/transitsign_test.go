package transitsign_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/awapf/terraform-provider-nebula/transitsign"
	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
)

func mustKey(t *testing.T, s *transittest.Server, name string, version int64) *transitsign.Key {
	t.Helper()
	k, err := s.Client(t).Key(context.Background(), name, version)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func hostPub(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

func TestKeyAndSign(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k := mustKey(t, s, "ca", 1)
	if len(k.PublicKey) != 32 || k.Latest != 1 || k.Name != "ca" || k.Version != 1 || k.Exportable {
		t.Fatalf("unexpected key %+v", k)
	}
	sig, err := k.Signer(context.Background())([]byte("hello"))
	if err != nil || len(sig) != 64 {
		t.Fatalf("sign: %v (len %d)", err, len(sig))
	}
	if s.LastHeaders().Get("X-Vault-Token") != s.Token {
		t.Fatal("token header not sent")
	}
}

func TestKeyMissingVersion(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	_, err := s.Client(t).Key(context.Background(), "ca", 2)
	if err == nil || !strings.Contains(err.Error(), "has no version 2") {
		t.Fatalf("want missing version error, got %v", err)
	}
}

func TestSignerRejectsBadSignature(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k := mustKey(t, s, "ca", 1)
	s.SetBadSignature(true)
	_, err := k.Signer(context.Background())([]byte("hello"))
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("want verification error, got %v", err)
	}
}

func TestClientErrorsAndNamespace(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	c, err := transitsign.NewClient(transitsign.Config{Address: s.URL, Token: "wrong", Namespace: "team-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Key(context.Background(), "ca", 1)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("want 403 permission denied, got %v", err)
	}
	if s.LastHeaders().Get("X-Vault-Namespace") != "team-a" {
		t.Fatal("namespace header not sent")
	}
	for _, cfg := range []transitsign.Config{{Token: "x"}, {Address: "http://x"}, {Address: "ftp://x", Token: "x"}} {
		if _, err := transitsign.NewClient(cfg); err == nil {
			t.Errorf("NewClient(%+v) should fail", cfg)
		}
	}
}

func TestClientDefaultMount(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	c, err := transitsign.NewClient(transitsign.Config{Address: s.URL + "/", Token: s.Token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Key(context.Background(), "ca", 1); err != nil {
		t.Fatalf("default mount should be %q: %v", transitsign.DefaultMount, err)
	}
}

func TestIssueCAAndHost(t *testing.T) {
	for _, v := range []int64{1, 2} {
		t.Run("v"+string(rune('0'+v)), func(t *testing.T) {
			s := transittest.NewServer(t)
			s.AddKey("ca")
			k := mustKey(t, s, "ca", 1)
			ctx := context.Background()
			ca, err := transitsign.IssueCA(k, k.Signer(ctx), transitsign.Spec{Version: v, Name: "test ca", Groups: []string{"a", "b"}})
			if err != nil {
				t.Fatal(err)
			}
			if !ca.IsCA() || ca.Version() != cert.Version(v) || !ca.CheckSignature(k.PublicKey) {
				t.Fatalf("bad CA: %s", ca)
			}
			if got := ca.NotAfter().Sub(ca.NotBefore()); got != transitsign.DefaultCADuration {
				t.Fatalf("default CA duration: got %s", got)
			}
			caPEM, _ := ca.MarshalPEM()
			parsed, err := transitsign.ParseCA(string(caPEM), k)
			if err != nil {
				t.Fatal(err)
			}
			pub := hostPub(t)
			host, err := transitsign.IssueHost(parsed, k, k.Signer(ctx), pub, transitsign.Spec{
				Version:  v,
				Name:     "node",
				Groups:   []string{"a"},
				Networks: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/24")},
				Duration: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			pool := cert.NewCAPool()
			if err := pool.AddCA(ca); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.VerifyCertificate(time.Now(), host); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if host.Version() != cert.Version(v) || string(host.PublicKey()) != string(pub) {
				t.Fatalf("host version %d / key mismatch, want %d", host.Version(), v)
			}
		})
	}
}

func TestParseCA(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	s.AddKey("ca") // version 2
	k1 := mustKey(t, s, "ca", 1)
	k2 := mustKey(t, s, "ca", 2)
	ctx := context.Background()
	ca, err := transitsign.IssueCA(k1, k1.Signer(ctx), transitsign.Spec{Version: 2, Name: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := ca.MarshalPEM()
	if _, err := transitsign.ParseCA(string(caPEM), nil); err != nil {
		t.Fatalf("nil key should skip the key check: %v", err)
	}
	if _, err := transitsign.ParseCA(string(caPEM), k2); err == nil || !strings.Contains(err.Error(), "does not belong to transit key") {
		t.Fatalf("want mismatch error, got %v", err)
	}
	if _, err := transitsign.ParseCA(string(caPEM)+string(caPEM), k1); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("want bundle error, got %v", err)
	}
	host, err := transitsign.IssueHost(ca, k1, k1.Signer(ctx), hostPub(t), transitsign.Spec{Version: 2, Name: "n", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}})
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, _ := host.MarshalPEM()
	if _, err := transitsign.ParseCA(string(hostPEM), nil); err == nil || !strings.Contains(err.Error(), "not a CA certificate") {
		t.Fatalf("want not-a-CA error, got %v", err)
	}
	if _, err := transitsign.ParseCA("garbage", nil); err == nil {
		t.Fatal("garbage should not parse")
	}
	expired, err := transitsign.IssueCA(k1, k1.Signer(ctx), transitsign.Spec{Version: 2, Name: "old", Duration: time.Hour, Now: time.Now().Add(-48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := expired.MarshalPEM()
	if _, err := transitsign.ParseCA(string(ep), k1); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expiry error, got %v", err)
	}
	if _, err := transitsign.ParseCAAt(string(ep), k1, time.Now().Add(-47*time.Hour-30*time.Minute)); err != nil {
		t.Fatalf("ParseCAAt inside the CA's lifetime: %v", err)
	}
}

func TestParseHostPublicKey(t *testing.T) {
	pub := hostPub(t)
	pemBytes := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)
	got, err := transitsign.ParseHostPublicKey(string(pemBytes))
	if err != nil || string(got) != string(pub) {
		t.Fatalf("ParseHostPublicKey: %v", err)
	}
	if _, err := transitsign.ParseHostPublicKey(string(pemBytes) + string(pemBytes)); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("want exactly-one error, got %v", err)
	}
	if _, err := transitsign.ParseHostPublicKey("nope"); err == nil {
		t.Fatal("garbage should not parse")
	}
	p256 := cert.MarshalPublicKeyToPEM(cert.Curve_P256, make([]byte, 65))
	if _, err := transitsign.ParseHostPublicKey(string(p256)); err == nil || !strings.Contains(err.Error(), "X25519") {
		t.Fatalf("want curve error, got %v", err)
	}
}

func TestHostValidity(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k := mustKey(t, s, "ca", 1)
	ca, err := transitsign.IssueCA(k, k.Signer(context.Background()), transitsign.Spec{Version: 2, Name: "ca", Duration: 48 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	caNA := now.Add(48 * time.Hour)

	cases := []struct {
		name    string
		spec    transitsign.Spec
		want    time.Time
		wantErr string
	}{
		{"no duration means CA expiry", transitsign.Spec{}, caNA, ""},
		{"short duration", transitsign.Spec{Duration: time.Hour}, now.Add(time.Hour), ""},
		{"long duration capped", transitsign.Spec{Duration: 1000 * time.Hour}, caNA, ""},
		{"explicit not_after", transitsign.Spec{NotAfter: now.Add(2 * time.Hour)}, now.Add(2 * time.Hour), ""},
		{"explicit not_after past CA", transitsign.Spec{NotAfter: caNA.Add(time.Second)}, time.Time{}, "after the CA's not_after"},
		{"explicit not_after in the past", transitsign.Spec{NotAfter: now.Add(-time.Hour)}, time.Time{}, "not in the future"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.spec.Now = now
			nb, na, err := transitsign.HostValidity(ca, tc.spec)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !nb.Equal(now) || !na.Equal(tc.want) {
				t.Fatalf("got %s..%s, want %s..%s", nb, na, now, tc.want)
			}
		})
	}
}

func TestHostValidityStartsWithCA(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k := mustKey(t, s, "ca", 1)
	ca, err := transitsign.IssueCA(k, k.Signer(context.Background()), transitsign.Spec{Version: 2, Name: "ca", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// A clock a little behind the CA's NotBefore must not produce a cert
	// that starts before its CA.
	nb, _, err := transitsign.HostValidity(ca, transitsign.Spec{Now: now.Add(-500 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	if !nb.Equal(ca.NotBefore()) {
		t.Fatalf("not_before %s, want CA's %s", nb, ca.NotBefore())
	}
}

func TestIssueHostRejectsOutsideCAConstraints(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k := mustKey(t, s, "ca", 1)
	ctx := context.Background()
	ca, err := transitsign.IssueCA(k, k.Signer(ctx), transitsign.Spec{
		Version:  2,
		Name:     "ca",
		Groups:   []string{"a"},
		Networks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = transitsign.IssueHost(ca, k, k.Signer(ctx), hostPub(t), transitsign.Spec{Version: 2, Name: "n", Networks: []netip.Prefix{netip.MustParsePrefix("10.100.0.2/24")}})
	if err == nil || !strings.Contains(err.Error(), "outside the limitations") {
		t.Fatalf("want network constraint error, got %v", err)
	}
	_, err = transitsign.IssueHost(ca, k, k.Signer(ctx), hostPub(t), transitsign.Spec{Version: 2, Name: "n", Groups: []string{"b"}, Networks: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/24")}})
	if err == nil || !strings.Contains(err.Error(), "group") {
		t.Fatalf("want group constraint error, got %v", err)
	}
}

func TestIssueHostRejectsKeyMismatch(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("a")
	s.AddKey("b")
	a, b := mustKey(t, s, "a", 1), mustKey(t, s, "b", 1)
	ctx := context.Background()
	ca, err := transitsign.IssueCA(a, a.Signer(ctx), transitsign.Spec{Version: 2, Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	// Signing a host under CA "a" with key "b" must never yield a cert.
	if _, err := transitsign.IssueHost(ca, b, b.Signer(ctx), hostPub(t), transitsign.Spec{Version: 2, Name: "n", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}}); err == nil {
		t.Fatal("want error when the signer key is not the CA key")
	}
}

func TestCertVersion(t *testing.T) {
	for v, want := range map[int64]cert.Version{1: cert.Version1, 2: cert.Version2} {
		if got, err := transitsign.CertVersion(v); err != nil || got != want {
			t.Errorf("CertVersion(%d) = %v, %v", v, got, err)
		}
	}
	for _, v := range []int64{0, 3, 258} {
		if _, err := transitsign.CertVersion(v); err == nil {
			t.Errorf("CertVersion(%d) should fail", v)
		}
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := transitsign.ParsePrefixes([]string{"10.0.0.1/24", "fd00::1/64"})
	if err != nil || len(got) != 2 || got[0] != netip.MustParsePrefix("10.0.0.1/24") {
		t.Fatalf("ParsePrefixes: %v %v", got, err)
	}
	if _, err := transitsign.ParsePrefixes([]string{"10.0.0.1"}); err == nil {
		t.Fatal("bare address should fail")
	}
}

func TestSigningPublicKeyPEM(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k := mustKey(t, s, "ca", 1)
	p := transitsign.SigningPublicKeyPEM(k.PublicKey)
	if !strings.Contains(p, "NEBULA ED25519 PUBLIC KEY") {
		t.Fatalf("unexpected PEM %q", p)
	}
}
