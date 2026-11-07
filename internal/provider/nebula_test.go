package provider

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/slackhq/nebula/cert"
)

func mustKey(t *testing.T, f *fakeTransit, name string, version int64) *transitKey {
	t.Helper()
	k, err := f.client(t).Key(context.Background(), name, version)
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

func withNow(t *testing.T, now time.Time) {
	t.Helper()
	old := nowFunc
	nowFunc = func() time.Time { return now }
	t.Cleanup(func() { nowFunc = old })
}

func TestTransitKeyAndSign(t *testing.T) {
	f := newFakeTransit(t)
	f.addKey("ca")
	k := mustKey(t, f, "ca", 1)
	if len(k.PublicKey) != 32 || k.Latest != 1 {
		t.Fatalf("unexpected key %+v", k)
	}
	sig, err := k.Signer(context.Background())([]byte("hello"))
	if err != nil || len(sig) != 64 {
		t.Fatalf("sign: %v (len %d)", err, len(sig))
	}
	if f.lastHeaders.Get("X-Vault-Token") != f.token {
		t.Fatal("token header not sent")
	}
}

func TestTransitMissingVersion(t *testing.T) {
	f := newFakeTransit(t)
	f.addKey("ca")
	_, err := f.client(t).Key(context.Background(), "ca", 2)
	if err == nil || !strings.Contains(err.Error(), "has no version 2") {
		t.Fatalf("want missing version error, got %v", err)
	}
}

func TestTransitRejectsBadSignature(t *testing.T) {
	f := newFakeTransit(t)
	f.addKey("ca")
	k := mustKey(t, f, "ca", 1)
	f.badSignature = true
	_, err := k.Signer(context.Background())([]byte("hello"))
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("want verification error, got %v", err)
	}
}

func TestTransitErrorsAndNamespace(t *testing.T) {
	f := newFakeTransit(t)
	f.addKey("ca")
	c, err := newTransitClient(transitConfig{Address: f.srv.URL, Token: "wrong", Namespace: "team-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Key(context.Background(), "ca", 1)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("want 403 permission denied, got %v", err)
	}
	if f.lastHeaders.Get("X-Vault-Namespace") != "team-a" {
		t.Fatal("namespace header not sent")
	}
	for _, cfg := range []transitConfig{{Token: "x"}, {Address: "http://x"}, {Address: "ftp://x", Token: "x"}} {
		if _, err := newTransitClient(cfg); err == nil {
			t.Errorf("newTransitClient(%+v) should fail", cfg)
		}
	}
}

func TestIssueCAAndHost(t *testing.T) {
	for _, v := range []int64{1, 2} {
		t.Run("v"+string(rune('0'+v)), func(t *testing.T) {
			f := newFakeTransit(t)
			f.addKey("ca")
			k := mustKey(t, f, "ca", 1)
			ctx := context.Background()
			ca, err := issueCA(k, k.Signer(ctx), certSpec{Version: v, Name: "test ca", Groups: []string{"a", "b"}})
			if err != nil {
				t.Fatal(err)
			}
			if !ca.IsCA() || ca.Version() != cert.Version(v) || !ca.CheckSignature(k.PublicKey) {
				t.Fatalf("bad CA: %s", ca)
			}
			if got := ca.NotAfter().Sub(ca.NotBefore()); got != defaultCADuration {
				t.Fatalf("default CA duration: got %s", got)
			}
			caPEM, _ := ca.MarshalPEM()
			parsed, err := parseCA(string(caPEM), k)
			if err != nil {
				t.Fatal(err)
			}
			host, err := issueHost(parsed, k, k.Signer(ctx), hostPub(t), certSpec{
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
			if host.Version() != cert.Version(v) {
				t.Fatalf("host version %d, want %d", host.Version(), v)
			}
		})
	}
}

func TestParseCAMismatch(t *testing.T) {
	f := newFakeTransit(t)
	f.addKey("ca")
	f.addKey("ca") // version 2
	k1 := mustKey(t, f, "ca", 1)
	k2 := mustKey(t, f, "ca", 2)
	ca, err := issueCA(k1, k1.Signer(context.Background()), certSpec{Version: 2, Name: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := ca.MarshalPEM()
	if _, err := parseCA(string(caPEM), k2); err == nil || !strings.Contains(err.Error(), "does not belong to transit key") {
		t.Fatalf("want mismatch error, got %v", err)
	}
	if _, err := parseCA(string(caPEM)+string(caPEM), k1); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("want bundle error, got %v", err)
	}
}

func TestHostValidity(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow(t, now)
	f := newFakeTransit(t)
	f.addKey("ca")
	k := mustKey(t, f, "ca", 1)
	ca, err := issueCA(k, k.Signer(context.Background()), certSpec{Version: 2, Name: "ca", Duration: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	caNA := now.Add(48 * time.Hour)

	cases := []struct {
		name    string
		spec    certSpec
		want    time.Time
		wantErr string
	}{
		{"no duration means CA expiry", certSpec{}, caNA, ""},
		{"short duration", certSpec{Duration: time.Hour}, now.Add(time.Hour), ""},
		{"long duration capped", certSpec{Duration: 1000 * time.Hour}, caNA, ""},
		{"explicit not_after", certSpec{NotAfter: now.Add(2 * time.Hour)}, now.Add(2 * time.Hour), ""},
		{"explicit not_after past CA", certSpec{NotAfter: caNA.Add(time.Second)}, time.Time{}, "after the CA's not_after"},
		{"explicit not_after in the past", certSpec{NotAfter: now.Add(-time.Hour)}, time.Time{}, "not in the future"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nb, na, err := hostValidity(ca, tc.spec)
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
	withNow(t, now)
	f := newFakeTransit(t)
	f.addKey("ca")
	k := mustKey(t, f, "ca", 1)
	ca, err := issueCA(k, k.Signer(context.Background()), certSpec{Version: 2, Name: "ca"})
	if err != nil {
		t.Fatal(err)
	}
	// A clock a little behind the CA's NotBefore must not produce a cert
	// that starts before its CA.
	withNow(t, now.Add(-500*time.Millisecond))
	nb, _, err := hostValidity(ca, certSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if !nb.Equal(ca.NotBefore()) {
		t.Fatalf("not_before %s, want CA's %s", nb, ca.NotBefore())
	}
}

func TestIssueHostRejectsOutsideCAConstraints(t *testing.T) {
	f := newFakeTransit(t)
	f.addKey("ca")
	k := mustKey(t, f, "ca", 1)
	ctx := context.Background()
	ca, err := issueCA(k, k.Signer(ctx), certSpec{Version: 2, Name: "ca", Networks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = issueHost(ca, k, k.Signer(ctx), hostPub(t), certSpec{Version: 2, Name: "n", Networks: []netip.Prefix{netip.MustParsePrefix("10.100.0.2/24")}})
	if err == nil || !strings.Contains(err.Error(), "outside the limitations") {
		t.Fatalf("want constraint error, got %v", err)
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	withNow(t, now)
	if needsRenewal(now.Add(2*time.Hour), time.Hour) {
		t.Error("2h left, 1h window: no renewal")
	}
	if !needsRenewal(now.Add(30*time.Minute), time.Hour) {
		t.Error("30m left, 1h window: renewal")
	}
	if !needsRenewal(now.Add(-time.Minute), 0) {
		t.Error("expired: renewal")
	}
}

func TestResolveConfigEnv(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://vault:8200")
	t.Setenv("BAO_ADDR", "http://bao:8200")
	t.Setenv("VAULT_TOKEN", "vt")
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("VAULT_NAMESPACE", "ns")
	t.Setenv("VAULT_SKIP_VERIFY", "true")
	var d diag.Diagnostics
	cfg := resolveConfig(providerModel{}, &d)
	if d.HasError() {
		t.Fatal(d)
	}
	want := transitConfig{Address: "http://bao:8200", Token: "vt", Namespace: "ns", Mount: "transit", SkipTLSVerify: true}
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
	cfg = resolveConfig(providerModel{
		Address:       types.StringValue("https://cfg:8200"),
		TransitMount:  types.StringValue("pki/transit"),
		SkipTLSVerify: types.BoolValue(false),
	}, &d)
	if cfg.Address != "https://cfg:8200" || cfg.Mount != "pki/transit" || cfg.SkipTLSVerify {
		t.Fatalf("config should win over env: %+v", cfg)
	}
	t.Setenv("VAULT_SKIP_VERIFY", "maybe")
	resolveConfig(providerModel{}, &d)
	if !d.HasError() {
		t.Fatal("invalid skip verify env should be an error")
	}
}

func TestCertVersion(t *testing.T) {
	for v, want := range map[int64]cert.Version{1: cert.Version1, 2: cert.Version2} {
		if got, err := certVersion(v); err != nil || got != want {
			t.Errorf("certVersion(%d) = %v, %v", v, got, err)
		}
	}
	for _, v := range []int64{0, 3, 258} {
		if _, err := certVersion(v); err == nil {
			t.Errorf("certVersion(%d) should fail", v)
		}
	}
}
