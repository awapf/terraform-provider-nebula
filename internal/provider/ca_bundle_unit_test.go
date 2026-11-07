package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func TestBuildBundleDropsExpired(t *testing.T) {
	f := newFakeTransit(t)
	f.addKey("old")
	f.addKey("new")
	ctx := context.Background()
	old, cur := mustKey(t, f, "old", 1), mustKey(t, f, "new", 1)

	withNow(t, time.Now().Add(-48*time.Hour))
	expired, err := issueCA(old, old.Signer(ctx), certSpec{Version: 2, Name: "old", Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	withNow(t, time.Now())
	valid, err := issueCA(cur, cur.Signer(ctx), certSpec{Version: 2, Name: "new"})
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := expired.MarshalPEM()
	vp, _ := valid.MarshalPEM()

	var d diag.Diagnostics
	bundle, fps := buildBundle([]string{string(ep) + string(vp)}, time.Now(), &d)
	if d.HasError() {
		t.Fatal(d)
	}
	if d.WarningsCount() != 1 || !strings.Contains(d.Warnings()[0].Detail(), "expired") {
		t.Fatalf("want one expiry warning, got %v", d)
	}
	vfp, _ := valid.Fingerprint()
	if len(fps) != 1 || fps[0] != vfp || bundle != string(vp) {
		t.Fatalf("bundle should hold only the valid CA, got %v", fps)
	}
}
