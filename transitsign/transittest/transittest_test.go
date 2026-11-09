package transittest_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
)

func TestServerServesKeysAndRecordsRequests(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k, err := s.Client(t).Key(context.Background(), "ca", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Signer(context.Background())([]byte("x")); err != nil {
		t.Fatal(err)
	}
	reqs := s.Requests()
	if len(reqs) != 2 {
		t.Fatalf("want 2 requests, got %v", reqs)
	}
	if reqs[0].Method != http.MethodGet || reqs[0].Path != "transit/keys/ca" ||
		reqs[1].Method != http.MethodPost || reqs[1].Path != "transit/sign/ca" {
		t.Fatalf("unexpected requests %v", reqs)
	}
	if s.LastHeaders().Get("X-Vault-Token") != s.Token {
		t.Fatal("token header not recorded")
	}
}

func TestServerSignCount(t *testing.T) {
	s := transittest.NewServer(t)
	s.AddKey("ca")
	k, err := s.Client(t).Key(context.Background(), "ca", 1)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := k.Signer(context.Background())([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.SignCount("ca"); got != 3 {
		t.Fatalf("SignCount = %d, want 3", got)
	}
}
