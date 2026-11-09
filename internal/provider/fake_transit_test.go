package provider

import (
	"testing"

	"github.com/awapf/terraform-provider-nebula/transitsign/transittest"
)

// fakeTransit wraps the exported fake transit for the provider's unit tests.
type fakeTransit struct{ *transittest.Server }

func newFakeTransit(t *testing.T) *fakeTransit {
	t.Helper()
	return &fakeTransit{transittest.NewServer(t)}
}

func (f *fakeTransit) addKey(name string) { f.AddKey(name) }

func (f *fakeTransit) client(t *testing.T) *transitClient { return f.Client(t) }
