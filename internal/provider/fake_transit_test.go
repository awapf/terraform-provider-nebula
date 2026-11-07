package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeTransit is an in-memory stand-in for the transit endpoints the
// provider uses, for unit tests that must not need a real OpenBao.
type fakeTransit struct {
	t     *testing.T
	mu    sync.Mutex
	keys  map[string][]ed25519.PrivateKey // name -> versions (index 0 = v1)
	token string
	// badSignature makes sign return a signature from a different key.
	badSignature bool
	// lastHeaders records the headers of the most recent request.
	lastHeaders http.Header
	srv         *httptest.Server
}

func newFakeTransit(t *testing.T) *fakeTransit {
	t.Helper()
	f := &fakeTransit{t: t, keys: map[string][]ed25519.PrivateKey{}, token: "test-token"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTransit) addKey(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	f.keys[name] = append(f.keys[name], priv)
}

func (f *fakeTransit) client(t *testing.T) *transitClient {
	t.Helper()
	c, err := newTransitClient(transitConfig{Address: f.srv.URL, Token: f.token, Mount: "transit"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

func (f *fakeTransit) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastHeaders = r.Header.Clone()
	if r.Header.Get("X-Vault-Token") != f.token {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if len(parts) != 3 || parts[0] != "transit" {
		writeErr(w, http.StatusNotFound, "no handler")
		return
	}
	versions, ok := f.keys[parts[2]]
	if !ok {
		writeErr(w, http.StatusNotFound, "no such key")
		return
	}
	switch {
	case parts[1] == "keys" && r.Method == http.MethodGet:
		keys := map[string]any{}
		for i, k := range versions {
			keys[strconv.Itoa(i+1)] = map[string]any{
				"public_key": base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)),
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"type": "ed25519", "exportable": false, "latest_version": len(versions), "keys": keys,
		}})
	case parts[1] == "sign" && r.Method == http.MethodPost:
		var body struct {
			Input      string `json:"input"`
			KeyVersion int    `json:"key_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		v := body.KeyVersion
		if v == 0 {
			v = len(versions)
		}
		if v < 1 || v > len(versions) {
			writeErr(w, http.StatusBadRequest, "invalid key version")
			return
		}
		in, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		key := versions[v-1]
		if f.badSignature {
			_, key, _ = ed25519.GenerateKey(rand.Reader)
		}
		sig := ed25519.Sign(key, in)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"signature": fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(sig)),
		}})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "unsupported")
	}
}
