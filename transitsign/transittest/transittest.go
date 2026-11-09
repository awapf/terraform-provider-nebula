// Package transittest provides an in-memory stand-in for the OpenBao/Vault
// transit endpoints transitsign uses, for tests that must not need a real
// server.
package transittest

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

	"github.com/awapf/terraform-provider-nebula/transitsign"
)

// Request is one request the server received.
type Request struct {
	Method string
	// Path is the API path without the /v1/ prefix, e.g. "transit/sign/ca".
	Path string
}

// Server is a fake transit engine mounted at "transit". It is safe for
// concurrent use.
type Server struct {
	// URL is the server's base URL, for transitsign.Config.Address.
	URL string
	// Token is the only accepted X-Vault-Token.
	Token string

	t            testing.TB
	mu           sync.Mutex
	keys         map[string][]ed25519.PrivateKey // name -> versions (index 0 = v1)
	badSignature bool
	lastHeaders  http.Header
	requests     []Request
	signs        map[string]int
}

// NewServer starts a Server that is closed when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		t:     t,
		Token: "test-token",
		keys:  map[string][]ed25519.PrivateKey{},
		signs: map[string]int{},
	}
	srv := httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// AddKey adds a new version to key name, creating it if needed.
func (s *Server) AddKey(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.t.Fatal(err)
	}
	s.keys[name] = append(s.keys[name], priv)
}

// Client returns a transitsign.Client for this server.
func (s *Server) Client(t testing.TB) *transitsign.Client {
	t.Helper()
	c, err := transitsign.NewClient(s.Config())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Config returns a transitsign.Config pointing at this server.
func (s *Server) Config() transitsign.Config {
	return transitsign.Config{Address: s.URL, Token: s.Token, Mount: "transit"}
}

// SetBadSignature makes sign return signatures from an unrelated key.
func (s *Server) SetBadSignature(bad bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.badSignature = bad
}

// LastHeaders returns the headers of the most recent request.
func (s *Server) LastHeaders() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHeaders.Clone()
}

// Requests returns all requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// SignCount returns how many successful sign calls key name received.
func (s *Server) SignCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signs[name]
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHeaders = r.Header.Clone()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	s.requests = append(s.requests, Request{Method: r.Method, Path: path})
	if r.Header.Get("X-Vault-Token") != s.Token {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != "transit" {
		writeErr(w, http.StatusNotFound, "no handler")
		return
	}
	versions, ok := s.keys[parts[2]]
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
		if s.badSignature {
			_, key, _ = ed25519.GenerateKey(rand.Reader)
		}
		s.signs[parts[2]]++
		sig := ed25519.Sign(key, in)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"signature": fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(sig)),
		}})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "unsupported")
	}
}
