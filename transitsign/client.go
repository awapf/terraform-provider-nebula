// Package transitsign issues Nebula certificates with an Ed25519 CA key held
// as a non-exportable key in the OpenBao/Vault transit secrets engine.
//
// The private key never leaves transit: certificates are built locally and
// only their to-be-signed bytes are sent to <mount>/sign/<key>. Every
// signature transit returns is verified against the key's public half before
// it is used. A caller needs only "read" on <mount>/keys/<key> and "update" on
// <mount>/sign/<key>.
package transitsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
)

// DefaultMount is the transit mount path used when Config.Mount is empty.
const DefaultMount = "transit"

// Config configures a Client.
type Config struct {
	// Address is the OpenBao/Vault base URL, http(s)://host[:port].
	Address string
	// Token is sent as X-Vault-Token.
	Token string
	// Namespace, when set, is sent as X-Vault-Namespace.
	Namespace string
	// Mount is the transit mount path; DefaultMount when empty.
	Mount string
	// CACertFile is an optional PEM bundle used to verify the server.
	CACertFile string
	// SkipTLSVerify disables server certificate verification.
	SkipTLSVerify bool
}

// Client is a minimal client for the two transit endpoints needed to sign
// Nebula certificates: reading a key's public half and signing with it.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient validates cfg and returns a Client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("no OpenBao/Vault address configured")
	}
	if cfg.Token == "" {
		return nil, errors.New("no OpenBao/Vault token configured")
	}
	u, err := url.Parse(cfg.Address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid OpenBao/Vault address %q: want http(s)://host[:port]", cfg.Address)
	}
	cfg.Address = strings.TrimRight(cfg.Address, "/")
	cfg.Mount = strings.Trim(cfg.Mount, "/")
	if cfg.Mount == "" {
		cfg.Mount = DefaultMount
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertFile != "" {
		pemBytes, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("reading ca_cert_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ca_cert_file %s contains no PEM certificates", cfg.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.SkipTLSVerify {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // explicit user opt-in
	}
	tr.TLSClientConfig = tlsCfg

	return &Client{
		cfg:  cfg,
		http: &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Address+"/v1/"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.cfg.Token)
	req.Header.Set("X-Vault-Request", "true")
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%s %s: reading response: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		if len(e.Errors) > 0 {
			return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.Join(e.Errors, "; "))
		}
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s %s: decoding response: %w", method, path, err)
	}
	return nil
}

func (c *Client) keyPath(op, name string) string {
	return c.cfg.Mount + "/" + op + "/" + url.PathEscape(name)
}

// Key is one pinned version of an Ed25519 transit key.
type Key struct {
	client     *Client
	Name       string
	Version    int64
	PublicKey  ed25519.PublicKey
	Exportable bool
	Latest     int64
}

// Key reads the public half of version `version` of transit key `name`. It
// requires only "read" on <mount>/keys/<name>.
func (c *Client) Key(ctx context.Context, name string, version int64) (*Key, error) {
	var r struct {
		Data struct {
			Type          string `json:"type"`
			Exportable    bool   `json:"exportable"`
			LatestVersion int64  `json:"latest_version"`
			Keys          map[string]json.RawMessage
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, c.keyPath("keys", name), nil, &r); err != nil {
		return nil, err
	}
	if r.Data.Type != "ed25519" {
		return nil, fmt.Errorf("transit key %q has type %q; Nebula CAs need type ed25519", name, r.Data.Type)
	}
	rawKey, ok := r.Data.Keys[strconv.FormatInt(version, 10)]
	if !ok {
		return nil, fmt.Errorf("transit key %q has no version %d (latest is %d, or the version was trimmed)", name, version, r.Data.LatestVersion)
	}
	var kv struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(rawKey, &kv); err != nil {
		return nil, fmt.Errorf("transit key %q version %d: %w", name, version, err)
	}
	pub, err := base64.StdEncoding.DecodeString(kv.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("transit key %q version %d: public key is not a 32-byte base64 Ed25519 key", name, version)
	}
	return &Key{
		client:     c,
		Name:       name,
		Version:    version,
		PublicKey:  pub,
		Exportable: r.Data.Exportable,
		Latest:     r.Data.LatestVersion,
	}, nil
}

// Signer returns a cert.SignerLambda that signs with the pinned key version
// via <mount>/sign/<name> and verifies every signature locally before use.
func (k *Key) Signer(ctx context.Context) cert.SignerLambda {
	return func(tbs []byte) ([]byte, error) {
		var r struct {
			Data struct {
				Signature string `json:"signature"`
			} `json:"data"`
		}
		err := k.client.do(ctx, http.MethodPost, k.client.keyPath("sign", k.Name), map[string]any{
			"input":       base64.StdEncoding.EncodeToString(tbs),
			"key_version": k.Version,
		}, &r)
		if err != nil {
			return nil, err
		}
		prefix := fmt.Sprintf("vault:v%d:", k.Version)
		if !strings.HasPrefix(r.Data.Signature, prefix) {
			return nil, fmt.Errorf("transit returned a signature without the expected %q prefix", prefix)
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Data.Signature, prefix))
		if err != nil {
			return nil, fmt.Errorf("decoding transit signature: %w", err)
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.PublicKey, tbs, sig) {
			return nil, errors.New("transit returned a signature that does not verify against the key's public key")
		}
		return sig, nil
	}
}
