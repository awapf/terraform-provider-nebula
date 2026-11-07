package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// Acceptance tests run against a throwaway `bao server -dev` started here.
// They need TF_ACC=1, `bao` on PATH and a terraform or tofu binary (see
// TF_ACC_TERRAFORM_PATH). Without bao they skip.

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"nebula": providerserver.NewProtocol6WithError(New("test")()),
}

var accBao struct {
	addr      string
	rootToken string
	skip      string
}

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	if os.Getenv("TF_ACC") == "" {
		accBao.skip = "TF_ACC not set"
		return m.Run()
	}
	baoBin, err := exec.LookPath("bao")
	if err != nil {
		accBao.skip = "bao not found on PATH"
		return m.Run()
	}
	stop, err := startDevBao(baoBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting bao dev server: %v\n", err)
		return 1
	}
	defer stop()
	return m.Run()
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func startDevBao(baoBin string) (func(), error) {
	// Never talk to a real server: drop anything inherited from the shell.
	for _, e := range []string{"BAO_ADDR", "VAULT_ADDR", "BAO_TOKEN", "VAULT_TOKEN", "BAO_NAMESPACE", "VAULT_NAMESPACE",
		"BAO_CACERT", "VAULT_CACERT", "BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"} {
		_ = os.Unsetenv(e)
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	accBao.addr = fmt.Sprintf("http://127.0.0.1:%d", port)
	accBao.rootToken = "root-" + randHex(8)
	dir, err := os.MkdirTemp("", "nebula-acc-bao-")
	if err != nil {
		return nil, err
	}
	logf, err := os.Create(dir + "/bao.log")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(baoBin, "server", "-dev",
		"-dev-listen-address=127.0.0.1:"+fmt.Sprint(port),
		"-dev-root-token-id="+accBao.rootToken,
		"-dev-no-store-token")
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = append(os.Environ(), "HOME="+dir)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logf.Close()
		_ = os.RemoveAll(dir)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(accBao.addr + "/v1/sys/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			stop()
			return nil, fmt.Errorf("bao did not become healthy at %s", accBao.addr)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := baoRoot(http.MethodPost, "sys/mounts/transit", map[string]any{"type": "transit"}); err != nil {
		stop()
		return nil, err
	}
	// The provider gets a token that may only read public keys and sign,
	// proving the documented minimal policy is enough.
	policy := `path "transit/sign/*" { capabilities = ["update"] }
path "transit/keys/*" { capabilities = ["read"] }`
	if err := baoRoot(http.MethodPut, "sys/policies/acl/nebula-signer", map[string]any{"policy": policy}); err != nil {
		stop()
		return nil, err
	}
	var tok struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := baoRootOut(http.MethodPost, "auth/token/create", map[string]any{
		"policies": []string{"nebula-signer"}, "no_default_policy": true, "ttl": "2h",
	}, &tok); err != nil {
		stop()
		return nil, err
	}
	_ = os.Setenv("BAO_ADDR", accBao.addr)
	_ = os.Setenv("BAO_TOKEN", tok.Auth.ClientToken)
	return stop, nil
}

func baoRoot(method, path string, body any) error {
	return baoRootOut(method, path, body, nil)
}

func baoRootOut(method, path string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), method, accBao.addr+"/v1/"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", accBao.rootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// testAccPreCheck skips when the dev server is unavailable.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if accBao.skip != "" {
		t.Skipf("acceptance test skipped: %s", accBao.skip)
	}
}

// accTransitKey creates a fresh non-exportable ed25519 transit key.
func accTransitKey(t *testing.T) string {
	t.Helper()
	testAccPreCheck(t)
	name := "nebula-ca-" + randHex(4)
	if err := baoRoot(http.MethodPost, "transit/keys/"+name, map[string]any{"type": "ed25519", "exportable": false}); err != nil {
		t.Fatal(err)
	}
	return name
}

// accRotateKey adds a new version to a transit key.
func accRotateKey(t *testing.T, name string) {
	t.Helper()
	if err := baoRoot(http.MethodPost, "transit/keys/"+name+"/rotate", map[string]any{}); err != nil {
		t.Fatal(err)
	}
}
