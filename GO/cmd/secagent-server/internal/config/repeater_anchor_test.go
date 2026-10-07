package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePub(t *testing.T, mode os.FileMode, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return writeRaw(t, mode, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func writeRaw(t *testing.T, mode os.FileMode, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "root.pub")
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadLinkAnchorConfig(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	good := writePub(t, 0o644, pub)

	t.Run("nothing set", func(t *testing.T) {
		c, err := loadLinkAnchorConfig(envOf(nil))
		if c != nil || err != nil {
			t.Fatalf("%v %v", c, err)
		}
	})
	t.Run("key and root id", func(t *testing.T) {
		c, err := loadLinkAnchorConfig(envOf(map[string]string{EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: good}))
		if err != nil || c.RootID != "root" || !c.Key.Equal(pub) {
			t.Fatalf("%+v %v", c, err)
		}
	})
	t.Run("root id alone (key persisted)", func(t *testing.T) {
		c, err := loadLinkAnchorConfig(envOf(map[string]string{EnvRepeaterRootID: "root"}))
		if err != nil || c.Key != nil {
			t.Fatalf("%+v %v", c, err)
		}
	})
	refusals := map[string]map[string]string{
		"key without root id": {EnvRepeaterRootLinkKeyFile: good},
		"bad root id":         {EnvRepeaterRootID: "ro ot", EnvRepeaterRootLinkKeyFile: good},
		"missing file":        {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: filepath.Join(t.TempDir(), "nope")},
		"world writable":      {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: writePub(t, 0o666, pub)},
		"group writable":      {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: writePub(t, 0o664, pub)},
		"directory":           {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: t.TempDir()},
		"not pem":             {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: writeRaw(t, 0o644, []byte("hello"))},
		"private key block":   {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: writeRaw(t, 0o644, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: make([]byte, 48)}))},
		"two blocks": {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: writeRaw(t, 0o644, append(
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustDER(t, pub)}),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustDER(t, pub)})...))},
		"too large": {EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: writeRaw(t, 0o644, []byte(strings.Repeat("a", 5000)))},
	}
	for name, env := range refusals {
		t.Run(name, func(t *testing.T) {
			if _, err := loadLinkAnchorConfig(envOf(env)); !errors.Is(err, ErrInvalidRepeaterConfig) {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(good, link); err != nil {
			t.Skip(err)
		}
		if _, err := loadLinkAnchorConfig(envOf(map[string]string{EnvRepeaterRootID: "root", EnvRepeaterRootLinkKeyFile: link})); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	t.Run("errors never echo the path content", func(t *testing.T) {
		_, err := loadLinkAnchorConfig(envOf(refusals["not pem"]))
		if err == nil || strings.Contains(err.Error(), "hello") {
			t.Fatalf("err = %v", err)
		}
	})
}

func mustDER(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	d, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
