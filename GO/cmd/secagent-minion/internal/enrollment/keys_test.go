package enrollment

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorePrivateKey_Success(t *testing.T) {
	key := generateTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "agent.pem")

	if err := StorePrivateKey(key, path); err != nil {
		t.Fatalf("StorePrivateKey: %v", err)
	}

	// Le fichier doit exister avec les permissions 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file mode: got %04o, want 0600", info.Mode().Perm())
	}

	// Le contenu doit être du PEM valide.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if !strings.Contains(string(data), "RSA PRIVATE KEY") {
		t.Errorf("key file does not contain expected PEM header")
	}
}

func TestStorePrivateKey_NoTmpFileAfterSuccess(t *testing.T) {
	key := generateTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.pem")

	if err := StorePrivateKey(key, path); err != nil {
		t.Fatalf("StorePrivateKey: %v", err)
	}

	// Aucun fichier .tmp ne doit rester après une écriture réussie.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover tmp file after successful StorePrivateKey: %q", e.Name())
		}
	}
}

func TestStorePrivateKey_CreatesIntermediateDirs(t *testing.T) {
	key := generateTestKey(t)
	dir := t.TempDir()
	// Chemin profond — les répertoires intermédiaires doivent être créés.
	path := filepath.Join(dir, "a", "b", "c", "agent.pem")

	if err := StorePrivateKey(key, path); err != nil {
		t.Fatalf("StorePrivateKey nested path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not found at nested path: %v", err)
	}
}

func TestStorePrivateKey_MkdirFails(t *testing.T) {
	key := generateTestKey(t)

	// Répertoire parent en lecture seule → MkdirAll doit échouer.
	parent := t.TempDir()
	if err := os.Chmod(parent, 0555); err != nil {
		t.Skip("cannot chmod temp dir, skipping: " + err.Error())
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0755) })

	path := filepath.Join(parent, "subdir", "agent.pem")
	err := StorePrivateKey(key, path)
	if err == nil {
		t.Fatal("expected error when parent directory is read-only, got nil")
	}
}

func TestPrivateKeyPEM_ContainsPEMHeader(t *testing.T) {
	key := generateTestKey(t)
	got := PrivateKeyPEM(key)
	if !strings.HasPrefix(got, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("PrivateKeyPEM: missing expected PEM header")
	}
}

// TestStorePrivateKey_WriteError_NoTmpFile vérifie que StorePrivateKey
// ne laisse aucun fichier .tmp sur disque quand l'écriture échoue.
// Détecte la mutation : supprimer os.Remove(tmp) du chemin d'erreur write.
func TestStorePrivateKey_WriteError_NoTmpFile(t *testing.T) {
	// Injecter une erreur d'écriture via la variable de package.
	orig := fileWriteString
	fileWriteString = func(f *os.File, s string) (int, error) {
		return 0, errors.New("injected write error")
	}
	defer func() { fileWriteString = orig }()

	key := generateTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.pem")

	err := StorePrivateKey(key, path)
	if err == nil {
		t.Fatal("expected error from injected write failure, got nil")
	}
	if !strings.Contains(err.Error(), "store private key: write") {
		t.Errorf("expected write error in message, got: %v", err)
	}

	// Le répertoire doit être VIDE : aucun fichier .tmp ne doit subsister.
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("ReadDir: %v", readErr)
	}
	for _, e := range entries {
		t.Errorf("file left on disk after write error: %q — potential key leak (mutation detected?)", e.Name())
	}

	// Le fichier de clef final ne doit pas exister.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("key file must not exist after write error")
	}
}

func TestPublicKeyPEM_ContainsPEMHeader(t *testing.T) {
	key := generateTestKey(t)
	pubPEM, err := PublicKeyPEM(key)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	if !strings.HasPrefix(pubPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("PublicKeyPEM: missing expected PEM header")
	}
}
