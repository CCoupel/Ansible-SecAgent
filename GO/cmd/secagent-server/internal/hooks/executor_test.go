package hooks

// Tests des exécuteurs d'actions hooks : WebhookExecutor, ShellExecutor,
// FileExecutor, APIExecutor.
//
// Référence : DOC/server/HOOKS_SPEC.md §3
//
// API réelle implémentée dans executor.go :
//
//   Executor interface {
//     Execute(ctx context.Context, action ActionDef, vars map[string]string) (success bool, errMsg string, durationMs int64)
//   }
//
//   WebhookExecutor{client *http.Client}  — pas de constructeur dédié
//   ShellExecutor{}
//   FileExecutor{}
//   APIExecutor{client *http.Client}
//
//   ActionDef.Body est json.RawMessage (pas map[string]interface{})

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ========================================================================
// testVars — variables de template minimales réutilisables
// ========================================================================

func testVars() map[string]string {
	return map[string]string{
		"hostname":    "test-host",
		"event":       "host.new",
		"timestamp":   "2026-05-22T14:30:00Z",
		"status":      "disconnected",
		"enrolled_at": "2026-05-22T14:30:00Z",
	}
}

// ========================================================================
// WebhookExecutor — action "webhook" (HTTP POST + HMAC + retry)
// ========================================================================

// TestWebhookExecutor_success_200
// Serveur répond 200 → success=true, errMsg vide, durationMs >= 0
func TestWebhookExecutor_success_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &WebhookExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "webhook",
		URL:            srv.URL,
		MaxRetries:     0,
		TimeoutSeconds: 5,
	}

	success, errMsg, durationMs := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Errorf("expected success=true, got false (errMsg: %q)", errMsg)
	}
	if errMsg != "" {
		t.Errorf("expected empty errMsg, got %q", errMsg)
	}
	if durationMs < 0 {
		t.Errorf("expected durationMs >= 0, got %d", durationMs)
	}
}

// TestWebhookExecutor_hmac_signature
// Secret non vide → header X-Signature présent, préfixe "sha256=", hex 64 chars
func TestWebhookExecutor_hmac_signature(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &WebhookExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "webhook",
		URL:            srv.URL,
		Secret:         "test-secret",
		MaxRetries:     0,
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	if gotSig == "" {
		t.Fatal("expected X-Signature header, got none")
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Errorf("X-Signature: got %q, want prefix sha256=", gotSig)
	}
	hexPart := strings.TrimPrefix(gotSig, "sha256=")
	if len(hexPart) != 64 {
		t.Errorf("HMAC hex length: got %d, want 64", len(hexPart))
	}
}

// TestWebhookExecutor_no_hmac_no_secret
// Secret vide → header X-Signature absent
func TestWebhookExecutor_no_hmac_no_secret(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &WebhookExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "webhook",
		URL:            srv.URL,
		Secret:         "", // pas de secret
		MaxRetries:     0,
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}
	if gotSig != "" {
		t.Errorf("expected no X-Signature header, got %q", gotSig)
	}
}

// TestWebhookExecutor_retry_on_5xx
// Serveur retourne 500 sur les 2 premiers appels, 200 au 3e →
// max_retries=2 (3 tentatives) → succès final, count=3
func TestWebhookExecutor_retry_on_5xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError) // tentatives 1 et 2 : échec
		} else {
			w.WriteHeader(http.StatusOK) // tentative 3 : succès
		}
	}))
	defer srv.Close()

	exec := &WebhookExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "webhook",
		URL:            srv.URL,
		MaxRetries:     2, // 2 retries → 3 tentatives max
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Errorf("expected success=true after retry, got false (errMsg: %q)", errMsg)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 HTTP calls (max_retries=2), got %d", calls.Load())
	}
}

// TestWebhookExecutor_no_retry_on_4xx
// Serveur retourne 404 → aucun retry, échec immédiat (errMsg préfixé "HTTP 4")
func TestWebhookExecutor_no_retry_on_4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound) // 404 = erreur permanente
	}))
	defer srv.Close()

	exec := &WebhookExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "webhook",
		URL:            srv.URL,
		MaxRetries:     3, // retries configurés mais ne doivent pas s'exécuter
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if success {
		t.Error("expected success=false for 4xx response")
	}
	if !strings.HasPrefix(errMsg, "HTTP 4") {
		t.Errorf("errMsg: got %q, expected prefix HTTP 4", errMsg)
	}
	if calls.Load() != 1 {
		t.Errorf("expected exactly 1 HTTP call (no retry on 4xx), got %d", calls.Load())
	}
}

// TestWebhookExecutor_timeout
// Serveur lent → timeout déclenché, success=false, errMsg non vide
func TestWebhookExecutor_timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // serveur très lent
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &WebhookExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "webhook",
		URL:            srv.URL,
		MaxRetries:     0,
		TimeoutSeconds: 1, // timeout 1 seconde
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if success {
		t.Error("expected success=false on timeout")
	}
	if errMsg == "" {
		t.Error("expected non-empty errMsg on timeout")
	}
}

// ========================================================================
// ShellExecutor — action "shell" (exécution de commande système)
// ========================================================================

// TestShellExecutor_success
// Commande exit 0 → success=true, errMsg vide
func TestShellExecutor_success(t *testing.T) {
	exec := &ShellExecutor{}
	action := ActionDef{
		Type:           "shell",
		Cmd:            "/bin/sh",
		Args:           []string{"-c", "exit 0"},
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Errorf("expected success=true, got false (errMsg: %q)", errMsg)
	}
	if errMsg != "" {
		t.Errorf("expected empty errMsg, got %q", errMsg)
	}
}

// TestShellExecutor_failure
// Commande exit 1 → success=false, errMsg non vide
func TestShellExecutor_failure(t *testing.T) {
	exec := &ShellExecutor{}
	action := ActionDef{
		Type:           "shell",
		Cmd:            "/bin/sh",
		Args:           []string{"-c", "exit 1"},
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if success {
		t.Error("expected success=false for non-zero exit code")
	}
	if errMsg == "" {
		t.Error("expected non-empty errMsg for failed shell command")
	}
}

// TestShellExecutor_env_vars
// Variables d'environnement SECAGENT_* injectées dans le sous-processus
func TestShellExecutor_env_vars(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "env.txt")

	// Script qui capture les variables SECAGENT_* dans un fichier
	script := `printf '%s\n' "$SECAGENT_EVENT" "$SECAGENT_HOSTNAME" "$SECAGENT_STATUS" "$SECAGENT_TIMESTAMP" > ` + outFile

	exec := &ShellExecutor{}
	action := ActionDef{
		Type:           "shell",
		Cmd:            "/bin/sh",
		Args:           []string{"-c", script},
		TimeoutSeconds: 5,
	}

	vars := testVars()
	success, errMsg, _ := exec.Execute(context.Background(), action, vars)
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}

	content := string(data)
	for _, want := range []string{vars["event"], vars["hostname"], vars["status"], vars["timestamp"]} {
		if !strings.Contains(content, want) {
			t.Errorf("env output missing %q; got:\n%s", want, content)
		}
	}
}

// TestShellExecutor_args_rendered
// Les placeholders {{hostname}} dans Args sont remplacés avant exécution
func TestShellExecutor_args_rendered(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "args.txt")

	exec := &ShellExecutor{}
	action := ActionDef{
		Type:           "shell",
		Cmd:            "/bin/sh",
		Args:           []string{"-c", "echo '{{hostname}}' > " + outFile},
		TimeoutSeconds: 5,
	}

	vars := testVars()
	success, errMsg, _ := exec.Execute(context.Background(), action, vars)
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read args output: %v", err)
	}

	got := strings.TrimSpace(string(data))
	if got != vars["hostname"] {
		t.Errorf("rendered arg: got %q, want %q", got, vars["hostname"])
	}
}

// TestShellExecutor_timeout
// Commande longue + timeout court → success=false, errMsg non vide
func TestShellExecutor_timeout(t *testing.T) {
	exec := &ShellExecutor{}
	action := ActionDef{
		Type:           "shell",
		Cmd:            "/bin/sh",
		Args:           []string{"-c", "sleep 10"},
		TimeoutSeconds: 1, // timeout 1 seconde
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if success {
		t.Error("expected success=false on timeout")
	}
	if errMsg == "" {
		t.Error("expected non-empty errMsg on timeout")
	}
}

// ========================================================================
// FileExecutor — action "file" (écriture dans un fichier)
// ========================================================================

// TestFileExecutor_creates_file
// Fichier absent → créé avec le contenu du champ Append
func TestFileExecutor_creates_file(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "events.log")

	exec := &FileExecutor{}
	action := ActionDef{
		Type:   "file",
		Path:   logFile,
		Append: "hello\n",
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Fatal("expected file to be created, but it doesn't exist")
	}
	data, _ := os.ReadFile(logFile)
	if string(data) != "hello\n" {
		t.Errorf("file content: got %q, want %q", string(data), "hello\n")
	}
}

// TestFileExecutor_appends_content
// Fichier existant → contenu ajouté à la fin (mode O_APPEND)
func TestFileExecutor_appends_content(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "events.log")

	// Pré-remplir le fichier
	if err := os.WriteFile(logFile, []byte("line1\n"), 0644); err != nil {
		t.Fatalf("pre-write: %v", err)
	}

	exec := &FileExecutor{}
	action := ActionDef{
		Type:   "file",
		Path:   logFile,
		Append: "line2\n",
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	data, _ := os.ReadFile(logFile)
	want := "line1\nline2\n"
	if string(data) != want {
		t.Errorf("file content: got %q, want %q", string(data), want)
	}
}

// TestFileExecutor_creates_dirs
// Répertoires parents absents → créés automatiquement
func TestFileExecutor_creates_dirs(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "sub", "nested", "events.log")

	exec := &FileExecutor{}
	action := ActionDef{
		Type:   "file",
		Path:   logFile,
		Append: "ok\n",
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Fatal("expected file to exist after creating nested dirs")
	}
}

// TestFileExecutor_template_applied
// Les placeholders dans Append sont remplacés avant écriture dans le fichier
func TestFileExecutor_template_applied(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "events.log")

	exec := &FileExecutor{}
	action := ActionDef{
		Type:   "file",
		Path:   logFile,
		Append: "{{timestamp}} {{event}} {{hostname}}\n",
	}

	vars := testVars()
	success, errMsg, _ := exec.Execute(context.Background(), action, vars)
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	data, _ := os.ReadFile(logFile)
	want := vars["timestamp"] + " " + vars["event"] + " " + vars["hostname"] + "\n"
	if string(data) != want {
		t.Errorf("file content: got %q, want %q", string(data), want)
	}
}

// ========================================================================
// APIExecutor — action "api" (HTTP avec méthode et body configurables)
// ========================================================================

// TestAPIExecutor_get
// Méthode GET, pas de body → requête bien formée, success=true
func TestAPIExecutor_get(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &APIExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "api",
		Method:         "GET",
		URL:            srv.URL + "/status",
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}
	if gotMethod != "GET" {
		t.Errorf("HTTP method: got %q, want GET", gotMethod)
	}
}

// TestAPIExecutor_patch_with_body
// Méthode PATCH avec body JSON → body reçu par le serveur, success=true
func TestAPIExecutor_patch_with_body(t *testing.T) {
	var (
		gotMethod string
		gotBody   []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &APIExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "api",
		Method:         "PATCH",
		URL:            srv.URL + "/hosts/test-host",
		Body:           json.RawMessage(`{"status":"offline"}`),
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}
	if gotMethod != "PATCH" {
		t.Errorf("HTTP method: got %q, want PATCH", gotMethod)
	}
	if len(gotBody) == 0 {
		t.Error("expected non-empty body for PATCH request")
	}
	if !strings.Contains(string(gotBody), "offline") {
		t.Errorf("body missing value: got %q", string(gotBody))
	}
}

// TestAPIExecutor_headers_sent
// Headers additionnels configurés → transmis dans la requête HTTP
func TestAPIExecutor_headers_sent(t *testing.T) {
	var gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &APIExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "api",
		Method:         "GET",
		URL:            srv.URL,
		Headers:        map[string]string{"X-Api-Key": "secret123"},
		TimeoutSeconds: 5,
	}

	success, errMsg, _ := exec.Execute(context.Background(), action, testVars())
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}
	if gotAPIKey != "secret123" {
		t.Errorf("X-Api-Key: got %q, want secret123", gotAPIKey)
	}
}

// TestAPIExecutor_body_template
// Les placeholders {{hostname}} dans le body JSON sont remplacés avant envoi
func TestAPIExecutor_body_template(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := &APIExecutor{client: srv.Client()}
	action := ActionDef{
		Type:           "api",
		Method:         "POST",
		URL:            srv.URL,
		Body:           json.RawMessage(`{"host":"{{hostname}}","event":"{{event}}"}`),
		TimeoutSeconds: 5,
	}

	vars := testVars()
	success, errMsg, _ := exec.Execute(context.Background(), action, vars)
	if !success {
		t.Fatalf("expected success=true, got false (errMsg: %q)", errMsg)
	}

	body := string(gotBody)
	if !strings.Contains(body, vars["hostname"]) {
		t.Errorf("body missing hostname %q; got: %s", vars["hostname"], body)
	}
	if !strings.Contains(body, vars["event"]) {
		t.Errorf("body missing event %q; got: %s", vars["event"], body)
	}
	// Le placeholder brut ne doit plus être présent
	if strings.Contains(body, "{{hostname}}") {
		t.Errorf("body still contains unrendered placeholder {{hostname}}: %s", body)
	}
}

// ── FileExecutor Close-error propagation ─────────────────────────────────────

// fakeWriteCloser is an io.WriteCloser whose Close() returns a controlled error.
type fakeWriteCloser struct {
	buf      strings.Builder
	closeErr error
}

func (f *fakeWriteCloser) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *fakeWriteCloser) Close() error                { return f.closeErr }

// TestFileExecutor_CloseErrorReturnsFailure verifies that an error returned by
// f.Close() on a write-open file is propagated as ok=false. The test uses an
// injectable openFileFn so the failure is deterministic without OS tricks.
// Discriminant: reverting to `_ = f.Close()` makes this test fail (ok stays true).
func TestFileExecutor_CloseErrorReturnsFailure(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeWriteCloser{closeErr: errors.New("disk full on close")}
	exec := &FileExecutor{
		openFileFn: func(_ string, _ int, _ os.FileMode) (io.WriteCloser, error) {
			return fake, nil
		},
	}
	ok, msg, _ := exec.Execute(context.Background(), ActionDef{
		Type:   "file",
		Path:   filepath.Join(dir, "out.txt"),
		Append: "hello",
	}, nil)
	if ok {
		t.Error("expected ok=false when f.Close() fails, got true")
	}
	if !strings.Contains(msg, "disk full on close") {
		t.Errorf("expected error message to contain 'disk full on close', got %q", msg)
	}
}

// TestFileExecutor_CloseSuccessIsOk verifies that a successful write+close
// is still reported as ok=true (non-regression).
func TestFileExecutor_CloseSuccessIsOk(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeWriteCloser{closeErr: nil}
	exec := &FileExecutor{
		openFileFn: func(_ string, _ int, _ os.FileMode) (io.WriteCloser, error) {
			return fake, nil
		},
	}
	ok, msg, _ := exec.Execute(context.Background(), ActionDef{
		Type:   "file",
		Path:   filepath.Join(dir, "out.txt"),
		Append: "world",
	}, nil)
	if !ok {
		t.Errorf("expected ok=true on success, got false (msg=%q)", msg)
	}
	if msg != "" {
		t.Errorf("expected empty msg on success, got %q", msg)
	}
}
