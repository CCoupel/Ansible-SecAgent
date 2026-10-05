package enrollment

// Contract test (#182): the field names of POST /api/register are read from the SERVER's own
// request struct (handlers.RegisterRequest) and compared with what this client really sends on
// the wire, step 1 and step 2. The root cause of #182 was a duplicated client with other field
// names (pubkey_pem / response): any client, in this package or copied elsewhere, that drifts from
// the server's tags now fails here. Reuses the idea of PR #184 (field name check).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// serverRegisterFields returns the JSON field names of the server's RegisterRequest, parsed from
// its source (the minion cannot import the server's internal packages).
func serverRegisterFields(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "..", "secagent-server", "internal", "handlers", "register.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse the server contract %s: %v", path, err)
	}
	fields := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "RegisterRequest" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil {
				continue
			}
			raw, _ := strconv.Unquote(fld.Tag.Value)
			if name := strings.Split(reflect.StructTag(raw).Get("json"), ",")[0]; name != "" && name != "-" {
				fields[name] = true
			}
		}
		return false
	})
	if len(fields) == 0 {
		t.Fatal("RegisterRequest not found in the server source: the contract test is blind")
	}
	return fields
}

func keysOf(m map[string]any) []string {
	var k []string
	for name := range m {
		k = append(k, name)
	}
	sort.Strings(k)
	return k
}

func TestEnrollmentFieldNamesMatchTheServerContract(t *testing.T) {
	server := serverRegisterFields(t)
	for _, want := range []string{"hostname", "public_key_pem", "enrollment_token", "challenge_response"} {
		if !server[want] {
			t.Fatalf("the server contract no longer has %q: update this test and the client together (fields: %v)", want, server)
		}
	}

	agentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("request is not a JSON object: %v", err)
			return
		}
		bodies = append(bodies, body)
		if len(bodies) == 1 { // step 1: a real challenge so that the client goes on to step 2
			nonce, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &agentKey.PublicKey, []byte("0123456789abcdef"), nil)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge":             base64.StdEncoding.EncodeToString(nonce),
				"server_public_key_pem": serverPub,
			})
			return
		}
		w.WriteHeader(http.StatusForbidden) // step 2: captured, stop here
	}))
	defer srv.Close()

	_, _ = ReEnroll(context.Background(), Config{
		RegisterURL: srv.URL, Hostname: "contract-host", PrivateKey: agentKey, EnrollmentToken: "contract-token", Insecure: true,
	})
	if len(bodies) != 2 {
		t.Fatalf("expected the two protocol steps on the wire, captured %d", len(bodies))
	}

	wantStep := [][]string{
		{"enrollment_token", "hostname", "public_key_pem"},
		{"challenge_response", "enrollment_token", "hostname", "public_key_pem"},
	}
	for i, body := range bodies {
		step := i + 1
		for name := range body {
			if !server[name] {
				t.Errorf("step %d sends %q, which the server does not read (server fields: %v): the server answers 400 missing_fields", step, name, server)
			}
		}
		if got := keysOf(body); !reflect.DeepEqual(got, wantStep[i]) {
			t.Errorf("step %d sends %v, want exactly %v", step, got, wantStep[i])
		}
		for name, v := range body {
			if s, _ := v.(string); s == "" {
				t.Errorf("step %d: field %q is empty", step, name)
			}
		}
	}
	for _, obsolete := range []string{"pubkey_pem", "response"} {
		for i, body := range bodies {
			if _, ok := body[obsolete]; ok {
				t.Errorf("step %d still sends the obsolete field %q", i+1, obsolete)
			}
		}
	}
}

// There is ONE enrollment client: no other non-test source of the minion builds a register body
// (the duplicated copy of #182 lived in internal/ws).
func TestNoSecondEnrollmentClientInTheMinion(t *testing.T) {
	root := filepath.Join("..", "..") // GO/cmd/secagent-minion
	self, _ := filepath.Abs(".")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if abs, _ := filepath.Abs(filepath.Dir(path)); abs == self {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, marker := range []string{`"pubkey_pem"`, `"public_key_pem"`, `"challenge_response"`, `json:"enrollment_token"`} {
			if strings.Contains(string(b), marker) {
				t.Errorf("%s builds an enrollment request body (%s): use internal/enrollment", path, marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
