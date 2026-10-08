package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	rekeyOld = "rekey-old-master-key"
	rekeyNew = "rekey-new-master-key-0123456789abcdef"
)

// rekeyState builds a state where EVERY encrypted field is populated: all secretConfigKeys (taken from
// the map, so a new secret key is covered automatically) and the token_secret of a push relay.
func rekeyState(t *testing.T) (dir string, plain map[string]string) {
	t.Helper()
	dir = t.TempDir()
	if err := Init(InitOptions{Dir: dir, MasterKey: rekeyOld, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	e, err := Open(Options{Dir: dir, MasterKey: rekeyOld, BeforeWrite: allowAll, Instance: "rekey-test"})
	if err != nil {
		t.Fatal(err)
	}
	plain = map[string]string{}
	if err := e.Mutate(func(tx *Tx) error {
		for k := range secretConfigKeys {
			v := "clear-" + k
			sealed, err := SealSecret(v, rekeyOld, ConfigAAD(k))
			if err != nil {
				return err
			}
			if err := tx.SetConfig(k, sealed); err != nil {
				return err
			}
			plain["server_config/"+k] = v
		}
		push := newRelay("pushy", ModePush)
		sealed, err := SealSecret("push-token", rekeyOld, RelayTokenSecretAAD("pushy"))
		if err != nil {
			return err
		}
		push.TokenSecret = sealed
		plain["relay_nodes/pushy/token_secret"] = "push-token"
		if err := tx.PutRelayNode(push); err != nil {
			return err
		}
		if err := tx.PutAgent(Agent{Hostname: "alpha", PublicKeyPEM: testPEM("alpha"), TokenJTI: "jti-alpha", EnrolledAt: time.Unix(1700000000, 0).UTC()}); err != nil {
			return err
		}
		return tx.PutBlacklist(BlacklistEntry{JTI: "revoked-1", RevokedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC()})
	}); err != nil {
		t.Fatal(err)
	}
	return dir, plain
}

func rekeyOpts(dir string) RekeyOptions {
	return RekeyOptions{Dir: dir, OldKey: rekeyOld, NewKey: rekeyNew, Operator: "tester"}
}

func openPayload(t *testing.T, dir, key string) Payload {
	t.Helper()
	opts := Options{MasterKey: key}
	c, _ := opts.codec()
	m, _, err := c.decode(mustFile(t, filepath.Join(dir, StateFile)), time.Now())
	if err != nil {
		t.Fatalf("open with %q: %v", key, err)
	}
	return m.Payload
}

func TestRekey_RoundTrip_AllEncryptedFieldsReencrypted(t *testing.T) {
	dir, plain := rekeyState(t)
	before := openPayload(t, dir, rekeyOld)
	beforeFields := rekeyedFields(&before)
	if len(beforeFields) != len(secretConfigKeys)+1 {
		t.Fatalf("fixture must populate every encrypted field: %d", len(beforeFields))
	}
	raw := mustFile(t, filepath.Join(dir, StateFile))

	res, err := Rekey(rekeyOpts(dir))
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields != len(plain) || res.SeqAfter != res.SeqBefore+1 || res.Restored {
		t.Fatalf("result = %+v", res)
	}
	// the backup is the verified original, 0600, readable with the OLD key
	bak := filepath.Join(dir, res.BackupFile)
	if !strings.HasPrefix(res.BackupFile, StateFile+".rekey.") || !strings.HasSuffix(res.BackupFile, ".bak") {
		t.Errorf("backup name %q", res.BackupFile)
	}
	if !bytes.Equal(mustFile(t, bak), raw) || mode(t, bak) != 0o600 {
		t.Error("the backup must be the verified original file, mode 0600")
	}
	if _, err := VerifyFile(bak, VerifyOptions{MasterKey: rekeyOld}); err != nil {
		t.Errorf("the backup must open with the old key: %v", err)
	}
	// new key opens it, old key is refused (fail closed)
	if _, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: rekeyNew}); err != nil {
		t.Fatalf("new key: %v", err)
	}
	if _, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: rekeyOld}); !errors.Is(err, ErrAuthentication) {
		t.Errorf("old key must be refused: %v", err)
	}
	if _, err := Open(Options{Dir: dir, MasterKey: rekeyOld}); err == nil {
		t.Error("a node started with the old key must refuse the state")
	}
	// every field: ciphertext changed, cleartext identical
	after := openPayload(t, dir, rekeyNew)
	afterFields := rekeyedFields(&after)
	var paths []string
	for p := range beforeFields {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		b, a := beforeFields[p], afterFields[p]
		if a.Value == "" || a.Value == b.Value {
			t.Errorf("%s: ciphertext not renewed", p)
		}
		got, err := OpenSecret(a.Value, rekeyNew, a.AAD)
		if err != nil || got != plain[p] {
			t.Errorf("%s: cleartext changed (%v)", p, err)
		}
		if _, err := OpenSecret(a.Value, rekeyOld, a.AAD); err == nil {
			t.Errorf("%s still opens with the old key", p)
		}
	}
	// nothing else changed
	wantPlain, _, _ := transformSecrets(before, rekeyOld, "")
	gotPlain, _, _ := transformSecrets(after, rekeyNew, "")
	if !reflect.DeepEqual(wantPlain, gotPlain) {
		t.Error("the cleartext content must be identical")
	}
	// the engine starts with the new key and the data is there
	e := openEngine(t, dir, func(o *Options) { o.MasterKey = rekeyNew })
	if e.Snapshot().AgentCount() != 1 || !e.Snapshot().Blacklisted("revoked-1") {
		t.Error("agents / blacklist lost")
	}
	// journal without any key or value
	j := string(mustFile(t, filepath.Join(dir, RestoreLogFile)))
	if !strings.Contains(j, `"source":"rekey"`) || strings.Contains(j, rekeyNew) || strings.Contains(j, rekeyOld) {
		t.Errorf("journal = %s", j)
	}
}

// Coverage guard: an "enc:" value anywhere else makes the rekey refuse (it would become unreadable).
func TestRekey_RefusesAnEncryptedValueInAnUncoveredField(t *testing.T) {
	dir, _ := rekeyState(t)
	e := openEngine(t, dir, func(o *Options) { o.MasterKey = rekeyOld })
	if err := e.Mutate(func(tx *Tx) error {
		return tx.PutAgent(Agent{Hostname: "sneaky", PublicKeyPEM: testPEM("sneaky"), TokenJTI: "enc:AAAA", EnrolledAt: time.Now().UTC()})
	}); err != nil {
		t.Fatal(err)
	}
	before := listDir(t, dir)
	raw := mustFile(t, filepath.Join(dir, StateFile))
	if _, err := Rekey(rekeyOpts(dir)); !errors.Is(err, ErrRekeyUncovered) {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) || strings.Join(before, ",") != strings.Join(listDir(t, dir), ",") {
		t.Error("nothing may be written")
	}
}

// rekeyedFields must cover every secret key declared by the model: a new secret config key added
// without being re-encrypted would make this fail.
func TestRekey_CoversEveryDeclaredSecretKey(t *testing.T) {
	p := newPayload()
	for k := range secretConfigKeys {
		p.ServerConfig[k] = EncPrefix + "x"
	}
	if got := rekeyedFields(&p); len(got) != len(secretConfigKeys) {
		t.Fatalf("rekeyedFields covers %d of %d secret config keys", len(got), len(secretConfigKeys))
	}
	if err := checkRekeyCoverage(&p); err != nil {
		t.Errorf("declared secret keys must be covered: %v", err)
	}
	p.ServerConfig["brand_new_secret"] = EncPrefix + "x" // not declared in secretConfigKeys
	if err := checkRekeyCoverage(&p); !errors.Is(err, ErrRekeyUncovered) {
		t.Errorf("an undeclared encrypted key must be refused: %v", err)
	}
}

func TestRekey_RefusesSameEmptyAndWrongKeys(t *testing.T) {
	dir, _ := rekeyState(t)
	raw := mustFile(t, filepath.Join(dir, StateFile))
	o := rekeyOpts(dir)
	o.NewKey = rekeyOld
	if _, err := Rekey(o); !errors.Is(err, ErrRekeySameKey) {
		t.Errorf("same key: %v", err)
	}
	o = rekeyOpts(dir)
	o.NewKey = ""
	if _, err := Rekey(o); !errors.Is(err, ErrRekeyNoNewKey) {
		t.Errorf("empty new key: %v", err)
	}
	o = rekeyOpts(dir)
	o.OldKey = "not-the-key"
	if _, err := Rekey(o); !errors.Is(err, ErrAuthentication) {
		t.Errorf("wrong current key: %v", err)
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) {
		t.Error("state modified")
	}
	// idempotence: a second run (new -> new) is refused cleanly
	if _, err := Rekey(rekeyOpts(dir)); err != nil {
		t.Fatal(err)
	}
	o = rekeyOpts(dir)
	o.OldKey = rekeyNew
	if _, err := Rekey(o); !errors.Is(err, ErrRekeySameKey) {
		t.Errorf("re-run: %v", err)
	}
}

func TestRekey_BackupFailureLeavesTheStateIntact(t *testing.T) {
	dir, _ := rekeyState(t)
	raw := mustFile(t, filepath.Join(dir, StateFile))
	o := rekeyOpts(dir)
	o.FS = &faultFS{failAt: 1} // the first operation is the creation of the backup
	if _, err := Rekey(o); err == nil || !strings.Contains(err.Error(), "backup failed") {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) {
		t.Error("state modified although the backup failed")
	}
	for _, n := range listDir(t, dir) {
		if strings.Contains(n, "rekey") {
			t.Errorf("leftover %s", n)
		}
	}
}

func TestRekey_VerificationFailureRestoresTheOriginal(t *testing.T) {
	dir, _ := rekeyState(t)
	raw := mustFile(t, filepath.Join(dir, StateFile))
	o := rekeyOpts(dir)
	o.afterWrite = func(fs FS, d string) { // corrupt the new file after it was written
		p := filepath.Join(d, StateFile)
		b, _ := os.ReadFile(p)
		b[len(b)/2] ^= 0x01
		_ = os.WriteFile(p, b, 0o600)
	}
	res, err := Rekey(o)
	if !errors.Is(err, ErrRekeyVerify) || res == nil || !res.Restored {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) {
		t.Error("the original must be put back")
	}
	if _, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: rekeyOld}); err != nil {
		t.Errorf("restored state must open with the old key: %v", err)
	}
}

// The guard re-reads the lock right before the rename: the replacement is abandoned, the original is
// untouched and the backup kept.
func TestRekey_GuardAbandonsBeforeTheRename(t *testing.T) {
	dir, _ := rekeyState(t)
	raw := mustFile(t, filepath.Join(dir, StateFile))
	o := rekeyOpts(dir)
	o.BeforeRename = func() error { return ErrInstanceAppeared }
	res, err := Rekey(o)
	if !errors.Is(err, ErrInstanceAppeared) || res == nil || res.BackupFile == "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) {
		t.Error("relay.state must be untouched")
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, res.BackupFile))) {
		t.Error("the backup must be kept")
	}
}

// Secrets never appear in errors or in the result.
func TestRekey_NeverEchoesAKey(t *testing.T) {
	dir, _ := rekeyState(t)
	o := rekeyOpts(dir)
	o.OldKey = "wrong-" + rekeyOld
	_, err := Rekey(o)
	if err == nil || strings.Contains(err.Error(), rekeyNew) || strings.Contains(err.Error(), rekeyOld) {
		t.Errorf("error = %v", err)
	}
}

func TestRekey_NewKeyMinimumLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		ok   bool
	}{
		{"one byte", "x", false},
		{"31 bytes", strings.Repeat("k", 31), false},
		{"32 bytes", strings.Repeat("k", 32), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := rekeyState(t) // the current key (rekeyOld) is shorter than 32 bytes: it stays openable
			raw := mustFile(t, filepath.Join(dir, StateFile))
			o := rekeyOpts(dir)
			o.NewKey = tc.key
			_, err := Rekey(o)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrRekeyKeyTooShort) {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), tc.key) && len(tc.key) > 1 {
				t.Errorf("the message must not echo the key: %v", err)
			}
			if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) {
				t.Error("state modified")
			}
			for _, n := range listDir(t, dir) {
				if strings.Contains(n, "rekey") {
					t.Errorf("leftover %s", n)
				}
			}
		})
	}
}
