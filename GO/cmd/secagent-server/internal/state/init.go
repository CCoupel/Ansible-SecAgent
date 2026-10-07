package state

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"
)

// InitOptions configures `secagent-server state init`.
type InitOptions struct {
	Dir string
	FS  FS
	// MasterKey is RSA_MASTER_KEY: the RSA private key and the JWT secret are encrypted with it.
	MasterKey string
	// AllowPlaintext lets init run without a master key (secrets written in clear). Test/dev only.
	AllowPlaintext bool
	// RSABits is the RSA key size (default 4096; tests use less to stay fast).
	RSABits int
	Now     func() time.Time
}

// Init creates the initial state: RSA keypair and JWT secret, encrypted when a master key is
// given (refused otherwise unless AllowPlaintext). It never starts a port and writes with the
// same atomic procedure as the engine. It refuses to act when relay.state, relay.state.prev or a
// lock file already exists: initializing over a live state would invalidate every agent.
func Init(o InitOptions) error {
	if o.Dir == "" {
		o.Dir = DefaultStateDir
	}
	if o.FS == nil {
		o.FS = OSFS{}
	}
	if o.RSABits == 0 {
		o.RSABits = 4096
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.MasterKey == "" && !o.AllowPlaintext {
		return errors.New("state init: RSA_MASTER_KEY is required (the RSA private key and the JWT secret are stored encrypted); it is only optional in test mode")
	}
	if o.MasterKey != "" && o.AllowPlaintext {
		return errors.New("state init: --insecure-test-mode is refused while RSA_MASTER_KEY is set (a server holding a master key never accepts clear-text secrets): unset RSA_MASTER_KEY or drop the flag")
	}
	if err := o.FS.MkdirAll(o.Dir, 0o700); err != nil {
		return fmt.Errorf("state init: create %s: %w", o.Dir, err)
	}
	for _, name := range []string{StateFile, PrevFile, LockFile} {
		p := filepath.Join(o.Dir, name)
		ok, err := exists(o.FS, p)
		if err != nil {
			return fmt.Errorf("state init: %w", err)
		}
		if ok {
			return fmt.Errorf("state init: refusing to initialize: %s already exists in STATE_DIR=%s (a state or a master lock is already there)", name, o.Dir)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, o.RSABits)
	if err != nil {
		return fmt.Errorf("state init: RSA key generation: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("state init: marshal RSA key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("state init: JWT secret: %w", err)
	}
	jwtSecret := base64.RawURLEncoding.EncodeToString(secret)

	rsaVal, jwtVal := privPEM, jwtSecret
	var cdc codec
	if o.MasterKey != "" {
		if rsaVal, err = sealSecret(privPEM, o.MasterKey, "rsa_key_current"); err != nil {
			return err
		}
		if jwtVal, err = sealSecret(jwtSecret, o.MasterKey, "jwt_secret_current"); err != nil {
			return err
		}
		opts := Options{MasterKey: o.MasterKey}
		if cdc, err = opts.codec(); err != nil {
			return err
		}
	} else {
		slog.Warn("[SECURITY WARNING] state init without RSA_MASTER_KEY: secrets are written in clear (test mode only)")
	}

	p := newPayload()
	p.ServerConfig["rsa_key_current"] = rsaVal
	p.ServerConfig["jwt_secret_current"] = jwtVal
	data, err := cdc.encode(&p, 1, "state-init", now())
	if err != nil {
		return err
	}
	if int64(len(data)) > DefaultMaxBytes {
		return ErrTooLarge
	}
	if err := atomicCreate(o.FS, o.Dir, data); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return fmt.Errorf("state init: refusing to initialize: %s already exists in STATE_DIR=%s (a concurrent init won, or a state is already there)", StateFile, o.Dir)
		}
		return err
	}
	slog.Info("state initialized", "dir", o.Dir, "encrypted", o.MasterKey != "")
	return nil
}

// sealSecret encrypts a server_config secret bound to its field name (AAD).
func sealSecret(plain, masterKey, field string) (string, error) {
	v, err := SealSecret(plain, masterKey, ConfigAAD(field))
	if err != nil {
		return "", fmt.Errorf("state init: %w", err)
	}
	return v, nil
}
