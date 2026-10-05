// Package tlsca builds the TLS client configuration of every OUTBOUND link of the relay (pull link to
// the parent, push dial-out to a child, admin CLI towards the relay API) from REPEATER_CA_FILE (#147).
//
// Rules (fail closed, no knob to relax them):
//   - the CA file REPLACES the system roots: nothing outside it is trusted;
//   - the file is read at start (restart to change it) and refused when unreadable, too large, empty,
//     when it holds anything but PEM CERTIFICATE blocks (a private key in it is refused), or when no
//     certificate in it is currently valid;
//   - there is deliberately no skip-verify option, here or anywhere.
package tlsca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// EnvCAFile is the environment variable naming the PEM bundle of the trusted CAs.
const EnvCAFile = "REPEATER_CA_FILE"

// maxCAFileBytes bounds the file read (a CA bundle is a few KiB).
const maxCAFileBytes = 1 << 20

// ErrInvalidCAFile marks (errors.Is) every refusal of the CA file. The messages carry the path and
// the reason, never the content of the file.
var ErrInvalidCAFile = errors.New("invalid " + EnvCAFile)

// FromEnv builds the client TLS configuration from REPEATER_CA_FILE: nil, nil when unset (system
// roots), an error when set but unusable.
func FromEnv() (*tls.Config, error) {
	return Load(strings.TrimSpace(os.Getenv(EnvCAFile)))
}

// Load builds the client TLS configuration trusting only the certificates of the PEM file path.
// An empty path returns nil, nil (the default configuration applies).
func Load(path string) (*tls.Config, error) {
	return load(path, time.Now())
}

func load(path string, now time.Time) (*tls.Config, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open %q: %v", ErrInvalidCAFile, path, errReason(err))
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot stat %q: %v", ErrInvalidCAFile, path, errReason(err))
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrInvalidCAFile, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %q: %v", ErrInvalidCAFile, path, errReason(err))
	}
	if len(data) > maxCAFileBytes {
		return nil, fmt.Errorf("%w: %q is larger than %d bytes", ErrInvalidCAFile, path, maxCAFileBytes)
	}

	pool := x509.NewCertPool() // NOT SystemCertPool: the file replaces the system roots
	valid := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// a private key (or anything else) in a CA file is a deployment mistake worth refusing
			return nil, fmt.Errorf("%w: %q contains a %q PEM block, only CERTIFICATE blocks are accepted", ErrInvalidCAFile, path, block.Type)
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("%w: %q contains an unparsable certificate", ErrInvalidCAFile, path)
		}
		pool.AddCert(cert)
		if !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) {
			valid++
		}
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("%w: %q contains data that is not a PEM certificate", ErrInvalidCAFile, path)
	}
	if pool.Equal(x509.NewCertPool()) {
		return nil, fmt.Errorf("%w: %q contains no certificate", ErrInvalidCAFile, path)
	}
	if valid == 0 {
		return nil, fmt.Errorf("%w: no certificate of %q is currently valid", ErrInvalidCAFile, path)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// errReason is the OS reason without the path the error already carries.
func errReason(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
