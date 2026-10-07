package server

// Native TLS of secagent-server (#175): TLS_CERT / TLS_KEY on the API (7770) and WebSocket (7772)
// listeners, fail closed, certificates validated BEFORE any port opens, hot reload without cutting
// the connections that are already established.
//
// Decisions:
//   - Admin port (7771): TLS only with ADMIN_TLS=true (same pair, same reload). Without it the
//     admin API stays plain HTTP and MUST be bound to loopback or to the admin network
//     (ADMIN_ADDR); a non-loopback bind without ADMIN_TLS logs a [SECURITY WARNING]. The CLI talks
//     to it through RELAY_API_URL (the CLI already refuses plain http:// to a non-local address).
//   - Reload: the pair is re-read when the CONTENT of either file changes (SHA-256, polled every
//     TLSReloadInterval, 60 s by default) or on SIGHUP. Content, not mtime/size: a replacement
//     within the same second and with the same size must be seen. An invalid new pair keeps the
//     previous one and logs a [SECURITY WARNING].
//   - NextProtos is http/1.1 only: HTTP/2 would break the WebSocket upgrade.
//   - Errors and logs name files and reasons, never key material.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// Environment variables of the TLS configuration.
const (
	EnvTLSCert    = "TLS_CERT"
	EnvTLSKey     = "TLS_KEY"
	EnvTLSDisable = "TLS_DISABLE" // "true" only: tests and local CI, never a default
	EnvAdminTLS   = "ADMIN_TLS"   // "true": the admin port also serves TLS
	// EnvAdminInsecureHTTP + EnvAdminInsecureHTTPAck: the explicit, double-confirmed derogation that
	// lets the admin port serve plain HTTP on a NON-loopback address (same model as the inventory's
	// RELAY_INSECURE_TLS + RELAY_INSECURE_TLS_ACK). Never a default.
	EnvAdminInsecureHTTP    = "ADMIN_INSECURE_HTTP"
	EnvAdminInsecureHTTPAck = "ADMIN_INSECURE_HTTP_ACK"
)

// AdminInsecureHTTPAckValue is the exact phrase ADMIN_INSECURE_HTTP_ACK must carry.
const AdminInsecureHTTPAckValue = "i-understand-the-risk"

// DefaultTLSReloadInterval is how often the certificate files are checked for a change.
const DefaultTLSReloadInterval = 60 * time.Second

// certExpirySoon is the remaining validity under which a startup warning is logged.
const certExpirySoon = 14 * 24 * time.Hour

// ErrTLSNotConfigured is returned when neither a certificate pair nor TLS_DISABLE=true is given.
var ErrTLSNotConfigured = errors.New("TLS is required: set TLS_CERT and TLS_KEY (PEM files), or TLS_DISABLE=true for tests only")

// certStore holds the pair currently served, replaced atomically on reload.
type certStore struct {
	certPath, keyPath string
	cur               atomic.Pointer[tls.Certificate]
	fingerprint       atomic.Pointer[[sha256.Size]byte] // of both files' content
	now               func() time.Time
}

// loadPair reads and validates a pair: both files readable, valid PEM, key matching the
// certificate, leaf parseable and not expired. It returns a clear error that never contains key
// material.
func (s *certStore) loadPair() (*tls.Certificate, [sha256.Size]byte, error) {
	var fp [sha256.Size]byte
	certPEM, err := os.ReadFile(s.certPath)
	if err != nil {
		return nil, fp, fmt.Errorf("%s: cannot read the certificate file %q: %v", EnvTLSCert, s.certPath, errReason(err))
	}
	keyPEM, err := os.ReadFile(s.keyPath)
	if err != nil {
		return nil, fp, fmt.Errorf("%s: cannot read the key file %q: %v", EnvTLSKey, s.keyPath, errReason(err))
	}
	fp = sha256.Sum256(append(append([]byte{}, certPEM...), keyPEM...))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// tls errors describe the problem ("failed to find any PEM data", "private key does not
		// match public key") without echoing any content
		return nil, fp, fmt.Errorf("invalid certificate/key pair (%s, %s): %v", s.certPath, s.keyPath, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fp, fmt.Errorf("invalid certificate %s: %v", s.certPath, err)
	}
	now := s.now()
	if now.After(leaf.NotAfter) {
		return nil, fp, fmt.Errorf("the certificate %s expired on %s", s.certPath, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fp, fmt.Errorf("the certificate %s is not valid before %s", s.certPath, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	pair.Leaf = leaf
	return &pair, fp, nil
}

// errReason keeps the reason of a file error without the path twice.
func errReason(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// warnKeyPermissions logs a [SECURITY WARNING] when the private key is readable by others.
func warnKeyPermissions(keyPath string) {
	fi, err := os.Stat(keyPath)
	if err != nil {
		return
	}
	if fi.Mode().Perm()&0o077 != 0 {
		log.Printf("[SECURITY WARNING] %s %q is accessible to other users (mode %04o): restrict it to the server user (chmod 600)", EnvTLSKey, keyPath, fi.Mode().Perm())
	}
}

// newCertStore loads and validates the pair; any problem is an error (the server must not start).
func newCertStore(certPath, keyPath string, now func() time.Time) (*certStore, error) {
	if now == nil {
		now = time.Now
	}
	s := &certStore{certPath: certPath, keyPath: keyPath, now: now}
	pair, fp, err := s.loadPair()
	if err != nil {
		return nil, err
	}
	s.cur.Store(pair)
	s.fingerprint.Store(&fp)
	warnKeyPermissions(keyPath)
	if left := pair.Leaf.NotAfter.Sub(now()); left < certExpirySoon {
		log.Printf("[WARN] the TLS certificate expires in %s (%s): renew it", left.Round(time.Hour), pair.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return s, nil
}

// reload re-reads the pair when its content changed. force re-reads without comparing (SIGHUP).
// An invalid new pair keeps the previous one: warning, no cut, no error to the caller.
func (s *certStore) reload(force bool) (changed bool) {
	certPEM, err1 := os.ReadFile(s.certPath)
	keyPEM, err2 := os.ReadFile(s.keyPath)
	if err1 == nil && err2 == nil && !force {
		fp := sha256.Sum256(append(append([]byte{}, certPEM...), keyPEM...))
		if old := s.fingerprint.Load(); old != nil && *old == fp {
			return false
		}
	}
	pair, fp, err := s.loadPair()
	if err != nil {
		log.Printf("[SECURITY WARNING] TLS certificate reload refused, keeping the previous pair: %v", err)
		// remember what was refused so that the same bad content is not re-reported at every poll
		s.fingerprint.Store(&fp)
		return false
	}
	s.cur.Store(pair)
	s.fingerprint.Store(&fp)
	log.Printf("[OK] TLS certificate reloaded (valid until %s)", pair.Leaf.NotAfter.UTC().Format(time.RFC3339))
	warnKeyPermissions(s.keyPath)
	return true
}

// tlsConfig is the minimal server configuration: TLS 1.2+, Go's default cipher suites, the
// certificate read at handshake time, HTTP/1.1 only (WebSocket upgrade).
func (s *certStore) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.cur.Load(), nil
		},
	}
}

// watch polls the files until stop is closed.
func (s *certStore) watch(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = DefaultTLSReloadInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.reload(false)
		}
	}
}

// validateTLSConfig is the fail-closed rule of Build: a complete valid pair, or TLS_DISABLE=true.
func validateTLSConfig(cfg Config) error {
	switch {
	case cfg.TLSCert != "" && cfg.TLSKey != "":
		return nil // loaded (and rejected if invalid) by Build
	case cfg.TLSCert != "" || cfg.TLSKey != "":
		return fmt.Errorf("%s and %s must be set together (only one of them is defined)", EnvTLSCert, EnvTLSKey)
	case cfg.TLSDisable:
		return nil
	default:
		return ErrTLSNotConfigured
	}
}

// prepareTLS validates the configuration and loads the pair BEFORE anything listens.
func (n *Node) prepareTLS() error {
	if err := validateTLSConfig(n.cfg); err != nil {
		return err
	}
	warn, err := adminExposure(n.cfg)
	if err != nil {
		return err
	}
	if warn != "" {
		log.Print(warn)
	}
	if n.cfg.TLSCert == "" {
		log.Printf("[SECURITY WARNING] TLS_DISABLE=true: every listener serves PLAIN HTTP/WS. For tests and local CI only: never in production")
		return nil
	}
	if n.cfg.TLSDisable {
		log.Printf("[SECURITY WARNING] TLS_DISABLE=true is ignored: a certificate pair is configured, TLS stays on")
	}
	cs := n.cfg.certs // already validated by RunInstance, before the lock loop
	if cs == nil {
		var err error
		if cs, err = newCertStore(n.cfg.TLSCert, n.cfg.TLSKey, n.cfg.tlsNow); err != nil {
			return err
		}
	}
	n.certs = cs
	return nil
}

// adminExposure applies the rule of the admin port (#175b): it carries the ADMIN_TOKEN, so plain
// HTTP is only accepted on loopback (127.0.0.0/8, ::1, localhost: the local CLI). On any other
// address the server REFUSES to start unless the admin port serves TLS (ADMIN_TLS=true with a
// certificate pair) or the operator wrote the explicit derogation (ADMIN_INSECURE_HTTP=true AND
// ADMIN_INSECURE_HTTP_ACK=<exact phrase>); the derogation is a [SECURITY WARNING] at every start
// and is ignored when the port is TLS. The message names the two solutions and echoes no value
// other than the (non-secret) address.
func adminExposure(cfg Config) (warning string, err error) {
	haveCert := cfg.TLSCert != "" && cfg.TLSKey != ""
	if cfg.AdminTLS && !haveCert {
		return "", fmt.Errorf("%s=true needs %s and %s (the admin port serves the same certificate pair)", EnvAdminTLS, EnvTLSCert, EnvTLSKey)
	}
	addr := cfg.adminAddr()
	if cfg.AdminListener != nil {
		addr = cfg.AdminListener.Addr().String()
	}
	if cfg.AdminTLS {
		if cfg.AdminInsecureHTTP {
			return fmt.Sprintf("[SECURITY WARNING] %s=true is ignored: the admin port serves TLS (%s=true)", EnvAdminInsecureHTTP, EnvAdminTLS), nil
		}
		return "", nil
	}
	if isLoopbackAddr(addr, nil) {
		return "", nil
	}
	if !cfg.AdminInsecureHTTP {
		return "", fmt.Errorf("the admin API (%s) would serve plain HTTP on a non-loopback address: it carries the admin token. "+
			"Either serve it over TLS (%s=true, with %s/%s), or bind %s to loopback / publish it only on the admin network, "+
			"or, if the network is protected by other means, declare the derogation explicitly: %s=true and %s=%s",
			addr, EnvAdminTLS, EnvTLSCert, EnvTLSKey, EnvAdminAddr, EnvAdminInsecureHTTP, EnvAdminInsecureHTTPAck, AdminInsecureHTTPAckValue)
	}
	if cfg.AdminInsecureHTTPAck != AdminInsecureHTTPAckValue {
		return "", fmt.Errorf("%s=true refused: the admin API (%s) is not loopback; confirm the plain-HTTP exposure with %s=%s",
			EnvAdminInsecureHTTP, addr, EnvAdminInsecureHTTPAck, AdminInsecureHTTPAckValue)
	}
	return fmt.Sprintf("[SECURITY WARNING] the admin API serves PLAIN HTTP on %s (derogation %s): the admin token crosses the network in clear; restrict access to the admin network", addr, EnvAdminInsecureHTTP), nil
}

// isLoopbackAddr reports whether the admin listener is loopback-only.
func isLoopbackAddr(addr string, ln net.Listener) bool {
	if ln != nil {
		addr = ln.Addr().String()
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// applyTLS configures a server to serve TLS from the store (admin only when ADMIN_TLS=true).
func (n *Node) applyTLS(srv *http.Server, admin bool) bool {
	if n.certs == nil || (admin && !n.cfg.AdminTLS) {
		return false
	}
	srv.TLSConfig = n.certs.tlsConfig()
	srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){} // no HTTP/2
	return true
}

// ReloadTLS forces a re-read of the certificate pair (also triggered by SIGHUP). It reports
// whether a new pair is now served; an invalid pair keeps the previous one.
func (n *Node) ReloadTLS() bool {
	if n.certs == nil {
		return false
	}
	return n.certs.reload(true)
}
