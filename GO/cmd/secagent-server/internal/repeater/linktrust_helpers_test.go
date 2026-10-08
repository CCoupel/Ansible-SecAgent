package repeater

import (
	"crypto/ed25519"
	"io"
	"log"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"secagent-server/cmd/secagent-server/internal/auth"
)

func forgeLinkToken(t *testing.T, priv ed25519.PrivateKey, jti string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "root", "sub": "child", "aud": "me", "role": "relay-child", "jti": jti,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = auth.LinkKID(priv.Public().(ed25519.PublicKey))
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func logWriterSwap(w io.Writer) (io.Writer, int) {
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(w)
	return prev, flags
}

func logWriterRestore(w io.Writer, flags int) { log.SetOutput(w); log.SetFlags(flags) }
