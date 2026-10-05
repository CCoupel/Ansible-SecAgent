package repeater

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/internal/endpoints"
)

// markSentConn tells endpoints.DialFirst that request bytes are leaving: the contract of a dial
// that writes by itself (here the WebSocket upgrade written by gorilla). It marks at the FIRST
// write on the connection ESTABLISHED (TLS handshake done): a failure before that (refusal,
// handshake, certificate) stays "before send" and the next address is tried; a timeout after the
// upgrade request left is "after send" and is NOT replayed on another address.
type markSentConn struct {
	net.Conn
	ctx  context.Context
	once sync.Once
}

func (c *markSentConn) Write(p []byte) (int, error) {
	c.once.Do(func() { endpoints.MarkSent(c.ctx) })
	return c.Conn.Write(p)
}

// dialWS opens the WebSocket u + path with header hdr. ctx must be the context received by the
// dial function of endpoints.DialFirst (it carries the "sent" flag).
func dialWS(ctx context.Context, u *url.URL, path string, tlsCfg *tls.Config, hdr http.Header, handshakeTimeout time.Duration) (*websocket.Conn, error) {
	target := *u
	target.Path = strings.TrimRight(u.Path, "/") + path
	cfg := tlsOrDefault(tlsCfg).Clone()
	// The deadline normally comes from ctx (the per-address bound of DialFirst): the expiry is then a
	// context.DeadlineExceeded, which DialFirst reads as "before send" UNLESS markSentConn flagged the
	// upgrade request as written. handshakeTimeout only applies to a ctx without deadline.
	if _, has := ctx.Deadline(); has {
		handshakeTimeout = 0
	}
	d := websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := guardedDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			c := cfg
			if c.ServerName == "" {
				host, _, serr := net.SplitHostPort(addr)
				if serr != nil {
					host = addr
				}
				c = cfg.Clone()
				c.ServerName = host
			}
			tc := tls.Client(raw, c)
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return &markSentConn{Conn: tc, ctx: ctx}, nil
		},
	}
	conn, _, err := d.DialContext(ctx, target.String(), hdr)
	return conn, err
}
