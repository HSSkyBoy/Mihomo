package outbound

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	tlsC "github.com/metacubex/tls"
	"golang.org/x/net/http2"
)

// naiveFirstPaddings is the number of leading frames padded in each direction,
// matching NaïveProxy's padded-HTTP scheme.
const naiveFirstPaddings = 8

type Naive struct {
	*Base
	user      string
	pass      string
	padding   bool
	tlsConfig *tlsC.Config
	option    *NaiveOption
}

type NaiveOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	UserName       string `proxy:"username,omitempty"`
	Password       string `proxy:"password,omitempty"`
	SNI            string `proxy:"sni,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string `proxy:"fingerprint,omitempty"`
	Padding        *bool  `proxy:"padding,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (n *Naive) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := n.dialer.DialContext(ctx, "tcp", n.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", n.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = n.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(c, n), nil
}

// StreamConnContext implements C.ProxyAdapter
func (n *Naive) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	tlsConn := tlsC.Client(c, n.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("%s tls handshake error: %w", n.addr, err)
	}

	transport := &http2.Transport{}
	clientConn, err := transport.NewClientConn(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("%s h2 error: %w", n.addr, err)
	}

	addr := metadata.RemoteAddress()
	header := http.Header{}
	if n.user != "" {
		auth := n.user + ":" + n.pass
		header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	if n.padding {
		header.Set("padding", randomPaddingHeader())
	}

	reader, writer := io.Pipe()
	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: addr},
		Host:   addr,
		Header: header,
		Body:   reader,
	}).WithContext(ctx)

	resp, err := clientConn.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", n.addr, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s connect failed, status: %d", n.addr, resp.StatusCode)
	}

	conn := &naiveConn{
		reader: resp.Body,
		writer: writer,
		conn:   tlsConn,
	}
	// Pad only when the server acknowledges padding support.
	if n.padding && resp.Header.Get("padding") != "" {
		return &naivePaddingConn{Conn: conn}, nil
	}
	return conn, nil
}

// ProxyInfo implements C.ProxyAdapter
func (n *Naive) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

func NewNaive(option NaiveOption) (*Naive, error) {
	sni := option.Server
	if option.SNI != "" {
		sni = option.SNI
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tlsC.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         sni,
			NextProtos:         []string{"h2"},
		},
		Fingerprint: option.Fingerprint,
	})
	if err != nil {
		return nil, err
	}

	padding := true
	if option.Padding != nil {
		padding = *option.Padding
	}

	outbound := &Naive{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Naive,
			ProviderName: option.ProviderName,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		user:      option.UserName,
		pass:      option.Password,
		padding:   padding,
		tlsConfig: tlsConfig,
		option:    &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

// naiveConn bridges the HTTP/2 CONNECT stream (a read half from the response
// body and a write half feeding the request body pipe) into a net.Conn.
type naiveConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	conn   net.Conn
}

func (c *naiveConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *naiveConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *naiveConn) Close() error {
	_ = c.writer.Close()
	_ = c.reader.Close()
	return c.conn.Close()
}

func (c *naiveConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *naiveConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *naiveConn) SetDeadline(t time.Time) error      { return nil }
func (c *naiveConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *naiveConn) SetWriteDeadline(t time.Time) error { return nil }

// naivePaddingConn applies NaïveProxy's leading-frame padding: for the first
// naiveFirstPaddings frames in each direction, the wire frame is
// [uint16 payloadLen][uint8 paddingLen][payload][padding].
type naivePaddingConn struct {
	net.Conn
	readCount  int
	writeCount int
	readBuf    []byte
}

func (c *naivePaddingConn) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 && c.writeCount < naiveFirstPaddings {
		payloadSize := len(b)
		if payloadSize > 65535 {
			payloadSize = 65535
		}
		paddingSize := int(randomByte())
		frame := make([]byte, 3+payloadSize+paddingSize)
		binary.BigEndian.PutUint16(frame[0:2], uint16(payloadSize))
		frame[2] = byte(paddingSize)
		copy(frame[3:], b[:payloadSize])
		if _, err := c.Conn.Write(frame); err != nil {
			return written, err
		}
		written += payloadSize
		b = b[payloadSize:]
		c.writeCount++
	}
	if len(b) > 0 {
		nn, err := c.Conn.Write(b)
		return written + nn, err
	}
	return written, nil
}

func (c *naivePaddingConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		nn := copy(b, c.readBuf)
		c.readBuf = c.readBuf[nn:]
		return nn, nil
	}
	if c.readCount >= naiveFirstPaddings {
		return c.Conn.Read(b)
	}
	header := make([]byte, 3)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}
	payloadSize := int(binary.BigEndian.Uint16(header[0:2]))
	paddingSize := int(header[2])
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}
	if paddingSize > 0 {
		if _, err := io.CopyN(io.Discard, c.Conn, int64(paddingSize)); err != nil {
			return 0, err
		}
	}
	c.readCount++
	nn := copy(b, payload)
	if nn < len(payload) {
		c.readBuf = payload[nn:]
	}
	return nn, nil
}

func randomByte() byte {
	var buf [1]byte
	_, _ = rand.Read(buf[:])
	return buf[0]
}

func randomPaddingHeader() string {
	var lengthBuf [1]byte
	_, _ = rand.Read(lengthBuf[:])
	length := 16 + int(lengthBuf[0]%17) // 16..32
	buf := make([]byte, length)
	_, _ = rand.Read(buf)
	const charset = "-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range buf {
		buf[i] = charset[int(buf[i])%len(charset)]
	}
	return string(buf)
}
