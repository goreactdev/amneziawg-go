package conceal

import (
	"crypto/rand"
	"encoding/binary"
	"net"

	"golang.org/x/net/ipv4"
)

type FramedOpts struct {
	H1 *rangedHeader
	H2 *rangedHeader
	H3 *rangedHeader
	H4 *rangedHeader
	S1 int
	S2 int
	S3 int
	S4 int
}

func (o FramedOpts) HasIntersections() bool {
	headers := []*rangedHeader{o.H1, o.H2, o.H3, o.H4}

	for i := 0; i < len(headers); i++ {
		left := headers[i]
		if left == nil {
			continue
		}

		for j := i + 1; j < len(headers); j++ {
			right := headers[j]
			if right == nil {
				continue
			}

			if left.start <= right.end && right.start <= left.end {
				return true
			}
		}
	}

	return false
}

func newFrameEncoding(opts FramedOpts) (enc frameEncoding, ok bool) {
	enc = frameEncoding{}

	if opts.H1 != nil {
		enc.header.initial = *opts.H1
		ok = true
	}

	if opts.H2 != nil {
		enc.header.response = *opts.H2
		ok = true
	}

	if opts.H3 != nil {
		enc.header.cookie = *opts.H3
		ok = true
	}

	if opts.H4 != nil {
		enc.header.transport = *opts.H4
		ok = true
	}

	if opts.S1 != 0 {
		enc.padding.initial = opts.S1
		ok = true
	}

	if opts.S2 != 0 {
		enc.padding.response = opts.S2
		ok = true
	}

	if opts.S3 != 0 {
		enc.padding.cookie = opts.S3
		ok = true
	}

	if opts.S4 != 0 {
		enc.padding.transport = opts.S4
		ok = true
	}

	return enc, ok
}

type frameEncoding struct {
	header struct {
		initial   rangedHeader
		response  rangedHeader
		cookie    rangedHeader
		transport rangedHeader
	}
	padding struct {
		initial   int
		response  int
		cookie    int
		transport int
	}
}

func encodeOne(b []byte, header rangedHeader, padding int) []byte {
	binary.LittleEndian.PutUint32(b[:4], header.Generate())

	oldLen := len(b)
	b = b[:oldLen+padding]
	copy(b[padding:], b[:oldLen])
	rand.Read(b[:padding])

	return b
}

func (enc frameEncoding) Encode(b []byte) []byte {
	switch b[0] {
	case WireguardMsgInitiationType:
		b = encodeOne(b, enc.header.initial, enc.padding.initial)
	case WireguardMsgResponseType:
		b = encodeOne(b, enc.header.response, enc.padding.response)
	case WireguardMsgCookieReplyType:
		b = encodeOne(b, enc.header.cookie, enc.padding.cookie)
	case WireguardMsgTransportType:
		b = encodeOne(b, enc.header.transport, enc.padding.transport)
	}

	return b
}

func decodeOne(b []byte, header rangedHeader, padding int) (res []byte, ok bool) {
	b = b[padding:]
	return b, header.Validate(binary.LittleEndian.Uint32(b[:4]))
}

func (enc frameEncoding) Decode(b []byte) []byte {
	if len(b) == WireguardMsgInitiationSize+enc.padding.initial {
		if bb, ok := decodeOne(b, enc.header.initial, enc.padding.initial); ok {
			return bb
		}
	}

	if len(b) == WireguardMsgResponseSize+enc.padding.response {
		if bb, ok := decodeOne(b, enc.header.response, enc.padding.response); ok {
			return bb
		}
	}

	if len(b) == WireguardMsgCookieReplySize+enc.padding.cookie {
		if bb, ok := decodeOne(b, enc.header.cookie, enc.padding.cookie); ok {
			return bb
		}
	}

	if len(b) >= WireguardMsgTransportMinSize+enc.padding.transport {
		if bb, ok := decodeOne(b, enc.header.transport, enc.padding.transport); ok {
			return bb
		}
	}

	return b
}

func NewFramedConn(conn net.Conn, opts FramedOpts) (c *FramedConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedConn{
		Conn: conn,
		enc:  enc,
	}, true
}

type FramedConn struct {
	net.Conn
	enc frameEncoding
}

func (c *FramedConn) Read(b []byte) (n int, err error) {
	b = c.enc.Decode(b)
	return c.Conn.Read(b)
}

func (c *FramedConn) Write(b []byte) (n int, err error) {
	b = c.enc.Encode(b)
	return c.Conn.Write(b)
}

func NewFramedUDPConn(conn *net.UDPConn, opts FramedOpts) (c *FramedUDPConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedUDPConn{
		UDPConn: conn,
		enc:     enc,
	}, true
}

type FramedUDPConn struct {
	*net.UDPConn
	enc frameEncoding
}

func (c *FramedUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	b = c.enc.Decode(b)
	return c.UDPConn.ReadMsgUDP(b, oob)
}

func (c *FramedUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	b = c.enc.Encode(b)
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

type FramedBatchConn struct {
	BatchConn
	enc frameEncoding
}

func (c *FramedBatchConn) ReadBatch(ms []ipv4.Message, flags int) (n int, err error) {
	n, err = c.BatchConn.ReadBatch(ms, flags)
	if err != nil {
		return 0, err
	}

	for _, m := range ms[:n] {
		m.Buffers[0] = c.enc.Decode(m.Buffers[0])
	}

	return n, err
}

func (c *FramedBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	for _, m := range ms {
		m.Buffers[0] = c.enc.Encode(m.Buffers[0])
	}

	return c.BatchConn.WriteBatch(ms, flags)
}
