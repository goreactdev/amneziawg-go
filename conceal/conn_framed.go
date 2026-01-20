package conceal

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"

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

func (o *FramedOpts) HasIntersections() bool {
	headers := []*rangedHeader{o.H1, o.H2, o.H3, o.H4}

	for i := range len(headers) {
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

func newFrameEncoding(opts FramedOpts) (e frameEncoding, ok bool) {
	e = frameEncoding{}

	if opts.H1 != nil {
		e.header.initial = *opts.H1
		ok = true
	} else {
		e.header.initial = rangedHeader{WireguardMsgInitiationType, WireguardMsgInitiationType}
	}

	if opts.H2 != nil {
		e.header.response = *opts.H2
		ok = true
	} else {
		e.header.response = rangedHeader{WireguardMsgResponseType, WireguardMsgResponseType}
	}

	if opts.H3 != nil {
		e.header.cookie = *opts.H3
		ok = true
	} else {
		e.header.cookie = rangedHeader{WireguardMsgCookieReplyType, WireguardMsgCookieReplyType}
	}

	if opts.H4 != nil {
		e.header.transport = *opts.H4
		ok = true
	} else {
		e.header.transport = rangedHeader{WireguardMsgTransportType, WireguardMsgTransportType}
	}

	if opts.S1 != 0 {
		e.padding.initial = opts.S1
		ok = true
	}

	if opts.S2 != 0 {
		e.padding.response = opts.S2
		ok = true
	}

	if opts.S3 != 0 {
		e.padding.cookie = opts.S3
		ok = true
	}

	if opts.S4 != 0 {
		e.padding.transport = opts.S4
		ok = true
	}

	return e, ok
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
	compat bool
}

func (e *frameEncoding) encodeOne(dst, src []byte, header rangedHeader, padding int) int {
	rand.Read(dst[:padding])
	n := copy(dst[padding:], src)

	if !e.compat {
		binary.LittleEndian.PutUint32(dst[padding:padding+4], header.Generate())
	}

	return padding + n
}

func (e *frameEncoding) Encode(dst, src []byte) int {
	header := binary.LittleEndian.Uint32(src[:4])
	if e.compat {
		if e.header.initial.Validate(header) {
			return e.encodeOne(dst, src, e.header.initial, e.padding.initial)
		} else if e.header.response.Validate(header) {
			return e.encodeOne(dst, src, e.header.response, e.padding.response)
		} else if e.header.cookie.Validate(header) {
			return e.encodeOne(dst, src, e.header.cookie, e.padding.cookie)
		} else if e.header.transport.Validate(header) {
			return e.encodeOne(dst, src, e.header.transport, e.padding.transport)
		}
	} else {
		switch src[0] {
		case WireguardMsgInitiationType:
			return e.encodeOne(dst, src, e.header.initial, e.padding.initial)
		case WireguardMsgResponseType:
			return e.encodeOne(dst, src, e.header.response, e.padding.response)
		case WireguardMsgCookieReplyType:
			return e.encodeOne(dst, src, e.header.cookie, e.padding.cookie)
		case WireguardMsgTransportType:
			return e.encodeOne(dst, src, e.header.transport, e.padding.transport)
		}
	}

	return 0
}

func (e *frameEncoding) decodeOne(b []byte, header rangedHeader, padding int, originalHeader uint32) (res []byte, ok bool) {
	bb := b[padding:]
	if !header.Validate(binary.LittleEndian.Uint32(bb[:4])) {
		return nil, false
	}

	n := copy(b, bb)
	b = b[:n]

	if !e.compat {
		binary.LittleEndian.PutUint32(b[:4], originalHeader)
	}

	return b, true
}

func (e *frameEncoding) Decode(b []byte) []byte {
	if len(b) == WireguardMsgInitiationSize+e.padding.initial {
		if bb, ok := e.decodeOne(b, e.header.initial, e.padding.initial, WireguardMsgInitiationType); ok {
			return bb
		}
	}

	if len(b) == WireguardMsgResponseSize+e.padding.response {
		if bb, ok := e.decodeOne(b, e.header.response, e.padding.response, WireguardMsgResponseType); ok {
			return bb
		}
	}

	if len(b) == WireguardMsgCookieReplySize+e.padding.cookie {
		if bb, ok := e.decodeOne(b, e.header.cookie, e.padding.cookie, WireguardMsgCookieReplyType); ok {
			return bb
		}
	}

	if len(b) >= WireguardMsgTransportMinSize+e.padding.transport {
		if bb, ok := e.decodeOne(b, e.header.transport, e.padding.transport, WireguardMsgTransportType); ok {
			return bb
		}
	}

	return b
}

func NewFramedConn(conn net.Conn, pool *sync.Pool, opts FramedOpts) (c *FramedConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedConn{
		Conn: conn,
		pool: WrapBufferPool(pool),
		enc:  enc,
	}, true
}

type FramedConn struct {
	net.Conn
	pool *BufferPool
	enc  frameEncoding
}

func (c *FramedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	b = c.enc.Decode(b[:n])
	return len(b), err
}

func (c *FramedConn) Write(b []byte) (n int, err error) {
	t := c.pool.Get()
	defer c.pool.Put(t)

	n = c.enc.Encode(t, b)
	diff := n - len(b)
	n, err = c.Conn.Write(t)

	return max(n-diff, 0), err
}

func NewFramedUDPConn(conn UDPConn, pool *sync.Pool, opts FramedOpts) (c UDPConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedUDPConn{
		UDPConn: conn,
		pool:    WrapBufferPool(pool),
		enc:     enc,
	}, true
}

type FramedUDPConn struct {
	UDPConn
	pool *BufferPool
	enc  frameEncoding
}

func (c *FramedUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
	b = c.enc.Decode(b[:n])
	return len(b), oobn, flags, addr, err
}

func (c *FramedUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	t := c.pool.Get()
	defer c.pool.Put(t)

	n = c.enc.Encode(t, b)
	diff := n - len(b)
	n, oobn, err = c.UDPConn.WriteMsgUDP(t[:n], oob, addr)

	return max(n-diff, 0), oobn, err
}

func NewFramedBatchConn(conn BatchConn, pool *sync.Pool, opts FramedOpts) (c BatchConn, ok bool) {
	enc, ok := newFrameEncoding(opts)
	if !ok {
		return nil, false
	}

	return &FramedBatchConn{
		BatchConn: conn,
		pool:      WrapBufferPool(pool),
		enc:       enc,
	}, true
}

type FramedBatchConn struct {
	BatchConn
	pool *BufferPool
	enc  frameEncoding
}

func (c *FramedBatchConn) ReadBatch(ms []ipv4.Message, flags int) (n int, err error) {
	n, err = c.BatchConn.ReadBatch(ms, flags)

	for i := range ms[:n] {
		b := ms[i].Buffers[0][:ms[i].N]
		b = c.enc.Decode(b)
		ms[i].N = len(b)
	}

	return n, err
}

func (c *FramedBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	for i := range ms {
		t := c.pool.Get()
		defer c.pool.Put(t)

		n = c.enc.Encode(t, ms[i].Buffers[0])
		ms[i].Buffers[0] = t[:n]
	}

	// ms[x].N has incorrect N because the original data was modifier above
	// however, WG does not check this field, so this is fine
	return c.BatchConn.WriteBatch(ms, flags)
}
