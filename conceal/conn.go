package conceal

import (
	"bytes"
	"net"
	"sync"
)

type ObfuscatedConn struct {
	net.Conn
	obfsIn  Obfs
	obfsOut Obfs
	bufs    BufferPool
}

type ObfuscatedConnOpts struct {
	ObfsIn  Obfs
	ObfsOut Obfs
}

func NewObfuscatedConn(conn net.Conn, opts ObfuscatedConnOpts) *ObfuscatedConn {
	if opts.ObfsIn == nil && opts.ObfsOut == nil {
		return nil
	}

	return &ObfuscatedConn{
		Conn:    conn,
		obfsIn:  opts.ObfsIn,
		obfsOut: opts.ObfsOut,
		bufs: BufferPool{
			Pool: sync.Pool{
				New: func() any {
					// FIXME: put reasonable bufsize here
					return make([]byte, 2048)
				},
			},
		},
	}
}

func (c *ObfuscatedConn) Read(b []byte) (n int, err error) {
	ctx := &readContext{
		flexBuffer: NewFlexBuffer(b),
		tmpPool:    &c.bufs,
	}
	if c.obfsIn == nil {
		return c.Conn.Read(b)
	}
	for _, obf := range c.obfsIn {
		if err := obf.Read(c.Conn, ctx); err != nil {
			return 0, err
		}
	}
	return ctx.Len(), nil
}

func (c *ObfuscatedConn) Write(b []byte) (n int, err error) {
	if c.obfsOut == nil {
		return c.Conn.Write(b)
	}

	ctx := &writeContext{
		flexBuffer: NewFlexBuffer(b),
		tmpPool:    &c.bufs,
	}

	buf := c.bufs.GetBuffer()
	defer c.bufs.Put(buf)

	writer := bytes.NewBuffer(buf[:0])

	for _, obf := range c.obfsOut {
		if err := obf.Write(writer, ctx); err != nil {
			return 0, err
		}
	}

	if _, err := c.Conn.Write(writer.Bytes()); err != nil {
		return 0, err
	}

	return ctx.Len(), nil
}
