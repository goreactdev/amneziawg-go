package conceal

import (
	"bytes"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type MasqueradeOpts struct {
	RulesIn  Rules
	RulesOut Rules
}

func NewMasqueradeConn(conn net.Conn, pool *sync.Pool, opts MasqueradeOpts) (c *MasqueradeConn, ok bool) {
	if opts.RulesIn == nil && opts.RulesOut == nil {
		return nil, false
	}

	return &MasqueradeConn{
		Conn:     conn,
		rulesIn:  opts.RulesIn,
		rulesOut: opts.RulesOut,
		pool:     WrapBufferPool(pool),
	}, true
}

type MasqueradeConn struct {
	net.Conn
	rulesIn  Rules
	rulesOut Rules
	pool     *BufferPool
}

func (c *MasqueradeConn) Read(b []byte) (n int, err error) {
	if c.rulesIn == nil {
		return c.Conn.Read(b)
	}

	ctx := &readContext{
		FlexBuffer: NewFlexBuffer(b),
		BufferPool: c.pool,
	}

	if err := c.rulesIn.Read(c.Conn, ctx); err != nil {
		return 0, err
	}

	return ctx.Len(), nil
}

func (c *MasqueradeConn) Write(b []byte) (n int, err error) {
	if c.rulesOut == nil {
		return c.Conn.Write(b)
	}

	ctx := &writeContext{
		FlexBuffer: NewFlexBuffer(b),
		BufferPool: c.pool,
	}

	buf := c.pool.Get()
	defer c.pool.Put(buf)

	w := bytes.NewBuffer(buf[:0])

	if err := c.rulesOut.Write(w, ctx); err != nil {
		return 0, err
	}

	if _, err := c.Conn.Write(w.Bytes()); err != nil {
		return 0, err
	}

	return ctx.Len(), nil
}

func NewMasqueradeUDPConn(conn UDPConn, pool *sync.Pool, opts MasqueradeOpts) (c *MasqueradeUDPConn, ok bool) {
	if opts.RulesIn == nil && opts.RulesOut == nil {
		return nil, false
	}

	return &MasqueradeUDPConn{
		rulesIn:  opts.RulesIn,
		rulesOut: opts.RulesOut,
		pool:     WrapBufferPool(pool),
	}, true
}

type MasqueradeUDPConn struct {
	UDPConn
	rulesIn  Rules
	rulesOut Rules
	pool     *BufferPool
}

func (c *MasqueradeUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	tmp := c.pool.Get()
	defer c.pool.Put(tmp)

	n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(tmp, oob)
	if err != nil {
		return n, oobn, flags, addr, err
	}

	r := bytes.NewBuffer(tmp)
	ctx := &readContext{
		FlexBuffer: NewFlexBuffer(b),
		BufferPool: c.pool,
	}

	if err = c.rulesIn.Read(r, ctx); err != nil {
		return 0, oobn, flags, addr, err
	}

	return ctx.Len(), oobn, flags, addr, err
}

func (c *MasqueradeUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	tmp := c.pool.Get()
	defer c.pool.Put(tmp)

	w := bytes.NewBuffer(tmp[:0])
	ctx := &writeContext{
		FlexBuffer: NewFlexBuffer(b),
		BufferPool: c.pool,
	}

	if err = c.rulesOut.Write(w, ctx); err != nil {
		return 0, 0, err
	}

	return c.UDPConn.WriteMsgUDP(tmp[:ctx.Len()], oob, addr)
}

func NewMasqueradeBatchConn(conn BatchConn, bp *sync.Pool, opts MasqueradeOpts) (c *MasqueradeBatchConn, ok bool) {
	if opts.RulesIn == nil && opts.RulesOut == nil {
		return nil, false
	}

	return &MasqueradeBatchConn{
		BatchConn: conn,
		rulesIn:   opts.RulesIn,
		rulesOut:  opts.RulesOut,
		pool:      WrapBufferPool(bp),
	}, true
}

type MasqueradeBatchConn struct {
	BatchConn
	rulesIn  Rules
	rulesOut Rules
	pool     *BufferPool
}

func (c *MasqueradeBatchConn) ReadBatch(ms []ipv4.Message, flags int) (n int, err error) {
	return c.BatchConn.ReadBatch(ms, flags)
}

func (c *MasqueradeBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	return c.WriteBatch(ms, flags)
}
