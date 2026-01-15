package conceal

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type PreludeOpts struct {
	Jc       int
	Jmin     int
	Jmax     int
	RulesArr [5]Rules
}

func newJunkGenerator(min, max int) *junkGenerator {
	return &junkGenerator{
		rang:   big.NewInt(int64(max - min + 1)),
		offset: min,
	}
}

type junkGenerator struct {
	rang   *big.Int
	offset int
}

func (p *junkGenerator) generate(b []byte) []byte {
	rndBig, _ := rand.Int(rand.Reader, p.rang)
	n := int(rndBig.Int64()) + p.offset

	junk := b[:n]
	rand.Read(junk)
	return junk
}

func NewPreludeConn(conn net.Conn, bp *BufferPool, opts PreludeOpts) (c *PreludeConn, ok bool) {
	empty := true
	for _, rules := range opts.RulesArr {
		if rules != nil {
			empty = false
		}
	}

	if empty && opts.Jc == 0 {
		return nil, false
	}

	return &PreludeConn{
		Conn:     conn,
		rulesArr: opts.RulesArr,
		pool:     bp,
	}, true
}

type PreludeConn struct {
	net.Conn
	rulesArr [5]Rules
	once     sync.Once
	pool     *BufferPool
}

func (c *PreludeConn) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *PreludeConn) Write(b []byte) (n int, err error) {
	c.once.Do(func() {
		tmp := c.pool.GetBuffer()
		defer c.pool.Put(tmp)

		ctx := &writeContext{
			FlexBuffer: NewFlexBuffer(nil),
			BufferPool: c.pool,
		}

		for _, rules := range c.rulesArr {
			if rules == nil {
				continue
			}

			w := bytes.NewBuffer(tmp)

			if err = rules.Write(w, ctx); err != nil {
				return
			}

			_, err = c.Conn.Write(tmp)
			if err != nil {
				return
			}
		}
	})

	if err != nil {
		return 0, err
	}

	return c.Conn.Write(b)
}

func NewPreludeUDPConn(conn *net.UDPConn, pool *BufferPool, opts PreludeOpts) (c *PreludeUDPConn, ok bool) {
	empty := true
	for _, rules := range opts.RulesArr {
		if rules != nil {
			empty = false
			break
		}
	}

	if empty && opts.Jc == 0 && opts.Jmin == 0 && opts.Jmax == 0 {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	return &PreludeUDPConn{
		UDPConn:   conn,
		pool:      pool,
		rulesArr:  opts.RulesArr,
		junkCount: opts.Jc,
		junkGen:   newJunkGenerator(opts.Jmin, opts.Jmax),
	}, true
}

type PreludeUDPConn struct {
	*net.UDPConn
	pool      *BufferPool
	rulesArr  [5]Rules
	junkCount int
	junkGen   *junkGenerator
}

func (c *PreludeUDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return c.UDPConn.ReadMsgUDP(b, oob)
}

func (c *PreludeUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if len(b) > 0 && b[0] == WireguardMsgInitiationType {
		tmp := c.pool.GetBuffer()
		defer c.pool.Put(tmp)

		ctx := &writeContext{
			FlexBuffer: NewFlexBuffer(nil),
			BufferPool: c.pool,
		}

		for _, rules := range c.rulesArr {
			if rules == nil {
				continue
			}

			w := bytes.NewBuffer(tmp[:0])

			if err = rules.Write(w, ctx); err != nil {
				return 0, 0, err
			}

			if _, _, err = c.UDPConn.WriteMsgUDP(w.Bytes(), oob, addr); err != nil {
				return 0, 0, err
			}
		}

		for range c.junkCount {
			junk := c.junkGen.generate(tmp)
			if _, _, err = c.UDPConn.WriteMsgUDP(junk, oob, addr); err != nil {
				return 0, 0, err
			}
		}
	}

	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

type PreludeBatchConn struct {
	BatchConn
	pool      *BufferPool
	rulesArr  [5]Rules
	junkCount int
	junkGen   *junkGenerator
}

func (c *PreludeBatchConn) ReadBatch(ms []ipv4.Message, flags int) (n int, err error) {
	return c.BatchConn.ReadBatch(ms, flags)
}

func (c *PreludeBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	hasInit := false
	for _, m := range ms {
		b := m.Buffers[0]
		if len(b) > 0 && b[0] == WireguardMsgInitiationType {
			hasInit = true
		}
	}

	if hasInit {

	}

	return c.BatchConn.WriteBatch(ms, flags)
}
