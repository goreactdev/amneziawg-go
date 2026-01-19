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

func NewPreludeUDPConn(conn UDPConn, origin UDPConn, pool *sync.Pool, opts PreludeOpts) (c *PreludeUDPConn, ok bool) {
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
		origin:    origin,
		pool:      WrapBufferPool(pool),
		rulesArr:  opts.RulesArr,
		junkCount: opts.Jc,
		junkGen:   newJunkGenerator(opts.Jmin, opts.Jmax),
	}, true
}

type PreludeUDPConn struct {
	UDPConn
	origin    UDPConn
	pool      *BufferPool
	rulesArr  [5]Rules
	junkCount int
	junkGen   *junkGenerator
}

func (c *PreludeUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if len(b) > 0 && b[0] == WireguardMsgInitiationType {
		tmp := c.pool.Get()
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

func NewPreludeBatchConn(conn BatchConn, origin BatchConn, bufPool *sync.Pool, msgsPool *sync.Pool, opts PreludeOpts) (c *PreludeBatchConn, ok bool) {
	empty := true
	for _, rules := range opts.RulesArr {
		if rules != nil {
			empty = false
		}
	}

	if empty && opts.Jc == 0 {
		return nil, false
	}

	if opts.Jmin > opts.Jmax {
		opts.Jmin, opts.Jmax = opts.Jmax, opts.Jmin
	}

	return &PreludeBatchConn{
		BatchConn: conn,
		origin:    origin,
		bufPool:   WrapBufferPool(bufPool),
		msgsPool:  msgsPool,
		rulesArr:  opts.RulesArr,
		junkCount: opts.Jc,
		junkGen:   newJunkGenerator(opts.Jmin, opts.Jmax),
	}, true
}

type PreludeBatchConn struct {
	BatchConn
	origin    BatchConn
	bufPool   *BufferPool
	msgsPool  *sync.Pool
	rulesArr  [5]Rules
	junkCount int
	junkGen   *junkGenerator
}

func (c *PreludeBatchConn) WriteBatch(ms []ipv4.Message, flags int) (n int, err error) {
	var initMsg *ipv4.Message
	for i := range ms {
		b := ms[i].Buffers[0]
		if len(b) > 0 && b[0] == WireguardMsgInitiationType {
			initMsg = &ms[i]
		}
	}

	if initMsg != nil {
		ctx := &writeContext{
			FlexBuffer: NewFlexBuffer(nil),
			BufferPool: c.bufPool,
		}

		msgs := c.msgsPool.Get().(*[]ipv4.Message)
		defer c.msgsPool.Put(msgs)
		n := 0

		for _, rules := range c.rulesArr {
			buf := c.bufPool.Get()
			defer c.bufPool.Put(buf)

			w := bytes.NewBuffer(buf[:0])
			if err = rules.Write(w, ctx); err != nil {
				return 0, err
			}

			(*msgs)[n].Buffers[0] = w.Bytes()
			(*msgs)[n].OOB = initMsg.OOB
			(*msgs)[n].Addr = initMsg.Addr
			n++
		}

		for range c.junkCount {
			buf := c.bufPool.Get()
			defer c.bufPool.Put(buf)

			(*msgs)[n].Buffers[0] = c.junkGen.generate(buf)
			(*msgs)[n].OOB = initMsg.OOB
			(*msgs)[n].Addr = initMsg.Addr
			n++
		}

		var start int
		for {
			n, err = c.BatchConn.WriteBatch((*msgs)[start:], flags)
			if err != nil {
				return 0, err
			}
			if n == len((*msgs)[start:]) {
				break
			}
			start += n
		}
	}

	return c.BatchConn.WriteBatch(ms, flags)
}
