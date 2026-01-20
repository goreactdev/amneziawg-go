package conn

import (
	"net"

	"github.com/amnezia-vpn/amneziawg-go/conceal"
)

type Framable interface {
	SetFramedOpts(opts conceal.FramedOpts)
}

type Preludable interface {
	SetPreludeOpts(opts conceal.PreludeOpts)
}

type Masqueradable interface {
	SetMasqueradeOpts(opts conceal.MasqueradeOpts)
}

func (b *StdNetBind) upgradeUDPConn(conn UDPConn) UDPConn {
	origin := conn
	if masquerade, ok := conceal.NewMasqueradeUDPConn(conn, &b.bufPool, b.masqueradeOpts); ok {
		conn = masquerade
	}
	if framed, ok := conceal.NewFramedUDPConn(conn, &b.bufPool, b.framedOpts); ok {
		conn = framed
	}
	if prelude, ok := conceal.NewPreludeUDPConn(conn, origin, &b.bufPool, b.preludeOpts); ok {
		conn = prelude
	}
	return conn
}

func (b *StdNetBind) upgradePacketConn(conn LinuxPacketConn) LinuxPacketConn {
	origin := conn
	if masquerade, ok := conceal.NewMasqueradeBatchConn(conn, &b.bufPool, b.masqueradeOpts); ok {
		conn = masquerade
	}
	if framed, ok := conceal.NewFramedBatchConn(conn, &b.bufPool, b.framedOpts); ok {
		conn = framed
	}
	if prelude, ok := conceal.NewPreludeBatchConn(conn, origin, &b.bufPool, &b.msgsPool, b.preludeOpts); ok {
		conn = prelude
	}
	return conn
}

func (b *StdNetBind) SetFramedOpts(opts conceal.FramedOpts) {
	b.framedOpts = opts
}

func (b *StdNetBind) SetPreludeOpts(opts conceal.PreludeOpts) {
	b.preludeOpts = opts
}

func (b *StdNetBind) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.masqueradeOpts = opts
}

func (b *BindStream) upgradeConn(conn net.Conn) net.Conn {
	if masquerade, ok := conceal.NewMasqueradeConn(conn, &b.bufferPool, b.masqueradeOpts); ok {
		conn = masquerade
	}
	if framed, ok := conceal.NewFramedConn(conn, &b.bufferPool, b.framedOpts); ok {
		conn = framed
	}
	return conn
}

func (b *BindStream) SetFramedOpts(opts conceal.FramedOpts) {
	b.framedOpts = opts
}

func (b *BindStream) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.masqueradeOpts = opts
}
