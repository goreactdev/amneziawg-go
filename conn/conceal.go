package conn

import "github.com/amnezia-vpn/amneziawg-go/conceal"

type Framable interface {
	SetFramedOpts(opts conceal.FramedOpts)
}

type Preludable interface {
	SetPreludeOpts(opts conceal.PreludeOpts)
}

type Masqueradable interface {
	SetMasqueradeOpts(opts conceal.MasqueradeOpts)
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

func (b *BindStream) SetFramedOpts(opts conceal.FramedOpts) {
	b.framedOpts = opts
}

func (b *BindStream) SetPreludeOpts(opts conceal.PreludeOpts) {
	b.preludeOpts = opts
}

func (b *BindStream) SetMasqueradeOpts(opts conceal.MasqueradeOpts) {
	b.masqueradeOpts = opts
}
