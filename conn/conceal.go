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
