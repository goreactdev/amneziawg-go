package conn

import "github.com/amnezia-vpn/amneziawg-go/conceal"

type Obfuscatable interface {
	SetObfsIn(obfs conceal.Obfs)
	SetObfsOut(obfs conceal.Obfs)
}
