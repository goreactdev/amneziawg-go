package conceal

import "golang.org/x/net/ipv4"

type BatchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (n int, err error)
	WriteBatch(ms []ipv4.Message, flags int) (n int, err error)
}
