package conceal

type NumFormat int

const (
	NumFormatBE NumFormat = iota
	NumFormatLE
	NumFormatAscii
	NumFormatHex
)

type BinFormat int

const (
	BinFormatAsIs BinFormat = iota
	BinFormatBase64
)
