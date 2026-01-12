package conceal

import (
	"fmt"
	"strings"
)

func (o Obfs) Spec() string {
	var builder strings.Builder
	for _, obf := range o {
		builder.WriteString(obf.Spec())
	}
	return builder.String()
}

func (o *timestampObf) Spec() string {
	return "<t>"
}

func (o *randDigitObf) Spec() string {
	return fmt.Sprintf("<rd %d>", o.length)
}

func (o *randCharObf) Spec() string {
	return fmt.Sprintf("<rc %d>", o.length)
}

func (o *randObf) Spec() string {
	return fmt.Sprintf("<r %d>", o.length)
}

func (o *dataSizeObf) Spec() string {
	switch o.format {
	case NumFormatAscii, NumFormatHex:
		return fmt.Sprintf("<dz %s 0x%02x>", o.format.Spec(), o.end)
	}
	return fmt.Sprintf("<dz %s %d>", o.format.Spec(), o.length)
}

func (f NumFormat) Spec() string {
	switch f {
	case NumFormatBE:
		return "be"
	case NumFormatLE:
		return "le"
	case NumFormatAscii:
		return "ascii"
	case NumFormatHex:
		return "hex"
	}
	return ""
}

func (o *dataObf) Spec() string {
	return "<d>"
}

func (o *dataStringObf) Spec() string {
	return "<dz>"
}

func (o *bytesObf) Spec() string {
	return fmt.Sprintf("<b 0x%x>", o.data)
}
