package conceal

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode"
)

var (
	errInvalidData = errors.New("invalid data")
)

type readContext struct {
	*flexBuffer
	*BufferPool
	nextDataSize int
}

func (o *bytesObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:len(o.data)]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	if !bytes.Equal(buf, o.data) {
		return errInvalidData
	}

	return nil
}

func (o *dataObf) Read(reader io.Reader, ctx *readContext) error {
	buf := ctx.PushTail(ctx.nextDataSize)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := io.ReadFull(reader, buf)
	return err
}

func (o *dataSizeObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	var size int

	switch o.format {
	case NumFormatBE:
		buf := tmp[:o.length]
		if _, err := io.ReadFull(reader, buf); err != nil {
			return err
		}
		for i := range buf {
			size <<= 8
			size |= int(buf[i])
		}
	case NumFormatLE:
		buf := tmp[:o.length]
		if _, err := io.ReadFull(reader, buf); err != nil {
			return err
		}
		for i := len(buf) - 1; i >= 0; i-- {
			size <<= 8
			size |= int(buf[i])
		}
	case NumFormatAscii:
		i := 0
		for {
			if _, err := io.ReadFull(reader, tmp[i:i+1]); err != nil {
				return err
			}
			if tmp[i] == o.end {
				break
			}
			i++
		}

		size64, err := strconv.ParseInt(string(tmp[:i]), 10, 32)
		if err != nil {
			return err
		}
		size = int(size64)

	case NumFormatHex:
		i := 0
		for {
			if _, err := io.ReadFull(reader, tmp[i:i+1]); err != nil {
				return err
			}
			if tmp[i] == o.end {
				break
			}
			i++
		}

		size64, err := strconv.ParseInt(string(tmp[:i]), 16, 32)
		if err != nil {
			return err
		}
		size = int(size64)
	}

	ctx.nextDataSize = size
	return nil
}

func (o *dataStringObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	base64len := base64.RawStdEncoding.EncodedLen(ctx.nextDataSize)
	buf := tmp[:base64len]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	data := ctx.PushTail(ctx.nextDataSize)
	if data == nil {
		return io.ErrShortBuffer
	}

	if _, err := base64.RawStdEncoding.Decode(data, buf); err != nil {
		// return buf in case of error
		ctx.PullTail(len(data))
		return fmt.Errorf("failed to decode base64: %w", err)
	}

	return nil
}

func (o *randObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	// I guess, there is no way to validate randomness
	// so just return nil here like everything is fine
	return nil
}

func (o *randCharObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	for _, b := range buf {
		if !unicode.IsLetter(rune(b)) {
			return errInvalidData
		}
	}

	return nil
}

func (o *randDigitObf) Read(reader io.Reader, ctx *readContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	for _, b := range buf {
		if !unicode.IsDigit(rune(b)) {
			return errInvalidData
		}
	}

	return nil
}

func (o *timestampObf) Read(reader io.Reader, ctx *readContext) error {
	var timestamp uint32
	if err := binary.Read(reader, binary.BigEndian, &timestamp); err != nil {
		return err
	}

	// TODO: check timestamp?

	return nil
}
