package conceal

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strconv"
	"time"
)

type writeContext struct {
	*flexBuffer
	*BufferPool
}

func (o *bytesObf) Write(writer io.Writer, ctx *writeContext) error {
	_, err := writer.Write(o.data)
	return err
}

func (o *dataObf) Write(writer io.Writer, ctx *writeContext) error {
	buf := ctx.PullHead(-1)
	if buf == nil {
		return io.ErrShortBuffer
	}

	_, err := writer.Write(buf)
	return err
}

func (o *dataSizeObf) Write(writer io.Writer, ctx *writeContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	size := int32(ctx.Cap())

	switch o.format {
	case NumFormatBE:
		for i := o.length - 1; i >= 0; i-- {
			tmp[i] = byte(size & 0xFF)
			size >>= 8
		}
		if _, err := writer.Write(tmp[:o.length]); err != nil {
			return err
		}
	case NumFormatLE:
		for i := range o.length {
			tmp[i] = byte(size & 0xFF)
			size >>= 8
		}
		if _, err := writer.Write(tmp[:o.length]); err != nil {
			return err
		}
	case NumFormatAscii:
		b := strconv.AppendInt(tmp[:0], int64(size), 10)
		b = append(b, o.end)

		if _, err := writer.Write(b); err != nil {
			return err
		}
	case NumFormatHex:
		b := strconv.AppendInt(tmp[:0], int64(size), 16)
		b = append(b, o.end)

		if _, err := writer.Write(b); err != nil {
			return err
		}
	}

	return nil
}

func (o *dataStringObf) Write(writer io.Writer, ctx *writeContext) error {
	data := ctx.PullHead(-1)
	if data == nil {
		return io.ErrShortBuffer
	}

	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	base64len := base64.RawStdEncoding.EncodedLen(len(data))
	buf := tmp[:base64len]

	base64.RawStdEncoding.Encode(buf, data)

	_, err := writer.Write(buf)
	return err
}

func (o *randObf) Write(writer io.Writer, ctx *writeContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	rand.Read(buf)

	_, err := writer.Write(buf)
	return err
}

const chars52 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func (o *randCharObf) Write(writer io.Writer, ctx *writeContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	rand.Read(buf)
	for i := range buf {
		buf[i] = chars52[buf[i]%52]
	}

	_, err := writer.Write(buf)
	return err
}

const digits10 = "0123456789"

func (o *randDigitObf) Write(writer io.Writer, ctx *writeContext) error {
	tmp := ctx.GetBuffer()
	defer ctx.Put(tmp)

	buf := tmp[:o.length]
	rand.Read(buf)
	for i := range buf {
		buf[i] = digits10[buf[i]%10]
	}

	_, err := writer.Write(buf)
	return err
}

func (o *timestampObf) Write(writer io.Writer, ctx *writeContext) error {
	timestamp := uint32(time.Now().Unix())
	return binary.Write(writer, binary.BigEndian, timestamp)
}
