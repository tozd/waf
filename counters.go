package waf

import (
	"io"
	"net"
	"sync/atomic"

	"gitlab.com/tozd/go/errors"
)

type counterConn struct {
	net.Conn
	read    *int64
	written *int64
}

func (c *counterConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(c.written, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

// Based on https://github.com/rs/zerolog/pull/562.
type counterReadCloser struct {
	rc   io.ReadCloser
	read *int64
}

func newCounterReadCloser(body io.ReadCloser) io.ReadCloser {
	var read int64
	if _, ok := body.(io.WriterTo); ok {
		return &counterReadCloserWriterTo{
			rc:   body,
			read: &read,
		}
	}
	return &counterReadCloser{
		rc:   body,
		read: &read,
	}
}

func (b *counterReadCloser) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	atomic.AddInt64(b.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (b *counterReadCloser) Close() error {
	return b.rc.Close() //nolint:wrapcheck
}

func (b *counterReadCloser) BytesRead() int64 {
	return atomic.LoadInt64(b.read)
}

type counterReadCloserWriterTo struct {
	rc   io.ReadCloser
	read *int64
}

func (b *counterReadCloserWriterTo) WriteTo(w io.Writer) (int64, error) {
	n, err := b.rc.(io.WriterTo).WriteTo(w)
	atomic.AddInt64(b.read, n)
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (b *counterReadCloserWriterTo) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	atomic.AddInt64(b.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (b *counterReadCloserWriterTo) Close() error {
	return b.rc.Close() //nolint:wrapcheck
}

func (b *counterReadCloserWriterTo) BytesRead() int64 {
	return atomic.LoadInt64(b.read)
}
