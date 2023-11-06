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

func (c *counterReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterReadCloser) Close() error {
	return c.rc.Close() //nolint:wrapcheck
}

func (c *counterReadCloser) BytesRead() int64 {
	return atomic.LoadInt64(c.read)
}

type counterReadCloserWriterTo struct {
	rc   io.ReadCloser
	read *int64
}

func (c *counterReadCloserWriterTo) WriteTo(w io.Writer) (int64, error) {
	n, err := c.rc.(io.WriterTo).WriteTo(w)
	atomic.AddInt64(c.read, n)
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterReadCloserWriterTo) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterReadCloserWriterTo) Close() error {
	return c.rc.Close() //nolint:wrapcheck
}

func (c *counterReadCloserWriterTo) BytesRead() int64 {
	return atomic.LoadInt64(c.read)
}
