package waf

import (
	"io"
	"net"
	"sync/atomic"

	"gitlab.com/tozd/go/errors"
)

// TODO: Do we have to test conn for *net.TCPConn and *tls.Conn concrete types and then wrap them instead?
func newCounterConn(c net.Conn) net.Conn {
	var read int64
	var written int64
	_, isWriterTo := c.(io.WriterTo)
	_, isReaderFrom := c.(io.ReaderFrom)
	if isWriterTo && isReaderFrom {
		return &counterConnWriterToReaderFrom{
			Conn:    c,
			read:    &read,
			written: &written,
		}
	} else if isWriterTo {
		return &counterConnWriterTo{
			Conn:    c,
			read:    &read,
			written: &written,
		}
	} else if isReaderFrom {
		return &counterConnReaderFrom{
			Conn:    c,
			read:    &read,
			written: &written,
		}
	}
	return &counterConn{
		Conn:    c,
		read:    &read,
		written: &written,
	}
}

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

func (c *counterConn) BytesRead() int64 {
	return atomic.LoadInt64(c.read)
}

func (c *counterConn) BytesWritten() int64 {
	return atomic.LoadInt64(c.written)
}

type counterConnWriterToReaderFrom struct {
	net.Conn
	read    *int64
	written *int64
}

func (c *counterConnWriterToReaderFrom) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterToReaderFrom) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(c.written, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterToReaderFrom) WriteTo(w io.Writer) (int64, error) {
	n, err := c.Conn.(io.WriterTo).WriteTo(w)
	atomic.AddInt64(c.read, n)
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterToReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	n, err := c.Conn.(io.ReaderFrom).ReadFrom(r)
	atomic.AddInt64(c.written, n)
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterToReaderFrom) BytesRead() int64 {
	return atomic.LoadInt64(c.read)
}

func (c *counterConnWriterToReaderFrom) BytesWritten() int64 {
	return atomic.LoadInt64(c.written)
}

type counterConnWriterTo struct {
	net.Conn
	read    *int64
	written *int64
}

func (c *counterConnWriterTo) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterTo) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(c.written, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterTo) WriteTo(w io.Writer) (int64, error) {
	n, err := c.Conn.(io.WriterTo).WriteTo(w)
	atomic.AddInt64(c.read, n)
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterTo) BytesRead() int64 {
	return atomic.LoadInt64(c.read)
}

func (c *counterConnWriterTo) BytesWritten() int64 {
	return atomic.LoadInt64(c.written)
}

type counterConnReaderFrom struct {
	net.Conn
	read    *int64
	written *int64
}

func (c *counterConnReaderFrom) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnReaderFrom) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(c.written, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	n, err := c.Conn.(io.ReaderFrom).ReadFrom(r)
	atomic.AddInt64(c.written, n)
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnReaderFrom) BytesRead() int64 {
	return atomic.LoadInt64(c.read)
}

func (c *counterConnReaderFrom) BytesWritten() int64 {
	return atomic.LoadInt64(c.written)
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

type counterReadCloser struct {
	rc   io.ReadCloser
	read *int64
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
	return errors.WithStack(c.rc.Close())
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
	return errors.WithStack(c.rc.Close())
}

func (c *counterReadCloserWriterTo) BytesRead() int64 {
	return atomic.LoadInt64(c.read)
}
