package waf

import (
	"io"
	"net"
	"sync"
	"sync/atomic"

	"gitlab.com/tozd/go/errors"
)

// pending is what was read from the client before the connection was hijacked and is not read yet. The connection
// hands it back before it reads the connection itself, so that a caller which goes straight to the connection, which
// is what websocket libraries do after they reset the reader they were given, does not lose it.
type pending struct {
	mu    sync.Mutex
	bytes []byte
}

// read copies what is left into b and returns how much, which is zero when there is nothing left and the connection
// itself is what should be read.
func (p *pending) read(b []byte) int {
	if p == nil || len(b) == 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.bytes) == 0 {
		return 0
	}
	n := copy(b, p.bytes)
	p.bytes = p.bytes[n:]
	return n
}

// writeTo writes what is left to w, for a connection which is asked to write itself out instead of being read.
func (p *pending) writeTo(w io.Writer) (int64, error) {
	if p == nil {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.bytes) == 0 {
		return 0, nil
	}
	n, err := w.Write(p.bytes)
	p.bytes = p.bytes[n:]
	return int64(n), errors.WithStack(err)
}

// newCounterConn wraps c so that bytes read and written can be counted. buffered is what was read from the client
// before c was hijacked, which the connection hands back before it reads c, and counts as read.
//
// TODO: Do we have to test conn for *net.TCPConn and *tls.Conn concrete types and then wrap them instead?
func newCounterConn(c net.Conn, buffered []byte) net.Conn {
	var read int64
	var written int64
	p := &pending{mu: sync.Mutex{}, bytes: buffered}
	_, isWriterTo := c.(io.WriterTo)
	_, isReaderFrom := c.(io.ReaderFrom)
	if isWriterTo && isReaderFrom {
		return &counterConnWriterToReaderFrom{
			Conn:    c,
			read:    &read,
			written: &written,
			pending: p,
		}
	} else if isWriterTo {
		return &counterConnWriterTo{
			Conn:    c,
			read:    &read,
			written: &written,
			pending: p,
		}
	} else if isReaderFrom {
		return &counterConnReaderFrom{
			Conn:    c,
			read:    &read,
			written: &written,
			pending: p,
		}
	}
	return &counterConn{
		Conn:    c,
		read:    &read,
		written: &written,
		pending: p,
	}
}

type counterConn struct {
	net.Conn

	read    *int64
	written *int64
	pending *pending
}

func (c *counterConn) Read(b []byte) (int, error) {
	// What was buffered before the hijack comes first, and counts as read, since it was read from the client.
	if n := c.pending.read(b); n > 0 {
		atomic.AddInt64(c.read, int64(n))
		return n, nil
	}
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
	pending *pending
}

func (c *counterConnWriterToReaderFrom) Read(b []byte) (int, error) {
	// What was buffered before the hijack comes first, and counts as read, since it was read from the client.
	if n := c.pending.read(b); n > 0 {
		atomic.AddInt64(c.read, int64(n))
		return n, nil
	}
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
	buffered, err := c.pending.writeTo(w)
	atomic.AddInt64(c.read, buffered)
	if err != nil {
		return buffered, err
	}
	n, err := c.Conn.(io.WriterTo).WriteTo(w) //nolint:forcetypeassert,errcheck
	atomic.AddInt64(c.read, n)
	n += buffered
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterConnWriterToReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	n, err := c.Conn.(io.ReaderFrom).ReadFrom(r) //nolint:forcetypeassert,errcheck
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
	pending *pending
}

func (c *counterConnWriterTo) Read(b []byte) (int, error) {
	// What was buffered before the hijack comes first, and counts as read, since it was read from the client.
	if n := c.pending.read(b); n > 0 {
		atomic.AddInt64(c.read, int64(n))
		return n, nil
	}
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
	buffered, err := c.pending.writeTo(w)
	atomic.AddInt64(c.read, buffered)
	if err != nil {
		return buffered, err
	}
	n, err := c.Conn.(io.WriterTo).WriteTo(w) //nolint:forcetypeassert,errcheck
	atomic.AddInt64(c.read, n)
	n += buffered
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
	pending *pending
}

func (c *counterConnReaderFrom) Read(b []byte) (int, error) {
	// What was buffered before the hijack comes first, and counts as read, since it was read from the client.
	if n := c.pending.read(b); n > 0 {
		atomic.AddInt64(c.read, int64(n))
		return n, nil
	}
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
	n, err := c.Conn.(io.ReaderFrom).ReadFrom(r) //nolint:forcetypeassert,errcheck
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

func (c *counterReadCloser) Read(b []byte) (int, error) {
	n, err := c.rc.Read(b)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF {
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
	n, err := c.rc.(io.WriterTo).WriteTo(w) //nolint:forcetypeassert,errcheck
	atomic.AddInt64(c.read, n)
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *counterReadCloserWriterTo) Read(b []byte) (int, error) {
	n, err := c.rc.Read(b)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF {
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
