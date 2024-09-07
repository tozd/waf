package waf

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockBase struct{}

func (*mockBase) Close() error {
	panic("unimplemented")
}

func (*mockBase) LocalAddr() net.Addr {
	panic("unimplemented")
}

func (*mockBase) Read(_ []byte) (int, error) {
	panic("unimplemented")
}

func (*mockBase) RemoteAddr() net.Addr {
	panic("unimplemented")
}

func (*mockBase) SetDeadline(_ time.Time) error {
	panic("unimplemented")
}

func (*mockBase) SetReadDeadline(_ time.Time) error {
	panic("unimplemented")
}

func (*mockBase) SetWriteDeadline(_ time.Time) error {
	panic("unimplemented")
}

func (*mockBase) Write(_ []byte) (int, error) {
	panic("unimplemented")
}

var _ net.Conn = (*mockBase)(nil)

type MockConn struct {
	mockBase
	buffer *bytes.Buffer
}

func (c *MockConn) Read(b []byte) (int, error) {
	return c.buffer.Read(b)
}

func (c *MockConn) Write(b []byte) (int, error) {
	return c.buffer.Write(b)
}

func (c *MockConn) Close() error {
	return nil
}

type MockConnWriterToReaderFrom struct {
	mockBase
	buffer *bytes.Buffer
}

func (c *MockConnWriterToReaderFrom) Read(b []byte) (int, error) {
	return c.buffer.Read(b)
}

func (c *MockConnWriterToReaderFrom) Write(b []byte) (int, error) {
	return c.buffer.Write(b)
}

func (c *MockConnWriterToReaderFrom) Close() error {
	return nil
}

func (c *MockConnWriterToReaderFrom) WriteTo(w io.Writer) (int64, error) {
	return c.buffer.WriteTo(w)
}

func (c *MockConnWriterToReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	return c.buffer.ReadFrom(r)
}

type MockConnWriterTo struct {
	mockBase
	buffer *bytes.Buffer
}

func (c *MockConnWriterTo) Read(b []byte) (int, error) {
	return c.buffer.Read(b)
}

func (c *MockConnWriterTo) Write(b []byte) (int, error) {
	return c.buffer.Write(b)
}

func (c *MockConnWriterTo) Close() error {
	return nil
}

func (c *MockConnWriterTo) WriteTo(w io.Writer) (int64, error) {
	return c.buffer.WriteTo(w)
}

type MockConnReaderFrom struct {
	mockBase
	buffer *bytes.Buffer
}

func (c *MockConnReaderFrom) Read(b []byte) (int, error) {
	return c.buffer.Read(b)
}

func (c *MockConnReaderFrom) Write(b []byte) (int, error) {
	return c.buffer.Write(b)
}

func (c *MockConnReaderFrom) Close() error {
	return nil
}

func (c *MockConnReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	return c.buffer.ReadFrom(r)
}

type MockReadCloser struct {
	buffer *bytes.Buffer
}

func (r *MockReadCloser) Read(p []byte) (int, error) {
	return r.buffer.Read(p)
}

func (r *MockReadCloser) Close() error {
	return nil
}

type MockReadCloserWriterTo struct {
	buffer *bytes.Buffer
}

func (r *MockReadCloserWriterTo) Read(p []byte) (int, error) {
	return r.buffer.Read(p)
}

func (r *MockReadCloserWriterTo) WriteTo(w io.Writer) (int64, error) {
	return r.buffer.WriteTo(w)
}

func (r *MockReadCloserWriterTo) Close() error {
	return nil
}

func TestNetConnCounters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Type interface{}
		Conn net.Conn
	}{
		{&counterConn{}, &MockConn{buffer: bytes.NewBufferString("test data")}},
		{&counterConnWriterToReaderFrom{}, &MockConnWriterToReaderFrom{buffer: bytes.NewBufferString("test data")}},
		{&counterConnWriterTo{}, &MockConnWriterTo{buffer: bytes.NewBufferString("test data")}},
		{&counterConnReaderFrom{}, &MockConnReaderFrom{buffer: bytes.NewBufferString("test data")}},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%T", tt.Type), func(t *testing.T) {
			t.Parallel()

			conn := newCounterConn(tt.Conn)
			assert.IsType(t, tt.Type, conn)

			data := make([]byte, 1024)
			n, err := conn.Read(data)
			require.NoError(t, err)
			assert.Equal(t, 9, n)
			assert.Equal(t, []byte("test data"), data[:n])

			n, err = conn.Write([]byte("foobar"))
			require.NoError(t, err)
			assert.Equal(t, 6, n)

			n, err = conn.Read(data)
			require.NoError(t, err)
			assert.Equal(t, 6, n)
			assert.Equal(t, []byte("foobar"), data[:n])

			assert.Equal(t, int64(9+6), conn.(interface{ BytesRead() int64 }).BytesRead())     //nolint:forcetypeassert
			assert.Equal(t, int64(6), conn.(interface{ BytesWritten() int64 }).BytesWritten()) //nolint:forcetypeassert
		})
	}

	t.Run("MockConnWriterToReaderFrom", func(t *testing.T) {
		t.Parallel()

		mockBuffer := bytes.NewBufferString("test data")
		mockConn := &MockConnWriterToReaderFrom{buffer: mockBuffer}
		conn := newCounterConn(mockConn)
		assert.IsType(t, &counterConnWriterToReaderFrom{}, conn)

		data := make([]byte, 1024)
		buff := &bytes.Buffer{}
		n, err := conn.(io.WriterTo).WriteTo(buff)
		require.NoError(t, err)
		assert.Equal(t, int64(9), n)
		n2, err := buff.Read(data)
		require.NoError(t, err)
		assert.Equal(t, 9, n2)
		assert.Equal(t, []byte("test data"), data[:n2])

		buff.Reset()
		buff.WriteString("foobar")
		n, err = conn.(io.ReaderFrom).ReadFrom(buff)
		require.NoError(t, err)
		assert.Equal(t, int64(6), n)

		buff.Reset()
		n, err = conn.(io.WriterTo).WriteTo(buff)
		require.NoError(t, err)
		assert.Equal(t, int64(6), n)
		assert.Equal(t, "foobar", buff.String())

		assert.Equal(t, int64(9+6), conn.(interface{ BytesRead() int64 }).BytesRead())     //nolint:forcetypeassert
		assert.Equal(t, int64(6), conn.(interface{ BytesWritten() int64 }).BytesWritten()) //nolint:forcetypeassert
	})

	t.Run("MockConnWriterTo", func(t *testing.T) {
		t.Parallel()

		mockBuffer := bytes.NewBufferString("test data")
		mockConn := &MockConnWriterTo{buffer: mockBuffer}
		conn := newCounterConn(mockConn)
		assert.IsType(t, &counterConnWriterTo{}, conn)

		data := make([]byte, 1024)
		buff := &bytes.Buffer{}
		n, err := conn.(io.WriterTo).WriteTo(buff)
		require.NoError(t, err)
		assert.Equal(t, int64(9), n)
		n2, err := buff.Read(data)
		require.NoError(t, err)
		assert.Equal(t, 9, n2)
		assert.Equal(t, []byte("test data"), data[:n2])

		n2, err = conn.Write([]byte("foobar"))
		require.NoError(t, err)
		assert.Equal(t, 6, n2)

		buff.Reset()
		n, err = conn.(io.WriterTo).WriteTo(buff)
		require.NoError(t, err)
		assert.Equal(t, int64(6), n)
		assert.Equal(t, "foobar", buff.String())

		assert.Equal(t, int64(9+6), conn.(interface{ BytesRead() int64 }).BytesRead())     //nolint:forcetypeassert
		assert.Equal(t, int64(6), conn.(interface{ BytesWritten() int64 }).BytesWritten()) //nolint:forcetypeassert
	})

	t.Run("MockConnReaderFrom", func(t *testing.T) {
		t.Parallel()

		mockBuffer := bytes.NewBufferString("test data")
		mockConn := &MockConnReaderFrom{buffer: mockBuffer}
		conn := newCounterConn(mockConn)
		assert.IsType(t, &counterConnReaderFrom{}, conn)

		data := make([]byte, 1024)
		n2, err := conn.Read(data)
		require.NoError(t, err)
		assert.Equal(t, 9, n2)
		assert.Equal(t, []byte("test data"), data[:n2])

		buff := &bytes.Buffer{}
		buff.WriteString("foobar")
		n, err := conn.(io.ReaderFrom).ReadFrom(buff)
		require.NoError(t, err)
		assert.Equal(t, int64(6), n)

		n2, err = conn.Read(data)
		require.NoError(t, err)
		assert.Equal(t, 6, n2)
		assert.Equal(t, []byte("foobar"), data[:n2])

		assert.Equal(t, int64(9+6), conn.(interface{ BytesRead() int64 }).BytesRead())     //nolint:forcetypeassert
		assert.Equal(t, int64(6), conn.(interface{ BytesWritten() int64 }).BytesWritten()) //nolint:forcetypeassert
	})
}

func TestReadCloserCounters(t *testing.T) {
	t.Parallel()

	t.Run("MockReadCloser", func(t *testing.T) {
		t.Parallel()

		mockBuffer := bytes.NewBufferString("test data")
		mockReadCloser := &MockReadCloser{buffer: mockBuffer}
		counter := newCounterReadCloser(mockReadCloser)
		assert.IsType(t, &counterReadCloser{}, counter)

		data := make([]byte, 1024)
		n, err := counter.Read(data)
		require.NoError(t, err)
		assert.Equal(t, 9, n)
		assert.Equal(t, []byte("test data"), data[:n])

		err = counter.Close()
		require.NoError(t, err)

		assert.Equal(t, int64(9), counter.(interface{ BytesRead() int64 }).BytesRead()) //nolint:forcetypeassert
	})

	t.Run("MockReadCloserWriterTo", func(t *testing.T) {
		t.Parallel()

		mockBuffer := bytes.NewBufferString("test data")
		mockReadCloser := &MockReadCloserWriterTo{buffer: mockBuffer}
		counter := newCounterReadCloser(mockReadCloser)
		assert.IsType(t, &counterReadCloserWriterTo{}, counter)

		data := make([]byte, 1024)
		buff := &bytes.Buffer{}
		n, err := counter.(io.WriterTo).WriteTo(buff)
		require.NoError(t, err)
		assert.Equal(t, int64(9), n)
		n2, err := buff.Read(data)
		require.NoError(t, err)
		assert.Equal(t, 9, n2)
		assert.Equal(t, []byte("test data"), data[:n2])

		mockBuffer.Reset()
		n2, err = mockBuffer.WriteString("foobar")
		require.NoError(t, err)
		assert.Equal(t, 6, n2)

		n2, err = counter.Read(data)
		require.NoError(t, err)
		assert.Equal(t, 6, n2)
		assert.Equal(t, []byte("foobar"), data[:n2])

		err = counter.Close()
		require.NoError(t, err)

		assert.Equal(t, int64(15), counter.(interface{ BytesRead() int64 }).BytesRead()) //nolint:forcetypeassert
	})
}
