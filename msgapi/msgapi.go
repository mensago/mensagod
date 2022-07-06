package msgapi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

var ErrIO = errors.New("i/o error")
var ErrNoInit = errors.New("not initialized")
var ErrEmptyData = errors.New("empty data")
var ErrInvalidFrame = errors.New("invalid data frame")
var ErrInvalidMultipartFrame = errors.New("invalid multipart data frame")
var ErrInvalidMsg = errors.New("invalid message")
var ErrSize = errors.New("invalid size")
var ErrMultipartSession = errors.New("multipart session error")

// Constants and Configurable Globals

// MaxCommandLength is the maximum number of bytes a command is permitted to be. Note that
// bulk transfers are not subject to this restriction -- just the initial command.
const MinCommandLength = 35

// DataFrame type codes
const (
	SingleFrame = uint8(50) + iota
	MultipartFrameStart
	MultipartFrame
	MultipartFrameFinal
)

// DataFrame is a structure for the lowest layer of network interaction in Oganesson. It
// represents a segment of data. Depending on the type code for the instance, it may indicate that
// the data payload is complete -- the SingleFrame type -- or it may be part of a larger set. In
// all cases a DataFrame is required to be equal to or smaller than the buffer size negotiated
// between the local host and the remote host.
type DataFrame struct {
	buffer []byte
	index  int
}

// NewDataFrame creates a new instance with an allocated memory buffer ready for use. If given a
// value less than the required 1024 bytes, it returns nil.
func NewDataFrame(bufferSize uint16) *DataFrame {
	if bufferSize < 1024 {
		return nil
	}

	var out DataFrame
	out.allocateDataFrameBuffer(bufferSize)
	return &out
}

func (df *DataFrame) allocateDataFrameBuffer(bufferSize uint16) {
	df.buffer = make([]byte, bufferSize)
}

// GetType returns the frame type or 255 if the frame is invalid
func (df *DataFrame) GetType() uint8 {

	if df.buffer == nil {
		return 255
	}
	return df.buffer[0]
}

// GetType returns the size of the payload or 0 if the frame is invalid/
func (df *DataFrame) GetSize() uint16 {

	if len(df.buffer) < 4 {
		return 0
	}

	return uint16(len(df.buffer) - 3)
}

// GetType returns the data held by the frame or nil if the frame is invalid
func (df *DataFrame) GetPayload() []byte {

	if len(df.buffer) < 4 {
		return nil
	}

	return df.buffer[3:df.index]
}

// Read() reads in a chunk of data from the network socket and ensures the frame structure is valid
func (df *DataFrame) Read(r io.Reader) error {

	// Invalidate the index in case we error out
	df.index = 0

	bytesRead, err := r.Read(df.buffer)
	if err != nil {
		return err
	}

	if bytesRead < 4 {
		return ErrIO
	}

	if df.buffer[0] < SingleFrame || df.buffer[0] >= MultipartFrameFinal {
		return ErrInvalidFrame
	}

	// The size bytes are in network order (MSB), so this makes dealing with CPU architecture much
	// less of a headache regardless of what archictecture this is compiled for.
	payloadSize := (uint16(df.buffer[1]) << 8) + uint16(df.buffer[2])
	if bytesRead != int(payloadSize)+3 {
		return ErrSize
	}

	df.index = bytesRead
	return nil
}

// WriteFrame exists because the way ReadMessage and WriteMessage are used, it's just simpler to do
// this way -- no state needs to be involved.
func WriteFrame(w io.Writer, fieldType uint8, payload []byte) error {
	payloadLen := len(payload)

	buffer := make([]byte, payloadLen+3)
	buffer[0] = SingleFrame
	buffer[1] = uint8((payloadLen >> 8) & 255)
	buffer[2] = uint8(payloadLen & 255)
	copy(buffer[3:], payload)

	_, err := w.Write(buffer)
	return err
}

func ReadMessage(conn net.Conn, timeout time.Duration) ([]byte, error) {

	chunk := NewDataFrame(65535)
	err := chunk.Read(conn)
	if err != nil {
		return nil, err
	}

	switch chunk.GetType() {
	case SingleFrame:
		return chunk.GetPayload(), nil
	case MultipartFrameFinal, MultipartFrame:
		return nil, ErrMultipartSession
	case MultipartFrameStart:
		// Keep calm and carry on 👑
	default:
		return nil, ErrInvalidFrame
	}

	// We got this far, so we have a multipart message which we need to reassemble.

	// No validity checking is performed on the actual data in a DataFrame, so we need to validate
	// the total payload size.
	var totalSize uint64
	totalSize, err = strconv.ParseUint(string(chunk.GetPayload()), 10, 64)
	if err != nil {
		return nil, err
	}

	msgparts := make([][]byte, 1)
	var sizeRead uint64

	for sizeRead < totalSize {
		conn.SetReadDeadline(time.Now().Add(timeout))
		err := chunk.Read(conn)
		if err != nil {
			return nil, err
		}

		msgparts = append(msgparts, chunk.GetPayload())
		sizeRead += uint64(chunk.GetSize())

		if chunk.GetType() == MultipartFrameFinal {
			break
		}
	}

	if sizeRead != totalSize {
		return nil, ErrSize
	}

	out := bytes.Join(msgparts, nil)
	if uint64(len(out)) != totalSize {
		return nil, ErrSize
	}

	return out, nil
}

func WriteMessage(conn net.Conn, message []byte, timeout time.Duration) error {

	if message == nil {
		return ErrEmptyData
	}

	msgLen := len(message)

	// If the message is small enough to fit into a single frame, just send it and be done.
	if msgLen < 65532 {
		conn.SetReadDeadline(time.Now().Add(timeout))
		conn.SetWriteDeadline(time.Now().Add(timeout))
		return WriteFrame(conn, SingleFrame, message)
	}

	ValueSize := 65532

	// If the message is bigger than the max command length, then we will send the Value as
	// a multipart message. This takes more work internally, but the benefits at the application
	// level are worth it. Fortunately, by using a binary wire format, we don't have to flatten
	// the message into JSON and deal with escaping and all sorts of other complications.

	// The initial message that indicates that it is the start of a multipart message contains the
	// total message size in the Value. All messages that follow contain the actual message data.
	// The size Value is actually a decimal string of the total message size

	if err := WriteFrame(conn, MultipartFrameStart,
		[]byte(fmt.Sprintf("%d", msgLen))); err != nil {
		return err
	}

	var index int
	for index+ValueSize < msgLen {
		if err := WriteFrame(conn, MultipartFrame,
			message[index:index+ValueSize]); err != nil {
			return err
		}

		index += ValueSize
	}

	return WriteFrame(conn, MultipartFrameFinal, message[index:])
}
