// TCP packet framing for ProudNet.
//
// Goley's TCP stream wraps each logical ProudNet payload as:
//
//	[0x32 marker] [uint16 LE payloadLen] [1B msgType] [payloadLen bytes payload]
//
// This was confirmed from live Goley captures:
//
//	hello        32 18 00 00 + 24B core payload
//	RequestLogin 32 0a 01 01 + 266B RMI payload
//
// The inner RMI payload still carries the ProudNet RMI header:
//
//	[HostID dest] [RMI ID] [encoded args...]
package proudnet

import (
	"encoding/binary"
	"errors"
	"io"
)

// MessageType -- internal message-class tag (first byte of each frame).
//
// Values were cross-checked against Nettention's public ProudNet WebGL bridge
// (`WebGL_ProudNet_*.jslib`). Native TCP framing is still not fully verified,
// but these inner message IDs are no longer guesses.
type MessageType byte

const (
	frameMarker byte = 0x32

	MessageTypeRMI                           MessageType = 0x01
	MessageTypeUserMsg                       MessageType = 0x02
	MessageTypeConnectServerTimedout         MessageType = 0x04
	MessageTypeNotifyStartupEnvironment      MessageType = 0x05
	MessageTypeRequestServerConnection       MessageType = 0x06
	MessageTypeNotifyProtocolVersionMismatch MessageType = 0x0B
	MessageTypeNotifyServerDeniedConnection  MessageType = 0x0C
	MessageTypeNotifyServerConnectSuccess    MessageType = 0x0D
	MessageTypeReliableRelay1                MessageType = 0x1A
	MessageTypeUnreliableRelay1              MessageType = 0x1B
	MessageTypeReliableRelay2                MessageType = 0x1E
	MessageTypeUnreliableRelay2              MessageType = 0x1F
	MessageTypePolicyRequest                 MessageType = 0x36
	MessageTypeNotifyLicenseMismatch         MessageType = 0x39
)

// Frame represents a parsed inbound message.
type Frame struct {
	MsgType MessageType
	DestID  HostID
	RmiID   int32 // 0 if not an RMI message
	Body    []byte
}

// ReadFrame reads a single Goley/ProudNet framed message from the connection.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != frameMarker {
		return nil, errors.New("proudnet: bad frame marker")
	}
	frameLen := binary.LittleEndian.Uint16(hdr[1:3])
	body := make([]byte, frameLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	f := &Frame{
		MsgType: MessageType(hdr[3]),
		Body:    body,
	}
	return f, nil
}

// WriteFrame sends a framed message.
func WriteFrame(w io.Writer, mt MessageType, body []byte) error {
	var hdr [4]byte
	hdr[0] = frameMarker
	binary.LittleEndian.PutUint16(hdr[1:3], uint16(len(body)))
	hdr[3] = byte(mt)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// WriteRMI builds and sends an RMI call from server to client.
func WriteRMI(w io.Writer, dest HostID, rmiID int32, args *Message) error {
	body := NewMessage()
	body.WriteHostID(dest)
	body.WriteInt32(rmiID)
	body.WriteBytes(args.Bytes())
	return WriteFrame(w, MessageTypeRMI, body.Bytes())
}
