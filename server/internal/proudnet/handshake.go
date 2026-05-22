// ProudNet connection handshake constants + scaffold.
//
// A ProudNet client validates the server's protocol version GUID during the
// connection handshake. On mismatch it disconnects immediately
// (ProtocolVersionMismatch) -- which is exactly why the scaffold server in
// server.go never gets past Accept(). The server MUST present the client's
// expected version GUID in its first message (NotifyServerConnectionHint).
//
// The GUID below was extracted statically from the unpacked Goley client
// (BinaryTr) -- see goley-rev/notes/faz18-proudnet-version-guid.md. The connect
// param builder at code VA 0x576f2b reads this 16-byte constant from data VA
// 0x0101eec4 (inside the ProudNet RMI/metadata table) dword-by-dword into a
// CNetConnectionParam-shaped stack struct, then passes it to CNetClient::Connect.
//
// Raw little-endian bytes in the image:
//   67 47 5e 9b 4f 3b 74 4f 9b 0b fe 23 fa 67 61 df
// As a GUID struct (Data1 LE u32, Data2 LE u16, Data3 LE u16, Data4 8 bytes):
//   {9B5E4767-3B4F-4F74-9B0B-FE23FA6761DF}
//
// STILL MISSING for a working handshake (deferred -- best nailed via a LIVE
// CAPTURE once the client's GameGuard init hang is solved, see faz17):
//   - exact NotifyServerConnectionHint byte layout (encryption mode, RSA public
//     key blob length, FallbackMethod, etc.)
//   - RSA key exchange + AES-128 session encryption (AES tables confirmed present
//     in the client at VA 0x00ec77d0 (Rcon) / 0x00ecbdc0 (S-box), see faz18)
package proudnet

import "fmt"

// ProtocolVersionGUID is the 16-byte ProudNet version GUID the Goley client
// expects, in the exact little-endian byte order it appears on the wire / in
// the image. Send these bytes verbatim where the handshake carries the version.
var ProtocolVersionGUID = [16]byte{
	0x67, 0x47, 0x5e, 0x9b, 0x4f, 0x3b, 0x74, 0x4f,
	0x9b, 0x0b, 0xfe, 0x23, 0xfa, 0x67, 0x61, 0xdf,
}

// Guid mirrors Proud::Guid (== Windows GUID layout).
type Guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// ProtocolVersion is ProtocolVersionGUID parsed into struct form:
// {9B5E4767-3B4F-4F74-9B0B-FE23FA6761DF}.
var ProtocolVersion = Guid{
	Data1: 0x9B5E4767,
	Data2: 0x3B4F,
	Data3: 0x4F74,
	Data4: [8]byte{0x9B, 0x0B, 0xFE, 0x23, 0xFA, 0x67, 0x61, 0xDF},
}

// String renders the canonical GUID text form.
func (g Guid) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// WriteGuid appends a 16-byte GUID in wire (little-endian field) order.
func (m *Message) WriteGuid(g Guid) {
	var b [16]byte
	b[0] = byte(g.Data1)
	b[1] = byte(g.Data1 >> 8)
	b[2] = byte(g.Data1 >> 16)
	b[3] = byte(g.Data1 >> 24)
	b[4] = byte(g.Data2)
	b[5] = byte(g.Data2 >> 8)
	b[6] = byte(g.Data3)
	b[7] = byte(g.Data3 >> 8)
	copy(b[8:], g.Data4[:])
	m.WriteBytes(b[:])
}

// Handshake message order observed/expected for ProudNet client connect
// (server perspective). Exact IDs/bytes to be confirmed by live capture:
//
//	1. (server -> client) NotifyServerConnectionHint
//	     carries: protocol version GUID (ProtocolVersionGUID), encryption settings,
//	     RSA public key blob. Client checks the GUID -> mismatch => disconnect.
//	2. (client -> server) NotifyCSEncryptedSessionKey / connection request
//	     carries: client's encrypted AES session key + its version.
//	3. (server -> client) NotifyServerConnectSuccess
//	     carries: assigned HostID. Client logs "HostID=%d Connecting to server
//	     successful." (client string VA 0xec8930). A malformed reply triggers
//	     "Bad format in NotifyServerConnectSuccess" (VA 0xec88d8).
//
// Until the crypto layer is implemented this is documentation only; the bytes
// are not yet emitted by server.go.
