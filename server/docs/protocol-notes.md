# Goley Protocol Notes

Notes captured during reverse engineering. Updated as we learn more.

## Status: 🟡 Largely Unknown

We know **WHERE** to connect but not yet **WHAT** to send.

## Server Endpoints (CONFIRMED)

### Login server
- Address: `213.74.179.12:2270`
- Transport: TCP (most likely, MMO standard)
- Protocol: Custom binary (no plaintext observed in pcap)

### Game/lobby/world server
- Address: `213.74.179.12:20260`
- Same transport assumption

Both share IP, suggesting single host or load balancer at Superonline.

## Hypothesis: Anipark / Netmarble MMO common packet header

Based on contemporary Korean MMOs (2010-2015 era) by Netmarble's subsidiaries:

```
[2 or 4 bytes: packet length]
[2 bytes: opcode / packet ID]
[1 byte: encryption flag (optional)]
[payload bytes]
```

Encryption: typically a stream cipher (RC4-like) keyed off a session key
established during handshake. First packet often plaintext.

## To Find (TODO)

- [ ] Packet header layout (length size, opcode size, byte order)
- [ ] Login request packet structure (username, password, client version)
- [ ] Login response (session token, character list)
- [ ] Handshake / key exchange
- [ ] Encryption algorithm (RC4? custom XOR? AES-CBC?)
- [ ] Game match packet types
- [ ] Heartbeat / keepalive packets

## How to Recover

1. **Static analysis of BinaryTr.bin** -- packed; needs unpack first
   - Run packed exe in VM with x64dbg, dump at OEP, fix imports
   - Look for `WSARecv`, `recv`, `connect` call sites
   - Trace back to find packet parsing functions
   
2. **240MB memory dump** at `goley-recon/goley_PID53268_2nd_FullMemFull.dmp`
   - Contains decrypted strings including function names
   - Search for `Packet`, `Opcode`, `RecvProc`, etc. references
   
3. **Live packet capture** -- when we get the client to connect to our login-server
   - login-server logs every byte to `logs/captures/`
   - Compare multiple sessions to find consistent header bytes
   - Look for username/password we sent (might be in cleartext or with predictable key)

## Useful Memory Dump Search Terms

When investigating the dump for protocol clues, look for:
- `Packet*` (function names)
- `Recv*Func`, `Send*Func`
- `OpcodeTable`, `MsgHandler`
- `Cipher*`, `Encrypt*`, `Decrypt*`
- `Login*`, `Auth*`
- Common Korean MMO library names: `NetEngine`, `MNetwork`, `INet`, `JNet`
