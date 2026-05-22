// login-server is a packet logger for the Goley TCP login/game protocol.
//
// Listens on all known candidate ProudNet TCP ports:
//   - 8000/8277: statically confirmed in the unpacked BinaryTr TR path.
//   - 2270/20260: older plan/sniff hints, kept for compatibility.
//
// For each incoming connection:
//   - logs source address
//   - reads up to 64 KB
//   - hex-dumps the bytes (to discover packet structure)
//   - tries a few generic responses to see what the client does next
//
// Until the protocol is reverse-engineered, the goal is to capture as many
// real client packets as possible so we can pattern-match the wire format.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uintptr/goley-server/internal/common"
)

func main() {
	portsArg := flag.String("ports", "8000,8277,2270,20260", "comma-separated TCP ports to capture")
	loginPort := flag.Int("login-port", 0, "legacy single login/auth port; appended when non-zero")
	gamePort := flag.Int("game-port", 0, "legacy single game/world port; appended when non-zero")
	host := flag.String("host", "0.0.0.0", "bind host")
	probe := flag.String("probe", "", "optional TCP8000 probe response: startup-raw,startup-len16le,startup-len16be,startup-len32le,startup-len32be,startup-pn32,success-pn32-afterread,success-pn32le-afterread,startup-success-pn32")
	flag.Parse()

	log := common.NewLogger("login-server")
	defer log.Close()
	log.Logf("=== Goley login/game packet logger ===")

	ports, err := parsePorts(*portsArg)
	if err != nil {
		log.Logf("FATAL bad -ports value %q: %v", *portsArg, err)
		os.Exit(1)
	}
	if *loginPort != 0 {
		ports = appendUnique(ports, *loginPort)
	}
	if *gamePort != 0 {
		ports = appendUnique(ports, *gamePort)
	}
	if len(ports) == 0 {
		log.Logf("FATAL no ports configured")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(len(ports))
	for _, port := range ports {
		port := port
		label := fmt.Sprintf("TCP%d", port)
		go func() { defer wg.Done(); listen(*host, port, label, *probe, log) }()
	}
	wg.Wait()
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}
		out = appendUnique(out, port)
	}
	return out, nil
}

func appendUnique(ports []int, port int) []int {
	for _, p := range ports {
		if p == port {
			return ports
		}
	}
	return append(ports, port)
}

func listen(host string, port int, label string, probe string, log *common.Logger) {
	addr := fmt.Sprintf("%s:%d", host, port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Logf("[%s] FATAL bind %s: %v", label, addr, err)
		os.Exit(1)
	}
	log.Logf("[%s] listening on %s", label, addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Logf("[%s] accept err: %v", label, err)
			continue
		}
		go handle(conn, label, probe, log)
	}
}

func handle(conn net.Conn, label string, probe string, log *common.Logger) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Logf("[%s] CONNECT from %s", label, remote)

	if label == "TCP8000" && probe != "" {
		payload, ok := buildProbe(probe)
		if ok {
			if n, err := conn.Write(payload); err != nil {
				log.Logf("[%s] %s probe %s write err after %d/%d bytes: %v", label, remote, probe, n, len(payload), err)
			} else {
				log.Logf("[%s] %s probe %s sent %d bytes:\n%s", label, remote, probe, n, common.HexDump(payload, 256))
			}
		} else {
			log.Logf("[%s] %s unknown probe mode %q", label, remote, probe)
		}
	}

	// TCP8000 is the live ProudNet login socket. Earlier builds closed it as
	// soon as the first burst timed out; the client then dropped its connection
	// state to 0 while the UI was still in the forced lobby. Keep this socket
	// open and log bursts as they arrive so menu clicks can be observed.
	keepAlive := label == "TCP8000"
	idleTimeout := 10 * time.Second
	if keepAlive {
		idleTimeout = 30 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))

	var buf [65536]byte
	totalRead := 0
	flush := func(reason string) {
		if totalRead == 0 {
			return
		}
		data := make([]byte, totalRead)
		copy(data, buf[:totalRead])
		log.Logf("[%s] %s captured %d bytes (%s):\n%s", label, remote, totalRead, reason, common.HexDump(data, 1024))
		saveCapture(label, remote, data, log)
		totalRead = 0
	}
	for {
		n, err := conn.Read(buf[totalRead:])
		if n > 0 {
			totalRead += n
			if label == "TCP8000" {
				if payload, ok := buildAfterReadProbe(probe); ok {
					if wn, werr := conn.Write(payload); werr != nil {
						log.Logf("[%s] %s after-read probe %s write err after %d/%d bytes: %v", label, remote, probe, wn, len(payload), werr)
					} else {
						log.Logf("[%s] %s after-read probe %s sent %d bytes:\n%s", label, remote, probe, wn, common.HexDump(payload, 256))
					}
					probe = "" // one-shot
				}
			}
		}
		if err == io.EOF {
			log.Logf("[%s] %s EOF after %d bytes", label, remote, totalRead)
			break
		}
		if err != nil {
			// timeout or other error
			if strings.Contains(err.Error(), "timeout") {
				if keepAlive {
					flush("idle-timeout keepalive")
					log.Logf("[%s] %s idle timeout; keeping connection open", label, remote)
					_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
					continue
				}
				log.Logf("[%s] %s read timeout after %d bytes", label, remote, totalRead)
				break
			}
			log.Logf("[%s] %s read err: %v (after %d bytes)", label, remote, err, totalRead)
			break
		}
		if totalRead == len(buf) {
			flush("buffer-full")
		}
		// extend deadline if we keep receiving
		if keepAlive {
			_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		} else {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		}
	}

	if totalRead == 0 {
		log.Logf("[%s] %s no pending data, closing", label, remote)
		return
	}
	flush("closing")

	// Try a generic response and see what the client does
	// (most binary protocols start with [length][opcode][...] or [magic][...])
	// For now we just close -- packet logger only.
}

func buildProbe(mode string) ([]byte, bool) {
	startup := buildNotifyStartupEnvironment()
	switch mode {
	case "startup-raw":
		return startup, true
	case "startup-len16le":
		var out []byte
		var hdr [2]byte
		binary.LittleEndian.PutUint16(hdr[:], uint16(len(startup)))
		out = append(out, hdr[:]...)
		out = append(out, startup...)
		return out, true
	case "startup-len16be":
		var out []byte
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(startup)))
		out = append(out, hdr[:]...)
		out = append(out, startup...)
		return out, true
	case "startup-len32le":
		var out []byte
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(startup)))
		out = append(out, hdr[:]...)
		out = append(out, startup...)
		return out, true
	case "startup-len32be":
		var out []byte
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(startup)))
		out = append(out, hdr[:]...)
		out = append(out, startup...)
		return out, true
	case "startup-pn32":
		return wrapPN32(startup), true
	case "startup-success-pn32":
		return wrapPN32(startup), true
	default:
		return nil, false
	}
}

func buildAfterReadProbe(mode string) ([]byte, bool) {
	switch mode {
	case "success-pn32-afterread", "startup-success-pn32":
		return wrapPN32(buildNotifyServerConnectSuccess(false)), true
	case "success-pn32le-afterread":
		return wrapPN32(buildNotifyServerConnectSuccess(true)), true
	default:
		return nil, false
	}
}

func wrapPN32(payload []byte) []byte {
	out := make([]byte, 4, len(payload)+4)
	out[0] = 0x32
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(payload)))
	out[3] = 0
	out = append(out, payload...)
	return out
}

func buildNotifyServerConnectSuccess(little bool) []byte {
	var out []byte
	putByte := func(v byte) { out = append(out, v) }
	putInt := func(v uint32) {
		var b [4]byte
		if little {
			binary.LittleEndian.PutUint32(b[:], v)
		} else {
			binary.BigEndian.PutUint32(b[:], v)
		}
		out = append(out, b[:]...)
	}
	putU16 := func(v uint16) {
		var b [2]byte
		if little {
			binary.LittleEndian.PutUint16(b[:], v)
		} else {
			binary.BigEndian.PutUint16(b[:], v)
		}
		out = append(out, b[:]...)
	}

	putByte(13) // NotifyServerConnectSuccess
	putInt(1)   // localHostID
	putByte(0)  // userData VLQ length 0
	out = append(out, []byte("127.0.0.1")...)
	putByte(0)
	putU16(8000)
	return out
}

func buildNotifyStartupEnvironment() []byte {
	var out []byte
	putBool := func(v bool) {
		if v {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
	}
	putByte := func(v byte) { out = append(out, v) }
	putInt := func(v uint32) {
		var b [4]byte
		// ProudNet's WebGL bridge ByteArray defaults to big-endian. Native TCP
		// may still wrap this differently; probe modes only test reachability.
		binary.BigEndian.PutUint32(b[:], v)
		out = append(out, b[:]...)
	}

	putByte(5)         // NotifyStartupEnvironment
	putBool(false)     // enableLog
	putByte(0)         // fallbackMethod
	putInt(0x00020000) // serverMessageMaxLength
	putInt(0x00020000) // clientMessageMaxLength
	putInt(10000)      // defaultTimeoutTime
	putInt(0)          // autoConnectionRecoveryTimeoutTimeMs
	putByte(0)         // directP2PStartCondition
	putInt(0)          // overSendSuspectingThresholdInBytes
	putBool(false)     // enableNagleAlgorithm
	putInt(128)        // encryptedMessageKeyLength
	putInt(512)        // fastEncryptedMessageKeyLength
	putBool(false)     // allowServerAsP2PGroupMember
	putBool(false)     // enableEncryptedMessaging
	putBool(false)     // enableP2PEncryptedMessaging
	putBool(false)     // upnpDetectNatDevice
	putBool(false)     // upnpTcpAddPortMapping
	putBool(false)     // enableLookaheadP2PSend
	putBool(false)     // enablePingTest
	putBool(true)      // ignoreFailedBindPort
	putInt(0)          // emergencyLogLineCount
	putInt(0)          // serverTcpLastPingMs
	return out
}

// saveCapture writes each captured packet to a separate file under logs/captures/
func saveCapture(label, remote string, data []byte, log *common.Logger) {
	dir := "logs/captures"
	_ = os.MkdirAll(dir, 0755)
	ts := time.Now().Format("20060102_150405.000")
	safeRemote := strings.ReplaceAll(remote, ":", "_")
	name := fmt.Sprintf("%s/%s_%s_%s.bin", dir, ts, label, safeRemote)
	if err := os.WriteFile(name, data, 0644); err != nil {
		log.Logf("[%s] saveCapture err: %v", label, err)
		return
	}
	log.Logf("[%s] saved capture: %s (%d bytes)", label, name, len(data))
}
