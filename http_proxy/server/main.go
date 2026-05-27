package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type TargetSession struct {
	mu          sync.Mutex
	conn        net.Conn
	pendingData []byte
	currentSeq  uint64
}

var activeSessions sync.Map
var prefix = []byte{0xaa, 0xaa, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}

func dump(data []byte, label string) {
	limit := len(data)
	if limit > 32 {
		limit = 32
	}
	log.Printf("[HEX] %s (%d bytes total) [The first 32 bytes]:\n%s", label, len(data), hex.Dump(data[:limit]))
}

func writeFrame(w io.Writer, header, payload, footer []byte) error {
	frameSize := len(header) + len(payload) + len(footer)
	buf := make([]byte, 2+frameSize)
	binary.BigEndian.PutUint16(buf[:2], uint16(frameSize))

	offset := 2
	copy(buf[offset:], header)
	offset += len(header)
	copy(buf[offset:], payload)
	offset += len(payload)
	copy(buf[offset:], footer)

	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, headerLen, footerLen int) ([]byte, error) {
	sizeBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, sizeBuf); err != nil {
		return nil, err
	}
	frameSize := int(binary.BigEndian.Uint16(sizeBuf))

	if frameSize < headerLen+footerLen {
		return nil, fmt.Errorf("invalid frame size")
	}

	frameBuf := make([]byte, frameSize)
	if _, err := io.ReadFull(r, frameBuf); err != nil {
		return nil, err
	}

	return frameBuf[headerLen : frameSize-footerLen], nil
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	meta, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	meta = strings.TrimSpace(meta)

	parts := strings.SplitN(meta, "|", 3)
	if len(parts) != 3 {
		return
	}
	sessionID, target := parts[0], parts[1]

	var ackSeq uint64
	fmt.Sscanf(parts[2], "%d", &ackSeq)

	payload, err := readFrame(reader, 12, 5)
	if err != nil {
		return
	}

	val, _ := activeSessions.LoadOrStore(sessionID, &TargetSession{})
	sess := val.(*TargetSession)

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if ackSeq == sess.currentSeq && sess.currentSeq > 0 {
		sess.pendingData = nil
	}

	if sess.conn == nil {
		log.Printf("[Session %s] New connect to %s", sessionID, target)
		conn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			log.Printf("[Session %s] Dial error to %s: %v", sessionID, target, err)
			activeSessions.Delete(sessionID)
			return
		}
		sess.conn = conn
	}

	if len(payload) > 0 {
		dump(payload, "input from client (PUSH)")
		_, err := sess.conn.Write(payload)
		if err != nil {
			sess.conn.Close()
			activeSessions.Delete(sessionID)
			return
		}
	}

	if sess.pendingData == nil {
		sess.conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		var fullResponse []byte
		buf := make([]byte, 8192)
		for {
			n, err := sess.conn.Read(buf)
			if n > 0 {
				fullResponse = append(fullResponse, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		sess.conn.SetReadDeadline(time.Time{})

		if len(fullResponse) > 0 {
			sess.currentSeq++
			sess.pendingData = make([]byte, 8+len(fullResponse))
			binary.BigEndian.PutUint64(sess.pendingData[:8], sess.currentSeq)
			copy(sess.pendingData[8:], fullResponse)
		}
	}

	if len(sess.pendingData) > 0 {
		writeFrame(clientConn, prefix, sess.pendingData, nil)
	} else {
		emptyResp := make([]byte, 8)
		binary.BigEndian.PutUint64(emptyResp[:8], 0)
		writeFrame(clientConn, prefix, emptyResp, nil)
	}
}

func main() {
	ln, err := net.Listen("tcp", ":53")
	if err != nil {
		log.Fatalf("Port binding error: %v", err)
	}
	log.Println("The server is listening on port 53 (Sequence Sync Mode)...")
	for {
		conn, _ := ln.Accept()
		go handleConnection(conn)
	}
}
