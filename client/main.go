package main

import (
	"context"
	"encoding/base32"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	LocalSocksAddr = "127.0.0.1:1080"
	DnsServerAddr  = "DNS_SERVER_IP:53"
	TunnelDomain   = "tunnel.local."
)

var resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: 5 * time.Second,
		}
		return d.DialContext(ctx, "udp", DnsServerAddr)
	},
}

func main() {
	ln, err := net.Listen("tcp", LocalSocksAddr)
	if err != nil {
		panic(err)
	}

	fmt.Println("[Client] SOCKS5 listening:", LocalSocksAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(client net.Conn) {
	defer client.Close()

	buf := make([]byte, 512)

	// SOCKS5 auth
	io.ReadFull(client, buf[:2])
	methods := int(buf[1])
	io.ReadFull(client, buf[:methods])
	client.Write([]byte{0x05, 0x00})

	// request
	io.ReadFull(client, buf[:4])
	atyp := buf[3]

	var host string

	switch atyp {
	case 0x01:
		io.ReadFull(client, buf[:4])
		host = net.IP(buf[:4]).String()

	case 0x03:
		io.ReadFull(client, buf[:1])
		l := int(buf[0])
		io.ReadFull(client, buf[:l])
		host = string(buf[:l])

	case 0x04:
		io.ReadFull(client, buf[:16])
		host = net.IP(buf[:16]).String()
	}

	io.ReadFull(client, buf[:2])
	port := (int(buf[0]) << 8) | int(buf[1])

	target := fmt.Sprintf("%s:%d", host, port)
	fmt.Println("[Client] CONNECT:", target)

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano()%100000)

	if !dnsInit(sessionID, target) {
		fmt.Println("[Client] init failed")
		return
	}

	client.Write([]byte{
		0x05, 0x00, 0x00, 0x01,
		0, 0, 0, 0,
		0, 0,
	})

	done := make(chan bool, 2)

	go uploadLoop(sessionID, client, done)
	go downloadLoop(sessionID, client, done)

	<-done
}

// ---------------- DNS LAYER ----------------

func dnsQuery(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	txts, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return "", err
	}

	if len(txts) == 0 {
		return "", fmt.Errorf("empty answer")
	}

	return strings.Join(txts, ""), nil
}

func encode(data []byte) string {
	s := base32.StdEncoding.EncodeToString(data)
	return strings.ToLower(strings.TrimRight(s, "="))
}

func decode(s string) ([]byte, error) {
	padding := len(s) % 8
	if padding != 0 {
		s += strings.Repeat("=", 8-padding)
	}
	return base32.StdEncoding.DecodeString(strings.ToUpper(s))
}

// ---------------- TUNNEL LOGIC ----------------

func dnsInit(sessionID string, target string) bool {
	q := fmt.Sprintf(
		"%s-init-%s.%s",
		sessionID,
		encode([]byte(target)),
		TunnelDomain,
	)

	reply, err := dnsQuery(q)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return reply == "OK"
}

func uploadLoop(sessionID string, client net.Conn, done chan bool) {
	buf := make([]byte, 20)

	for {
		n, err := client.Read(buf)
		if err != nil {
			break
		}

		payload := encode(buf[:n])

		q := fmt.Sprintf(
			"%s-data-%s.%s",
			sessionID,
			payload,
			TunnelDomain,
		)

		_, err = dnsQuery(q)
		if err != nil {
			break
		}
	}

	done <- true
}

func downloadLoop(sessionID string, client net.Conn, done chan bool) {
	offset := 0

	for {
		q := fmt.Sprintf(
			"%s-poll-%d.%s",
			sessionID,
			offset,
			TunnelDomain,
		)

		reply, err := dnsQuery(q)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		if reply == "EMPTY" {
			time.Sleep(20 * time.Millisecond)
			continue
		}

		data, err := decode(reply)
		if err != nil {
			continue
		}

		if len(data) == 0 {
			continue
		}

		_, err = client.Write(data)
		if err != nil {
			break
		}

		offset += len(data)
	}

	done <- true
}
