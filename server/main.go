package main

import (
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type Session struct {
	Conn net.Conn

	Buffer []byte

	Mu sync.Mutex
}

var (
	sessions = map[string]*Session{}

	globalMu sync.Mutex
)

func main() {

	dns.HandleFunc("tunnel.local.", handleDNS)

	server := &dns.Server{
		Addr: ":53",
		Net:  "udp",
	}

	fmt.Println("[Server] listening on :53")

	err := server.ListenAndServe()

	if err != nil {
		panic(err)
	}
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {

	m := new(dns.Msg)

	m.SetReply(r)

	if len(r.Question) == 0 {

		w.WriteMsg(m)

		return
	}

	name := strings.ToLower(r.Question[0].Name)

	fmt.Println("[DNS]", name)

	prefix := strings.TrimSuffix(name, ".tunnel.local.")

	parts := strings.SplitN(prefix, "-", 3)

	if len(parts) != 3 {

		reply(w, m, name, "ERR")

		return
	}

	sessionID := parts[0]

	cmd := parts[1]

	payload := parts[2]

	globalMu.Lock()

	session := sessions[sessionID]

	globalMu.Unlock()

	switch cmd {

	case "init":

		targetBytes, err := decode(payload)

		if err != nil {

			reply(w, m, name, "ERR")

			return
		}

		target := string(targetBytes)

		fmt.Println("[CONNECT]", target)

		conn, err := net.Dial("tcp", target)

		if err != nil {

			fmt.Println(err)

			reply(w, m, name, "ERR")

			return
		}

		session = &Session{
			Conn:   conn,
			Buffer: make([]byte, 0),
		}

		globalMu.Lock()

		sessions[sessionID] = session

		globalMu.Unlock()

		go readLoop(sessionID, session)

		reply(w, m, name, "OK")

	case "data":

		if session == nil {

			reply(w, m, name, "NOSESSION")

			return
		}

		data, err := decode(payload)

		if err != nil {

			reply(w, m, name, "ERR")

			return
		}

		_, err = session.Conn.Write(data)

		if err != nil {

			reply(w, m, name, "ERR")

			return
		}

		reply(w, m, name, "OK")

	case "poll":

		if session == nil {

			reply(w, m, name, "NOSESSION")

			return
		}

		offset, _ := strconv.Atoi(payload)

		session.Mu.Lock()

		if offset >= len(session.Buffer) {

			session.Mu.Unlock()

			reply(w, m, name, "EMPTY")

			return
		}

		end := offset + 120

		if end > len(session.Buffer) {
			end = len(session.Buffer)
		}

		chunk := session.Buffer[offset:end]

		session.Mu.Unlock()

		reply(w, m, name, encode(chunk))

	default:

		reply(w, m, name, "ERR")
	}
}

func readLoop(sessionID string, s *Session) {

	buf := make([]byte, 4096)

	for {

		n, err := s.Conn.Read(buf)

		if err != nil {
			break
		}

		if n > 0 {

			s.Mu.Lock()

			s.Buffer = append(s.Buffer, buf[:n]...)

			s.Mu.Unlock()
		}
	}

	s.Conn.Close()

	globalMu.Lock()

	delete(sessions, sessionID)

	globalMu.Unlock()

	fmt.Println("[CLOSED]", sessionID)
}

func reply(
	w dns.ResponseWriter,
	m *dns.Msg,
	name string,
	text string,
) {

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: []string{text},
	}

	m.Answer = []dns.RR{rr}

	w.WriteMsg(m)
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
