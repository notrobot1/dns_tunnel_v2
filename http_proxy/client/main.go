package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

func dump(data []byte, label string) {
	limit := len(data)
	if limit > 32 {
		limit = 32
	}
	log.Printf("[HEX] %s (%d bytes total) [Первые 32 байта]:\n%s", label, len(data), hex.Dump(data[:limit]))
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
		return nil, fmt.Errorf("фрейм слишком мал")
	}

	frameBuf := make([]byte, frameSize)
	if _, err := io.ReadFull(r, frameBuf); err != nil {
		return nil, err
	}

	return frameBuf[headerLen : frameSize-footerLen], nil
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Базовая функция отправки пакета
func sendPacket(sessionID, target string, payload []byte, ackSeq uint64) ([]byte, error) {
	dnsConn, err := net.DialTimeout("tcp", "IP:53", 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer dnsConn.Close()

	// Используем таймауты, чтобы зависший сокет не остановил всё
	dnsConn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(dnsConn, "%s|%s|%d\n", sessionID, target, ackSeq)

	header := []byte{0xAA, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	footer := []byte{0x00, 0x00, 0x01, 0x00, 0x01}

	if err := writeFrame(dnsConn, header, payload, footer); err != nil {
		return nil, err
	}

	return readFrame(dnsConn, 41, 0)
}

// Обертка с логикой Retry (попыток отправки)
func sendPacketWithRetry(sessionID, target string, payload []byte, ackSeq uint64) []byte {
	attempt := 1
	for {
		resp, err := sendPacket(sessionID, target, payload, ackSeq)
		if err == nil {
			if attempt > 1 {
				log.Printf("[СЕТЬ] Успешная отправка после %d попыток", attempt)
			}
			return resp // Успешно доставили, возвращаем ответ
		}

		// Если произошла ошибка сети - логируем и повторяем
		log.Printf("[RETRY] Ошибка сети (попытка %d): %v. Повтор через 500мс...", attempt, err)
		time.Sleep(500 * time.Millisecond)
		attempt++
	}
}

func tunnel(src net.Conn, target string) {
	defer src.Close()
	sessionID := generateSessionID()
	closeChan := make(chan struct{})

	var seqMu sync.Mutex
	var lastReceivedSeq uint64

	// Функция для потокобезопасного получения текущего ACK
	getAck := func() uint64 {
		seqMu.Lock()
		defer seqMu.Unlock()
		return lastReceivedSeq
	}

	// Единая функция обработки ответа с жесткой блокировкой от гонок
	processResponse := func(resp []byte) error {
		if len(resp) < 8 {
			return nil
		}
		serverSeq := binary.BigEndian.Uint64(resp[:8])
		actualData := resp[8:]

		if serverSeq == 0 {
			return nil // Данных нет
		}

		// Блокируем мьютекс ДО проверки номера пакета
		seqMu.Lock()
		defer seqMu.Unlock()

		if serverSeq > lastReceivedSeq {
			if len(actualData) > 0 {
				dump(actualData, fmt.Sprintf("Response from DNS (Seq %d)", serverSeq))
				if _, err := src.Write(actualData); err != nil {
					return err
				}
			}
			lastReceivedSeq = serverSeq
		} else {
			log.Printf("[DEDUPLICATOR] Пропущен дубликат пакета №%d", serverSeq)
		}
		return nil
	}

	// ============================
	// ГОРУТИНА: ПУЛЛЕР (receive loop)
	// ============================
	go func() {
		defer src.Close()
		for {
			select {
			case <-closeChan:
				return
			default:
			}

			currentAck := getAck()
			// Используем функцию с ретраями. Она гарантированно вернет []byte без ошибки.
			resp := sendPacketWithRetry(sessionID, target, []byte{}, currentAck)

			if err := processResponse(resp); err != nil {
				return // Ошибка записи в локальный браузер/curl (клиент отвалился)
			}

			// Если сервер вернул пустой Seq (0), спим
			if len(resp) < 8 || binary.BigEndian.Uint64(resp[:8]) == 0 {
				time.Sleep(30 * time.Millisecond)
			}
		}
	}()

	// ============================
	// ОСНОВНОЙ ЦИКЛ: PUSH (client -> server)
	// ============================
	buf := make([]byte, 32000)
	for {
		n, err := src.Read(buf)
		if err != nil {
			break // Локальный клиент (curl) завершил работу
		}

		currentAck := getAck()
		// Отправляем PUSH с ретраями
		resp := sendPacketWithRetry(sessionID, target, buf[:n], currentAck)

		if err := processResponse(resp); err != nil {
			break // Ошибка записи в curl
		}
	}
	close(closeChan)
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	tunnel(clientConn, r.Host)
}

func main() {
	log.Println("Клиент-прокси слушает на :8080 (Sequence Sync & Auto-Retry Mode)...")
	http.ListenAndServe(":8080", http.HandlerFunc(handleTunneling))
}
