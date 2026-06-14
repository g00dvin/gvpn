package authgate

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTCPDecoyReplaysPrefixAndRelays(t *testing.T) {
	// Fake decoy origin: read one request line, reply with a canned page.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	defer origin.Close()

	gotLine := make(chan string, 1)
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		gotLine <- line
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nDECOY"))
	}()

	client, server := net.Pipe()
	defer client.Close()

	decoy := TCPDecoy{Origin: origin.Addr().String()}
	go decoy.Handle(server, []byte("GET / HTTP/1.1\r\n"))

	select {
	case line := <-gotLine:
		if line != "GET / HTTP/1.1\r\n" {
			t.Fatalf("origin got %q, want the replayed prefix", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin never received the replayed prefix")
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read relayed response: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("DECOY")) {
		t.Fatalf("client got %q, want the decoy page relayed back", buf[:n])
	}
}

func TestTCPDecoyDialError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	// 127.0.0.1:1 should refuse; Handle must return an error and close server.
	decoy := TCPDecoy{Origin: "127.0.0.1:1", DialTimeout: time.Second}
	if err := decoy.Handle(server, nil); err == nil {
		t.Fatal("Handle to dead origin: want error, got nil")
	}
}
