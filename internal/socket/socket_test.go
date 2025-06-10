package socket

import (
	"testing"
)

func TestNewSocket(t *testing.T) {
	socket := NewSocket()
	if socket == nil {
		t.Fatal("NewSocket() returned nil")
	}
	
	if socket.State() != StateClosed {
		t.Errorf("Expected initial state to be CLOSED, got %v", socket.State())
	}
}

func TestSocketStateString(t *testing.T) {
	tests := []struct {
		state    SocketState
		expected string
	}{
		{StateClosed, "CLOSED"},
		{StateListen, "LISTEN"},
		{StateSynSent, "SYN_SENT"},
		{StateEstablished, "ESTABLISHED"},
	}
	
	for _, test := range tests {
		if got := test.state.String(); got != test.expected {
			t.Errorf("State %d: expected %s, got %s", test.state, test.expected, got)
		}
	}
}

func TestSocketListen(t *testing.T) {
	socket := NewSocket()
	
	err := socket.Listen(":0") // Listen on any available port
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	
	if socket.State() != StateListen {
		t.Errorf("Expected state to be LISTEN, got %v", socket.State())
	}
	
	localAddr := socket.LocalAddr()
	if localAddr == nil {
		t.Error("LocalAddr() returned nil after Listen")
	}
}

func TestSocketConnect(t *testing.T) {
	socket := NewSocket()
	
	// Try to connect to localhost on an arbitrary port
	err := socket.Connect("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	
	if socket.State() != StateEstablished {
		t.Errorf("Expected state to be ESTABLISHED, got %v", socket.State())
	}
	
	remoteAddr := socket.RemoteAddr()
	if remoteAddr == nil {
		t.Error("RemoteAddr() returned nil after Connect")
	}
}

func TestSocketSendReceive(t *testing.T) {
	socket := NewSocket()
	
	// Connect first
	err := socket.Connect("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	
	// Test send
	testData := []byte("Hello, TinyTCP!")
	n, err := socket.Send(testData)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to send %d bytes, sent %d", len(testData), n)
	}
	
	// For this basic test, we'll simulate received data
	socket.recvBuffer = append(socket.recvBuffer, testData...)
	
	// Test receive
	received, err := socket.Receive()
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	if string(received) != string(testData) {
		t.Errorf("Expected to receive %s, got %s", string(testData), string(received))
	}
}

func TestSocketClose(t *testing.T) {
	socket := NewSocket()
	
	err := socket.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	
	if socket.State() != StateClosed {
		t.Errorf("Expected state to be CLOSED after close, got %v", socket.State())
	}
}
