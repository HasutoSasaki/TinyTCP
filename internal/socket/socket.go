// Package socket implements socket API for TinyTCP
package socket

import (
	"errors"
	"net"
	"sync"
)

// SocketState represents the state of a TCP socket
type SocketState int

const (
	StateClosed SocketState = iota
	StateListen
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateCloseWait
	StateClosing
	StateLastAck
	StateTimeWait
)

// String returns the string representation of the socket state
func (s SocketState) String() string {
	states := []string{
		"CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED",
		"ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2",
		"CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT",
	}
	if int(s) < len(states) {
		return states[s]
	}
	return "UNKNOWN"
}

// TinySocket represents a TCP socket
type TinySocket struct {
	mu           sync.RWMutex
	state        SocketState
	localAddr    *net.TCPAddr
	remoteAddr   *net.TCPAddr
	isListening  bool
	connections  map[string]*TinySocket // For listening sockets
	
	// TCP sequence numbers
	sendSeq      uint32
	recvSeq      uint32
	sendAck      uint32
	recvAck      uint32
	
	// Buffers
	sendBuffer   []byte
	recvBuffer   []byte
	
	// Channels for communication
	acceptChan   chan *TinySocket
	closeChan    chan struct{}
	
	// Connection management
	parent       *TinySocket // For accepted connections
}

// SocketAPI defines the interface for socket operations
type SocketAPI interface {
	Listen(addr string) error
	Accept() (*TinySocket, error)
	Connect(addr string) error
	Send(data []byte) (int, error)
	Receive() ([]byte, error)
	Close() error
	State() SocketState
	LocalAddr() *net.TCPAddr
	RemoteAddr() *net.TCPAddr
}

// NewSocket creates a new TinySocket
func NewSocket() *TinySocket {
	return &TinySocket{
		state:       StateClosed,
		connections: make(map[string]*TinySocket),
		acceptChan:  make(chan *TinySocket, 10),
		closeChan:   make(chan struct{}),
		sendBuffer:  make([]byte, 0, 4096),
		recvBuffer:  make([]byte, 0, 4096),
	}
}

// State returns the current state of the socket
func (s *TinySocket) State() SocketState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// LocalAddr returns the local address of the socket
func (s *TinySocket) LocalAddr() *net.TCPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localAddr
}

// RemoteAddr returns the remote address of the socket
func (s *TinySocket) RemoteAddr() *net.TCPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.remoteAddr
}

// setState changes the socket state (internal use)
func (s *TinySocket) setState(newState SocketState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = newState
}

// Listen starts listening on the specified address
func (s *TinySocket) Listen(addr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.localAddr = tcpAddr
	s.state = StateListen
	s.isListening = true
	
	return nil
}

// Accept waits for and returns the next connection
func (s *TinySocket) Accept() (*TinySocket, error) {
	if s.State() != StateListen {
		return nil, &net.OpError{Op: "accept", Err: errors.New("socket not listening")}
	}
	
	// Wait for incoming connection
	select {
	case conn := <-s.acceptChan:
		return conn, nil
	case <-s.closeChan:
		return nil, &net.OpError{Op: "accept", Err: errors.New("socket closed")}
	}
}

// Connect establishes a connection to the remote address
func (s *TinySocket) Connect(addr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.remoteAddr = tcpAddr
	s.state = StateSynSent
	
	// TODO: Implement TCP handshake
	// For now, simulate successful connection
	s.state = StateEstablished
	
	return nil
}

// Send sends data through the socket
func (s *TinySocket) Send(data []byte) (int, error) {
	if s.State() != StateEstablished {
		return 0, &net.OpError{Op: "send", Err: errors.New("socket not connected")}
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Add to send buffer for now
	s.sendBuffer = append(s.sendBuffer, data...)
	
	// TODO: Implement actual TCP sending
	// For now, simulate successful send
	return len(data), nil
}

// Receive receives data from the socket
func (s *TinySocket) Receive() ([]byte, error) {
	if s.State() != StateEstablished {
		return nil, &net.OpError{Op: "receive", Err: errors.New("socket not connected")}
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if len(s.recvBuffer) == 0 {
		return nil, &net.OpError{Op: "receive", Err: errors.New("no data available")}
	}
	
	// Return all available data for now
	data := make([]byte, len(s.recvBuffer))
	copy(data, s.recvBuffer)
	s.recvBuffer = s.recvBuffer[:0] // Clear buffer
	
	return data, nil
}

// Close closes the socket
func (s *TinySocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.state == StateClosed {
		return nil
	}
	
	s.state = StateClosed
	
	// Signal closure
	select {
	case <-s.closeChan:
		// Already closed
	default:
		close(s.closeChan)
	}
	
	return nil
}
