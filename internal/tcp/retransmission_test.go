package tcp

import (
	"net"
	"testing"
	"time"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
)

func TestRetransmissionQueue(t *testing.T) {
	rq := NewRetransmissionQueue()

	// Test empty queue
	if rq.Size() != 0 {
		t.Errorf("Expected empty queue, got size %d", rq.Size())
	}

	// Add a packet
	header := packet.NewTCPHeader(8080, 9090)
	header.SequenceNumber = 1000
	data := []byte("test data")

	rq.Add(header, data)

	if rq.Size() != 1 {
		t.Errorf("Expected queue size 1, got %d", rq.Size())
	}

	// Test timeout entries (should be empty immediately)
	timeoutEntries := rq.GetTimeoutEntries(1*time.Second, 3)
	if len(timeoutEntries) != 0 {
		t.Errorf("Expected no timeout entries immediately, got %d", len(timeoutEntries))
	}

	// Wait and check timeout
	time.Sleep(10 * time.Millisecond)
	timeoutEntries = rq.GetTimeoutEntries(5*time.Millisecond, 3)
	if len(timeoutEntries) != 1 {
		t.Errorf("Expected 1 timeout entry, got %d", len(timeoutEntries))
	}

	// Remove acknowledged packet
	rq.Remove(1009) // ack for sequence 1000-1008 (data length)
	if rq.Size() != 0 {
		t.Errorf("Expected empty queue after removal, got size %d", rq.Size())
	}
}

func TestDataTransferWithRetransmission(t *testing.T) {
	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateEstablished
	tcb.SendNext = 1000
	tcb.RecvNext = 2000
	tcb.RetransmissionTimeout = 10 * time.Millisecond

	dt := NewDataTransfer(tcb)

	// Send data
	testData := []byte("Hello, World!")
	header, err := dt.Send(testData)
	if err != nil {
		t.Fatalf("Failed to send data: %v", err)
	}

	if header.SequenceNumber != 1000 {
		t.Errorf("Expected sequence number 1000, got %d", header.SequenceNumber)
	}

	// Check retransmission queue
	if dt.GetRetransmissionQueueSize() != 1 {
		t.Errorf("Expected retransmission queue size 1, got %d", dt.GetRetransmissionQueueSize())
	}

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Check for timeout entries
	timeoutEntries, err := dt.CheckRetransmissions()
	if err != nil {
		t.Fatalf("Failed to check retransmissions: %v", err)
	}

	if len(timeoutEntries) != 1 {
		t.Errorf("Expected 1 timeout entry, got %d", len(timeoutEntries))
	}

	if timeoutEntries[0].Attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", timeoutEntries[0].Attempts)
	}

	// Simulate ACK
	ackHeader := packet.NewTCPHeader(9090, 8080)
	ackHeader.AckNumber = 1000 + uint32(len(testData))
	ackHeader.SetFlag(packet.FlagACK)

	err = dt.ReceiveAck(ackHeader)
	if err != nil {
		t.Fatalf("Failed to process ACK: %v", err)
	}

	// Check retransmission queue is cleared
	if dt.GetRetransmissionQueueSize() != 0 {
		t.Errorf("Expected empty retransmission queue, got size %d", dt.GetRetransmissionQueueSize())
	}
}

func TestHandshakeWithRetransmission(t *testing.T) {
	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.RetransmissionTimeout = 10 * time.Millisecond

	handshake := NewThreeWayHandshake(tcb)

	// Start client handshake (send SYN)
	synHeader, err := handshake.StartClient()
	if err != nil {
		t.Fatalf("Failed to start client handshake: %v", err)
	}

	// Check SYN is in retransmission queue
	if tcb.RetransmissionQueue.Size() != 1 {
		t.Errorf("Expected SYN in retransmission queue, got size %d", tcb.RetransmissionQueue.Size())
	}

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Check for timeout entries
	dt := NewDataTransfer(tcb)
	timeoutEntries, err := dt.CheckRetransmissions()
	if err != nil {
		t.Fatalf("Failed to check retransmissions: %v", err)
	}

	if len(timeoutEntries) != 1 {
		t.Errorf("Expected 1 timeout entry for SYN, got %d", len(timeoutEntries))
	}

	// Simulate SYN-ACK response
	synAckHeader := packet.NewTCPHeader(9090, 8080)
	synAckHeader.SequenceNumber = 2000
	synAckHeader.AckNumber = synHeader.SequenceNumber + 1
	synAckHeader.SetFlag(packet.FlagSYN | packet.FlagACK)

	ackHeader, err := handshake.HandleSynAck(synAckHeader)
	if err != nil {
		t.Fatalf("Failed to handle SYN-ACK: %v", err)
	}

	// Check SYN is removed from retransmission queue
	if tcb.RetransmissionQueue.Size() != 0 {
		t.Errorf("Expected empty retransmission queue after SYN-ACK, got size %d", tcb.RetransmissionQueue.Size())
	}

	// Check state is ESTABLISHED
	if tcb.State != socket.StateEstablished {
		t.Errorf("Expected ESTABLISHED state, got %s", tcb.State.String())
	}

	// Check ACK header
	if ackHeader.AckNumber != synAckHeader.SequenceNumber+1 {
		t.Errorf("Expected ACK number %d, got %d", synAckHeader.SequenceNumber+1, ackHeader.AckNumber)
	}
}

func TestCloseWithRetransmission(t *testing.T) {
	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateEstablished
	tcb.SendNext = 1000
	tcb.RecvNext = 2000
	tcb.RetransmissionTimeout = 10 * time.Millisecond

	handshake := NewFourWayHandshake(tcb)

	// Send FIN
	finHeader, err := handshake.Close()
	if err != nil {
		t.Fatalf("Failed to close connection: %v", err)
	}

	// Check FIN is in retransmission queue
	if tcb.RetransmissionQueue.Size() != 1 {
		t.Errorf("Expected FIN in retransmission queue, got size %d", tcb.RetransmissionQueue.Size())
	}

	// Check state transition
	if tcb.State != socket.StateFinWait1 {
		t.Errorf("Expected FIN_WAIT_1 state, got %s", tcb.State.String())
	}

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Check for timeout entries
	dt := NewDataTransfer(tcb)
	timeoutEntries, err := dt.CheckRetransmissions()
	if err != nil {
		t.Fatalf("Failed to check retransmissions: %v", err)
	}

	if len(timeoutEntries) != 1 {
		t.Errorf("Expected 1 timeout entry for FIN, got %d", len(timeoutEntries))
	}

	// Check FIN header
	if finHeader.SequenceNumber != 1000 {
		t.Errorf("Expected FIN sequence number 1000, got %d", finHeader.SequenceNumber)
	}

	if !finHeader.HasFlag(packet.FlagFIN) {
		t.Error("Expected FIN flag to be set")
	}
}

func TestRetransmissionTimeout(t *testing.T) {
	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateEstablished
	tcb.SendNext = 1000
	tcb.RecvNext = 2000

	dt := NewDataTransfer(tcb)

	// Test setting custom timeout
	customTimeout := 2 * time.Second
	dt.SetRetransmissionTimeout(customTimeout)
	if tcb.RetransmissionTimeout != customTimeout {
		t.Errorf("Expected timeout %v, got %v", customTimeout, tcb.RetransmissionTimeout)
	}

	// Test setting max attempts
	maxAttempts := 5
	dt.SetMaxRetransmissionAttempts(maxAttempts)
	if tcb.MaxRetransmissionAttempts != maxAttempts {
		t.Errorf("Expected max attempts %d, got %d", maxAttempts, tcb.MaxRetransmissionAttempts)
	}
}
