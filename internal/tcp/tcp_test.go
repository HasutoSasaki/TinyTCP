package tcp

import (
	"net"
	"testing"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
)

func TestTCB_NewTCB(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)

	if tcb.LocalAddr.String() != localAddr.String() {
		t.Errorf("Expected local address %s, got %s", localAddr.String(), tcb.LocalAddr.String())
	}
	if tcb.RemoteAddr.String() != remoteAddr.String() {
		t.Errorf("Expected remote address %s, got %s", remoteAddr.String(), tcb.RemoteAddr.String())
	}
	if tcb.State != socket.StateClosed {
		t.Errorf("Expected initial state CLOSED, got %s", tcb.State.String())
	}
	if tcb.RecvWindow != 65535 {
		t.Errorf("Expected receive window 65535, got %d", tcb.RecvWindow)
	}
}

func TestTCB_GenerateISN(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")
	tcb := NewTCB(localAddr, remoteAddr)

	isn1 := tcb.GenerateISN()
	isn2 := tcb.GenerateISN()

	// ISNは毎回異なる値である必要がある（確率的テスト）
	if isn1 == isn2 {
		t.Logf("Warning: Generated ISNs are identical: %d", isn1)
	}
}

func TestThreeWayHandshake_Complete(t *testing.T) {
	// Setup addresses
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// Create TCBs
	clientTCB := NewTCB(clientAddr, serverAddr)
	serverTCB := NewTCB(serverAddr, clientAddr)

	// Set initial states
	clientTCB.State = socket.StateClosed
	serverTCB.State = socket.StateListen

	// Create handshake handlers
	clientHandshake := NewThreeWayHandshake(clientTCB)
	serverHandshake := NewThreeWayHandshake(serverTCB)

	// Step 1: Client sends SYN
	synPacket, err := clientHandshake.StartClient()
	if err != nil {
		t.Fatalf("Failed to start client handshake: %v", err)
	}

	// Verify client state and SYN packet
	if clientTCB.State != socket.StateSynSent {
		t.Errorf("Expected client state SYN_SENT, got %s", clientTCB.State.String())
	}
	if !synPacket.HasFlag(packet.FlagSYN) {
		t.Error("SYN packet should have SYN flag set")
	}
	if synPacket.HasFlag(packet.FlagACK) {
		t.Error("SYN packet should not have ACK flag set")
	}

	// Step 2: Server handles SYN and sends SYN-ACK
	synAckPacket, err := serverHandshake.HandleSyn(synPacket)
	if err != nil {
		t.Fatalf("Failed to handle SYN: %v", err)
	}

	// Verify server state and SYN-ACK packet
	if serverTCB.State != socket.StateSynReceived {
		t.Errorf("Expected server state SYN_RECEIVED, got %s", serverTCB.State.String())
	}
	if !synAckPacket.HasFlag(packet.FlagSYN) {
		t.Error("SYN-ACK packet should have SYN flag set")
	}
	if !synAckPacket.HasFlag(packet.FlagACK) {
		t.Error("SYN-ACK packet should have ACK flag set")
	}
	if synAckPacket.AckNumber != synPacket.SequenceNumber+1 {
		t.Errorf("Expected ACK number %d, got %d", 
			synPacket.SequenceNumber+1, synAckPacket.AckNumber)
	}

	// Step 3: Client handles SYN-ACK and sends ACK
	ackPacket, err := clientHandshake.HandleSynAck(synAckPacket)
	if err != nil {
		t.Fatalf("Failed to handle SYN-ACK: %v", err)
	}

	// Verify client state and ACK packet
	if clientTCB.State != socket.StateEstablished {
		t.Errorf("Expected client state ESTABLISHED, got %s", clientTCB.State.String())
	}
	if ackPacket.HasFlag(packet.FlagSYN) {
		t.Error("ACK packet should not have SYN flag set")
	}
	if !ackPacket.HasFlag(packet.FlagACK) {
		t.Error("ACK packet should have ACK flag set")
	}
	if ackPacket.AckNumber != synAckPacket.SequenceNumber+1 {
		t.Errorf("Expected ACK number %d, got %d", 
			synAckPacket.SequenceNumber+1, ackPacket.AckNumber)
	}

	// Step 4: Server handles final ACK
	err = serverHandshake.HandleAck(ackPacket)
	if err != nil {
		t.Fatalf("Failed to handle final ACK: %v", err)
	}

	// Verify server final state
	if serverTCB.State != socket.StateEstablished {
		t.Errorf("Expected server state ESTABLISHED, got %s", serverTCB.State.String())
	}

	t.Logf("Handshake completed successfully!")
	t.Logf("Client TCB: %s", clientTCB.String())
	t.Logf("Server TCB: %s", serverTCB.String())
}

func TestThreeWayHandshake_InvalidStates(t *testing.T) {
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// Test StartClient with invalid state
	tcb := NewTCB(clientAddr, serverAddr)
	tcb.State = socket.StateEstablished // Invalid state for starting handshake
	handshake := NewThreeWayHandshake(tcb)

	_, err := handshake.StartClient()
	if err == nil {
		t.Error("Expected error when starting handshake from non-CLOSED state")
	}

	// Test HandleSyn with invalid state
	tcb.State = socket.StateClosed // Invalid state for handling SYN (should be LISTEN)
	synHeader := packet.NewTCPHeader(8080, 9090)
	synHeader.SetFlag(packet.FlagSYN)

	_, err = handshake.HandleSyn(synHeader)
	if err == nil {
		t.Error("Expected error when handling SYN from non-LISTEN state")
	}
}

func TestThreeWayHandshake_InvalidACKNumbers(t *testing.T) {
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	clientTCB := NewTCB(clientAddr, serverAddr)
	clientTCB.State = socket.StateSynSent
	clientTCB.SendNext = 1000

	handshake := NewThreeWayHandshake(clientTCB)

	// Create SYN-ACK with invalid ACK number
	synAckHeader := packet.NewTCPHeader(9090, 8080)
	synAckHeader.SetFlag(packet.FlagSYN | packet.FlagACK)
	synAckHeader.SequenceNumber = 2000
	synAckHeader.AckNumber = 999 // Invalid - should be 1000

	_, err := handshake.HandleSynAck(synAckHeader)
	if err == nil {
		t.Error("Expected error when handling SYN-ACK with invalid ACK number")
	}
}
