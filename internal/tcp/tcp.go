// Package tcp implements the TCP protocol layer
package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
)

// TCB (Transmission Control Block) represents the state of a TCP connection
type TCB struct {
	// Connection identification
	LocalAddr  *net.TCPAddr
	RemoteAddr *net.TCPAddr

	// Sequence numbers
	SendNext    uint32 // 次に送信するシーケンス番号
	SendUnack   uint32 // 未確認の最古のシーケンス番号
	RecvNext    uint32 // 次に受信を期待するシーケンス番号
	RecvWindow  uint16 // 受信ウィンドウサイズ

	// State
	State socket.SocketState

	// Buffers
	SendBuffer []byte
	RecvBuffer []byte
}

// NewTCB creates a new TCP Control Block
func NewTCB(localAddr, remoteAddr *net.TCPAddr) *TCB {
	return &TCB{
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		State:      socket.StateClosed,
		RecvWindow: 65535, // デフォルトウィンドウサイズ
	}
}

// GenerateISN generates an Initial Sequence Number
func (tcb *TCB) GenerateISN() uint32 {
	// 簡易的なISN生成（実際にはより複雑なアルゴリズムを使用）
	var isn [4]byte
	rand.Read(isn[:])
	return binary.BigEndian.Uint32(isn[:])
}

// ThreeWayHandshake handles the TCP three-way handshake process
type ThreeWayHandshake struct {
	tcb *TCB
}

// NewThreeWayHandshake creates a new three-way handshake handler
func NewThreeWayHandshake(tcb *TCB) *ThreeWayHandshake {
	return &ThreeWayHandshake{tcb: tcb}
}

// StartClient initiates a client-side connection (sends SYN)
func (h *ThreeWayHandshake) StartClient() (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateClosed {
		return nil, fmt.Errorf("connection must be in CLOSED state to start handshake")
	}

	// Step 1: Generate ISN and create SYN packet
	isn := h.tcb.GenerateISN()
	h.tcb.SendNext = isn + 1
	h.tcb.SendUnack = isn

	synHeader := packet.NewTCPHeader(
		uint16(h.tcb.LocalAddr.Port),
		uint16(h.tcb.RemoteAddr.Port),
	)
	synHeader.SequenceNumber = isn
	synHeader.SetFlag(packet.FlagSYN)
	synHeader.WindowSize = h.tcb.RecvWindow

	// Transition to SYN_SENT state
	h.tcb.State = socket.StateSynSent

	return synHeader, nil
}

// HandleSyn handles incoming SYN packet (server-side)
func (h *ThreeWayHandshake) HandleSyn(synHeader *packet.TCPHeader) (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateListen {
		return nil, fmt.Errorf("connection must be in LISTEN state to handle SYN")
	}

	// Store client's sequence number
	h.tcb.RecvNext = synHeader.SequenceNumber + 1

	// Generate our ISN and create SYN-ACK packet
	isn := h.tcb.GenerateISN()
	h.tcb.SendNext = isn + 1
	h.tcb.SendUnack = isn

	synAckHeader := packet.NewTCPHeader(
		uint16(h.tcb.LocalAddr.Port),
		uint16(h.tcb.RemoteAddr.Port),
	)
	synAckHeader.SequenceNumber = isn
	synAckHeader.AckNumber = h.tcb.RecvNext
	synAckHeader.SetFlag(packet.FlagSYN | packet.FlagACK)
	synAckHeader.WindowSize = h.tcb.RecvWindow

	// Transition to SYN_RECEIVED state
	h.tcb.State = socket.StateSynReceived

	return synAckHeader, nil
}

// HandleSynAck handles incoming SYN-ACK packet (client-side)
func (h *ThreeWayHandshake) HandleSynAck(synAckHeader *packet.TCPHeader) (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateSynSent {
		return nil, fmt.Errorf("connection must be in SYN_SENT state to handle SYN-ACK")
	}

	// Verify ACK number
	if synAckHeader.AckNumber != h.tcb.SendNext {
		return nil, fmt.Errorf("invalid ACK number in SYN-ACK")
	}

	// Store server's sequence number
	h.tcb.RecvNext = synAckHeader.SequenceNumber + 1

	// Create ACK packet
	ackHeader := packet.NewTCPHeader(
		uint16(h.tcb.LocalAddr.Port),
		uint16(h.tcb.RemoteAddr.Port),
	)
	ackHeader.SequenceNumber = h.tcb.SendNext
	ackHeader.AckNumber = h.tcb.RecvNext
	ackHeader.SetFlag(packet.FlagACK)
	ackHeader.WindowSize = h.tcb.RecvWindow

	// Connection established
	h.tcb.State = socket.StateEstablished

	return ackHeader, nil
}

// HandleAck handles incoming ACK packet (server-side, completes handshake)
func (h *ThreeWayHandshake) HandleAck(ackHeader *packet.TCPHeader) error {
	if h.tcb.State != socket.StateSynReceived {
		return fmt.Errorf("connection must be in SYN_RECEIVED state to handle final ACK")
	}

	// Verify ACK number
	if ackHeader.AckNumber != h.tcb.SendNext {
		return fmt.Errorf("invalid ACK number in final ACK")
	}

	// Verify sequence number
	if ackHeader.SequenceNumber != h.tcb.RecvNext {
		return fmt.Errorf("invalid sequence number in final ACK")
	}

	// Connection established
	h.tcb.State = socket.StateEstablished

	return nil
}

// GetState returns the current state of the TCB
func (tcb *TCB) GetState() socket.SocketState {
	return tcb.State
}

// SetState sets the state of the TCB
func (tcb *TCB) SetState(state socket.SocketState) {
	tcb.State = state
}

// String returns a string representation of the TCB
func (tcb *TCB) String() string {
	return fmt.Sprintf("TCB[%s -> %s, State: %s, SendNext: %d, RecvNext: %d]",
		tcb.LocalAddr, tcb.RemoteAddr, tcb.State.String(), tcb.SendNext, tcb.RecvNext)
}
