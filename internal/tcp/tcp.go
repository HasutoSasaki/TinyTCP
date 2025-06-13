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

// DataTransfer handles data transmission and reception
type DataTransfer struct {
	tcb *TCB
}

// NewDataTransfer creates a new data transfer handler
func NewDataTransfer(tcb *TCB) *DataTransfer {
	return &DataTransfer{tcb: tcb}
}

// Send sends data and returns a TCP packet with the data
func (dt *DataTransfer) Send(data []byte) (*packet.TCPHeader, error) {
	if dt.tcb.State != socket.StateEstablished {
		return nil, fmt.Errorf("connection must be in ESTABLISHED state to send data")
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("cannot send empty data")
	}

	// Create data packet
	header := packet.NewTCPHeader(
		uint16(dt.tcb.LocalAddr.Port),
		uint16(dt.tcb.RemoteAddr.Port),
	)
	
	header.SequenceNumber = dt.tcb.SendNext
	header.AckNumber = dt.tcb.RecvNext
	header.SetFlag(packet.FlagACK | packet.FlagPSH) // ACK + PSH for data
	header.WindowSize = dt.tcb.RecvWindow

	// データを送信バッファに追加（学習目的のためシンプルに）
	dt.tcb.SendBuffer = append(dt.tcb.SendBuffer, data...)

	// シーケンス番号を更新（送信データ長分進める）
	dt.tcb.SendNext += uint32(len(data))

	return header, nil
}

// Receive processes incoming data packet and returns received data
func (dt *DataTransfer) Receive(header *packet.TCPHeader, data []byte) ([]byte, *packet.TCPHeader, error) {
	if dt.tcb.State != socket.StateEstablished {
		return nil, nil, fmt.Errorf("connection must be in ESTABLISHED state to receive data")
	}

	// シーケンス番号の検証
	if header.SequenceNumber != dt.tcb.RecvNext {
		return nil, nil, fmt.Errorf("out-of-order packet: expected seq %d, got %d", 
			dt.tcb.RecvNext, header.SequenceNumber)
	}

	// データを受信バッファに追加
	dt.tcb.RecvBuffer = append(dt.tcb.RecvBuffer, data...)
	
	// 受信シーケンス番号を更新
	dt.tcb.RecvNext += uint32(len(data))

	// ACKパケットを作成
	ackHeader := packet.NewTCPHeader(
		uint16(dt.tcb.LocalAddr.Port),
		uint16(dt.tcb.RemoteAddr.Port),
	)
	
	ackHeader.SequenceNumber = dt.tcb.SendNext
	ackHeader.AckNumber = dt.tcb.RecvNext // 更新された受信シーケンス番号
	ackHeader.SetFlag(packet.FlagACK)
	ackHeader.WindowSize = dt.tcb.RecvWindow

	return data, ackHeader, nil
}

// ReceiveAck processes incoming ACK packet for sent data
func (dt *DataTransfer) ReceiveAck(header *packet.TCPHeader) error {
	if dt.tcb.State != socket.StateEstablished {
		return fmt.Errorf("connection must be in ESTABLISHED state to process ACK")
	}

	// ACK番号の検証
	if header.AckNumber < dt.tcb.SendUnack || header.AckNumber > dt.tcb.SendNext {
		return fmt.Errorf("invalid ACK number: %d (expected between %d and %d)", 
			header.AckNumber, dt.tcb.SendUnack, dt.tcb.SendNext)
	}

	// 確認済みデータの更新
	dt.tcb.SendUnack = header.AckNumber

	return nil
}

// GetSendBuffer returns a copy of the send buffer
func (dt *DataTransfer) GetSendBuffer() []byte {
	return append([]byte(nil), dt.tcb.SendBuffer...)
}

// GetReceiveBuffer returns a copy of the receive buffer
func (dt *DataTransfer) GetReceiveBuffer() []byte {
	return append([]byte(nil), dt.tcb.RecvBuffer...)
}

// ClearReceiveBuffer clears the receive buffer (after application reads data)
func (dt *DataTransfer) ClearReceiveBuffer() {
	dt.tcb.RecvBuffer = dt.tcb.RecvBuffer[:0]
}
