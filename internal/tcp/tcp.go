// Package tcp implements the TCP protocol layer
package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
)

// RetransmissionEntry represents a packet waiting for acknowledgment
type RetransmissionEntry struct {
	Header   *packet.TCPHeader
	Data     []byte
	SentTime time.Time
	Attempts int
}

// RetransmissionQueue manages packets that need potential retransmission
type RetransmissionQueue struct {
	entries []RetransmissionEntry
	mutex   sync.Mutex
}

// NewRetransmissionQueue creates a new retransmission queue
func NewRetransmissionQueue() *RetransmissionQueue {
	return &RetransmissionQueue{
		entries: make([]RetransmissionEntry, 0),
	}
}

// Add adds a packet to the retransmission queue
func (rq *RetransmissionQueue) Add(header *packet.TCPHeader, data []byte) {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()

	entry := RetransmissionEntry{
		Header:   header,
		Data:     data,
		SentTime: time.Now(),
		Attempts: 1,
	}
	rq.entries = append(rq.entries, entry)
}

// Remove removes acknowledged packets from the queue
func (rq *RetransmissionQueue) Remove(ackNumber uint32) {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()

	// Remove entries that have been acknowledged
	newEntries := make([]RetransmissionEntry, 0)
	for _, entry := range rq.entries {
		// If the ACK number is greater than the sequence number + data length,
		// this packet has been acknowledged
		seqEnd := entry.Header.SequenceNumber + uint32(len(entry.Data))
		if entry.Header.HasFlag(packet.FlagSYN) || entry.Header.HasFlag(packet.FlagFIN) {
			seqEnd++ // SYN and FIN consume one sequence number
		}

		if ackNumber < seqEnd {
			newEntries = append(newEntries, entry)
		}
	}
	rq.entries = newEntries
}

// GetTimeoutEntries returns entries that have timed out and need retransmission
func (rq *RetransmissionQueue) GetTimeoutEntries(timeout time.Duration, maxAttempts int) []RetransmissionEntry {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()

	var timeoutEntries []RetransmissionEntry
	now := time.Now()

	for i := range rq.entries {
		entry := &rq.entries[i]
		if now.Sub(entry.SentTime) > timeout && entry.Attempts < maxAttempts {
			// Update the entry for next potential retransmission
			entry.SentTime = now
			entry.Attempts++
			// Add the updated entry to timeout entries
			timeoutEntries = append(timeoutEntries, *entry)
		}
	}

	return timeoutEntries
}

// Size returns the number of entries in the queue
func (rq *RetransmissionQueue) Size() int {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()
	return len(rq.entries)
}

// TCB (Transmission Control Block) represents the state of a TCP connection
type TCB struct {
	// Connection identification
	LocalAddr  *net.TCPAddr
	RemoteAddr *net.TCPAddr

	// Sequence numbers
	SendNext   uint32 // 次に送信するシーケンス番号
	SendUnack  uint32 // 未確認の最古のシーケンス番号
	RecvNext   uint32 // 次に受信を期待するシーケンス番号
	RecvWindow uint16 // 受信ウィンドウサイズ

	// State
	State socket.SocketState

	// Buffers
	SendBuffer []byte
	RecvBuffer []byte

	// Retransmission management
	RetransmissionQueue       *RetransmissionQueue
	RetransmissionTimeout     time.Duration
	MaxRetransmissionAttempts int
}

// NewTCB creates a new TCP Control Block
func NewTCB(localAddr, remoteAddr *net.TCPAddr) *TCB {
	return &TCB{
		LocalAddr:                 localAddr,
		RemoteAddr:                remoteAddr,
		State:                     socket.StateClosed,
		RecvWindow:                65535, // デフォルトウィンドウサイズ
		RetransmissionQueue:       NewRetransmissionQueue(),
		RetransmissionTimeout:     1 * time.Second, // デフォルト1秒
		MaxRetransmissionAttempts: 3,               // 最大3回再送
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

	// Add SYN packet to retransmission queue
	h.tcb.RetransmissionQueue.Add(synHeader, nil)

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

	// Remove SYN from retransmission queue (it's been acknowledged by SYN-ACK)
	h.tcb.RetransmissionQueue.Remove(synAckHeader.AckNumber)

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

	// Remove SYN-ACK from retransmission queue
	h.tcb.RetransmissionQueue.Remove(ackHeader.AckNumber)

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

	// Add to retransmission queue
	dt.tcb.RetransmissionQueue.Add(header, data)

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

	// Remove acknowledged packets from retransmission queue
	dt.tcb.RetransmissionQueue.Remove(header.AckNumber)

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

// CheckRetransmissions checks for packets that need retransmission
func (dt *DataTransfer) CheckRetransmissions() ([]RetransmissionEntry, error) {
	timeoutEntries := dt.tcb.RetransmissionQueue.GetTimeoutEntries(
		dt.tcb.RetransmissionTimeout,
		dt.tcb.MaxRetransmissionAttempts,
	)
	return timeoutEntries, nil
}

// GetRetransmissionQueueSize returns the current size of retransmission queue
func (dt *DataTransfer) GetRetransmissionQueueSize() int {
	return dt.tcb.RetransmissionQueue.Size()
}

// SetRetransmissionTimeout sets the retransmission timeout
func (dt *DataTransfer) SetRetransmissionTimeout(timeout time.Duration) {
	dt.tcb.RetransmissionTimeout = timeout
}

// SetMaxRetransmissionAttempts sets the maximum number of retransmission attempts
func (dt *DataTransfer) SetMaxRetransmissionAttempts(maxAttempts int) {
	dt.tcb.MaxRetransmissionAttempts = maxAttempts
}

// FourWayHandshake handles the TCP four-way handshake process for connection termination
type FourWayHandshake struct {
	tcb *TCB
}

// NewFourWayHandshake creates a new four-way handshake handler
func NewFourWayHandshake(tcb *TCB) *FourWayHandshake {
	return &FourWayHandshake{tcb: tcb}
}

// Close initiates connection termination (sends FIN)
func (h *FourWayHandshake) Close() (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateEstablished {
		return nil, fmt.Errorf("connection must be in ESTABLISHED state to close")
	}

	// Create FIN packet
	finHeader := packet.NewTCPHeader(
		uint16(h.tcb.LocalAddr.Port),
		uint16(h.tcb.RemoteAddr.Port),
	)
	finHeader.SequenceNumber = h.tcb.SendNext
	finHeader.AckNumber = h.tcb.RecvNext
	finHeader.SetFlag(packet.FlagFIN | packet.FlagACK)
	finHeader.WindowSize = h.tcb.RecvWindow

	// Add FIN packet to retransmission queue
	h.tcb.RetransmissionQueue.Add(finHeader, nil)

	// Update sequence number (FIN consumes one sequence number)
	h.tcb.SendNext++

	// Transition to FIN_WAIT_1 state
	h.tcb.State = socket.StateFinWait1

	return finHeader, nil
}

// HandleFin handles incoming FIN packet (passive close)
func (h *FourWayHandshake) HandleFin(finHeader *packet.TCPHeader) (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateEstablished && h.tcb.State != socket.StateFinWait1 && h.tcb.State != socket.StateFinWait2 {
		return nil, fmt.Errorf("unexpected FIN in state %s", h.tcb.State.String())
	}

	// Verify sequence number
	if finHeader.SequenceNumber != h.tcb.RecvNext {
		return nil, fmt.Errorf("unexpected sequence number in FIN: expected %d, got %d",
			h.tcb.RecvNext, finHeader.SequenceNumber)
	}

	// Update receive sequence number (FIN consumes one sequence number)
	h.tcb.RecvNext++

	// Create ACK for FIN
	ackHeader := packet.NewTCPHeader(
		uint16(h.tcb.LocalAddr.Port),
		uint16(h.tcb.RemoteAddr.Port),
	)
	ackHeader.SequenceNumber = h.tcb.SendNext
	ackHeader.AckNumber = h.tcb.RecvNext
	ackHeader.SetFlag(packet.FlagACK)
	ackHeader.WindowSize = h.tcb.RecvWindow

	// State transition depends on current state
	switch h.tcb.State {
	case socket.StateEstablished:
		// Passive close: ESTABLISHED -> CLOSE_WAIT
		h.tcb.State = socket.StateCloseWait
	case socket.StateFinWait1:
		// Simultaneous close: FIN_WAIT_1 -> CLOSING
		h.tcb.State = socket.StateClosing
	case socket.StateFinWait2:
		// Normal close completion: FIN_WAIT_2 -> TIME_WAIT
		h.tcb.State = socket.StateTimeWait
	}

	return ackHeader, nil
}

// HandleFinAck handles ACK for our FIN packet
func (h *FourWayHandshake) HandleFinAck(ackHeader *packet.TCPHeader) error {
	if h.tcb.State != socket.StateFinWait1 && h.tcb.State != socket.StateClosing && h.tcb.State != socket.StateLastAck {
		return fmt.Errorf("unexpected FIN ACK in state %s", h.tcb.State.String())
	}

	// Verify ACK number (should acknowledge our FIN)
	if ackHeader.AckNumber != h.tcb.SendNext {
		return fmt.Errorf("invalid ACK number for FIN: expected %d, got %d",
			h.tcb.SendNext, ackHeader.AckNumber)
	}

	// Update unacknowledged sequence number
	h.tcb.SendUnack = ackHeader.AckNumber

	// State transition depends on current state
	switch h.tcb.State {
	case socket.StateFinWait1:
		// FIN_WAIT_1 -> FIN_WAIT_2 (our FIN acknowledged, waiting for their FIN)
		h.tcb.State = socket.StateFinWait2
	case socket.StateClosing:
		// CLOSING -> TIME_WAIT (both FINs sent and acknowledged)
		h.tcb.State = socket.StateTimeWait
	case socket.StateLastAck:
		// LAST_ACK -> CLOSED (final ACK received)
		h.tcb.State = socket.StateClosed
	}

	return nil
}

// CloseFromCloseWait completes passive close from CLOSE_WAIT state
func (h *FourWayHandshake) CloseFromCloseWait() (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateCloseWait {
		return nil, fmt.Errorf("connection must be in CLOSE_WAIT state")
	}

	// Create FIN packet for final close
	finHeader := packet.NewTCPHeader(
		uint16(h.tcb.LocalAddr.Port),
		uint16(h.tcb.RemoteAddr.Port),
	)
	finHeader.SequenceNumber = h.tcb.SendNext
	finHeader.AckNumber = h.tcb.RecvNext
	finHeader.SetFlag(packet.FlagFIN | packet.FlagACK)
	finHeader.WindowSize = h.tcb.RecvWindow

	// Update sequence number (FIN consumes one sequence number)
	h.tcb.SendNext++

	// Transition to LAST_ACK state
	h.tcb.State = socket.StateLastAck

	return finHeader, nil
}

// IsConnectionClosed returns true if the connection is fully closed
func (h *FourWayHandshake) IsConnectionClosed() bool {
	return h.tcb.State == socket.StateClosed
}

// CanSendData returns true if the connection can still send data
func (h *FourWayHandshake) CanSendData() bool {
	return h.tcb.State == socket.StateEstablished
}

// CanReceiveData returns true if the connection can still receive data
func (h *FourWayHandshake) CanReceiveData() bool {
	return h.tcb.State == socket.StateEstablished || h.tcb.State == socket.StateCloseWait
}
