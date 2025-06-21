package tcp

import (
	"fmt"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
)

// ThreeWayHandshake はTCPの3ウェイハンドシェイク処理を担当する構造体
// ThreeWayHandshake handles the TCP three-way handshake process
type ThreeWayHandshake struct {
	tcb *TCB
}

// NewThreeWayHandshake は新しい3ウェイハンドシェイクハンドラを生成する
// NewThreeWayHandshake creates a new three-way handshake handler
func NewThreeWayHandshake(tcb *TCB) *ThreeWayHandshake {
	return &ThreeWayHandshake{tcb: tcb}
}

// StartClient はクライアント側の接続開始処理（SYN送信）を行う
// StartClient initiates a client-side connection (sends SYN)
func (h *ThreeWayHandshake) StartClient() (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateClosed {
		return nil, fmt.Errorf("connection must be in CLOSED state to start handshake")
	}

	// ステップ1: ISNを生成しSYNパケットを作成
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

	// SYNパケットを再送キューに追加
	h.tcb.RetransmissionQueue.Add(synHeader, nil)

	// 状態をSYN_SENTへ遷移
	h.tcb.State = socket.StateSynSent

	return synHeader, nil
}

// HandleSyn は受信したSYNパケット（サーバ側）を処理する
// HandleSyn handles incoming SYN packet (server-side)
func (h *ThreeWayHandshake) HandleSyn(synHeader *packet.TCPHeader) (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateListen {
		return nil, fmt.Errorf("connection must be in LISTEN state to handle SYN")
	}

	// クライアントのシーケンス番号を保存
	h.tcb.RecvNext = synHeader.SequenceNumber + 1

	// サーバ側のISNを生成しSYN-ACKパケットを作成
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

	// 状態をSYN_RECEIVEDへ遷移
	h.tcb.State = socket.StateSynReceived

	return synAckHeader, nil
}

// HandleSynAck は受信したSYN-ACKパケット（クライアント側）を処理する
// HandleSynAck handles incoming SYN-ACK packet (client-side)
func (h *ThreeWayHandshake) HandleSynAck(synAckHeader *packet.TCPHeader) (*packet.TCPHeader, error) {
	if h.tcb.State != socket.StateSynSent {
		return nil, fmt.Errorf("connection must be in SYN_SENT state to handle SYN-ACK")
	}

	// ACK番号を検証
	if synAckHeader.AckNumber != h.tcb.SendNext {
		return nil, fmt.Errorf("invalid ACK number in SYN-ACK")
	}

	// サーバのシーケンス番号を保存
	h.tcb.RecvNext = synAckHeader.SequenceNumber + 1

	// ACKパケットを作成
	ackHeader := packet.NewTCPHeader(
		uint16(h.tcb.LocalAddr.Port),
		uint16(h.tcb.RemoteAddr.Port),
	)
	ackHeader.SequenceNumber = h.tcb.SendNext
	ackHeader.AckNumber = h.tcb.RecvNext
	ackHeader.SetFlag(packet.FlagACK)
	ackHeader.WindowSize = h.tcb.RecvWindow

	// SYNがSYN-ACKで確認されたので再送キューから削除
	h.tcb.RetransmissionQueue.Remove(synAckHeader.AckNumber)

	// 接続確立
	h.tcb.State = socket.StateEstablished

	return ackHeader, nil
}

// HandleAck は受信したACKパケット（サーバ側、ハンドシェイク完了）を処理する
// HandleAck handles incoming ACK packet (server-side, completes handshake)
func (h *ThreeWayHandshake) HandleAck(ackHeader *packet.TCPHeader) error {
	if h.tcb.State != socket.StateSynReceived {
		return fmt.Errorf("connection must be in SYN_RECEIVED state to handle final ACK")
	}

	// ACK番号を検証
	if ackHeader.AckNumber != h.tcb.SendNext {
		return fmt.Errorf("invalid ACK number in final ACK")
	}

	// シーケンス番号を検証
	if ackHeader.SequenceNumber != h.tcb.RecvNext {
		return fmt.Errorf("invalid sequence number in final ACK")
	}

	// SYN-ACKを再送キューから削除
	h.tcb.RetransmissionQueue.Remove(ackHeader.AckNumber)

	// 接続確立
	h.tcb.State = socket.StateEstablished

	return nil
}
