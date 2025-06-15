package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
	"github.com/sasakihasuto/tinytcp/internal/tcp"
)

func main() {
	fmt.Println("=== TCP 再送機能デモ ===")

	// Create local and remote addresses
	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}

	// Create TCB
	tcb := tcp.NewTCB(localAddr, remoteAddr)

	// Set shorter timeout for demo purposes
	tcb.RetransmissionTimeout = 500 * time.Millisecond
	tcb.MaxRetransmissionAttempts = 2

	fmt.Printf("初期設定: タイムアウト=%v, 最大再送回数=%d\n",
		tcb.RetransmissionTimeout, tcb.MaxRetransmissionAttempts)

	// Test 1: Three-way handshake with retransmission
	fmt.Println("\n--- テスト1: 3ウェイハンドシェイクの再送 ---")
	testHandshakeRetransmission(tcb)

	// Test 2: Data transfer with retransmission
	fmt.Println("\n--- テスト2: データ転送の再送 ---")
	testDataRetransmission(tcb)

	// Test 3: Connection close with retransmission
	fmt.Println("\n--- テスト3: 接続切断の再送 ---")
	testCloseRetransmission(tcb)

	fmt.Println("\n=== デモ完了 ===")
}

func testHandshakeRetransmission(tcb *tcp.TCB) {
	// Start handshake
	handshake := tcp.NewThreeWayHandshake(tcb)

	// Client sends SYN
	synHeader, err := handshake.StartClient()
	if err != nil {
		log.Fatalf("SYN送信エラー: %v", err)
	}

	fmt.Printf("SYN送信: seq=%d\n", synHeader.SequenceNumber)
	fmt.Printf("再送キューサイズ: %d\n", tcb.RetransmissionQueue.Size())

	// Simulate timeout and check retransmission
	time.Sleep(600 * time.Millisecond) // Wait for timeout

	dt := tcp.NewDataTransfer(tcb)
	timeoutEntries, err := dt.CheckRetransmissions()
	if err != nil {
		log.Fatalf("再送チェックエラー: %v", err)
	}

	if len(timeoutEntries) > 0 {
		fmt.Printf("タイムアウト検出: %d個のパケットが再送対象\n", len(timeoutEntries))
		for i, entry := range timeoutEntries {
			fmt.Printf("  再送パケット%d: seq=%d, 試行回数=%d\n",
				i+1, entry.Header.SequenceNumber, entry.Attempts)
		}
	} else {
		fmt.Println("タイムアウトなし")
	}

	// Simulate receiving SYN-ACK (to clean up retransmission queue)
	synAckHeader := packet.NewTCPHeader(9090, 8080)
	synAckHeader.SequenceNumber = 2000
	synAckHeader.AckNumber = synHeader.SequenceNumber + 1
	synAckHeader.SetFlag(packet.FlagSYN | packet.FlagACK)

	ackHeader, err := handshake.HandleSynAck(synAckHeader)
	if err != nil {
		log.Printf("SYN-ACK処理エラー: %v", err)
	} else {
		fmt.Printf("SYN-ACK受信、ACK送信: seq=%d, ack=%d\n",
			ackHeader.SequenceNumber, ackHeader.AckNumber)
		fmt.Printf("再送キューサイズ: %d\n", tcb.RetransmissionQueue.Size())
	}
}

func testDataRetransmission(tcb *tcp.TCB) {
	// Set to ESTABLISHED state for data transfer
	tcb.State = socket.StateEstablished

	dt := tcp.NewDataTransfer(tcb)

	// Send data
	testData := []byte("Hello, TCP Retransmission!")
	dataHeader, err := dt.Send(testData)
	if err != nil {
		log.Fatalf("データ送信エラー: %v", err)
	}

	fmt.Printf("データ送信: seq=%d, len=%d\n",
		dataHeader.SequenceNumber, len(testData))
	fmt.Printf("再送キューサイズ: %d\n", dt.GetRetransmissionQueueSize())

	// Wait for timeout
	time.Sleep(600 * time.Millisecond)

	// Check for retransmissions
	timeoutEntries, err := dt.CheckRetransmissions()
	if err != nil {
		log.Fatalf("再送チェックエラー: %v", err)
	}

	if len(timeoutEntries) > 0 {
		fmt.Printf("データ再送検出: %d個のパケット\n", len(timeoutEntries))
		for i, entry := range timeoutEntries {
			fmt.Printf("  再送データ%d: seq=%d, len=%d, 試行回数=%d\n",
				i+1, entry.Header.SequenceNumber, len(entry.Data), entry.Attempts)
		}
	}

	// Simulate ACK to clear retransmission queue
	ackHeader := packet.NewTCPHeader(9090, 8080)
	ackHeader.SequenceNumber = tcb.RecvNext
	ackHeader.AckNumber = dataHeader.SequenceNumber + uint32(len(testData))
	ackHeader.SetFlag(packet.FlagACK)

	err = dt.ReceiveAck(ackHeader)
	if err != nil {
		log.Printf("ACK処理エラー: %v", err)
	} else {
		fmt.Printf("ACK受信: ack=%d\n", ackHeader.AckNumber)
		fmt.Printf("再送キューサイズ: %d\n", dt.GetRetransmissionQueueSize())
	}
}

func testCloseRetransmission(tcb *tcp.TCB) {
	// Set to ESTABLISHED state for close
	tcb.State = socket.StateEstablished

	handshake := tcp.NewFourWayHandshake(tcb)

	// Send FIN
	finHeader, err := handshake.Close()
	if err != nil {
		log.Fatalf("FIN送信エラー: %v", err)
	}

	fmt.Printf("FIN送信: seq=%d\n", finHeader.SequenceNumber)
	fmt.Printf("再送キューサイズ: %d\n", tcb.RetransmissionQueue.Size())

	// Wait for timeout
	time.Sleep(600 * time.Millisecond)

	// Check for retransmissions
	dt := tcp.NewDataTransfer(tcb)
	timeoutEntries, err := dt.CheckRetransmissions()
	if err != nil {
		log.Fatalf("再送チェックエラー: %v", err)
	}

	if len(timeoutEntries) > 0 {
		fmt.Printf("FIN再送検出: %d個のパケット\n", len(timeoutEntries))
		for i, entry := range timeoutEntries {
			fmt.Printf("  再送FIN%d: seq=%d, 試行回数=%d\n",
				i+1, entry.Header.SequenceNumber, entry.Attempts)
		}
	}

	fmt.Printf("最終状態: %s\n", tcb.State.String())
}
