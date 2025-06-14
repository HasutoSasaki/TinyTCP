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

func TestDataTransfer_Send(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateEstablished
	tcb.SendNext = 1000
	tcb.RecvNext = 2000

	dt := NewDataTransfer(tcb)

	testData := []byte("Hello, TCP!")
	dataPacket, err := dt.Send(testData)
	if err != nil {
		t.Fatalf("Failed to send data: %v", err)
	}

	// パケットの検証
	if dataPacket.SequenceNumber != 1000 {
		t.Errorf("Expected sequence number 1000, got %d", dataPacket.SequenceNumber)
	}
	if dataPacket.AckNumber != 2000 {
		t.Errorf("Expected ACK number 2000, got %d", dataPacket.AckNumber)
	}
	if !dataPacket.HasFlag(packet.FlagACK) {
		t.Error("Data packet should have ACK flag")
	}
	if !dataPacket.HasFlag(packet.FlagPSH) {
		t.Error("Data packet should have PSH flag")
	}

	// TCBの状態更新確認
	expectedSendNext := 1000 + uint32(len(testData))
	if tcb.SendNext != expectedSendNext {
		t.Errorf("Expected SendNext %d, got %d", expectedSendNext, tcb.SendNext)
	}

	// 送信バッファの確認
	if string(dt.GetSendBuffer()) != string(testData) {
		t.Errorf("Expected send buffer %q, got %q", string(testData), string(dt.GetSendBuffer()))
	}
}

func TestDataTransfer_Receive(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateEstablished
	tcb.SendNext = 1000
	tcb.RecvNext = 2000

	dt := NewDataTransfer(tcb)

	// 受信データパケットを作成
	incomingHeader := packet.NewTCPHeader(9090, 8080)
	incomingHeader.SequenceNumber = 2000 // 期待されるシーケンス番号
	incomingHeader.SetFlag(packet.FlagACK | packet.FlagPSH)

	testData := []byte("Hello from remote!")
	receivedData, ackPacket, err := dt.Receive(incomingHeader, testData)
	if err != nil {
		t.Fatalf("Failed to receive data: %v", err)
	}

	// 受信データの検証
	if string(receivedData) != string(testData) {
		t.Errorf("Expected received data %q, got %q", string(testData), string(receivedData))
	}

	// ACKパケットの検証
	if ackPacket.SequenceNumber != 1000 {
		t.Errorf("Expected ACK sequence number 1000, got %d", ackPacket.SequenceNumber)
	}
	expectedAckNumber := 2000 + uint32(len(testData))
	if ackPacket.AckNumber != expectedAckNumber {
		t.Errorf("Expected ACK number %d, got %d", expectedAckNumber, ackPacket.AckNumber)
	}
	if !ackPacket.HasFlag(packet.FlagACK) {
		t.Error("ACK packet should have ACK flag")
	}

	// TCBの状態更新確認
	if tcb.RecvNext != expectedAckNumber {
		t.Errorf("Expected RecvNext %d, got %d", expectedAckNumber, tcb.RecvNext)
	}

	// 受信バッファの確認
	if string(dt.GetReceiveBuffer()) != string(testData) {
		t.Errorf("Expected receive buffer %q, got %q", string(testData), string(dt.GetReceiveBuffer()))
	}
}

func TestDataTransfer_ReceiveAck(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateEstablished
	tcb.SendNext = 1050
	tcb.SendUnack = 1000

	dt := NewDataTransfer(tcb)

	// ACKパケットを作成
	ackHeader := packet.NewTCPHeader(9090, 8080)
	ackHeader.AckNumber = 1025 // 25バイト確認
	ackHeader.SetFlag(packet.FlagACK)

	err := dt.ReceiveAck(ackHeader)
	if err != nil {
		t.Fatalf("Failed to process ACK: %v", err)
	}

	// SendUnackの更新確認
	if tcb.SendUnack != 1025 {
		t.Errorf("Expected SendUnack 1025, got %d", tcb.SendUnack)
	}
}

func TestDataTransfer_InvalidStates(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateClosed // Invalid state

	dt := NewDataTransfer(tcb)

	// 非ESTABLISHED状態でのSendテスト
	_, err := dt.Send([]byte("test"))
	if err == nil {
		t.Error("Expected error when sending in non-ESTABLISHED state")
	}

	// 非ESTABLISHED状態でのReceiveテスト
	header := packet.NewTCPHeader(9090, 8080)
	_, _, err = dt.Receive(header, []byte("test"))
	if err == nil {
		t.Error("Expected error when receiving in non-ESTABLISHED state")
	}
}

func TestDataTransfer_OutOfOrderPacket(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)
	tcb.State = socket.StateEstablished
	tcb.RecvNext = 2000

	dt := NewDataTransfer(tcb)

	// 順序が異なるパケット
	outOfOrderHeader := packet.NewTCPHeader(9090, 8080)
	outOfOrderHeader.SequenceNumber = 2050 // 期待より大きい

	_, _, err := dt.Receive(outOfOrderHeader, []byte("out of order"))
	if err == nil {
		t.Error("Expected error for out-of-order packet")
	}
}

func TestDataTransfer_CompleteExchange(t *testing.T) {
	// 送信者と受信者のTCBを作成
	senderAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	receiverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	senderTCB := NewTCB(senderAddr, receiverAddr)
	receiverTCB := NewTCB(receiverAddr, senderAddr)

	// 両方ともESTABLISHED状態に設定
	senderTCB.State = socket.StateEstablished
	receiverTCB.State = socket.StateEstablished
	senderTCB.SendNext = 1000
	senderTCB.RecvNext = 2000
	receiverTCB.SendNext = 2000
	receiverTCB.RecvNext = 1000

	senderDT := NewDataTransfer(senderTCB)
	receiverDT := NewDataTransfer(receiverTCB)

	// Step 1: 送信者がデータを送信
	testData := []byte("Hello, receiver!")
	dataPacket, err := senderDT.Send(testData)
	if err != nil {
		t.Fatalf("Sender failed to send data: %v", err)
	}

	// Step 2: 受信者がデータを受信してACKを返す
	receivedData, ackPacket, err := receiverDT.Receive(dataPacket, testData)
	if err != nil {
		t.Fatalf("Receiver failed to receive data: %v", err)
	}

	if string(receivedData) != string(testData) {
		t.Errorf("Data mismatch: expected %q, got %q", string(testData), string(receivedData))
	}

	// Step 3: 送信者がACKを処理
	err = senderDT.ReceiveAck(ackPacket)
	if err != nil {
		t.Fatalf("Sender failed to process ACK: %v", err)
	}

	// 最終状態確認
	expectedSenderNext := 1000 + uint32(len(testData))
	if senderTCB.SendNext != expectedSenderNext {
		t.Errorf("Expected sender SendNext %d, got %d", expectedSenderNext, senderTCB.SendNext)
	}
	if senderTCB.SendUnack != expectedSenderNext {
		t.Errorf("Expected sender SendUnack %d, got %d", expectedSenderNext, senderTCB.SendUnack)
	}

	expectedReceiverNext := 1000 + uint32(len(testData))
	if receiverTCB.RecvNext != expectedReceiverNext {
		t.Errorf("Expected receiver RecvNext %d, got %d", expectedReceiverNext, receiverTCB.RecvNext)
	}

	t.Logf("Data exchange completed successfully!")
	t.Logf("Sent data: %q", string(testData))
	t.Logf("Received data: %q", string(receivedData))
}

func TestFourWayHandshake_ActiveClose(t *testing.T) {
	// Setup addresses
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// Create TCBs in ESTABLISHED state
	clientTCB := NewTCB(clientAddr, serverAddr)
	serverTCB := NewTCB(serverAddr, clientAddr)

	clientTCB.State = socket.StateEstablished
	serverTCB.State = socket.StateEstablished
	clientTCB.SendNext = 1000
	clientTCB.RecvNext = 2000
	serverTCB.SendNext = 2000
	serverTCB.RecvNext = 1000

	// Create handshake handlers
	clientHandshake := NewFourWayHandshake(clientTCB)
	serverHandshake := NewFourWayHandshake(serverTCB)

	// Step 1: Client initiates close (sends FIN)
	finPacket1, err := clientHandshake.Close()
	if err != nil {
		t.Fatalf("Failed to initiate close: %v", err)
	}

	// Verify client state and FIN packet
	if clientTCB.State != socket.StateFinWait1 {
		t.Errorf("Expected client state FIN_WAIT_1, got %s", clientTCB.State.String())
	}
	if !finPacket1.HasFlag(packet.FlagFIN) {
		t.Error("First FIN packet should have FIN flag set")
	}
	if !finPacket1.HasFlag(packet.FlagACK) {
		t.Error("First FIN packet should have ACK flag set")
	}

	// Step 2: Server handles FIN and sends ACK
	ackPacket1, err := serverHandshake.HandleFin(finPacket1)
	if err != nil {
		t.Fatalf("Failed to handle FIN: %v", err)
	}

	// Verify server state and ACK packet
	if serverTCB.State != socket.StateCloseWait {
		t.Errorf("Expected server state CLOSE_WAIT, got %s", serverTCB.State.String())
	}
	if !ackPacket1.HasFlag(packet.FlagACK) {
		t.Error("ACK packet should have ACK flag set")
	}
	if ackPacket1.AckNumber != finPacket1.SequenceNumber+1 {
		t.Errorf("Expected ACK number %d, got %d",
			finPacket1.SequenceNumber+1, ackPacket1.AckNumber)
	}

	// Step 3: Client handles ACK for its FIN
	err = clientHandshake.HandleFinAck(ackPacket1)
	if err != nil {
		t.Fatalf("Failed to handle FIN ACK: %v", err)
	}

	// Verify client state transition
	if clientTCB.State != socket.StateFinWait2 {
		t.Errorf("Expected client state FIN_WAIT_2, got %s", clientTCB.State.String())
	}

	// Step 4: Server closes from CLOSE_WAIT (sends FIN)
	finPacket2, err := serverHandshake.CloseFromCloseWait()
	if err != nil {
		t.Fatalf("Failed to close from CLOSE_WAIT: %v", err)
	}

	// Verify server state and second FIN packet
	if serverTCB.State != socket.StateLastAck {
		t.Errorf("Expected server state LAST_ACK, got %s", serverTCB.State.String())
	}
	if !finPacket2.HasFlag(packet.FlagFIN) {
		t.Error("Second FIN packet should have FIN flag set")
	}

	// Step 5: Client handles server's FIN and sends final ACK
	ackPacket2, err := clientHandshake.HandleFin(finPacket2)
	if err != nil {
		t.Fatalf("Failed to handle server FIN: %v", err)
	}

	// Verify client state
	if clientTCB.State != socket.StateTimeWait {
		t.Errorf("Expected client state TIME_WAIT, got %s", clientTCB.State.String())
	}
	if !ackPacket2.HasFlag(packet.FlagACK) {
		t.Error("Final ACK packet should have ACK flag set")
	}

	// Step 6: Server handles final ACK
	err = serverHandshake.HandleFinAck(ackPacket2)
	if err != nil {
		t.Fatalf("Failed to handle final ACK: %v", err)
	}

	// Verify server final state
	if serverTCB.State != socket.StateClosed {
		t.Errorf("Expected server state CLOSED, got %s", serverTCB.State.String())
	}

	t.Logf("Active close handshake completed successfully!")
	t.Logf("Final client state: %s", clientTCB.State.String())
	t.Logf("Final server state: %s", serverTCB.State.String())
}

func TestFourWayHandshake_SimultaneousClose(t *testing.T) {
	// Setup addresses
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// Create TCBs in ESTABLISHED state
	clientTCB := NewTCB(clientAddr, serverAddr)
	serverTCB := NewTCB(serverAddr, clientAddr)

	clientTCB.State = socket.StateEstablished
	serverTCB.State = socket.StateEstablished
	clientTCB.SendNext = 1000
	clientTCB.RecvNext = 2000
	serverTCB.SendNext = 2000
	serverTCB.RecvNext = 1000

	// Create handshake handlers
	clientHandshake := NewFourWayHandshake(clientTCB)
	serverHandshake := NewFourWayHandshake(serverTCB)

	// Step 1: Both sides initiate close simultaneously
	clientFinPacket, err := clientHandshake.Close()
	if err != nil {
		t.Fatalf("Failed to initiate client close: %v", err)
	}

	serverFinPacket, err := serverHandshake.Close()
	if err != nil {
		t.Fatalf("Failed to initiate server close: %v", err)
	}

	// Both should be in FIN_WAIT_1 state
	if clientTCB.State != socket.StateFinWait1 {
		t.Errorf("Expected client state FIN_WAIT_1, got %s", clientTCB.State.String())
	}
	if serverTCB.State != socket.StateFinWait1 {
		t.Errorf("Expected server state FIN_WAIT_1, got %s", serverTCB.State.String())
	}

	// Step 2: Each side handles the other's FIN
	clientAckPacket, err := clientHandshake.HandleFin(serverFinPacket)
	if err != nil {
		t.Fatalf("Failed to handle server FIN: %v", err)
	}

	serverAckPacket, err := serverHandshake.HandleFin(clientFinPacket)
	if err != nil {
		t.Fatalf("Failed to handle client FIN: %v", err)
	}

	// Both should now be in CLOSING state
	if clientTCB.State != socket.StateClosing {
		t.Errorf("Expected client state CLOSING, got %s", clientTCB.State.String())
	}
	if serverTCB.State != socket.StateClosing {
		t.Errorf("Expected server state CLOSING, got %s", serverTCB.State.String())
	}

	// Step 3: Each side handles the ACK for their FIN
	err = clientHandshake.HandleFinAck(serverAckPacket)
	if err != nil {
		t.Fatalf("Failed to handle server ACK: %v", err)
	}

	err = serverHandshake.HandleFinAck(clientAckPacket)
	if err != nil {
		t.Fatalf("Failed to handle client ACK: %v", err)
	}

	// Both should now be in TIME_WAIT state
	if clientTCB.State != socket.StateTimeWait {
		t.Errorf("Expected client state TIME_WAIT, got %s", clientTCB.State.String())
	}
	if serverTCB.State != socket.StateTimeWait {
		t.Errorf("Expected server state TIME_WAIT, got %s", serverTCB.State.String())
	}

	t.Logf("Simultaneous close handshake completed successfully!")
}

func TestFourWayHandshake_InvalidStates(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)
	handshake := NewFourWayHandshake(tcb)

	// Test Close from invalid state
	tcb.State = socket.StateClosed
	_, err := handshake.Close()
	if err == nil {
		t.Error("Expected error when closing from CLOSED state")
	}

	// Test HandleFin from invalid state
	tcb.State = socket.StateClosed
	finHeader := packet.NewTCPHeader(9090, 8080)
	finHeader.SetFlag(packet.FlagFIN)
	_, err = handshake.HandleFin(finHeader)
	if err == nil {
		t.Error("Expected error when handling FIN from CLOSED state")
	}

	// Test CloseFromCloseWait from invalid state
	tcb.State = socket.StateEstablished
	_, err = handshake.CloseFromCloseWait()
	if err == nil {
		t.Error("Expected error when calling CloseFromCloseWait from ESTABLISHED state")
	}
}

func TestFourWayHandshake_ConnectionState(t *testing.T) {
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	tcb := NewTCB(localAddr, remoteAddr)
	handshake := NewFourWayHandshake(tcb)

	// Test different states
	testStates := []struct {
		state      socket.SocketState
		canSend    bool
		canReceive bool
		isClosed   bool
	}{
		{socket.StateEstablished, true, true, false},
		{socket.StateFinWait1, false, false, false},
		{socket.StateFinWait2, false, false, false},
		{socket.StateCloseWait, false, true, false},
		{socket.StateClosing, false, false, false},
		{socket.StateLastAck, false, false, false},
		{socket.StateTimeWait, false, false, false},
		{socket.StateClosed, false, false, true},
	}

	for _, test := range testStates {
		tcb.State = test.state

		if handshake.CanSendData() != test.canSend {
			t.Errorf("State %s: expected CanSendData=%v, got %v",
				test.state.String(), test.canSend, handshake.CanSendData())
		}

		if handshake.CanReceiveData() != test.canReceive {
			t.Errorf("State %s: expected CanReceiveData=%v, got %v",
				test.state.String(), test.canReceive, handshake.CanReceiveData())
		}

		if handshake.IsConnectionClosed() != test.isClosed {
			t.Errorf("State %s: expected IsConnectionClosed=%v, got %v",
				test.state.String(), test.isClosed, handshake.IsConnectionClosed())
		}
	}
}
