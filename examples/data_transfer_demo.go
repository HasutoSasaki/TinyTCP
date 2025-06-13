// data_transfer_demo.go - TCP データ送受信のデモプログラム
package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/sasakihasuto/tinytcp/internal/socket"
	"github.com/sasakihasuto/tinytcp/internal/tcp"
)

func main() {
	// フェーズ2のデモ：3ウェイハンドシェイク
	runHandshakeDemo()
	
	fmt.Println("\n" + strings.Repeat("=", 50) + "\n")
	
	// フェーズ3のデモ：データ送受信
	runDataTransferDemo()
}

func runDataTransferDemo() {
	fmt.Println("=== TCP データ送受信デモ ===")

	// クライアントとサーバーのアドレス設定
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// TCB（Transmission Control Block）を作成
	clientTCB := tcp.NewTCB(clientAddr, serverAddr)
	serverTCB := tcp.NewTCB(serverAddr, clientAddr)

	// コネクション確立（3ウェイハンドシェイク）をシミュレート
	fmt.Println("\n--- 3ウェイハンドシェイク ---")
	
	clientHandshake := tcp.NewThreeWayHandshake(clientTCB)
	serverHandshake := tcp.NewThreeWayHandshake(serverTCB)

	// ハンドシェイクプロセス
	serverTCB.SetState(socket.StateListen)
	
	// 1. SYN
	synPacket, _ := clientHandshake.StartClient()
	fmt.Printf("クライアント -> サーバー: %s\n", synPacket.String())

	// 2. SYN-ACK
	synAckPacket, _ := serverHandshake.HandleSyn(synPacket)
	fmt.Printf("サーバー -> クライアント: %s\n", synAckPacket.String())

	// 3. ACK
	ackPacket, _ := clientHandshake.HandleSynAck(synAckPacket)
	fmt.Printf("クライアント -> サーバー: %s\n", ackPacket.String())

	serverHandshake.HandleAck(ackPacket)

	fmt.Printf("コネクション確立完了！\n")
	fmt.Printf("クライアントTCB: %s\n", clientTCB.String())
	fmt.Printf("サーバーTCB: %s\n", serverTCB.String())

	// データ送受信デモ
	fmt.Println("\n--- データ送受信 ---")

	clientDT := tcp.NewDataTransfer(clientTCB)
	serverDT := tcp.NewDataTransfer(serverTCB)

	// Step 1: クライアントからサーバーへデータ送信
	clientData := []byte("Hello, Server! This is a message from client.")
	fmt.Printf("送信データ: %q\n", string(clientData))

	dataPacket1, err := clientDT.Send(clientData)
	if err != nil {
		log.Fatalf("データ送信エラー: %v", err)
	}
	fmt.Printf("クライアント -> サーバー: %s (データ長: %d)\n", 
		dataPacket1.String(), len(clientData))

	// Step 2: サーバーがデータを受信してACK送信
	receivedData1, ackPacket1, err := serverDT.Receive(dataPacket1, clientData)
	if err != nil {
		log.Fatalf("データ受信エラー: %v", err)
	}
	fmt.Printf("サーバーが受信: %q\n", string(receivedData1))
	fmt.Printf("サーバー -> クライアント: %s\n", ackPacket1.String())

	// Step 3: クライアントがACKを処理
	err = clientDT.ReceiveAck(ackPacket1)
	if err != nil {
		log.Fatalf("ACK処理エラー: %v", err)
	}
	fmt.Println("クライアント: ACK確認完了")

	// Step 4: サーバーからクライアントへデータ送信（応答）
	serverData := []byte("Hello, Client! Server received your message.")
	fmt.Printf("\n応答データ: %q\n", string(serverData))

	dataPacket2, err := serverDT.Send(serverData)
	if err != nil {
		log.Fatalf("応答送信エラー: %v", err)
	}
	fmt.Printf("サーバー -> クライアント: %s (データ長: %d)\n", 
		dataPacket2.String(), len(serverData))

	// Step 5: クライアントが応答を受信してACK送信
	receivedData2, ackPacket2, err := clientDT.Receive(dataPacket2, serverData)
	if err != nil {
		log.Fatalf("応答受信エラー: %v", err)
	}
	fmt.Printf("クライアントが受信: %q\n", string(receivedData2))
	fmt.Printf("クライアント -> サーバー: %s\n", ackPacket2.String())

	// Step 6: サーバーがACKを処理
	err = serverDT.ReceiveAck(ackPacket2)
	if err != nil {
		log.Fatalf("応答ACK処理エラー: %v", err)
	}
	fmt.Println("サーバー: ACK確認完了")

	// 最終状態表示
	fmt.Println("\n--- 最終状態 ---")
	fmt.Printf("クライアントTCB: %s\n", clientTCB.String())
	fmt.Printf("サーバーTCB: %s\n", serverTCB.String())

	// バッファ状態表示
	fmt.Println("\n--- バッファ状態 ---")
	fmt.Printf("クライアント送信バッファ: %q\n", string(clientDT.GetSendBuffer()))
	fmt.Printf("クライアント受信バッファ: %q\n", string(clientDT.GetReceiveBuffer()))
	fmt.Printf("サーバー送信バッファ: %q\n", string(serverDT.GetSendBuffer()))
	fmt.Printf("サーバー受信バッファ: %q\n", string(serverDT.GetReceiveBuffer()))

	fmt.Println("\n=== データ送受信デモ完了 ===")
}
