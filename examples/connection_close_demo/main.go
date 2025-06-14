package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
	"github.com/sasakihasuto/tinytcp/internal/tcp"
)

func main() {
	fmt.Println("=== TCP コネクション切断デモ ===")

	// アクティブクローズのデモ
	runActiveCloseDemo()

	fmt.Println("\n" + strings.Repeat("=", 50) + "\n")

	// 同時クローズのデモ
	runSimultaneousCloseDemo()
}

func runActiveCloseDemo() {
	fmt.Println("--- アクティブクローズ（4ウェイハンドシェイク）デモ ---")

	// クライアントとサーバーのアドレス設定
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// TCBを作成（ESTABLISHED状態から開始）
	clientTCB := tcp.NewTCB(clientAddr, serverAddr)
	serverTCB := tcp.NewTCB(serverAddr, clientAddr)

	// コネクションを確立状態に設定
	clientTCB.SetState(socket.StateEstablished)
	serverTCB.SetState(socket.StateEstablished)
	clientTCB.SendNext = 1000
	clientTCB.RecvNext = 2000
	serverTCB.SendNext = 2000
	serverTCB.RecvNext = 1000

	fmt.Printf("初期状態:\n")
	fmt.Printf("  クライアント: %s\n", clientTCB.String())
	fmt.Printf("  サーバー: %s\n", serverTCB.String())
	fmt.Println()

	// 4ウェイハンドシェイクハンドラを作成
	clientHandshake := tcp.NewFourWayHandshake(clientTCB)
	serverHandshake := tcp.NewFourWayHandshake(serverTCB)

	// Step 1: クライアントがクローズを開始（FIN送信）
	fmt.Println("Step 1: クライアントがクローズを開始")
	finPacket1, err := clientHandshake.Close()
	if err != nil {
		log.Fatalf("クローズ開始に失敗: %v", err)
	}

	fmt.Printf("  クライアント -> サーバー: %s\n", finPacket1.String())
	fmt.Printf("  クライアント状態: %s\n", clientTCB.GetState().String())
	fmt.Println()

	// Step 2: サーバーがFINを受信してACKを送信
	fmt.Println("Step 2: サーバーがFINを受信してACKを送信")
	ackPacket1, err := serverHandshake.HandleFin(finPacket1)
	if err != nil {
		log.Fatalf("FIN処理に失敗: %v", err)
	}

	fmt.Printf("  サーバー -> クライアント: %s\n", ackPacket1.String())
	fmt.Printf("  サーバー状態: %s\n", serverTCB.GetState().String())
	fmt.Println()

	// Step 3: クライアントがFINのACKを受信
	fmt.Println("Step 3: クライアントがFINのACKを受信")
	err = clientHandshake.HandleFinAck(ackPacket1)
	if err != nil {
		log.Fatalf("FIN ACK処理に失敗: %v", err)
	}

	fmt.Printf("  クライアント状態: %s\n", clientTCB.GetState().String())
	fmt.Println()

	// Step 4: サーバーがCLOSE_WAITからクローズ（FIN送信）
	fmt.Println("Step 4: サーバーがCLOSE_WAITからクローズ")
	finPacket2, err := serverHandshake.CloseFromCloseWait()
	if err != nil {
		log.Fatalf("CLOSE_WAITからのクローズに失敗: %v", err)
	}

	fmt.Printf("  サーバー -> クライアント: %s\n", finPacket2.String())
	fmt.Printf("  サーバー状態: %s\n", serverTCB.GetState().String())
	fmt.Println()

	// Step 5: クライアントがサーバーのFINを受信して最終ACKを送信
	fmt.Println("Step 5: クライアントがサーバーのFINを受信して最終ACKを送信")
	ackPacket2, err := clientHandshake.HandleFin(finPacket2)
	if err != nil {
		log.Fatalf("サーバーFIN処理に失敗: %v", err)
	}

	fmt.Printf("  クライアント -> サーバー: %s\n", ackPacket2.String())
	fmt.Printf("  クライアント状態: %s\n", clientTCB.GetState().String())
	fmt.Println()

	// Step 6: サーバーが最終ACKを受信
	fmt.Println("Step 6: サーバーが最終ACKを受信")
	err = serverHandshake.HandleFinAck(ackPacket2)
	if err != nil {
		log.Fatalf("最終ACK処理に失敗: %v", err)
	}

	fmt.Printf("  サーバー状態: %s\n", serverTCB.GetState().String())
	fmt.Println()

	fmt.Println("=== アクティブクローズ完了! ===")
	fmt.Printf("最終状態:\n")
	fmt.Printf("  クライアント: %s\n", clientTCB.String())
	fmt.Printf("  サーバー: %s\n", serverTCB.String())
	fmt.Printf("  接続状態: クライアント=%v, サーバー=%v\n",
		clientHandshake.IsConnectionClosed(), serverHandshake.IsConnectionClosed())
}

func runSimultaneousCloseDemo() {
	fmt.Println("--- 同時クローズデモ ---")

	// クライアントとサーバーのアドレス設定
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// TCBを作成（ESTABLISHED状態から開始）
	clientTCB := tcp.NewTCB(clientAddr, serverAddr)
	serverTCB := tcp.NewTCB(serverAddr, clientAddr)

	clientTCB.SetState(socket.StateEstablished)
	serverTCB.SetState(socket.StateEstablished)
	clientTCB.SendNext = 1000
	clientTCB.RecvNext = 2000
	serverTCB.SendNext = 2000
	serverTCB.RecvNext = 1000

	fmt.Printf("初期状態:\n")
	fmt.Printf("  クライアント: %s\n", clientTCB.String())
	fmt.Printf("  サーバー: %s\n", serverTCB.String())
	fmt.Println()

	// 4ウェイハンドシェイクハンドラを作成
	clientHandshake := tcp.NewFourWayHandshake(clientTCB)
	serverHandshake := tcp.NewFourWayHandshake(serverTCB)

	// Step 1: 両側が同時にクローズを開始
	fmt.Println("Step 1: 両側が同時にクローズを開始")
	clientFinPacket, err := clientHandshake.Close()
	if err != nil {
		log.Fatalf("クライアントクローズ開始に失敗: %v", err)
	}

	serverFinPacket, err := serverHandshake.Close()
	if err != nil {
		log.Fatalf("サーバークローズ開始に失敗: %v", err)
	}

	fmt.Printf("  クライアント -> サーバー: %s\n", clientFinPacket.String())
	fmt.Printf("  サーバー -> クライアント: %s\n", serverFinPacket.String())
	fmt.Printf("  クライアント状態: %s\n", clientTCB.GetState().String())
	fmt.Printf("  サーバー状態: %s\n", serverTCB.GetState().String())
	fmt.Println()

	// Step 2: 互いのFINを処理
	fmt.Println("Step 2: 互いのFINを処理")
	clientAckPacket, err := clientHandshake.HandleFin(serverFinPacket)
	if err != nil {
		log.Fatalf("クライアントでのサーバーFIN処理に失敗: %v", err)
	}

	serverAckPacket, err := serverHandshake.HandleFin(clientFinPacket)
	if err != nil {
		log.Fatalf("サーバーでのクライアントFIN処理に失敗: %v", err)
	}

	fmt.Printf("  クライアント -> サーバー: %s\n", clientAckPacket.String())
	fmt.Printf("  サーバー -> クライアント: %s\n", serverAckPacket.String())
	fmt.Printf("  クライアント状態: %s\n", clientTCB.GetState().String())
	fmt.Printf("  サーバー状態: %s\n", serverTCB.GetState().String())
	fmt.Println()

	// Step 3: 互いのFIN ACKを処理
	fmt.Println("Step 3: 互いのFIN ACKを処理")
	err = clientHandshake.HandleFinAck(serverAckPacket)
	if err != nil {
		log.Fatalf("クライアントでのACK処理に失敗: %v", err)
	}

	err = serverHandshake.HandleFinAck(clientAckPacket)
	if err != nil {
		log.Fatalf("サーバーでのACK処理に失敗: %v", err)
	}

	fmt.Printf("  クライアント状態: %s\n", clientTCB.GetState().String())
	fmt.Printf("  サーバー状態: %s\n", serverTCB.GetState().String())
	fmt.Println()

	fmt.Println("=== 同時クローズ完了! ===")
	fmt.Printf("最終状態:\n")
	fmt.Printf("  クライアント: %s\n", clientTCB.String())
	fmt.Printf("  サーバー: %s\n", serverTCB.String())
	fmt.Printf("  接続状態: クライアント=%v, サーバー=%v\n",
		clientHandshake.IsConnectionClosed(), serverHandshake.IsConnectionClosed())
}

// getFlagsString returns a human-readable string representation of TCP flags
func getFlagsString(header *packet.TCPHeader) string {
	var flags []string

	if header.HasFlag(packet.FlagSYN) {
		flags = append(flags, "SYN")
	}
	if header.HasFlag(packet.FlagACK) {
		flags = append(flags, "ACK")
	}
	if header.HasFlag(packet.FlagFIN) {
		flags = append(flags, "FIN")
	}
	if header.HasFlag(packet.FlagRST) {
		flags = append(flags, "RST")
	}
	if header.HasFlag(packet.FlagPSH) {
		flags = append(flags, "PSH")
	}
	if header.HasFlag(packet.FlagURG) {
		flags = append(flags, "URG")
	}

	if len(flags) == 0 {
		return "NONE"
	}

	result := flags[0]
	for i := 1; i < len(flags); i++ {
		result += "|" + flags[i]
	}
	return result
}
