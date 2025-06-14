package main

import (
	"fmt"
	"log"
	"net"

	"github.com/sasakihasuto/tinytcp/internal/packet"
	"github.com/sasakihasuto/tinytcp/internal/socket"
	"github.com/sasakihasuto/tinytcp/internal/tcp"
)

func main() {
	fmt.Println("=== TinyTCP 3-Way Handshake Demo ===")

	// Setup addresses
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	serverAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")

	// Create TCBs
	clientTCB := tcp.NewTCB(clientAddr, serverAddr)
	serverTCB := tcp.NewTCB(serverAddr, clientAddr)

	// Set initial states
	clientTCB.SetState(socket.StateClosed)
	serverTCB.SetState(socket.StateListen)

	// Create handshake handlers
	clientHandshake := tcp.NewThreeWayHandshake(clientTCB)
	serverHandshake := tcp.NewThreeWayHandshake(serverTCB)

	fmt.Printf("Initial states:\n")
	fmt.Printf("  Client: %s\n", clientTCB.String())
	fmt.Printf("  Server: %s\n", serverTCB.String())
	fmt.Println()

	// Step 1: Client sends SYN
	fmt.Println("Step 1: Client sends SYN")
	synPacket, err := clientHandshake.StartClient()
	if err != nil {
		log.Fatalf("Failed to start client handshake: %v", err)
	}

	fmt.Printf("  SYN packet: Seq=%d, Ack=%d, Flags=%s\n",
		synPacket.SequenceNumber, synPacket.AckNumber, getFlagsString(synPacket))
	fmt.Printf("  Client state: %s\n", clientTCB.GetState().String())
	fmt.Println()

	// Step 2: Server handles SYN and sends SYN-ACK
	fmt.Println("Step 2: Server handles SYN and sends SYN-ACK")
	synAckPacket, err := serverHandshake.HandleSyn(synPacket)
	if err != nil {
		log.Fatalf("Failed to handle SYN: %v", err)
	}

	fmt.Printf("  SYN-ACK packet: Seq=%d, Ack=%d, Flags=%s\n",
		synAckPacket.SequenceNumber, synAckPacket.AckNumber, getFlagsString(synAckPacket))
	fmt.Printf("  Server state: %s\n", serverTCB.GetState().String())
	fmt.Println()

	// Step 3: Client handles SYN-ACK and sends ACK
	fmt.Println("Step 3: Client handles SYN-ACK and sends ACK")
	ackPacket, err := clientHandshake.HandleSynAck(synAckPacket)
	if err != nil {
		log.Fatalf("Failed to handle SYN-ACK: %v", err)
	}

	fmt.Printf("  ACK packet: Seq=%d, Ack=%d, Flags=%s\n",
		ackPacket.SequenceNumber, ackPacket.AckNumber, getFlagsString(ackPacket))
	fmt.Printf("  Client state: %s\n", clientTCB.GetState().String())
	fmt.Println()

	// Step 4: Server handles final ACK
	fmt.Println("Step 4: Server handles final ACK")
	err = serverHandshake.HandleAck(ackPacket)
	if err != nil {
		log.Fatalf("Failed to handle final ACK: %v", err)
	}

	fmt.Printf("  Server state: %s\n", serverTCB.GetState().String())
	fmt.Println()

	fmt.Println("=== Handshake Complete! ===")
	fmt.Printf("Final states:\n")
	fmt.Printf("  Client: %s\n", clientTCB.String())
	fmt.Printf("  Server: %s\n", serverTCB.String())
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
