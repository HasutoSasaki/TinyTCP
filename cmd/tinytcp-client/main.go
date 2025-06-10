package main

import (
	"fmt"
	"log"

	"github.com/sasakihasuto/tinytcp/internal/socket"
)

func main() {
	fmt.Println("TinyTCP Client - TCP/IP Stack Implementation")
	fmt.Println("Starting client...")
	
	// Create a new socket
	clientSocket := socket.NewSocket()
	
	// Connect to server
	serverAddr := "127.0.0.1:8080"
	err := clientSocket.Connect(serverAddr)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", serverAddr, err)
	}
	
	fmt.Printf("Connected to %s\n", serverAddr)
	fmt.Printf("Client state: %s\n", clientSocket.State())
	fmt.Printf("Remote address: %s\n", clientSocket.RemoteAddr())
	
	// Send test data
	testMessage := []byte("Hello from TinyTCP client!")
	n, err := clientSocket.Send(testMessage)
	if err != nil {
		log.Fatalf("Failed to send data: %v", err)
	}
	fmt.Printf("Sent %d bytes: %s\n", n, string(testMessage))
	
	// For now, just demonstrate that the socket is working
	fmt.Println("Client prototype working successfully!")
	
	// Clean shutdown
	err = clientSocket.Close()
	if err != nil {
		log.Printf("Error closing socket: %v", err)
	}
	fmt.Println("Client stopped.")
}
