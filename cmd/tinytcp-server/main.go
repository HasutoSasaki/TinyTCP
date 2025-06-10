package main

import (
	"fmt"
	"log"

	"github.com/sasakihasuto/tinytcp/internal/socket"
)

func main() {
	fmt.Println("TinyTCP Server - TCP/IP Stack Implementation")
	fmt.Println("Starting server...")
	
	// Create a new socket
	serverSocket := socket.NewSocket()
	
	// Listen on port 8080
	addr := ":8080"
	err := serverSocket.Listen(addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	
	fmt.Printf("Server listening on %s\n", addr)
	fmt.Printf("Server state: %s\n", serverSocket.State())
	fmt.Printf("Local address: %s\n", serverSocket.LocalAddr())
	
	// For now, just demonstrate that the socket is working
	fmt.Println("Socket created and listening successfully!")
	fmt.Println("Server prototype ready.")
	
	// Clean shutdown
	err = serverSocket.Close()
	if err != nil {
		log.Printf("Error closing socket: %v", err)
	}
	fmt.Println("Server stopped.")
}
