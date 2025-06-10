// Package packet implements packet structures and header processing
package packet

import (
	"fmt"
)

// TCPHeader represents the TCP header structure
// Based on RFC 793: https://tools.ietf.org/html/rfc793
type TCPHeader struct {
	SourcePort      uint16 // Source port number
	DestinationPort uint16 // Destination port number
	SequenceNumber  uint32 // Sequence number
	AckNumber       uint32 // Acknowledgment number
	DataOffset      uint8  // Data offset (header length in 32-bit words)
	Reserved        uint8  // Reserved (must be zero)
	Flags           uint8  // Control flags (URG, ACK, PSH, RST, SYN, FIN)
	WindowSize      uint16 // Window size
	Checksum        uint16 // Checksum
	UrgentPointer   uint16 // Urgent pointer
}

// TCP Control Flags
const (
	FlagFIN = 1 << 0 // Finish
	FlagSYN = 1 << 1 // Synchronize
	FlagRST = 1 << 2 // Reset
	FlagPSH = 1 << 3 // Push
	FlagACK = 1 << 4 // Acknowledgment
	FlagURG = 1 << 5 // Urgent
)

// NewTCPHeader creates a new TCP header with default values
func NewTCPHeader(srcPort, dstPort uint16) *TCPHeader {
	return &TCPHeader{
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		DataOffset:      5, // 20 bytes (minimum header size)
		WindowSize:      65535, // Maximum window size for now
	}
}

// SetFlag sets a specific control flag
func (h *TCPHeader) SetFlag(flag uint8) {
	h.Flags |= flag
}

// HasFlag checks if a specific control flag is set
func (h *TCPHeader) HasFlag(flag uint8) bool {
	return h.Flags&flag != 0
}

// HeaderLength returns the header length in bytes
func (h *TCPHeader) HeaderLength() int {
	return int(h.DataOffset) * 4
}

// String returns a string representation of the TCP header
func (h *TCPHeader) String() string {
	flags := ""
	if h.HasFlag(FlagFIN) {
		flags += "FIN "
	}
	if h.HasFlag(FlagSYN) {
		flags += "SYN "
	}
	if h.HasFlag(FlagRST) {
		flags += "RST "
	}
	if h.HasFlag(FlagPSH) {
		flags += "PSH "
	}
	if h.HasFlag(FlagACK) {
		flags += "ACK "
	}
	if h.HasFlag(FlagURG) {
		flags += "URG "
	}
	
	return fmt.Sprintf("TCP[%d->%d seq=%d ack=%d flags=%swin=%d]",
		h.SourcePort, h.DestinationPort, h.SequenceNumber, h.AckNumber,
		flags, h.WindowSize)
}
