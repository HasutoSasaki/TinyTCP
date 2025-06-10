package packet

import (
	"testing"
)

func TestNewTCPHeader(t *testing.T) {
	header := NewTCPHeader(8080, 80)
	
	if header.SourcePort != 8080 {
		t.Errorf("Expected source port 8080, got %d", header.SourcePort)
	}
	
	if header.DestinationPort != 80 {
		t.Errorf("Expected destination port 80, got %d", header.DestinationPort)
	}
	
	if header.DataOffset != 5 {
		t.Errorf("Expected data offset 5, got %d", header.DataOffset)
	}
	
	if header.HeaderLength() != 20 {
		t.Errorf("Expected header length 20, got %d", header.HeaderLength())
	}
}

func TestTCPHeaderFlags(t *testing.T) {
	header := NewTCPHeader(8080, 80)
	
	// Test SYN flag
	header.SetFlag(FlagSYN)
	if !header.HasFlag(FlagSYN) {
		t.Error("SYN flag should be set")
	}
	
	// Test ACK flag
	header.SetFlag(FlagACK)
	if !header.HasFlag(FlagACK) {
		t.Error("ACK flag should be set")
	}
	
	// Test that both flags are set
	if !header.HasFlag(FlagSYN | FlagACK) {
		t.Error("Both SYN and ACK flags should be set")
	}
	
	// Test flag that is not set
	if header.HasFlag(FlagFIN) {
		t.Error("FIN flag should not be set")
	}
}

func TestTCPHeaderString(t *testing.T) {
	header := NewTCPHeader(8080, 80)
	header.SequenceNumber = 12345
	header.AckNumber = 67890
	header.SetFlag(FlagSYN)
	
	str := header.String()
	t.Logf("TCP Header String: %s", str)
	
	// Check that the string contains expected values
	if str == "" {
		t.Error("String representation should not be empty")
	}
}
