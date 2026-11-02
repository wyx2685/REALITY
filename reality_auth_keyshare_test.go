package reality

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestSelectRealityAuthPublicKey(t *testing.T) {
	standalone := bytes.Repeat([]byte{0x11}, 32)
	hybrid := append(bytes.Repeat([]byte{0x22}, mlkem.EncapsulationKeySize768), bytes.Repeat([]byte{0x33}, 32)...)
	hybridECDHE := hybrid[mlkem.EncapsulationKeySize768:]
	x := keyShare{group: X25519, data: standalone}
	pq := keyShare{group: X25519MLKEM768, data: hybrid}

	tests := []struct {
		name   string
		shares []keyShare
		want   []byte
	}{
		{"standalone X25519", []keyShare{x}, standalone},
		{"hybrid only", []keyShare{pq}, hybridECDHE},
		{"hybrid before standalone", []keyShare{pq, x}, standalone},
		{"standalone before hybrid", []keyShare{x, pq}, standalone},
		{"no supported shares", nil, nil},
		{"duplicate X25519", []keyShare{x, x}, nil},
		{"duplicate hybrid", []keyShare{pq, pq}, nil},
		{"short X25519", []keyShare{{group: X25519, data: standalone[:31]}}, nil},
		{"short hybrid", []keyShare{{group: X25519MLKEM768, data: hybrid[:len(hybrid)-1]}}, nil},
		{"malformed after valid", []keyShare{x, {group: X25519MLKEM768, data: hybrid[:len(hybrid)-1]}}, nil},
		{"duplicate after valid", []keyShare{pq, x, x}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectRealityAuthPublicKey(tt.shares)
			if !bytes.Equal(got, tt.want) || (got == nil) != (tt.want == nil) {
				t.Fatalf("selectRealityAuthPublicKey() = %x, want %x", got, tt.want)
			}
		})
	}
}
