package keypair

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	base58 "github.com/itchyny/base58-go"
)

func TestWIFMarkers(t *testing.T) {
	parsers := map[string]func([]byte) (PrivateKey, error){
		"WIF2Key":               WIF2Key,
		"GetP256KeyPairFromWIF": GetP256KeyPairFromWIF,
	}
	for name, parse := range parsers {
		t.Run(name, func(t *testing.T) {
			for _, markers := range [][2]byte{{0x80, 1}, {0x81, 1}, {0x80, 2}, {0x81, 2}, {0x80, 0}, {0xef, 1}} {
				payload := make([]byte, 34)
				payload[0], payload[32], payload[33] = markers[0], 1, markers[1]
				// Recompute checksum so rejection exercises format validation.
				sum := sha256.Sum256(payload)
				sum = sha256.Sum256(sum[:])
				encoded, err := base58.BitcoinEncoding.Encode([]byte(new(big.Int).SetBytes(append(payload, sum[:4]...)).Text(10)))
				if err != nil {
					t.Fatal(err)
				}
				key, err := parse(encoded)
				valid := markers == [2]byte{0x80, 1}
				if !valid {
					if err == nil {
						t.Fatalf("accepted markers %x", markers)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				roundtrip, err := Key2WIF(key)
				if err != nil || !bytes.Equal(roundtrip, encoded) {
					t.Fatalf("valid WIF round trip failed: %v", err)
				}
			}
		})
	}
}
