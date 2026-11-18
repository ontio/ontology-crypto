package signature

import (
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
)

// FuzzDeserialize asserts that the signature parser never panics on arbitrary
// input and that any input it successfully parses can also be serialized
// without panicking.
func FuzzDeserialize(f *testing.F) {
	// Seed the corpus with one real serialised signature per wire format so
	// the fuzzer has valid starting points for each branch.
	for _, tc := range []struct {
		kt     keypair.KeyType
		curve  interface{}
		scheme SignatureScheme
	}{
		{keypair.PK_ECDSA, keypair.P256, SHA256withECDSA},
		{keypair.PK_ECDSA, keypair.SECP256K1, SHA256withECDSA},
		{keypair.PK_SM2, keypair.SM2P256V1, SM3withSM2},
		{keypair.PK_EDDSA, keypair.ED25519, SHA512withEDDSA},
		{keypair.PK_ETHECDSA, nil, KECCAK256WithECDSA},
	} {
		pri, _, err := keypair.GenerateKeyPair(tc.kt, tc.curve)
		if err != nil {
			continue
		}
		sig, err := Sign(tc.scheme, pri, []byte("fuzz seed"), nil)
		if err != nil {
			continue
		}
		raw, err := Serialize(sig)
		if err != nil {
			continue
		}
		f.Add(raw)
	}

	// A few hand-crafted corner cases.
	f.Add([]byte(nil))
	f.Add([]byte{0x00})
	f.Add([]byte{byte(SHA256withECDSA), 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{byte(SM3withSM2), 0x00, 0x01, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		sig, err := Deserialize(data)
		if err != nil {
			return
		}
		// Any input Deserialize accepts must also be serialisable without
		// panicking; callers rely on the round-trip being safe.
		_, _ = Serialize(sig)
	})
}
