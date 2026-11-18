package signature

import (
	"bytes"
	"github.com/ontio/ontology-crypto/keypair"
	"testing"
)

func TestDeserializeCompactOwnsBuffer(t *testing.T) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.SECP256K1)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("owned signature")
	sig, err := Sign(SHA256withECDSA, pri, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Serialize(sig)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), raw...)
	decoded, err := Deserialize(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0
	}
	if !Verify(pub, msg, decoded) {
		t.Fatal("source buffer mutation changed parsed signature")
	}
	encoded, err := Serialize(decoded)
	if err != nil || !bytes.Equal(encoded, original) {
		t.Fatalf("round trip changed: %v", err)
	}
	raw = append([]byte(nil), original...)
	decoded, err = Deserialize(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Value.([]byte)[0] ^= 1
	if !bytes.Equal(raw, original) {
		t.Fatal("parsed signature mutation changed source buffer")
	}
}

func TestByteSignatureLengths(t *testing.T) {
	for _, c := range []struct {
		scheme SignatureScheme
		size   int
		kt     keypair.KeyType
		opt    interface{}
	}{
		{SHA512withEDDSA, 64, keypair.PK_EDDSA, keypair.ED25519},
		{KECCAK256WithECDSA, 65, keypair.PK_ETHECDSA, nil},
	} {
		for _, n := range []int{0, 1, c.size - 1, c.size + 1, 100} {
			payload := bytes.Repeat([]byte{1}, n)
			if _, err := Serialize(&Signature{Scheme: c.scheme, Value: payload}); err == nil {
				t.Fatalf("scheme %d serialized length %d", c.scheme, n)
			}
			raw := append([]byte{byte(c.scheme)}, payload...)
			// Exactly 64 bytes is the historical untagged ECDSA format, not a
			// tagged Ed25519/Ethereum signature; its first byte is part of R.
			if len(raw) == 64 {
				decoded, err := Deserialize(raw)
				if err != nil || decoded.Scheme != SHA256withECDSA {
					t.Fatalf("legacy 64-byte ECDSA interpretation changed: %v", err)
				}
				continue
			}
			if _, err := Deserialize(raw); err == nil {
				t.Fatalf("scheme %d parsed length %d", c.scheme, n)
			}
		}
		pri, pub, err := keypair.GenerateKeyPair(c.kt, c.opt)
		if err != nil {
			t.Fatal(err)
		}
		msg := bytes.Repeat([]byte{2}, 32)
		sig, err := Sign(c.scheme, pri, msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := Serialize(sig)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Deserialize(raw)
		if err != nil || !Verify(pub, msg, decoded) {
			t.Fatalf("scheme %d round trip: %v", c.scheme, err)
		}
	}
}
