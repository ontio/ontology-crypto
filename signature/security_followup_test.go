package signature

import (
	"github.com/ontio/ontology-crypto/keypair"
	"testing"
)

func TestTypedNilSignatures(t *testing.T) {
	_, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []*Signature{
		{Scheme: SHA256withECDSA, Value: (*DSASignature)(nil)},
		{Scheme: SM3withSM2, Value: (*SM2Signature)(nil)},
	} {
		if Verify(pub, []byte("m"), sig) {
			t.Fatal("accepted nil signature")
		}
		if _, err := Serialize(sig); err == nil {
			t.Fatal("serialized nil signature")
		}
	}
}

func TestCanonicalWidths(t *testing.T) {
	for size := 1; size <= 67; size++ {
		raw := make([]byte, 1+size*2)
		raw[0] = byte(SHA224withECDSA)
		raw[size] = 1
		raw[size*2] = 1
		_, err := Deserialize(raw)
		valid := size == 28 || size == 32 || size == 48 || size == 66
		if (err == nil) != valid {
			t.Fatalf("size=%d error=%v", size, err)
		}
	}
	for _, curve := range []byte{keypair.P224, keypair.P256, keypair.P384, keypair.P521} {
		pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, curve)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(SHA256withECDSA, pri, []byte("message"), nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := Serialize(sig)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Deserialize(raw)
		if err != nil || !Verify(pub, []byte("message"), decoded) {
			t.Fatalf("curve=%d error=%v", curve, err)
		}
	}
}
