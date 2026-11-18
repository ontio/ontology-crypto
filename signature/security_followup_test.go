package signature

import (
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
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

// TestVariableWidthVerification guards against regression of the backward-compat
func TestVariableWidthVerification(t *testing.T) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("compact width regression test")
	sig, err := Sign(SHA256withECDSA, pri, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	dsa := sig.Value.(*DSASignature)

	// Simulate old unpadded encoding: component width 31 < curve field width 32.
	// The integers R and S are unchanged; only the recorded encoding width differs.
	unpadded := &DSASignature{R: dsa.R, S: dsa.S, size: 31}
	unpaddedSig := &Signature{Scheme: SHA256withECDSA, Value: unpadded}
	if !Verify(pub, msg, unpaddedSig) {
		t.Fatal("Verify rejected a valid signature whose encoded component width (31) is less than the curve field width (32)")
	}

	// Oversized width must still be rejected.
	oversized := &DSASignature{R: dsa.R, S: dsa.S, size: 33}
	oversizedSig := &Signature{Scheme: SHA256withECDSA, Value: oversized}
	if Verify(pub, msg, oversizedSig) {
		t.Fatal("Verify accepted a signature with oversized component width (33 > 32)")
	}
}

func TestCanonicalWidths(t *testing.T) {
	for size := 1; size <= 67; size++ {
		raw := make([]byte, 1+size*2)
		raw[0] = byte(SHA224withECDSA)
		raw[size] = 1
		raw[size*2] = 1
		_, err := Deserialize(raw)
		valid := size > 0 && size <= maxComponentSize
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
