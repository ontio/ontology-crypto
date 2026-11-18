package signature

import (
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
)

func TestSM2IDEncoding(t *testing.T) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_SM2, keypair.SM2P256V1)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	if _, err := Sign(SM3withSM2, pri, msg, "a\x00b"); err == nil {
		t.Fatal("accepted NUL ID")
	}
	sig, err := Sign(SM3withSM2, pri, msg, "valid ID")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Serialize(sig)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Deserialize(raw)
	if err != nil || !Verify(pub, msg, decoded) {
		t.Fatalf("round trip failed: %v", err)
	}
	sig.Value.(*SM2Signature).ID = "a\x00b"
	if _, err := Serialize(sig); err == nil {
		t.Fatal("serialized NUL ID")
	}
}
