package vrf

import (
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
)

func TestVrf(t *testing.T) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test")
	vrf, proof, err := Vrf(pri, msg)
	if err != nil {
		t.Fatalf("compute vrf: %v", err)
	}

	ret, err := Verify(pub, msg, vrf, proof)
	if err != nil {
		t.Fatalf("verify vrf: %v", err)
	}
	if !ret {
		t.Fatal("failed")
	}
}
