package encryption

import (
	"bytes"
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
)

func TestECIES(t *testing.T) {
	sk, pk, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	msg := []byte("test message")

	c, err := Encrypt(pk, msg)
	if err != nil {
		t.Fatal(err)
	}

	m, err := Decrypt(sk, c)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(m, msg) {
		t.Fatal("decrypted message is wrong")
	}

	sk1, _, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	_, err = Decrypt(sk1, c)
	if err == nil {
		t.Fatal("decrypted by invalid private key")
	}
}
