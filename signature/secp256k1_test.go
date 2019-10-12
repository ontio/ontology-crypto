package signature

import "github.com/ontio/ontology-crypto/keypair"
import "testing"

func TestSecp256k1(t *testing.T) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.SECP256K1)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message")
	sig, err := Sign(SHA3_512withECDSA, pri, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := sig.Value.([]byte)
	if !ok {
		t.Fatal("invalid signature type")
	}
	if len(v) != 65 {
		t.Fatal("invalid signature length")
	}

	b, err := Serialize(sig)
	if err != nil {
		t.Fatal(err)
	}

	sig1, err := Deserialize(b)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pub, msg, sig1) {
		t.Fatal("verification failed")
	}
}
