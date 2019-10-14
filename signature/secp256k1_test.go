package signature

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
)

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

func TestEthComp(t *testing.T) {
	pri, pub, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.SECP256K1)
	msg := []byte("test")
	sig, err := Sign(SHA3_256withECDSA, pri, msg, nil)
	if err != nil {
		t.Fatal("sign error,", err)
	}

	b, err := Serialize(sig)
	if err != nil {
		t.Fatal("serialize error,", err)
	}

	eb, err := ConvertToEthCompatible(b)
	if err != nil {
		t.Fatal("convert error,", err)
	}

	h := hashKeccak256(msg)

	pubkey, err := crypto.SigToPub(h, eb)
	if err != nil {
		t.Fatal("recover public key error,", err)
	}
	k := pub.(*ec.PublicKey)
	if k.X.Cmp(pubkey.X) != 0 || k.Y.Cmp(pubkey.Y) != 0 {
		t.Fatal("recovered public key not match")
	}
}
