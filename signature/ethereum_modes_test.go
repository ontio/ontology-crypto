package signature

import (
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"testing"
)

func TestEthereumExplicitModes(t *testing.T) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ETHECDSA, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := pub.(*ec.EthereumPublicKey)
	for _, n := range []int{0, 31, 32, 33} {
		msg := make([]byte, n)
		sig, err := Sign(KECCAK256WithECDSA, pri, msg, true)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyEthereumMessage(key, msg, sig) {
			t.Fatalf("message length %d failed", n)
		}
		digest := ethcrypto.Keccak256(msg)
		if !VerifyEthereumDigest(key, digest, sig) {
			t.Fatal("digest verification failed")
		}
		if n == 32 && VerifyEthereumDigest(key, msg, sig) {
			t.Fatal("confused message and digest")
		}
		ds, err := Sign(KECCAK256WithECDSA, pri, digest, false)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyEthereumDigest(key, digest, ds) {
			t.Fatal("digest signing failed")
		}
		if VerifyEthereumMessage(key, digest, ds) {
			t.Fatal("accepted double hash")
		}
	}
	if VerifyEthereumDigest(key, make([]byte, 31), nil) || VerifyEthereumMessage(nil, nil, nil) {
		t.Fatal("accepted invalid input")
	}
}
