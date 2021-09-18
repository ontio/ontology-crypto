package keypair

import (
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

func TestName(t *testing.T) {
	if btcec.S256().Name != "secp256k1" {
		t.Fatal("not expected name")
	}
}
