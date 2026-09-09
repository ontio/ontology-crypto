package keypair

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestName(t *testing.T) {
	if btcec.S256().Name != "secp256k1" {
		t.Fatal("not expected name")
	}
}
