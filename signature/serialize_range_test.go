package signature

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestSerializeRejectsInvalidComponents(t *testing.T) {
	c := elliptic.P256()
	for _, bad := range []*big.Int{big.NewInt(-1), big.NewInt(0), new(big.Int).Set(c.Params().N), new(big.Int).Add(c.Params().N, big.NewInt(1))} {
		for _, rBad := range []bool{true, false} {
			r, s := big.NewInt(1), big.NewInt(1)
			if rBad {
				r = bad
			} else {
				s = bad
			}
			if _, err := Serialize(&Signature{Scheme: SHA256withECDSA, Value: &DSASignature{R: r, S: s, Curve: c}}); err == nil {
				t.Fatalf("accepted R=%v S=%v", r, s)
			}
		}
	}
	// Deserialized signatures have an encoding width but no curve.
	if _, err := serializeDSA(&DSASignature{R: big.NewInt(-1), S: big.NewInt(1), size: 32}); err == nil {
		t.Fatal("accepted negative component without curve")
	}
	if _, err := serializeDSA(&DSASignature{R: new(big.Int).Sub(c.Params().N, big.NewInt(1)), S: big.NewInt(1), Curve: c}); err != nil {
		t.Fatal(err)
	}
}
