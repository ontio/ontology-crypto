package sm2

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ontio/ontology-crypto/ec"
)

// fieldBytes encodes a validated field element as fixed-width big endian.
func fieldBytes(v *big.Int, size int) []byte { return v.FillBytes(make([]byte, size)) }

func validatePrivateKey(priv *ecdsa.PrivateKey, signing bool) error {
	if priv == nil || priv.Curve == nil || priv.D == nil {
		return errors.New("sm2: invalid private key")
	}
	if _, ok := priv.Curve.(SM2Curve); !ok {
		return errors.New("sm2: invalid curve")
	}
	n := priv.Params().N
	if priv.D.Sign() <= 0 || priv.D.Cmp(n) >= 0 {
		return errors.New("sm2: private scalar out of range")
	}
	// Signing requires (1+d)^-1 mod N, which does not exist for d=N-1.
	if signing && new(big.Int).Add(priv.D, big.NewInt(1)).Cmp(n) == 0 {
		return errors.New("sm2: invalid signing scalar")
	}
	if err := ec.ValidatePoint(priv.Curve, priv.X, priv.Y); err != nil {
		return err
	}
	x, y := priv.ScalarBaseMult(priv.D.Bytes())
	if x.Cmp(priv.X) != 0 || y.Cmp(priv.Y) != 0 {
		return errors.New("sm2: private/public key mismatch")
	}
	return nil
}
