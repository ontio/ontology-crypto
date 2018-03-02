// SM2 key pair

package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"
)

type PrivateKey struct {
	PublicKey ecdsa.PublicKey
	D *big.Int
}

func GenerateKeyPair(c elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	d, x, y, err := elliptic.GenerateKey(c, rand)
	if err != nil {
		return nil, nil, err
	}

	pri := ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(d),
		PublicKey: ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: c,
		},
	}
	return &pri, &pri.PublicKey, nil
}

func (pri *PrivateKey) Public() ecdsa.PublicKey {
	return pri.PublicKey
}

/*
func EncodePublicKey(pub *ecdsa.PublicKey, compress bool) []byte {

	return ecc.EncodePublicKey((*ecdsa.PublicKey)(pub), compress)
}

func DecodePublicKey(data []byte, curve elliptic.Curve) (pub *ecdsa.PublicKey, err error) {
	key, err := ecc.DecodePublicKey(data, curve)
	if err != nil {
		return
	}

	pub = (*PublicKey)(key)
	return
}

func ConstructPrivateKey(data []byte, curve elliptic.Curve) *PrivateKey {
	pri := ecc.ConstructPrivateKey(data, curve)
	return &PrivateKey{
		PublicKey: PublicKey(pri.PublicKey),
		D:         pri.D,
	}
}
*/