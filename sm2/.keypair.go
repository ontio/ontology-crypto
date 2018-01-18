// SM2 key pair

package sm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"

	"github.com/Ontology/crypto/ecc"
)

type PublicKey ecdsa.PublicKey

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func GenerateKeyPair(c elliptic.Curve, rand io.Reader) (*PrivateKey, *PublicKey, error) {
	d, x, y, err := elliptic.GenerateKey(c, rand)
	if err != nil {
		return nil, nil, err
	}

	pri := PrivateKey{
		D: new(big.Int).SetBytes(d),
		PublicKey: PublicKey{
			X:     x,
			Y:     y,
			Curve: c,
		},
	}
	return &pri, &pri.PublicKey, nil
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func EncodePublicKey(pub *PublicKey, compress bool) []byte {
	return ecc.EncodePublicKey((*ecdsa.PublicKey)(pub), compress)
}

func DecodePublicKey(data []byte, curve elliptic.Curve) (pub *PublicKey, err error) {
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
