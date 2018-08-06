package bn256

import (
	"crypto"
	"io"
	"math/big"

	originBN256 "golang.org/x/crypto/bn256"
)

// PublicKey is the type of Ed25519 public keys.
type PublicKey struct {
	v *originBN256.G1
}

// Value returns the value of this.
func (this PublicKey) Value() *originBN256.G1 {
	v := *(this.v)
	return &v
}

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey struct {
	v *big.Int
}

// Public returns the PublicKey corresponding to priv.
func (this PrivateKey) Public() crypto.PublicKey {
	pub := new(originBN256.G1).ScalarBaseMult(this.v)
	publicKey := new(PublicKey)
	publicKey.v = pub
	return publicKey
}

// Value returns the value of this.
func (this PrivateKey) Value() *big.Int {
	v := new(big.Int)
	v.Set(this.v)
	return v
}

// GenerateKey generates a new key pair of BN256 Pairing Curve
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	pri, pub, err := originBN256.RandomG1(rand)

	privateKey := new(PrivateKey)
	privateKey.v = pri

	publicKey := new(PublicKey)
	publicKey.v = pub

	return *publicKey, *privateKey, err
}
