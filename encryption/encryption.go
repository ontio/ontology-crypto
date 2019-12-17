package encryption

import (
	"crypto/rand"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/ontio/ontology/core/types"
)

func Encrypt(pub keypair.PublicKey, m []byte) ([]byte, error) {
	switch key := pub.(type) {
	case *ec.PublicKey:
		if key.Algorithm == ec.SM2 {
			return sm2.Encrypt(key.PublicKey, m)
		} else if key.Algorithm == ec.ECDSA {
			addr := types.AddressFromPubKey(key)
			pk := &ecies.PublicKey{
				X:      key.X,
				Y:      key.Y,
				Curve:  key.Curve,
				Params: ecies.ParamsFromCurve(key.Curve),
			}
			return ecies.Encrypt(rand.Reader, pk, m, addr[:], addr[:])
		} else {
			panic("unknown public key type")
		}
	default:
		return nil, errors.New("unsupported encryption key")
	}

}

func Decrypt(pri keypair.PublicKey, c []byte) ([]byte, error) {
	switch key := pri.(type) {
	case *ec.PrivateKey:
		if key.Algorithm == ec.SM2 {
			return sm2.Decrypt(key.PrivateKey, c)
		} else if key.Algorithm == ec.ECDSA {
			sk := &ecies.PrivateKey{
				PublicKey: ecies.PublicKey{
					X:      key.X,
					Y:      key.Y,
					Curve:  key.Curve,
					Params: ecies.ParamsFromCurve(key.Curve),
				},
				D: key.D,
			}
			addr := types.AddressFromPubKey(key.Public())
			return sk.Decrypt(c, addr[:], addr[:])
		} else {
			panic("unknown private key type")
		}
	default:
		return nil, errors.New("unsupported decryption key")
	}
}
