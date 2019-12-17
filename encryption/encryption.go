package encryption

import (
	"crypto/rand"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm2"
)

func Encrypt(pub keypair.PublicKey, m []byte) ([]byte, error) {
	switch key := pub.(type) {
	case *ec.PublicKey:
		if key.Algorithm == ec.SM2 {
			return sm2.Encrypt(key.PublicKey, m)
		} else if key.Algorithm == ec.ECDSA {
			pk := &ecies.PublicKey{
				X:      key.X,
				Y:      key.Y,
				Curve:  key.Curve,
				Params: ecies.ParamsFromCurve(key.Curve),
			}
			return ecies.Encrypt(rand.Reader, pk, m, nil, keypair.SerializePublicKey(key))
		} else {
			panic("unknown public key type")
		}
	default:
		return nil, errors.New("unsupported encryption key")
	}

}

func Decrypt(pri keypair.PrivateKey, c []byte) ([]byte, error) {
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
			return sk.Decrypt(c, nil, keypair.SerializePublicKey(key.Public()))
		} else {
			panic("unknown private key type")
		}
	default:
		return nil, errors.New("unsupported decryption key")
	}
}
