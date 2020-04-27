package signature

import (
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ontio/ontology-crypto/ec"
)

func Secp256k1Sign(pri *ec.PrivateKey, hash []byte) ([]byte, error) {
	return btcec.SignCompact(btcec.S256(), (*btcec.PrivateKey)(pri.PrivateKey), hash, false)
}

func Secp256k1Verify(pub *ec.PublicKey, hash []byte, sig []byte) bool {
	recKey, _, err := btcec.RecoverCompact(btcec.S256(), sig, hash)
	if err != nil {
		return false
	}
	return recKey.IsEqual((*btcec.PublicKey)(pub.PublicKey))
}

func ConvertToEthCompatible(sig []byte) ([]byte, error) {
	s, err := Deserialize(sig)
	if err != nil {
		return nil, err
	}

	t, ok := s.Value.([]byte)
	if !ok {
		return nil, errors.New("invalid signature type")
	}

	if len(t) != 65 {
		return nil, errors.New("invalid signature length")
	}

	v := t[0] - 27
	copy(t, t[1:])
	t[64] = v
	return t, nil
}
