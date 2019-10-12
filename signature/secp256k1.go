package signature

import (
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ontio/ontology-crypto/ec"
	"golang.org/x/crypto/sha3"
)

func hashKeccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func Secp256k1Sign(pri *ec.PrivateKey, msg []byte) ([]byte, error) {
	digest := hashKeccak256(msg)
	return btcec.SignCompact(btcec.S256(), (*btcec.PrivateKey)(pri.PrivateKey), digest, false)
}

func Secp256k1Verify(pub *ec.PublicKey, msg []byte, sig []byte) bool {
	digest := hashKeccak256(msg)
	recKey, _, err := btcec.RecoverCompact(btcec.S256(), sig, digest)
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
	if s.Scheme != SHA3_256withECDSA {
		return nil, errors.New("invalid signature scheme")
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
