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

	// The compact signature header encodes the recovery id: btcec writes
	// 27+recid for uncompressed keys and 31+recid for compressed keys. Reject
	// anything outside that range instead of underflowing on t[0]-27.
	if t[0] < 27 || t[0] > 34 {
		return nil, errors.New("invalid compact signature header")
	}
	v := t[0] - 27
	if v >= 4 {
		v -= 4 // strip the compressed-key offset
	}

	// Build a new buffer so the caller's input is not modified in place.
	res := make([]byte, 65)
	copy(res[:64], t[1:])
	res[64] = v
	return res, nil
}
