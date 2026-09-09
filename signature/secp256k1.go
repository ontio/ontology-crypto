package signature

import (
	"crypto/elliptic"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/ontio/ontology-crypto/ec"
)

func Secp256k1Sign(pri *ec.PrivateKey, hash []byte) ([]byte, error) {
	// btcec/v2's PrivateKey is no longer ecdsa.PrivateKey-shaped (it wraps
	// decred/dcrd's own secp256k1 type), so it can't be built with a type
	// conversion like the old btcec.PrivateKey could. Reconstruct it from
	// the same scalar bytes instead.
	privKey, _ := btcec.PrivKeyFromBytes(pri.D.Bytes())
	return ecdsa.SignCompact(privKey, hash, false)
}

func Secp256k1Verify(pub *ec.PublicKey, hash []byte, sig []byte) bool {
	recKey, _, err := ecdsa.RecoverCompact(sig, hash)
	if err != nil {
		return false
	}
	wantKey, err := btcec.ParsePubKey(elliptic.Marshal(pub.Curve, pub.X, pub.Y))
	if err != nil {
		return false
	}
	return recKey.IsEqual(wantKey)
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
