package vrf

import (
	"crypto/elliptic"
	"fmt"

	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"gitlab.com/abhvious/vrf/psvrf"
)

func Vrf(pri keypair.PrivateKey, msg []byte) ([]byte, []byte, error) {
	switch t := pri.(type) {
	case *ec.PrivateKey:
		//currently psvrf only supports secp256r1 curve
		if t.Params().Gx.Cmp(elliptic.P256().Params().Gx) != 0 ||
			t.Params().Gy.Cmp(elliptic.P256().Params().Gy) != 0 {
			return nil, nil, fmt.Errorf("does not support")
		}

		sk := new(psvrf.PrivateKey)
		_, err := sk.Unmarshal(t.D.Bytes())
		if err != nil {
			return nil, nil, err
		}
		return sk.Vrf(msg)

	default:
		return nil, nil, fmt.Errorf("does not support")
	}
}

func Verify(pub keypair.PublicKey, msg, vrf, proof []byte) (bool, error) {
	switch t := pub.(type) {
	case *ec.PublicKey:
		if t.Params().Gx.Cmp(elliptic.P256().Params().Gx) != 0 ||
			t.Params().Gy.Cmp(elliptic.P256().Params().Gy) != 0 {
			return false, fmt.Errorf("does not support")
		}
		pk := new(psvrf.PublicKey)
		_, err := pk.Unmarshal(elliptic.Marshal(t.Curve, t.X, t.Y))
		if err != nil {
			return false, err
		}

		return pk.Verify(msg, vrf, proof), nil
	default:
		return false, fmt.Errorf("does not support")
	}
}
