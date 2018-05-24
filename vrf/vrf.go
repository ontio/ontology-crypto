/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

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
