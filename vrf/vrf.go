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

//This package is a wrapper of verifiable random function using curve secp256r1.
package vrf

import (
	"crypto/elliptic"
	"errors"

	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
)

var (
	ErrCurveNotSupported = errors.New("only support secp256r1 curve")
	ErrKeyNotSupported   = errors.New("only support ECC key")
	ErrEvalVRF           = errors.New("failed to evaluate vrf")
)

//Vrf returns the verifiable random function evaluated m and a NIZK proof
func Vrf(pri keypair.PrivateKey, msg []byte) (vrf, nizk []byte, err error) {
	switch t := pri.(type) {
	case *ec.PrivateKey:
		//currently only supports secp256r1 curve
		if t.Params().Gx.Cmp(elliptic.P256().Params().Gx) != 0 ||
			t.Params().Gy.Cmp(elliptic.P256().Params().Gy) != 0 {
			return nil, nil, ErrCurveNotSupported
		}

		sk := new(p256.PrivateKey)
		sk.PrivateKey = t.PrivateKey
		_, proof := sk.Evaluate(msg)
		if proof == nil || len(proof) != 64+65 {
			return nil, nil, ErrEvalVRF
		}

		nizk = proof[0:64]
		vrf = proof[64 : 64+65]
		err = nil
		return

	default:
		return nil, nil, ErrKeyNotSupported
	}
}

//Verify returns true if vrf and nizk is correct for msg
func Verify(pub keypair.PublicKey, msg, vrf, nizk []byte) (bool, error) {
	switch t := pub.(type) {
	case *ec.PublicKey:
		if t.Params().Gx.Cmp(elliptic.P256().Params().Gx) != 0 ||
			t.Params().Gy.Cmp(elliptic.P256().Params().Gy) != 0 {
			return false, ErrCurveNotSupported
		}

		pk := new(p256.PublicKey)
		pk.PublicKey = t.PublicKey

		if len(vrf) != 65 || len(nizk) != 64 {
			return false, nil
		}
		proof := append(nizk, vrf...)
		_, err := pk.ProofToHash(msg, proof)
		if err != nil {
			return false, err
		}

		return true, nil
	default:
		return false, ErrKeyNotSupported
	}
}
