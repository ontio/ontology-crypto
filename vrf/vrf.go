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
	"crypto"
	"crypto/elliptic"
	"errors"
	"hash"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/sm3"
)

var (
	ErrKeyNotSupported = errors.New("only support ECC key")
	ErrEvalVRF         = errors.New("failed to evaluate vrf")
)

//Vrf returns the verifiable random function evaluated m and a NIZK proof
func Vrf(pri keypair.PrivateKey, msg []byte) (vrf, nizk []byte, err error) {
	isValid := ValidatePrivateKey(pri)
	if !isValid {
		return nil, nil, ErrKeyNotSupported
	}
	sk := pri.(*ec.PrivateKey)
	h := getHash(sk.Curve)
	byteLen := (sk.Params().BitSize + 7) >> 3
	_, proof := Evaluate(sk.PrivateKey, h, msg)
	if proof == nil {
		return nil, nil, ErrEvalVRF
	}

	nizk = proof[0 : 2*byteLen]
	vrf = proof[2*byteLen : 2*byteLen+2*byteLen+1]
	err = nil
	return
}

//Verify returns true if vrf and nizk is correct for msg
func Verify(pub keypair.PublicKey, msg, vrf, nizk []byte) (bool, error) {
	isValid := ValidatePublicKey(pub)
	if !isValid {
		return false, ErrKeyNotSupported
	}
	pk := pub.(*ec.PublicKey)
	h := getHash(pk.Curve)
	byteLen := (pk.Params().BitSize + 7) >> 3
	if len(vrf) != byteLen*2+1 || len(nizk) != byteLen*2 {
		return false, nil
	}
	proof := append(nizk, vrf...)
	_, err := ProofToHash(pk.PublicKey, h, msg, proof)
	if err != nil {
		return false, nil
	}
	return true, nil
}

/*
 * ValidatePrivateKey checks two conditions:
 *  - the private key must be of type ec.PrivateKey
 *	- the private key must use curve secp256r1
 */
func ValidatePrivateKey(pri keypair.PrivateKey) bool {
	switch t := pri.(type) {
	case *ec.PrivateKey:
		h := getHash(t.Curve)
		if h == nil {
			return false
		}
		return true
	default:
		return false
	}
}

/*
 * ValidatePublicKey checks two conditions:
 *  - the public key must be of type ec.PublicKey
 *	- the public key must use curve secp256r1
 */
func ValidatePublicKey(pub keypair.PublicKey) bool {
	switch t := pub.(type) {
	case *ec.PublicKey:
		h := getHash(t.Curve)
		if h == nil {
			return false
		}
		return true

	default:
		return false
	}
}

func getHash(curve elliptic.Curve) hash.Hash {
	bitSize := curve.Params().BitSize
	switch bitSize {
	case 224:
		return crypto.SHA224.New()
	case 256:
		switch curve.Params().Name {
		case "sm2p256v1":
			return sm3.New()
		case "P-256", btcec.S256().Name:
			return crypto.SHA256.New()
		default:
			return nil
		}
	case 384:
		return crypto.SHA384.New()
	default:
		return nil
	}
}
