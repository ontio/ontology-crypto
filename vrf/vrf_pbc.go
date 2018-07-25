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

/*
 * The pairing based vrf is an implentation of
 * [A Verifiable Random Function With Short Proofs and Keys]
 * (https://eprint.iacr.org/2004/310.pdf),
 * authored by Yevgeniy Dodis and Aleksandr Yampolskiy.
 * There are some changes made to use BN256 curve.
 * The security of this implentation demands to analyze.
 */

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"reflect"

	"golang.org/x/crypto/bn256"
)

// KeyPairBN256 contains private key and public key
type KeyPairBN256 struct {
	pri *big.Int
	pub *bn256.G1
}

// GenerateKey generates a new key pair of BN256 Pairing Curve
func GenerateKey() (kp *KeyPairBN256, err error) {
	kp = new(KeyPairBN256)

	pri, pub, err := bn256.RandomG1(rand.Reader)

	kp.pri = pri
	kp.pub = pub

	return
}

// GetPri return private key
func (this *KeyPairBN256) GetPri() *big.Int {
	return this.pri
}

// GetPub return public key
func (this *KeyPairBN256) GetPub() *bn256.G1 {
	return this.pub
}

// SelfCheck checks the key pair
func (this *KeyPairBN256) SelfCheck() error {
	if this.pri == nil {
		return errors.New("private key is null")
	}

	if this.pub == nil {
		return errors.New("public key is null")
	}

	pub := new(bn256.G1).ScalarBaseMult(this.pri)

	// String() or Marshal() ??
	if !reflect.DeepEqual(this.pub.Marshal(), pub.Marshal()) {
		return errors.New("public key and private key are not matched")
	}

	return nil
}

/* Main functions */

// PbcSign returns the verifiable random function evaluated m and a NIZK proof
func PbcSign(kp *KeyPairBN256, msg []byte) ([]byte, []byte, error) {
	// check key pair
	if kp.SelfCheck() != nil {
		return nil, nil, errors.New("key pair is in wrong format")
	}
	// check message
	if msg == nil {
		return nil, nil, errors.New("message is empty")
	}
	// compute
	// g1
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	// g2
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	// hash message
	// TODO: use HashToInt of crypto
	digest := sha256.Sum256(msg)
	x := big.NewInt(0).SetBytes(digest[:])

	// F(sk, x)
	egg := bn256.Pair(g1, g2) // egg = e(g1, g2)

	tmp := x.Add(x, kp.pri)
	tmp = tmp.ModInverse(tmp, bn256.Order) // 1/(x+sk) mod n
	f := egg.ScalarMult(egg, tmp)

	pi := new(bn256.G2)
	pi = pi.ScalarBaseMult(tmp)

	// marshal
	mF := f.Marshal()
	mPi := pi.Marshal()

	// return
	return mF, mPi, nil
}

// PbcVerify verifies a proof and vrf with message m.
func PbcVerify(pk *bn256.G1, msg []byte, mF []byte, mPi []byte) (bool, error) {
	f, ok := new(bn256.GT).Unmarshal(mF)
	if !ok {
		return false, errors.New("failed to unmarshal mF")
	}

	pi, ok := new(bn256.G2).Unmarshal(mPi)
	if !ok {
		return false, errors.New("failed to unmarshal mPi")
	}

	// hash message
	digest := sha256.Sum256(msg)
	x := big.NewInt(0).SetBytes(digest[:])

	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1)) // g1
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1)) // g2

	egg := bn256.Pair(g1, g2) // egg = e(g1, g2)

	g1.ScalarBaseMult(x)
	g1.Add(g1, pk)                                          // g^x · PK
	first := bn256.Pair(g1, pi)                             // first = e(g^x · PK, π)
	if !reflect.DeepEqual(first.Marshal(), egg.Marshal()) { // check if first = e(g, g)
		return false, errors.New("failed checking VRF output")
	}

	g1.ScalarBaseMult(big.NewInt(1))
	second := bn256.Pair(g1, pi)                           // second = e(g, π)
	if !reflect.DeepEqual(second.Marshal(), f.Marshal()) { // check if y = second
		return false, errors.New("failed checking the proof of correctness")
	}

	return true, nil
}
