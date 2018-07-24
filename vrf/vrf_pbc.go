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
 * TODO: implement the vrf scheme in the case that the underlying curve
 *  is a pairing-friendly curve. In this case, there is no need to
 *  include a NIZK proof for it suffices to verify the equation
 *      e(vrf, g) = e(Hg(m), pk)
 */

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"

	"golang.org/x/crypto/bn256"
)

// KeyPairBN256 contains private key and public key
type KeyPairBN256 struct {
	pri *big.Int
	pub *bn256.G1
}

// GenKeyPair generates a new key pair of BN256 Pairing Curve
func GenKeyPair() (kp *KeyPairBN256, err error) {

	// pri, err := rand.Int(rand.Reader, bn256.Order)

	// pub := new(bn256.G1)
	// pub.ScalarBaseMult(pri)

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

func (this *KeyPairBN256) SelfCheck() error {

	if this.pri == nil {
		return *new(error)
	}

	if this.pub == nil {
		return *new(error)
	}

	pub := new(bn256.G1)
	pub.ScalarBaseMult(this.pri)

	if this.pub.String() != pub.String() {
		return *new(error)
	}

	return nil
}

/* funcs */

// VrfPbc returns the verifiable random function evaluated m and a NIZK proof
// Proof()
func VrfPbc(kp *KeyPairBN256, msg []byte) ([]byte, []byte) {

	// check key pair
	if kp.SelfCheck() != nil {
		fmt.Printf("key pairis in wrong format. \n")
	}

	// check message
	if msg == nil {
		fmt.Printf("message is empty. \n")
	}

	// compute

	// g1
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	// g2
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	// hash message
	digest := sha256.Sum256(msg)
	x := big.NewInt(0).SetBytes(digest[:])
	// _x := big.NewInt(0).SetBytes(digest[:])

	// F(sk, x)
	egg := bn256.Pair(g1, g2) // egg = e(g1, g2)

	// fmt.Printf("#### x: %v \n", x)

	tmp := x.Add(x, kp.pri)
	tmp = tmp.ModInverse(tmp, bn256.Order) // 1/... mod n
	f := egg.ScalarMult(egg, tmp)

	// fmt.Printf("#### tmp: %v \n", tmp)
	// fmt.Printf("#### f: %v \n", f.Marshal())

	// _egg := bn256.Pair(g1.ScalarMult(g1, tmp), g2) // egg = e(g1, g2)

	// fmt.Printf("#### _x: %v \n", _x)
	// fmt.Printf("#### _egg: %v \n", _egg.Marshal())
	// fmt.Printf("#### _egg: %v \n", _egg.Marshal())

	// pi(sk, x)

	pi := new(bn256.G2)
	pi = pi.ScalarBaseMult(tmp)

	// marshal

	m_f := f.Marshal()
	m_pi := pi.Marshal()

	// return
	return m_f, m_pi
}

func VrfPbcVerify(pk *bn256.G1, msg []byte, m_f []byte, m_pi []byte) (bool, error) {
	f, ok := new(bn256.GT).Unmarshal(m_f)

	if !ok {
		fmt.Printf("### m_f ### \n")
		return false, nil
	}

	pi, ok := new(bn256.G2).Unmarshal(m_pi)

	if !ok {
		fmt.Printf("### m_pi ### \n")
		return false, nil
	}

	// hash message
	digest := sha256.Sum256(msg)
	x := big.NewInt(0).SetBytes(digest[:])

	// g1
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	// g2
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	egg := bn256.Pair(g1, g2) // egg = e(g1, g2)

	g1.ScalarBaseMult(x)
	g1.Add(g1, pk)

	first := bn256.Pair(g1, pi)
	fmt.Printf("first: %v \n", first)
	fmt.Printf("egg: %v \n", egg)
	if !reflect.DeepEqual(first.Marshal(), egg.Marshal()) {
		fmt.Printf("### first ### \n")
		return false, nil
	}

	g1.ScalarBaseMult(big.NewInt(1))
	second := bn256.Pair(g1, pi)
	if !reflect.DeepEqual(second.Marshal(), f.Marshal()) {
		fmt.Printf("### second ### \n")
		return false, nil
	}

	return true, nil

}

// //Vrf returns the verifiable random function evaluated m and a NIZK proof
// func Vrf(pri *big.Int, pub *bn256.G1, msg []byte) (vrf, nizk []byte, err error) {

// }
