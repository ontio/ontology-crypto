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

package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ontio/ontology-crypto/sm3"
)

var d_hex = "5be7e4b09a761bf5562ddf8e6a33184e00d0c09c942c6adbad1141d5d08431f0"
var x_hex = "bed1c52a2bb67d2cc82b0d099c5832b7886e21828c3745f84990c249cf8d5890"
var y_hex = "762a3a2e07c0e4ef2dee435d4f2b76d8892b42e77727eef72b9cbfa29c5eb76b"
var r_hex = "6e833daf8bd2cb5b09786a0ad5e6e5617242f8e60938f64afd11285e9d719a51"
var s_hex = "bdf93e24fe552d716f9ef1e1ae477af8f39a06b5d86222e76cbe5f14c0f063b1"
var msg = []byte("test message")

func TestVerify(t *testing.T) {
	x, _ := new(big.Int).SetString(x_hex, 16)
	y, _ := new(big.Int).SetString(y_hex, 16)
	pub := &ecdsa.PublicKey{
		Curve: SM2P256V1(),
		X:     x,
		Y:     y,
	}

	r, _ := new(big.Int).SetString(r_hex, 16)
	s, _ := new(big.Int).SetString(s_hex, 16)

	if !Verify(pub, "", msg, sm3.New(), r, s) {
		t.Error("verification failed")
	}
}

func TestSignAndVerify(t *testing.T) {
	pri, _ := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	hasher := sm3.New()
	r, s, err := Sign(rand.Reader, pri, "", msg, hasher)
	if err != nil {
		t.Fatalf("signing error: %s", err)
	}

	if !Verify(&pri.PublicKey, "", msg, hasher, r, s) {
		t.Error("verification failed")
	}
}
