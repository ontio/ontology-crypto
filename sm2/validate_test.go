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

func TestEncryptRejectsInvalidPublicKey(t *testing.T) {
	curve := SM2P256V1()
	params := curve.Params()

	if _, err := Encrypt(nil, []byte("hi")); err == nil {
		t.Error("expected error for nil public key")
	}

	// X = Gx, Y = 0 is not on the SM2 curve.
	offCurve := &ecdsa.PublicKey{X: new(big.Int).Set(params.Gx), Y: new(big.Int), Curve: curve}
	if _, err := Encrypt(offCurve, []byte("hi")); err == nil {
		t.Error("expected error for off-curve public key")
	}

	// A coordinate equal to the field prime must be rejected.
	outOfRange := &ecdsa.PublicKey{X: new(big.Int).Set(params.P), Y: new(big.Int).Set(params.Gy), Curve: curve}
	if _, err := Encrypt(outOfRange, []byte("hi")); err == nil {
		t.Error("expected error for out-of-range public key")
	}
}

func TestVerifyRejectsInvalidArguments(t *testing.T) {
	curve := SM2P256V1()
	params := curve.Params()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")

	r := new(big.Int).SetInt64(1)
	s := new(big.Int).SetInt64(1)
	if Verify(nil, "", msg, sm3.New(), r, s) {
		t.Error("nil public key must not verify")
	}
	if Verify(&priv.PublicKey, "", msg, nil, r, s) {
		t.Error("nil hasher must not verify")
	}
	if Verify(&priv.PublicKey, "", msg, sm3.New(), nil, s) {
		t.Error("nil r must not verify")
	}
	badPub := &ecdsa.PublicKey{X: new(big.Int).Set(params.Gx), Y: new(big.Int), Curve: curve}
	if Verify(badPub, "", msg, sm3.New(), r, s) {
		t.Error("off-curve public key must not verify")
	}
}
