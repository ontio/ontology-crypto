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

package keypair

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/sm2"
)

func TestComparePublicKeyDistinguishesY(t *testing.T) {
	curve := sm2.SM2P256V1()
	params := curve.Params()
	negY := new(big.Int).Sub(params.P, params.Gy)
	if negY.Cmp(params.Gy) == 0 {
		t.Skip("degenerate curve, cannot build (X, P-Y)")
	}

	k0 := &ec.PublicKey{
		Algorithm: ec.SM2,
		PublicKey: &ecdsa.PublicKey{X: new(big.Int).Set(params.Gx), Y: new(big.Int).Set(params.Gy), Curve: curve},
	}
	k1 := &ec.PublicKey{
		Algorithm: ec.SM2,
		PublicKey: &ecdsa.PublicKey{X: new(big.Int).Set(params.Gx), Y: negY, Curve: curve},
	}

	if ComparePublicKey(k0, k1) {
		t.Error("(X, Y) and (X, P-Y) must not compare equal")
	}
	if !ComparePublicKey(k0, k0) {
		t.Error("identical public keys must compare equal")
	}
}

func TestComparePublicKeyHandlesNil(t *testing.T) {
	if ComparePublicKey(nil, nil) {
		t.Error("nil keys must not compare equal")
	}
	if ComparePublicKey((*ec.PublicKey)(nil), (*ec.PublicKey)(nil)) {
		t.Error("typed nil keys must not compare equal")
	}
	valid := &ec.PublicKey{Algorithm: ec.ECDSA}
	if ComparePublicKey(valid, (*ec.PublicKey)(nil)) {
		t.Error("nil operand must not compare equal")
	}
}
