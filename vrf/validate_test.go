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
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
)

func TestValidatePublicKeyRejectsInvalidPoints(t *testing.T) {
	_, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}
	valid := pub.(*ec.PublicKey)

	// Same X but a Y that does not satisfy the curve equation.
	offCurve := &ec.PublicKey{
		Algorithm: valid.Algorithm,
		PublicKey: &ecdsa.PublicKey{
			X:     valid.X,
			Y:     new(big.Int).Add(valid.Y, big.NewInt(1)),
			Curve: valid.Curve,
		},
	}
	if ValidatePublicKey(offCurve) {
		t.Error("expected off-curve public key to be rejected")
	}

	// Coordinates outside the field.
	outOfRange := &ec.PublicKey{
		Algorithm: valid.Algorithm,
		PublicKey: &ecdsa.PublicKey{
			X:     new(big.Int).Set(valid.Curve.Params().P),
			Y:     valid.Y,
			Curve: valid.Curve,
		},
	}
	if ValidatePublicKey(outOfRange) {
		t.Error("expected out-of-range public key to be rejected")
	}

	if ValidatePublicKey((*ec.PublicKey)(nil)) {
		t.Error("expected typed nil public key to be rejected")
	}

	if !ValidatePublicKey(valid) {
		t.Error("expected valid public key to be accepted")
	}
}
