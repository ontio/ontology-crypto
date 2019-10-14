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
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
)

func testVrf(t *testing.T, kt keypair.KeyType, curve byte) {
	pri, pub, err := keypair.GenerateKeyPair(kt, curve)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test")
	vrf, proof, err := Vrf(pri, msg)
	if err != nil {
		t.Fatalf("compute vrf: %v", err)
	}

	ret, err := Verify(pub, msg, vrf, proof)
	if err != nil {
		t.Fatalf("verify vrf: %v", err)
	}
	if !ret {
		t.Fatal("failed")
	}
}

func TestVrf(t *testing.T) {
	testVrf(t, keypair.PK_ECDSA, keypair.SECP256K1)
	testVrf(t, keypair.PK_ECDSA, keypair.P224)
	testVrf(t, keypair.PK_ECDSA, keypair.P256)
	testVrf(t, keypair.PK_ECDSA, keypair.P384)
	testVrf(t, keypair.PK_SM2, keypair.SM2P256V1)
}

func testInvalidKey(t *testing.T, kt keypair.KeyType, curve byte) {
	pri, pub, err := keypair.GenerateKeyPair(kt, curve)
	if err != nil {
		t.Fatal(err)
	}

	isValid := ValidatePrivateKey(pri)
	if isValid {
		t.Fatal("should return false")
	}

	isValid = ValidatePublicKey(pub)
	if isValid {
		t.Fatal("should return false")
	}
}

func TestInvalidKey(t *testing.T) {
	testInvalidKey(t, keypair.PK_ECDSA, keypair.P521)
	testInvalidKey(t, keypair.PK_EDDSA, keypair.ED25519)
}

func testValidKey(t *testing.T, kt keypair.KeyType, curve byte) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}

	isValid := ValidatePrivateKey(pri)
	if !isValid {
		t.Fatal("should return true")
	}

	isValid = ValidatePublicKey(pub)
	if !isValid {
		t.Fatal("should return true")
	}
}

func TestValidKey(t *testing.T) {
	testValidKey(t, keypair.PK_ECDSA, keypair.SECP256K1)
	testValidKey(t, keypair.PK_ECDSA, keypair.P224)
	testValidKey(t, keypair.PK_ECDSA, keypair.P256)
	testValidKey(t, keypair.PK_ECDSA, keypair.P384)
	testValidKey(t, keypair.PK_SM2, keypair.SM2P256V1)
}

func BenchmarkVrf(b *testing.B) {
	pri, _, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := []byte("test")
		Vrf(pri, msg)
	}
}
