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
	"bytes"
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
)

func TestVerifyPreservesInputBuffers(t *testing.T) {
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("buffer ownership regression")
	value, nizk, err := Vrf(pri, msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []bool{true, false} {
		// The trailing bytes represent another field in the caller's message.
		backing := bytes.Repeat([]byte{0xa5}, len(nizk)+len(value))
		copy(backing, nizk)
		before := append([]byte(nil), backing...)
		valueBefore := append([]byte(nil), value...)
		inputMsg := append([]byte(nil), msg...)
		if !valid {
			inputMsg[0] ^= 1
		}
		msgBefore := append([]byte(nil), inputMsg...)
		ok, err := Verify(pub, inputMsg, value, backing[:len(nizk)])
		if err != nil || ok != valid {
			t.Fatalf("valid=%v: got %v, %v", valid, ok, err)
		}
		if !bytes.Equal(backing, before) || !bytes.Equal(value, valueBefore) || !bytes.Equal(inputMsg, msgBefore) {
			t.Fatalf("valid=%v: Verify modified caller-owned memory", valid)
		}
	}
}

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
		t.Fatalf("key type %v curve %v: private key should be invalid", kt, curve)
	}

	isValid = ValidatePublicKey(pub)
	if isValid {
		t.Fatalf("key type %v curve %v: public key should be invalid", kt, curve)
	}
}

func TestInvalidKey(t *testing.T) {
	testInvalidKey(t, keypair.PK_ECDSA, keypair.P521)
	testInvalidKey(t, keypair.PK_EDDSA, keypair.ED25519)
}

func testValidKey(t *testing.T, kt keypair.KeyType, curve byte) {
	pri, pub, err := keypair.GenerateKeyPair(kt, curve)
	if err != nil {
		t.Fatalf("key type %v curve %v: %v", kt, curve, err)
	}

	isValid := ValidatePrivateKey(pri)
	if !isValid {
		t.Fatalf("key type %v curve %v: private key should be valid", kt, curve)
	}

	isValid = ValidatePublicKey(pub)
	if !isValid {
		t.Fatalf("key type %v curve %v: public key should be valid", kt, curve)
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
