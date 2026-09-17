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

package signature

import (
	"bytes"
	"crypto"
	"math/big"
	"testing"

	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
)

func TestDeserializeSerializeRoundTrip(t *testing.T) {
	pri, _, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}
	sm2pri, _, err := keypair.GenerateKeyPair(keypair.PK_SM2, keypair.SM2P256V1)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("round trip message")
	cases := []struct {
		scheme SignatureScheme
		pri    crypto.PrivateKey
	}{
		{SHA224withECDSA, pri},
		{SHA256withECDSA, pri},
		{SHA384withECDSA, pri},
		{SHA3_256withECDSA, pri},
		{RIPEMD160withECDSA, pri},
		{SM3withSM2, sm2pri},
	}

	for _, c := range cases {
		sig, err := Sign(c.scheme, c.pri, msg, nil)
		if err != nil {
			t.Fatalf("%s: sign failed: %v", c.scheme.Name(), err)
		}
		raw, err := Serialize(sig)
		if err != nil {
			t.Fatalf("%s: serialize failed: %v", c.scheme.Name(), err)
		}
		sig2, err := Deserialize(raw)
		if err != nil {
			t.Fatalf("%s: deserialize failed: %v", c.scheme.Name(), err)
		}
		// This used to panic because the deserialized DSA signature had no
		// Curve attached.
		raw2, err := Serialize(sig2)
		if err != nil {
			t.Fatalf("%s: re-serialize failed: %v", c.scheme.Name(), err)
		}
		if !bytes.Equal(raw, raw2) {
			t.Errorf("%s: round trip mismatch\nraw1=%x\nraw2=%x", c.scheme.Name(), raw, raw2)
		}
	}
}

func TestSerializeDSASignatureWithoutCurveReturnsError(t *testing.T) {
	sig := &Signature{
		Scheme: SHA256withECDSA,
		Value:  &DSASignature{R: big.NewInt(1), S: big.NewInt(2)},
	}
	if _, err := Serialize(sig); err == nil {
		t.Error("expected an error instead of a panic for a signature without curve/width")
	}
}

func TestVerifyRejectsMalformedValues(t *testing.T) {
	_, pub, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	if err != nil {
		t.Fatal(err)
	}
	_, edPub, err := keypair.GenerateKeyPair(keypair.PK_EDDSA, keypair.ED25519)
	if err != nil {
		t.Fatal(err)
	}
	_, ethPub, err := keypair.GenerateKeyPair(keypair.PK_ETHECDSA, nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("message")

	// Wrong dynamic types must be rejected without panicking.
	if Verify(edPub, msg, &Signature{Scheme: SHA512withEDDSA, Value: 1234}) {
		t.Error("ed25519: wrong value type must not verify")
	}
	if Verify(ethPub, msg, &Signature{Scheme: KECCAK256WithECDSA, Value: "not bytes"}) {
		t.Error("ethereum: wrong value type must not verify")
	}
	if Verify(pub, msg, &Signature{Scheme: SHA256withECDSA, Value: &DSASignature{}}) {
		t.Error("ecdsa: nil R/S must not verify")
	}
	if Verify(pub, msg, &Signature{Scheme: SM3withSM2, Value: []byte("nope")}) {
		t.Error("sm2: wrong value type must not verify")
	}

	// A typed nil public key must not panic.
	if Verify((*ec.PublicKey)(nil), msg, &Signature{Scheme: SHA256withECDSA, Value: []byte("x")}) {
		t.Error("nil public key must not verify")
	}
}

func TestDeserializeDSASignatureRejectsMalformed(t *testing.T) {
	// SM3withSM2, empty user ID, all-zero R and S.
	zeros := append([]byte{byte(SM3withSM2), 0x00}, make([]byte, 64)...)
	if _, err := Deserialize(zeros); err == nil {
		t.Error("expected error for zero signature components")
	}

	// Components wider than the widest supported curve (P-521, 66 bytes).
	oversized := append([]byte{byte(SHA256withECDSA)}, make([]byte, 140)...)
	if _, err := Deserialize(oversized); err == nil {
		t.Error("expected error for oversized signature components")
	}

	// Odd total length cannot be split into two equal components.
	if _, err := Deserialize([]byte{byte(SHA256withECDSA), 0x01, 0x02, 0x03}); err == nil {
		t.Error("expected error for odd signature length")
	}

	// SM2 components must fit the SM2 curve order.
	tooBig := make([]byte, 64)
	for i := range tooBig {
		tooBig[i] = 0xff
	}
	payload := append([]byte{byte(SM3withSM2), 0x00}, tooBig...)
	if _, err := Deserialize(payload); err == nil {
		t.Error("expected error for out-of-range SM2 components")
	}
}

func TestConvertToEthCompatibleDoesNotMutateInput(t *testing.T) {
	pri, _, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.SECP256K1)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(SHA3_256withECDSA, pri, []byte("message"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Serialize(sig)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte{}, b...)

	if _, err := ConvertToEthCompatible(b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, original) {
		t.Error("ConvertToEthCompatible modified its input buffer")
	}

	// A compact signature header below 27 used to underflow when subtracting 27.
	bad := append([]byte{}, b...)
	bad[1] = 0x01
	if _, err := ConvertToEthCompatible(bad); err == nil {
		t.Error("expected an error for an out-of-range compact signature header")
	}
}
