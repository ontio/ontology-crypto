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

package ec

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestDecodePublicKeyRoundTrip(t *testing.T) {
	curve := elliptic.P256()
	pri, pub, err := GenerateECKeyPair(curve, rand.Reader, ECDSA)
	if err != nil {
		t.Fatal("generate key pair:", err)
	}
	_ = pri

	for _, compressed := range []bool{true, false} {
		data := EncodePublicKey(pub.PublicKey, compressed)
		decoded, err := DecodePublicKey(data, curve)
		if err != nil {
			t.Fatalf("compressed=%v: decode failed: %v", compressed, err)
		}
		if decoded.X.Cmp(pub.X) != 0 || decoded.Y.Cmp(pub.Y) != 0 {
			t.Fatalf("compressed=%v: decoded point mismatch", compressed)
		}
	}
}

func TestDecodePublicKeyRejectsInvalidPoints(t *testing.T) {
	curve := elliptic.P256()
	params := curve.Params()
	length := (params.BitSize + 7) >> 3

	_, pub, err := GenerateECKeyPair(curve, rand.Reader, ECDSA)
	if err != nil {
		t.Fatal("generate key pair:", err)
	}
	valid := EncodePublicKey(pub.PublicKey, false)

	// A valid point with a trailing byte must be rejected.
	withTrailing := append(append([]byte{}, valid...), 0x00)
	if _, err := DecodePublicKey(withTrailing, curve); err == nil {
		t.Error("expected error for trailing data")
	}

	// (x, y) = (0, 0) is the infinity marker and is not a valid public key.
	infinity := make([]byte, length*2+1)
	infinity[0] = nocompress
	if _, err := DecodePublicKey(infinity, curve); err == nil {
		t.Error("expected error for point at infinity")
	}

	// Coordinate equal to the field prime is out of range.
	outOfRange := make([]byte, length*2+1)
	outOfRange[0] = nocompress
	pBytes := params.P.Bytes()
	copy(outOfRange[1:], pBytes)
	copy(outOfRange[1+length:], pBytes)
	if _, err := DecodePublicKey(outOfRange, curve); err == nil {
		t.Error("expected error for out of range coordinate")
	}

	// A point that does not satisfy the curve equation must be rejected.
	offCurve := make([]byte, length*2+1)
	offCurve[0] = nocompress
	copy(offCurve[1:], pub.X.Bytes())
	veryBad := new(big.Int).Add(pub.Y, big.NewInt(1))
	veryBad.Mod(veryBad, params.P)
	copy(offCurve[1+length:], veryBad.Bytes())
	if curve.IsOnCurve(pub.X, veryBad) {
		t.Skip("unexpected on-curve neighbour, cannot test off-curve rejection")
	}
	if _, err := DecodePublicKey(offCurve, curve); err == nil {
		t.Error("expected error for point not on curve")
	}
}

func TestDecodePublicKeyRejectsWrongLength(t *testing.T) {
	curve := elliptic.P256()
	_, pub, err := GenerateECKeyPair(curve, rand.Reader, ECDSA)
	if err != nil {
		t.Fatal("generate key pair:", err)
	}

	compressed := EncodePublicKey(pub.PublicKey, true)
	if _, err := DecodePublicKey(compressed[:len(compressed)-1], curve); err == nil {
		t.Error("expected error for short compressed key")
	}

	uncompressed := EncodePublicKey(pub.PublicKey, false)
	if _, err := DecodePublicKey(uncompressed[:len(uncompressed)-1], curve); err == nil {
		t.Error("expected error for short uncompressed key")
	}

	if _, err := DecodePublicKey(nil, curve); err == nil {
		t.Error("expected error for nil input")
	}
}
