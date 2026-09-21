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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
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

func TestConstructPrivateKeyValidatesScalar(t *testing.T) {
	curve := elliptic.P256()
	n := curve.Params().N

	if _, err := ConstructPrivateKey(big.NewInt(1).Bytes(), curve); err != nil {
		t.Errorf("D=1 must be accepted: %v", err)
	}
	if _, err := ConstructPrivateKey(new(big.Int).Sub(n, big.NewInt(1)).Bytes(), curve); err != nil {
		t.Errorf("D=N-1 must be accepted: %v", err)
	}

	invalid := map[string][]byte{
		"D=0":   {},
		"D=0b":  big.NewInt(0).Bytes(),
		"D=N":   n.Bytes(),
		"D=N+1": new(big.Int).Add(n, big.NewInt(1)).Bytes(),
	}
	for name, data := range invalid {
		if _, err := ConstructPrivateKey(data, curve); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}

	if _, err := ConstructPrivateKey(big.NewInt(1).Bytes(), nil); err == nil {
		t.Error("nil curve must be rejected")
	}
}

// TestEncodePublicKeyStandardVector checks the SEC1 encoding of the P-256
// generator point against its well-known hex representation.
func TestEncodePublicKeyStandardVector(t *testing.T) {
	curve := elliptic.P256()
	params := curve.Params()
	const gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	const gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

	pub := &ecdsa.PublicKey{X: params.Gx, Y: params.Gy, Curve: curve}

	wantUncompressed, _ := hex.DecodeString("04" + gx + gy)
	if got := EncodePublicKey(pub, false); !bytes.Equal(got, wantUncompressed) {
		t.Errorf("uncompressed encoding mismatch:\n got=%x\nwant=%x", got, wantUncompressed)
	}

	// Gy is odd, so the compressed prefix must be 0x03.
	wantCompressed, _ := hex.DecodeString("03" + gx)
	if got := EncodePublicKey(pub, true); !bytes.Equal(got, wantCompressed) {
		t.Errorf("compressed encoding mismatch:\n got=%x\nwant=%x", got, wantCompressed)
	}

	for _, data := range [][]byte{wantUncompressed, wantCompressed} {
		decoded, err := DecodePublicKey(data, curve)
		if err != nil {
			t.Fatalf("decode %x: %v", data[0], err)
		}
		if decoded.X.Cmp(params.Gx) != 0 || decoded.Y.Cmp(params.Gy) != 0 {
			t.Errorf("decoded generator mismatch for prefix %x", data[0])
		}
	}
}

func TestDecodePublicKeyRejectsUnknownEncodingMode(t *testing.T) {
	curve := elliptic.P256()
	length := (curve.Params().BitSize + 7) >> 3
	bad := make([]byte, length*2+1)
	bad[0] = 0x05
	if _, err := DecodePublicKey(bad, curve); err == nil {
		t.Error("expected error for unknown encoding mode")
	}
}
