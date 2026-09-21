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
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ontio/ontology-crypto/sm3"
)

func TestSignRejectsOverlongUserID(t *testing.T) {
	priv, err := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// ENTL can only encode up to 8191 bytes of user ID.
	if _, _, err := Sign(rand.Reader, priv, strings.Repeat("a", 8192), []byte("msg"), sm3.New()); err == nil {
		t.Error("expected an error for an overlong user ID")
	}

	if _, _, err := Sign(rand.Reader, priv, strings.Repeat("a", 8191), []byte("msg"), sm3.New()); err != nil {
		t.Errorf("8191-byte user ID should be accepted: %v", err)
	}
}

// FuzzDecrypt asserts that decrypting arbitrary bytes never panics.
func FuzzDecrypt(f *testing.F) {
	priv, err := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(make([]byte, 96))
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		Decrypt(priv, data)
	})
}

func TestEncryptRejectsEmptyMessage(t *testing.T) {
	priv, err := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := Encrypt(&priv.PublicKey, nil); err == nil {
			t.Error("expected an explicit error for an empty message")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Encrypt hung on an empty message")
	}
}

func TestSm3KdfDerivesRequestedLength(t *testing.T) {
	for _, n := range []int{1, 31, 32, 33, 64, 200} {
		out, ret := sm3kdf([]byte("seed"), n)
		if ret != n || len(out) != n {
			t.Errorf("kLen=%d: got len(out)=%d ret=%d", n, len(out), ret)
		}
	}
	if out, ret := sm3kdf([]byte("seed"), 0); ret != 0 || out != nil {
		t.Errorf("zero length request: expected (nil, 0), got (%x, %d)", out, ret)
	}
}

func TestDecryptRejectsShortCiphertext(t *testing.T) {
	priv, err := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 31, 32, 63, 64, 95} {
		if _, err := Decrypt(priv, make([]byte, n)); err == nil {
			t.Errorf("expected error for %d-byte ciphertext", n)
		}
	}
	if _, err := Decrypt(nil, make([]byte, 96)); err == nil {
		t.Error("expected error for nil private key")
	}
}

func TestDecryptTamperedCiphertextReturnsNoPlaintext(t *testing.T) {
	priv, err := ecdsa.GenerateKey(SM2P256V1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("authenticated message")
	ct, err := Encrypt(&priv.PublicKey, msg)
	if err != nil {
		t.Fatal("encrypt:", err)
	}
	if pt, err := Decrypt(priv, ct); err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("round trip failed: pt=%x err=%v", pt, err)
	}

	// Tampering with C3 (the authentication tag) must not yield plaintext.
	tamperedC3 := append([]byte{}, ct...)
	tamperedC3[64] ^= 0xff
	if pt, err := Decrypt(priv, tamperedC3); err == nil || pt != nil {
		t.Errorf("tampered C3: expected nil plaintext and error, got pt=%x err=%v", pt, err)
	}

	// Tampering with C2 must also fail authentication and return nil.
	tamperedC2 := append([]byte{}, ct...)
	tamperedC2[len(tamperedC2)-1] ^= 0xff
	if pt, err := Decrypt(priv, tamperedC2); err == nil || pt != nil {
		t.Errorf("tampered C2: expected nil plaintext and error, got pt=%x err=%v", pt, err)
	}
}

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
