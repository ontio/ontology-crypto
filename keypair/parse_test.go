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
	"testing"

	"golang.org/x/crypto/ed25519"
)

// TestParsersDoNotPanicOnShortInput exercises the public parsers with inputs
// that previously triggered index-out-of-range panics.
func TestParsersDoNotPanicOnShortInput(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x00},
		{byte(PK_ECDSA)},
		{byte(PK_ECDSA), P256},
		{byte(PK_EDDSA)},
		{byte(PK_EDDSA), ED25519},
		{byte(PK_ETHECDSA)},
		{byte(PK_ETHECDSA), 0x01},
		{0xff, 0xff, 0xff},
		{byte(PK_P256_E), 0x02, 0x03},
	}

	for _, in := range inputs {
		in := in
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DeserializePublicKey(%x) panicked: %v", in, r)
				}
			}()
			if _, err := DeserializePublicKey(in); err == nil {
				t.Errorf("DeserializePublicKey(%x): expected error", in)
			}
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DeserializePrivateKey(%x) panicked: %v", in, r)
				}
			}()
			if _, err := DeserializePrivateKey(in); err == nil {
				t.Errorf("DeserializePrivateKey(%x): expected error", in)
			}
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("GetP256KeyPairFromWIF(%x) panicked: %v", in, r)
				}
			}()
			GetP256KeyPairFromWIF(in)
		}()
	}
}

func TestDeserializePrivateKeyUnknownAlgorithm(t *testing.T) {
	if _, err := DeserializePrivateKey([]byte{0xee, 0x01}); err == nil {
		t.Error("expected error for unknown algorithm label")
	}
}

func TestDeserializeEd25519PrivateKeyRequiresExactLength(t *testing.T) {
	pri, _, err := GenerateKeyPair(PK_EDDSA, ED25519)
	if err != nil {
		t.Fatal(err)
	}
	raw := SerializePrivateKey(pri)
	if _, err := DeserializePrivateKey(raw); err != nil {
		t.Fatalf("exact-length key rejected: %v", err)
	}

	// Trailing data must be rejected rather than silently included in the key.
	extended := append(append([]byte{}, raw...), 0x00)
	if _, err := DeserializePrivateKey(extended); err == nil {
		t.Error("expected error for Ed25519 private key with trailing data")
	}

	// Truncated data must be rejected too.
	if _, err := DeserializePrivateKey(raw[:len(raw)-1]); err == nil {
		t.Error("expected error for truncated Ed25519 private key")
	}
}

func TestDeserializeEd25519PrivateKeyIsCopied(t *testing.T) {
	pri, _, err := GenerateKeyPair(PK_EDDSA, ED25519)
	if err != nil {
		t.Fatal(err)
	}
	raw := SerializePrivateKey(pri)
	parsed, err := DeserializePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(ed25519.PrivateKey)
	original := append([]byte{}, key...)

	// Mutating the source buffer must not affect the parsed key.
	for i := 2; i < len(raw); i++ {
		raw[i] = 0xff
	}
	if string(key) != string(original) {
		t.Error("deserialized Ed25519 key aliases the input buffer")
	}
	if len(key) != ed25519.PrivateKeySize {
		t.Errorf("unexpected key size %d", len(key))
	}
}

// FuzzDeserializePublicKey asserts the parser never panics on arbitrary input.
func FuzzDeserializePublicKey(f *testing.F) {
	f.Add([]byte{byte(PK_P256_E), 0x01, 0x02})
	f.Add([]byte{byte(PK_EDDSA), ED25519})
	f.Add([]byte{byte(PK_ETHECDSA), 0x01, 0x02})
	f.Fuzz(func(t *testing.T, data []byte) {
		DeserializePublicKey(data)
	})
}

// FuzzDeserializePrivateKey asserts the parser never panics on arbitrary input.
func FuzzDeserializePrivateKey(f *testing.F) {
	f.Add([]byte{byte(PK_ECDSA), P256})
	f.Add([]byte{byte(PK_EDDSA), ED25519})
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		DeserializePrivateKey(data)
	})
}
