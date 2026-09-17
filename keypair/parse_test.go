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

import "testing"

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
