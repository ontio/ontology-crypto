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

package aes

import (
	"bytes"
	"testing"
)

func TestUnpaddingDoesNotPanicOnEmptyInput(t *testing.T) {
	if _, err := PKCS5UnPadding(nil, 16); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := PKCS5UnPadding([]byte{}, 16); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestUnPaddingValidation(t *testing.T) {
	const blockSize = 16

	valid := append([]byte("hello"), bytes.Repeat([]byte{11}, 11)...)
	if out, err := PKCS5UnPadding(valid, blockSize); err != nil || string(out) != "hello" {
		t.Fatalf("valid padding rejected: out=%q err=%v", out, err)
	}

	// padding value 0
	if _, err := PKCS5UnPadding(make([]byte, blockSize), blockSize); err == nil {
		t.Error("expected error for zero padding length")
	}

	// padding value greater than the block size
	tooBig := make([]byte, blockSize)
	tooBig[blockSize-1] = blockSize + 1
	if _, err := PKCS5UnPadding(tooBig, blockSize); err == nil {
		t.Error("expected error for padding larger than block size")
	}

	// inconsistent padding bytes
	inconsistent := bytes.Repeat([]byte{3}, blockSize)
	inconsistent[blockSize-3] = 4
	if _, err := PKCS5UnPadding(inconsistent, blockSize); err == nil {
		t.Error("expected error for inconsistent padding bytes")
	}

	// length not a multiple of the block size
	if _, err := PKCS5UnPadding(make([]byte, blockSize-1), blockSize); err == nil {
		t.Error("expected error for non block-sized input")
	}

	// invalid block size
	if _, err := PKCS5UnPadding(make([]byte, blockSize), 0); err == nil {
		t.Error("expected error for invalid block size")
	}
}

func TestCBCRejectsWrongIVLength(t *testing.T) {
	key := make([]byte, 16)
	for _, ivLen := range []int{0, 15, 17} {
		iv := make([]byte, ivLen)
		if _, err := AesEncrypt([]byte("plaintext"), key, iv); err == nil {
			t.Errorf("AesEncrypt: expected error for %d-byte IV", ivLen)
		}
		if _, err := AesDecrypt(make([]byte, 16), key, iv); err == nil {
			t.Errorf("AesDecrypt: expected error for %d-byte IV", ivLen)
		}
	}
}

func TestAesRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)

	messages := [][]byte{
		nil,
		{},
		[]byte("a"),
		[]byte("exactly 16 bytes"),
		bytes.Repeat([]byte("y"), 17),
		bytes.Repeat([]byte("z"), 4096),
	}
	for i, msg := range messages {
		ct, err := AesEncrypt(msg, key, iv)
		if err != nil {
			t.Fatalf("case %d: encrypt: %v", i, err)
		}
		if len(ct) == 0 || len(ct)%16 != 0 {
			t.Fatalf("case %d: unexpected ciphertext length %d", i, len(ct))
		}
		pt, err := AesDecrypt(ct, key, iv)
		if err != nil {
			t.Fatalf("case %d: decrypt: %v", i, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Errorf("case %d: round trip mismatch: got %x want %x", i, pt, msg)
		}
	}
}

func TestAesRejectsBadParameters(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	// Invalid key length.
	if _, err := AesEncrypt([]byte("x"), make([]byte, 15), iv); err == nil {
		t.Error("expected error for a 15-byte key")
	}
	if _, err := AesDecrypt(make([]byte, 16), make([]byte, 15), iv); err == nil {
		t.Error("expected error for a 15-byte key")
	}

	// Ciphertext shorter than one block.
	if _, err := AesDecrypt(make([]byte, 8), key, iv); err == nil {
		t.Error("expected error for a short ciphertext")
	}

	// Ciphertext not a multiple of the block size.
	if _, err := AesDecrypt(make([]byte, 20), key, iv); err == nil {
		t.Error("expected error for a non block-sized ciphertext")
	}
}
