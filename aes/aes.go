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

// Package aes provides legacy AES helpers kept for backward compatibility.
//
// AesEncrypt and AesDecrypt implement AES-CBC with PKCS#7 padding. CBC
// provides confidentiality only and does not authenticate the ciphertext, so a
// tampered message can decrypt to attacker-influenced plaintext and the
// padding check can be abused as a padding oracle. These functions exist only
// to read data produced by older releases.
//
// New formats must use an authenticated encryption mode such as AES-GCM (see
// keypair.EncryptWithCustomScrypt) instead of the raw CBC helpers here.
package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AesEncrypt encrypts plaintext with AES-CBC and PKCS#7 padding.
//
// The returned ciphertext is NOT authenticated. Do not use this function for
// new formats; use an AEAD instead.
func AesEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid key")
	}
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("invalid IV length")
	}
	plaintext = PKCS5Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// AesDecrypt decrypts an AES-CBC ciphertext produced by AesEncrypt.
//
// The ciphertext is not authenticated, so a successful return does not prove
// the data was not modified. Prefer an AEAD for new formats.
func AesDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid key")
	}

	blockSize := block.BlockSize()

	if len(iv) != blockSize {
		return nil, errors.New("invalid IV length")
	}

	if len(ciphertext) < blockSize {
		return nil, errors.New("ciphertext too short")
	}

	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	blockModel := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plaintext, ciphertext)
	return PKCS5UnPadding(plaintext, blockSize)
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(src, padtext...)
}

// PKCS5UnPadding validates and removes PKCS#7 padding from src. It rejects
// empty input, a padding length outside [1, blockSize], a length larger than
// the buffer and buffers whose length is not a multiple of the block size, and
// verifies that every padding byte carries the same value.
func PKCS5UnPadding(src []byte, blockSize int) ([]byte, error) {
	errInvalidPadding := errors.New("unpadding error: invalid padding")
	if blockSize <= 0 || len(src) == 0 || len(src)%blockSize != 0 {
		return nil, errInvalidPadding
	}
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding < 1 || unpadding > blockSize || unpadding > length {
		return nil, errInvalidPadding
	}

	// Compare every padding byte in constant time so the position of a
	// mismatch is not observable through timing.
	var diff byte
	for i := length - unpadding; i < length; i++ {
		diff |= src[i] ^ byte(unpadding)
	}
	if diff != 0 {
		return nil, errInvalidPadding
	}
	return src[:(length - unpadding)], nil
}
