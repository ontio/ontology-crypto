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

package sm4

import (
	"crypto/cipher"
)

func Sm4Encrypt_CBC(plain []byte,key []byte, iv []byte) ([]byte){
	c, _ := NewCipher(key)

	encrypter := cipher.NewCBCEncrypter(c, iv)
	padding := PKCS5Padding(plain,16)

	Message := make([]byte, len(padding))
	encrypter.CryptBlocks(Message, padding)

	return Message
}
func Sm4Decrypt_CBC(ciphertext []byte, key []byte, iv []byte) ([]byte) {
	c, _ := NewCipher(key)

	P := make([]byte, len(ciphertext))
	decrypter := cipher.NewCBCDecrypter(c, iv)

	decrypter.CryptBlocks(P, ciphertext)
	P = PKCS5UnPadding(P)

	return P
}

func Sm4Encrypt_GCM(plain []byte,key []byte, nonce []byte, ad []byte) ([]byte){
	sm4, _ := NewCipher(key)
	sm4gcm, _ := cipher.NewGCMWithNonceSize(sm4, len(nonce))

	padding := PKCS5Padding(plain,16)
	Message := sm4gcm.Seal(nil, nonce, padding, ad)

	return Message
}
func Sm4Decrypt_GCM(Message []byte, key []byte, nonce []byte,ad []byte) ([]byte) {
	sm4, _ := NewCipher(key)
	sm4gcm, _ := cipher.NewGCMWithNonceSize(sm4, len(nonce))

	padding, _ := sm4gcm.Open(nil, nonce, Message, ad)
	plain := PKCS5UnPadding(padding)

	return plain
}
