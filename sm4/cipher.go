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

/*
 * Package sm4 implements the Chinese SM4 Digest Algorithm,
 * according to "go/src/crypto/aes"
 * author: weizhang <d5c5ceb0@gmail.com>
 * 2017.02.24
 */

package sm4

import (
	"crypto/cipher"
	"strconv"
)

// The SM4 block size in bytes.
const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "sm4: invalid key size " + strconv.Itoa(int(k))
}

// sm4Cipher is an instance of SM4 encryption.
type sm4Cipher struct {
	subkeys [32]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, KeySizeError(len(key))
	}

	c := new(sm4Cipher)
	c.generateSubkeys(key)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) { encryptBlock(c.subkeys[:], dst, src) }

func (c *sm4Cipher) Decrypt(dst, src []byte) { decryptBlock(c.subkeys[:], dst, src) }
