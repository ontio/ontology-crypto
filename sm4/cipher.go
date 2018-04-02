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
	"strconv"
)

// The SM4 block size in bytes.
const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "ontology-crypto/sm4: invalid key size " + strconv.Itoa(int(k))
}

type sm4Cipher struct {
	roundkeys []uint32
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {		return nil, KeySizeError(len(key))	}
	c := new(sm4Cipher)
	c.roundkeys = make([]uint32,32,32)
	c.KeySchedule(key)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) { encryptBlock(&c.roundkeys, &dst, &src) }

func (c *sm4Cipher) Decrypt(dst, src []byte) { decryptBlock(&c.roundkeys, &dst, &src) }

func (c *sm4Cipher) KeySchedule(MK []uint8) {
	var tmp uint32
	var buf uint32
	var K [36] uint32
	var i int

	for i = 0; i < 4; i++ {
		K[i] = FK[i] ^ ( (uint32(MK[4*i])<<24) | (uint32(MK[4*i+1])<<16) | (uint32(MK[4*i+2])<<8) | (uint32(MK[4*i+3]) ) )
	}

	for i = 0 ; i < 32 ; i++ {
		tmp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]
		//nonlinear operation
		buf= uint32(Sbox[(tmp >> 24) & 0xFF]) << 24	| uint32(Sbox[(tmp >> 16) & 0xFF]) << 16| uint32(Sbox[(tmp >> 8) & 0xFF]) << 8 | uint32(Sbox[tmp & 0xFF])
		//linear operation
		K[i+4] = K[i] ^ ( (buf)^( SM4_Rotl32((buf),13) )^( SM4_Rotl32((buf),23) ) )
		c.roundkeys[i] = K[i+4]
	}
}