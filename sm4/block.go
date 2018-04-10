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

// creates subkeys 32 32-bit from the original key
func (c *sm4Cipher) generateSubkeys(keyBytes []byte) {
	var key = make([]uint32, 4)
	var k = make([]uint32, 4)
	key[0] = (uint32(keyBytes[0]) << 24) | (uint32(keyBytes[1]) << 16) | (uint32(keyBytes[2]) << 8) | (uint32(keyBytes[3]))
	key[1] = (uint32(keyBytes[4]) << 24) | (uint32(keyBytes[5]) << 16) | (uint32(keyBytes[6]) << 8) | (uint32(keyBytes[7]))
	key[2] = (uint32(keyBytes[8]) << 24) | (uint32(keyBytes[9]) << 16) | (uint32(keyBytes[10]) << 8) | (uint32(keyBytes[11]))
	key[3] = (uint32(keyBytes[12]) << 24) | (uint32(keyBytes[13]) << 16) | (uint32(keyBytes[14]) << 8) | (uint32(keyBytes[15]))

	k[0] = key[0] ^ sm4_fk[0]
	k[1] = key[1] ^ sm4_fk[1]
	k[2] = key[2] ^ sm4_fk[2]
	k[3] = key[3] ^ sm4_fk[3]

	for i := 0; i < 32; i++ {
		c.subkeys[i] = k[0] ^ sm4_kt(k[1]^k[2]^k[3]^sm4_ck[i])
		k[0] = k[1]
		k[1] = k[2]
		k[2] = k[3]
		k[3] = c.subkeys[i]
	}
}

func encryptBlock(subkeys []uint32, dst, src []byte) {
	cryptBlock(subkeys, dst, src, false)
}
func decryptBlock(subkeys []uint32, dst, src []byte) {
	cryptBlock(subkeys, dst, src, true)
}

func cryptBlock(subkeys []uint32, dst, src []byte, decrypt bool) {
	var m = make([]uint32, 4)
	var o = make([]uint32, 4)
	m[0] = (uint32(src[0]) << 24) | (uint32(src[1]) << 16) | (uint32(src[2]) << 8) | (uint32(src[3]))
	m[1] = (uint32(src[4]) << 24) | (uint32(src[5]) << 16) | (uint32(src[6]) << 8) | (uint32(src[7]))
	m[2] = (uint32(src[8]) << 24) | (uint32(src[9]) << 16) | (uint32(src[10]) << 8) | (uint32(src[11]))
	m[3] = (uint32(src[12]) << 24) | (uint32(src[13]) << 16) | (uint32(src[14]) << 8) | (uint32(src[15]))

	if decrypt {
		for j := 32; j > 0; j-- {
			tmp := sm4_f(m[0], m[1], m[2], m[3], subkeys[j-1])
			m[0] = m[1]
			m[1] = m[2]
			m[2] = m[3]
			m[3] = tmp
		}
	} else {
		for j := 0; j < 32; j++ {
			tmp := sm4_f(m[0], m[1], m[2], m[3], subkeys[j])
			m[0] = m[1]
			m[1] = m[2]
			m[2] = m[3]
			m[3] = tmp
		}
	}

	sm4_r(o, m)

	for j := 0; j < 4; j++ {
		dst[j*4] = uint8((o[j] >> 24))
		dst[j*4+1] = uint8((o[j] >> 16))
		dst[j*4+2] = uint8((o[j] >> 8))
		dst[j*4+3] = uint8((o[j]))
	}
}

func sm4_rotl(x uint32, i uint8) uint32 {
	return (x << (i % 32)) | (x >> (32 - (i % 32)))
}

func sm4_tao(a uint32) uint32 {
	return sm4_sbox[uint8(a)] | (sm4_sbox[uint8(a>>8)] << 8) | (sm4_sbox[uint8(a>>16)] << 16) | (sm4_sbox[uint8(a>>24)] << 24)
}

func sm4_l(b uint32) uint32 {
	return b ^ sm4_rotl(b, 2) ^ sm4_rotl(b, 10) ^ sm4_rotl(b, 18) ^ sm4_rotl(b, 24)
}

func sm4_t(x uint32) uint32 {
	return sm4_l(sm4_tao(x))
}

func sm4_f(x0, x1, x2, x3, rk uint32) uint32 {
	return x0 ^ sm4_t(x1^x2^x3^rk)
}

func sm4_r(o, i []uint32) {
	o[0] = i[3]
	o[1] = i[2]
	o[2] = i[1]
	o[3] = i[0]
}

func sm4_kl(b uint32) uint32 {
	return b ^ sm4_rotl(b, 13) ^ sm4_rotl(b, 23)
}

func sm4_kt(x uint32) uint32 {
	return sm4_kl(sm4_tao(x))
}
