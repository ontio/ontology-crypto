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
	//"encoding/binary"
)

func cryptBlock(rk *[]uint32, dst, src *[]byte, decrypt bool) {
	X := make([]uint32, 36)
	for j:=0 ; j<4 ; j++ {
		X[j]=(uint32((*src)[j*4])<<24) | (uint32((*src)[j*4+1])<<16) | (uint32((*src)[j*4+2])<<8) | uint32((*src)[j*4+3])
	}
	var tmp uint32
	for i:=0;i<32;i++ {
		if decrypt {
			tmp = X[i+1]^X[i+2]^X[i+3]^(*rk)[31-i]
		}else{
			tmp = X[i+1]^X[i+2]^X[i+3]^(*rk)[i]
		}

		/* operation τ */
		buf := Sbox[(tmp >> 24) & 0xFF] << 24 | Sbox[(tmp >> 16) & 0xFF] << 16| Sbox[(tmp >> 8) & 0xFF] << 8 | Sbox[tmp & 0xFF]
		/* operation L */
		X[i+4]=X[i]^(buf^SM4_Rotl32((buf),2)^ SM4_Rotl32((buf),10) ^ SM4_Rotl32((buf),18)^ SM4_Rotl32((buf),24))
	}
	for j:=0;j<4;j++ {
		(*dst)[4*j] = uint8((X[35-j])>> 24)
		(*dst)[4*j+1] = uint8((X[35-j])>> 16)
		(*dst)[4*j+2] = uint8((X[35-j])>> 8)
		(*dst)[4*j+3] = uint8((X[35-j]))
	}
}

func encryptBlock(rk *[]uint32, dst, src *[]byte) {
	cryptBlock(rk, dst, src, false)
}

func decryptBlock(rk *[]uint32, dst, src *[]byte) {
	cryptBlock(rk, dst, src, true)
}

func SM4_Rotl32(buf uint32, n uint32) uint32{
	return (buf<<n) | (buf>>(32-n))
}