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

package pdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type BlockPdpHash []byte

type FilePdpHashSt struct {
	Version        uint64
	BlockPdpHashes []BlockPdpHash
}

func (this *FilePdpHashSt) Serialize() []byte {
	buf := new(bytes.Buffer)

	uint64Tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(uint64Tmp, this.Version)
	buf.Write(uint64Tmp)

	blockHashCount := uint64(len(this.BlockPdpHashes))
	binary.LittleEndian.PutUint64(uint64Tmp, blockHashCount)
	buf.Write(uint64Tmp)

	if 0 == blockHashCount {
		return buf.Bytes()
	}

	for i := uint64(0); i < blockHashCount; i++ {
		blockHashLength := uint64(len(this.BlockPdpHashes[i]))
		binary.LittleEndian.PutUint64(uint64Tmp, blockHashLength)
		buf.Write(uint64Tmp)
		buf.Write(this.BlockPdpHashes[i])
	}
	return buf.Bytes()
}

func (this *FilePdpHashSt) Deserialize(src []byte) error {
	iv := uint64(0)
	srcLength := uint64(len(src))
	if srcLength -iv < 16 {
		return fmt.Errorf("FilePdpHashSt Deserialize length error")
	}
	this.Version = binary.LittleEndian.Uint64(src[: iv + 8])
	iv += 8

	blockHashCount := binary.LittleEndian.Uint64(src[iv: iv + 8])
	if 0 == blockHashCount {
		return nil
	}
	iv += 8

	for i := uint64(0); i < blockHashCount; i++ {
		if srcLength -iv < 8 {
			return fmt.Errorf("FilePdpHashSt Deserialize length error")
		}
		blockHashLength := binary.LittleEndian.Uint64(src[iv: iv+8])
		iv += 8


		if srcLength -iv < blockHashLength {
			return fmt.Errorf("FilePdpHashSt Deserialize length error")
		}
		hashTmp := make([]byte, blockHashLength)
		copy(hashTmp[:], src[iv: iv + blockHashLength])
		this.BlockPdpHashes = append(this.BlockPdpHashes, hashTmp)
		iv += blockHashLength
	}

	return nil
}

