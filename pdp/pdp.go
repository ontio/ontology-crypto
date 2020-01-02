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
	"crypto/sha256"
	"math/big"

	"github.com/ontio/ontology-crypto/pdp/pdpV2"
)

type Pdp struct {}

//GenChallenge compute the index to choose block
func (p *Pdp) GenChallenge(nodeId [20]byte, blockHash []byte, fileBlockNum uint64) uint64 {
	blockNum := big.NewInt(int64(fileBlockNum))

	plant := append(nodeId[:], blockHash...)
	hash := sha256.Sum256(plant)

	bigTmp := new(big.Int).SetBytes(hash[:])
	return bigTmp.Mod(bigTmp, blockNum).Uint64()
}

//BlockHash compute the block hash
func (p *Pdp) FileBlockHash(fileBlock []byte) []byte {
	return pdpV2.BlkHash(fileBlock)
}

//BuildProof need parameters
func (p *Pdp) GenProof(fileBlockData []byte, nonce [32]byte, pdpParamBuf []byte) []byte {
	return pdpV2.BuildProof(fileBlockData, nonce[:], pdpParamBuf)
}

//VerifyProof used in consensus algorithm
func (p *Pdp) VerifyProof(vk []byte, proof []byte, nonce []byte, blockPdpHash []byte) bool {
	return pdpV2.ValidateProof(vk, proof, nonce, blockPdpHash)
}

//FilePdpHash compute the file FilePdpHashSt
func (p *Pdp) FilePdpHash(fileBlocksData [][]byte) *FilePdpHashSt {
	var filePdpHashSt FilePdpHashSt
	for i := 0; i < len(fileBlocksData); i++ {
		pdpV2.BlkHash(fileBlocksData[i])
		filePdpHashSt.BlockPdpHashes = append(filePdpHashSt.BlockPdpHashes, )
	}
	return &filePdpHashSt
}
