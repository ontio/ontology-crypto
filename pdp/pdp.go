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

type Pdp struct {
	Version uint64
}

func NewPdp(version uint64) *Pdp {
	return &Pdp{Version:version}
}

//FilePdpHash compute the file FilePdpHashSt
func (p *Pdp) FilePdpHash(fileBlocksData [][]byte) *FilePdpHashSt {
	var filePdpHashSt FilePdpHashSt
	filePdpHashSt.Version = p.Version
	for i := 0; i < len(fileBlocksData); i++ {
		blockHash := pdpV2.BlkHash(fileBlocksData[i])
		filePdpHashSt.BlockPdpHashes = append(filePdpHashSt.BlockPdpHashes, blockHash)
	}
	return &filePdpHashSt
}

//GenChallenge compute the index to choose block
func (p *Pdp) GenChallenge(nodeId [20]byte, blockHash []byte, fileBlockNum uint64) []uint64 {
	blockNum := big.NewInt(int64(fileBlockNum))

	plant := append(nodeId[:], blockHash...)
	hash := sha256.Sum256(plant)

	bigTmp := new(big.Int).SetBytes(hash[:])
	challenge := bigTmp.Mod(bigTmp, blockNum).Uint64()
	return []uint64{challenge}
}

//BuildProof need parameters
func (p *Pdp) GenProofWithPerBlock(fileBlockData []byte, nonce []byte, pdpParamBuf []byte) []byte {
	return pdpV2.BuildProof(fileBlockData, nonce[:], pdpParamBuf)
}

//VerifyProof used in consensus algorithm
func (p *Pdp) VerifyProofWithPerBlock(vk []byte, proof []byte, nonce []byte, blockPdpHash []byte) bool {
	return pdpV2.ValidateProof(vk, proof, nonce, blockPdpHash)
}
