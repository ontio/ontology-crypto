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

package pdpV2

//#cgo darwin LDFLAGS: -L"./libsnark/mac/" -lsnarkpdp -ldl
//#cgo linux LDFLAGS: -L"./libsnark/linux/" -lsnarkpdp -ldl
//#include <stdint.h>
//extern void create_new_parameters();
//extern void create_block_hash(unsigned char*,unsigned char*);
//extern void print_hash(unsigned char*);
//extern void build_proof(unsigned char*,unsigned int,unsigned char*,unsigned char*,unsigned char*);
//extern int validate_proof(unsigned char*,unsigned int,unsigned char*,unsigned char*,unsigned char*);
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	HASH_LEN  = 32
	BLOCK_LEN = 16 * 1024
	PROOF_LEN = 192
)

func toC(buf []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&buf[0]))
}

func CreateParameters() {
	C.create_new_parameters()
}

//BlkHash compute the block hash
func BlkHash(blk []byte) []byte {
	hash := make([]byte, HASH_LEN, HASH_LEN)
	C.create_block_hash(toC(blk), toC(hash))
	return hash
}
func PrintHash(hash []byte) {
	fmt.Println("blk array:", hash)
	C.print_hash(toC(hash))
}

//BuildProof need parameters
func BuildProof(blk, nonce []byte, pdpParamBuf []byte) []byte {
	proof := make([]byte, PROOF_LEN, PROOF_LEN)
	C.build_proof(toC(pdpParamBuf), C.uint(len(pdpParamBuf)), toC(blk), toC(nonce), toC(proof))
	return proof
}

//ValidateProof used in consensus algorithm
func ValidateProof(vkBuf, proofBuf, nonce, hash []byte) bool {
	if C.validate_proof(toC(vkBuf), C.uint(len(vkBuf)), toC(proofBuf), toC(nonce), toC(hash)) == 1 {
		return true
	} else {
		return false
	}
}
