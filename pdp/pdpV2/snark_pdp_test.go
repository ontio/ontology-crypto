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

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"testing"
	"time"
)

func TestCreateParameters(t *testing.T) {
	fmt.Println("start create parameter test")
	CreateParameters()
}
func TestBlkHash(t *testing.T) {
	fmt.Println("start calc block hash test")
	buf, err := ioutil.ReadFile("block")
	if err != nil {
		t.Fatal("write block file error", err)
	}
	hash := BlkHash(buf)
	PrintHash(hash)
}
func TestProofBuild(t *testing.T) {
	fmt.Println("start build proof test")
	buf, err := ioutil.ReadFile("block")
	if err != nil {
		t.Fatal("read block file error", err)
	}
	nonceBuf, err := ioutil.ReadFile("nonce")
	if err != nil {
		t.Fatal("read nonce file error", err)
	}
	paramBuf, err := ioutil.ReadFile("parameters")
	if err != nil {
		t.Fatal("read parameters file error", err)
	}
	proof := BuildProof(buf, nonceBuf, paramBuf)
	t.Logf("output proof array: %x", proof)
}

func TestBuildProofAndVerification(t *testing.T) {
	fmt.Println("start build & verify test")
	buf, err := ioutil.ReadFile("block")
	if err != nil {
		t.Fatal("read block file error", err)
	}
	hash := BlkHash(buf)
	nonceBuf, err := ioutil.ReadFile("nonce")
	if err != nil {
		t.Fatal("read nonce file error", err)
	}
	paramBuf, err := ioutil.ReadFile("parameters")
	if err != nil {
		t.Fatal("read parameters file error", err)
	}

	proof := BuildProof(buf, nonceBuf, paramBuf)
	fmt.Printf("output proof array: %x\n", proof)
	vk, err := ioutil.ReadFile("verifying-key")
	if err != nil {
		t.Fatal("read vk file error", err)
	}

	ret := ValidateProof(vk, proof, nonceBuf, hash)
	if !ret {
		t.Fail()
	}
}

func TestBuildProofAndVerifyModifyBlock(t *testing.T) {
	fmt.Println("start build & modify & verify test")
	buf, err := ioutil.ReadFile("block")
	if err != nil {
		t.Fatal("read block file error", err)
	}

	hash := BlkHash(buf)

	nonceBuf, err := ioutil.ReadFile("nonce")
	if err != nil {
		t.Fatal("read nonce file error", err)
	}
	paramBuf, err := ioutil.ReadFile("parameters")
	if err != nil {
		t.Fatal("read parameters file error", err)
	}
	proof := BuildProof(buf, nonceBuf, paramBuf)
	fmt.Printf("proof before modify: %x\n", proof)

	//modify the random byte in block
	rand.NewSource(time.Now().Unix())
	buf[rand.Intn(BLOCK_LEN)] = buf[rand.Intn(BLOCK_LEN)] ^ 0xFF


	proof = BuildProof(buf, nonceBuf, paramBuf)
	fmt.Printf("proof after modify: %x\n", proof)

	vk, err := ioutil.ReadFile("verifying-key")
	if err != nil {
		t.Fatal("read vk file error", err)
	}

	ret := ValidateProof(vk, proof, nonceBuf, hash)
	if ret {
		t.Fail()
	}
}
func BenchmarkBuildProofAndVerification(b *testing.B) {
	fmt.Println("start build & verify benchmark test")
	buf, err := ioutil.ReadFile("block")
	if err != nil {
		b.Fatal("read block file error", err)
	}
	hash := BlkHash(buf)
	nonceBuf, err := ioutil.ReadFile("nonce")
	if err != nil {
		b.Fatal("read nonce file error", err)
	}
	vk, err := ioutil.ReadFile("verifying-key")
	if err != nil {
		b.Fatal("read vk file error", err)
	}
	paramBuf, err := ioutil.ReadFile("parameters")
	if err != nil {
		b.Fatal("read parameters file error", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof := BuildProof(buf, nonceBuf, paramBuf)
		ret := ValidateProof(vk, proof, nonceBuf, hash)
		if !ret {
			b.Fail()
		}
	}

}
