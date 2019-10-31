package test

import (
	"fmt"
	"io"
	"os"
	"testing"

	PDP "github.com/ontio/ontology-crypto/pdp"
)

func GenerateBlocks(path string) ([]PDP.Block, error) {
	fi, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer fi.Close()

	buf := make([]byte, 1024*64)
	chunks := make([]PDP.Block, 0)

	for {
		n, err := fi.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if 0 == n {
			break
		}

		chunks = append(chunks, PDP.Block{buf})
	}

	return chunks, nil
}

func TestRun(t *testing.T) {
	bigger := "./data/bigger_than_256k.txt"
	g, g0, pubKey, privKey, fileID := PDP.Init(bigger)
	pubKey = pubKey
	g = g
	blocks, _ := GenerateBlocks(bigger)
	challenge := []PDP.Challenge{{uint32(1), uint32(1)}}
	tag, _ := PDP.SignGenerate(blocks[0].Buffer, fileID, challenge[0].Index, g0, privKey)
	multiRes, addRes := PDP.ProofGenerate(challenge, []PDP.Element{{tag}}, blocks)
	res := PDP.Verify(g, g0, pubKey, multiRes, addRes, fileID, challenge)
	fmt.Println("result: ", res)
}

func TestProofGenerate(t *testing.T) {
	bigger := "./data/bigger_than_256k.txt"
	g, g0, pubKey, privKey, fileID := PDP.Init(bigger)
	pubKey = pubKey
	g = g
	blocknum := 32
	blocks, _ := GenerateBlocks(bigger)
	challenge := []PDP.Challenge{{uint32(1), uint32(1)}}
	tag, _ := PDP.SignGenerate(blocks[0].Buffer, fileID, challenge[0].Index, g0, privKey)
	for i := 0; i < blocknum; i++ {
		PDP.ProofGenerate(challenge, []PDP.Element{{tag}}, blocks)
	}
}

func TestVerify(t *testing.T) {
	bigger := "./data/bigger_than_256k.txt"
	g, g0, pubKey, privKey, fileID := PDP.Init(bigger)
	pubKey = pubKey
	g = g
	blocknum := 32
	blocks, _ := GenerateBlocks(bigger)
	challenge := []PDP.Challenge{{uint32(1), uint32(1)}}
	tag, _ := PDP.SignGenerate(blocks[0].Buffer, fileID, challenge[0].Index, g0, privKey)

	fmt.Printf("%v\n", tag)


	multiRes, addRes := PDP.ProofGenerate(challenge, []PDP.Element{{tag}}, blocks)
	fmt.Printf("%v\n", multiRes)
	fmt.Printf("%s\n", addRes)
	for i := 0; i < blocknum; i++ {
		_ = PDP.Verify(g, g0, pubKey, multiRes, addRes, fileID, challenge)
	}
}
