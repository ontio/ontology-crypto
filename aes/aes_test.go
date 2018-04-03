package aes

import (
	"bytes"
	"math/rand"
	"testing"
)

const datasize = 1 //MB
var key = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
//var plain = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
var iv = []uint8{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
//var ad = []uint8{0x00}

func TestCorrectness(t *testing.T) {
	N := datasize*1024*1024
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	c,_ := AesEncrypt(data,key,iv)
	p,_ := AesDecrypt(c,key,iv)

	if !bytes.Equal(data, p) {
		t.Fatalf("CBC mode has error! \n")
	}

}

func BenchmarkLoopsForCbcEnc(b *testing.B) {
	N := datasize*1024*1024
	b.SetBytes(int64(N))
	b.ReportAllocs()
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}
	b.ResetTimer()

	for i:=0 ; i<b.N ; i++ {
		AesEncrypt(data,key,iv)
	}
}

func BenchmarkLoopsForCbcDec(b *testing.B) {
	N := datasize*1024*1024
	b.SetBytes(int64(N))
	b.ReportAllocs()
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}
	c,_ := AesEncrypt(data,key,iv)

	b.ResetTimer()
	for i:=0 ; i<b.N ; i++ {
		AesDecrypt(c,key,iv)
	}
}
