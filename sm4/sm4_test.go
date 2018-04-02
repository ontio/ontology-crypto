package sm4

import (
	"bytes"
	"math/rand"
	"testing"
)

//type sm4Test struct {
//	desc string
//	key []byte
//	iv []byte
//	plaintext []byte
//	ciphertext []byte
//
//}
const datasize = 1 //MB
var key = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
var plain = []uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}
var iv = []uint8{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
var ad = []uint8{ }

func TestCorrectness(t *testing.T) {
	N := datasize*1024*1024
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	c := Sm4Encrypt_CBC(data,key,iv)
	p := Sm4Decrypt_CBC(c,key,iv)

	if !bytes.Equal(data, p) {
		t.Fatalf("CBC mode has error! \n")
	}

	cc := Sm4Encrypt_GCM(data,key,iv,ad)
	pp := Sm4Decrypt_GCM(cc,key,iv,ad)

	if !bytes.Equal(data, pp) {
		t.Fatalf("GCM mode has error! \n")
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
		Sm4Encrypt_CBC(data,key,iv)
	}
}

func BenchmarkLoopsForCbcDec(b *testing.B) {
	N := datasize*1024*1024
	b.SetBytes(int64(N))
	b.ReportAllocs()
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}
	c := Sm4Encrypt_CBC(data,key,iv)

	b.ResetTimer()
	for i:=0 ; i<b.N ; i++ {
		Sm4Decrypt_CBC(c,key,iv)
	}
}

func BenchmarkLoopsForGcmEnc(b *testing.B) {
	N := datasize*1024*1024
	b.SetBytes(int64(N))
	b.ReportAllocs()
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	b.ResetTimer()
	for i:=0 ; i<b.N ; i++ {
		Sm4Encrypt_GCM(data,key,iv, ad)
	}
}

func BenchmarkLoopsForGcmDec(b *testing.B) {
	N := datasize*1024*1024
	b.SetBytes(int64(N))
	b.ReportAllocs()
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}
	c := Sm4Encrypt_GCM(data,key,iv, ad)

	b.ResetTimer()
	for i:=0 ; i<b.N ; i++ {
		Sm4Decrypt_GCM(c,key,iv, ad)
	}
}

