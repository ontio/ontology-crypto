package padding

import (
	"bytes"
	//"bytes"
	//"errors"
	"math/rand"
	"testing"
)

const MB = 8
const MAX = 1024*1024*1024
const blocksize = 16

func TestPKCS5Padding(t *testing.T) {
	N := rand.Int()*rand.Int()*rand.Int()%MAX

	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	pad := PKCS5Padding(data, blocksize)

	if len(pad)!=(len(data)/16+1)*16 {
		t.Fatalf("length not matched\n")
	}

	ori,_ := PKCS5UnPadding(pad)
	if !bytes.Equal(ori,data) {
		t.Fatalf("unpadding result not matched\n")
	}
}

func Benchmark_PKCS5Padding(b *testing.B) {
	N := MB*1024*1024
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	b.SetBytes(int64(N))
	b.ResetTimer()
	b.ReportAllocs()
	for i:=0; i<b.N; i++ {
		PKCS5Padding(data, blocksize)
	}
}
func BenchmarkPKCS5UnPadding(b *testing.B) {
	N := MB*1024*1024
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}
	p := PKCS5Padding(data, blocksize)

	b.SetBytes(int64(N))
	b.ResetTimer()
	b.ReportAllocs()
	for i:=0; i<b.N; i++ {
		PKCS5UnPadding(p)
	}
}
