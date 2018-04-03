package aes

import (
	"bytes"
	"math/rand"
	"testing"
)

type keySize struct{
	size uint8
	key []uint8
}

var keys = map[string]keySize{
	"0":{0,nil},
	"1":{1,[]uint8{0x01}},
	"15":{15,[]uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32}},
	"16":{16,[]uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}},
	"24":{24,[]uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}},
	"32":{32,[]uint8{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}},
	"33":{33,[]uint8{0x01,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}},
}

const B = 1 //KB
const KB = 1024 //KB
const MB = 1024*1024 //MB
var iv = []uint8{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func TestKeysize(t *testing.T) {
	N := 1*MB
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	for k,v := range keys  {
		c,err := AesEncrypt(data,v.key,iv)
		if err!=nil {
			t.Errorf("encrypt has error! keysize is %v byte, err_info:%v \n",k, err)
		}

		p,err := AesDecrypt(c,v.key,iv)
		if err!=nil {
			t.Errorf("decrypt has error! keysize is %v byte, err_info:%v \n",k,err)
		}else{
			if !bytes.Equal(data, p) {
				t.Errorf("decypher and plaintext is not euqal! \n")
			}
		}
	}
}

func TestDatasize(t *testing.T) {
	N := 0
	N = 0*B
	check(t,N,keys["16"] )
	N = 1*B
	check(t,N,keys["16"] )
	N = 1*KB
	check(t,N,keys["16"] )
	N = 1*MB
	check(t,N,keys["16"] )
	N = 10*MB
	check(t,N,keys["16"] )
	N = 100*MB
	check(t,N,keys["16"] )
	N = 1000*MB
	check(t,N,keys["16"] )
}

func TestCorrectness(t *testing.T) {
	N := 1*MB
	check(t,N,keys["16"] )
}
func TestChinese(t *testing.T) {
	data := "一去二三里"
	//for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	c,err := AesEncrypt([]byte(data),keys["16"].key,iv)

	if err!=nil {
		t.Errorf("encrypt has error! data is [%v], keysize is %v byte, err_info:%v \n",data, keys["16"].key, err)
	}

	p,err := AesDecrypt(c,keys["16"].key,iv)
	if err!=nil {
		t.Errorf("decrypt has error! data is [%v], keysize is %v byte, err_info:%v \n",data, keys["16"].key, err)
	}else{
		if !bytes.Equal([]byte(data), p) {
			t.Errorf("decypher and plaintext is not euqal! \n")
		}
	}
}

func BenchmarkLoopsForCbcEnc(b *testing.B) {
	N := 1*MB
	b.SetBytes(int64(N))
	b.ReportAllocs()
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}
	b.ResetTimer()

	for i:=0 ; i<b.N ; i++ {
		AesEncrypt(data,keys["16"].key,iv)
	}
}

func BenchmarkLoopsForCbcDec(b *testing.B) {
	N := 1*MB
	b.SetBytes(int64(N))
	b.ReportAllocs()
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}
	c,_ := AesEncrypt(data,keys["16"].key,iv)

	b.ResetTimer()
	for i:=0 ; i<b.N ; i++ {
		AesDecrypt(c,keys["16"].key,iv)
	}
}


func check(t *testing.T, N int, onekey keySize) {
	data := make([]byte,N, N)
	for i:=0 ; i<N ; i++ {data[i]=byte(rand.Int()%256)}

	c,err := AesEncrypt(data,onekey.key,iv)

	if err!=nil {
		t.Errorf("encrypt has error! keysize is %v byte, err_info:%v \n",onekey.size, err)
	}

	p,err := AesDecrypt(c,keys["16"].key,iv)
	if err!=nil {
		t.Errorf("decrypt has error! keysize is %v byte, err_info:%v \n",onekey.size,err)
	}else{
		if !bytes.Equal(data, p) {
			t.Errorf("decypher and plaintext is not euqal! \n")
		}
	}
}

