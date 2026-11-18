package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/ontio/ontology-crypto/sm3"
	"math/big"
	"testing"
)

func TestLeadingZeroEncoding(t *testing.T) {
	c := SM2P256V1()
	// Locate a reproducible point whose Y needs a leading zero byte.
	var x, y *big.Int
	for d := int64(1); d < 10000; d++ {
		x, y = c.ScalarBaseMult(big.NewInt(d).Bytes())
		if len(y.Bytes()) < 32 {
			break
		}
	}
	if len(y.Bytes()) >= 32 {
		t.Fatal("no short coordinate")
	}
	pub := &ecdsa.PublicKey{Curve: c, X: x, Y: y}
	got, err := getZ(nil, pub, "id", sm3.New())
	if err != nil {
		t.Fatal(err)
	}
	h := sm3.New()
	h.Write([]byte{0, 16})
	h.Write([]byte("id"))
	for _, v := range []*big.Int{new(big.Int).SetBytes(c.(SM2Curve).ABytes()), c.Params().B, c.Params().Gx, c.Params().Gy, x, y} {
		b := make([]byte, 32)
		vb := v.Bytes()
		copy(b[32-len(vb):], vb)
		h.Write(b)
	}
	if !bytes.Equal(got, h.Sum(nil)) {
		t.Fatal("ZA is not fixed-width")
	}
	// d=1 means the shared point equals C1. Construct C3 independently.
	priv := &ecdsa.PrivateKey{D: big.NewInt(1), PublicKey: ecdsa.PublicKey{Curve: c, X: c.Params().Gx, Y: c.Params().Gy}}
	msg := []byte("leading zero C3")
	ct := make([]byte, 96+len(msg))
	x.FillBytes(ct[:32])
	y.FillBytes(ct[32:64])
	k, _ := sm3kdf(ct[:64], len(msg))
	for i := range msg {
		ct[96+i] = msg[i] ^ k[i]
	}
	h.Reset()
	h.Write(ct[:32])
	h.Write(msg)
	h.Write(ct[32:64])
	copy(ct[64:96], h.Sum(nil))
	plain, err := Decrypt(priv, ct)
	if err != nil || !bytes.Equal(plain, msg) {
		t.Fatalf("canonical ciphertext rejected: %v", err)
	}
}

func TestPrivateKeyValidation(t *testing.T) {
	c := SM2P256V1()
	good, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Encrypt(&good.PublicKey, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Set(c.Params().N)} {
		bad := *good
		bad.D = d
		if _, err := Decrypt(&bad, ct); err == nil {
			t.Fatal("accepted invalid scalar")
		}
		if _, _, err := Sign(rand.Reader, &bad, "", []byte("m"), sm3.New()); err == nil {
			t.Fatal("signed invalid scalar")
		}
	}
	d := new(big.Int).Sub(c.Params().N, big.NewInt(1))
	x, y := c.ScalarBaseMult(d.Bytes())
	bad := &ecdsa.PrivateKey{D: d, PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}}
	if _, _, err := Sign(rand.Reader, bad, "", []byte("m"), sm3.New()); err == nil {
		t.Fatal("accepted N-1 signing scalar")
	}
}
