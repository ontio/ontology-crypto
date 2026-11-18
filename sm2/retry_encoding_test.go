package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"testing"
)

// Force two valid ephemeral points while keeping the real KDF and cipher
// assembly. With recipient d=1 the shared point is the ephemeral point.
type retryCurve struct {
	SM2Curve
	points [2][2]*big.Int
	calls  int
}

func (c *retryCurve) ScalarBaseMult(_ []byte) (*big.Int, *big.Int) {
	i := c.calls
	c.calls++
	if i > 1 {
		i = 1
	}
	return c.points[i][0], c.points[i][1]
}
func (c *retryCurve) ScalarMult(_, _ *big.Int, _ []byte) (*big.Int, *big.Int) {
	i := c.calls - 1
	if i > 1 {
		i = 1
	}
	return c.points[i][0], c.points[i][1]
}

func TestEncryptRetryClearsLeadingBytes(t *testing.T) {
	base := SM2P256V1().(SM2Curve)
	c := &retryCurve{SM2Curve: base}
	for i := int64(1); i < 10000 && (c.points[0][0] == nil || c.points[1][0] == nil); i++ {
		x, y := base.ScalarBaseMult(big.NewInt(i).Bytes())
		z := make([]byte, 64)
		x.FillBytes(z[:32])
		y.FillBytes(z[32:])
		_, n := sm3kdf(z, 1)
		if n == 0 && len(x.Bytes()) == 32 && len(y.Bytes()) == 32 {
			c.points[0] = [2]*big.Int{x, y}
		}
		if n != 0 && (len(x.Bytes()) < 32 || len(y.Bytes()) < 32) {
			c.points[1] = [2]*big.Int{x, y}
		}
	}
	if c.points[0][0] == nil || c.points[1][0] == nil {
		t.Fatal("missing retry fixtures")
	}
	params := base.Params()
	msg := []byte{42}
	ct, err := Encrypt(&ecdsa.PublicKey{Curve: c, X: params.Gx, Y: params.Gy}, msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.calls != 2 {
		t.Fatalf("expected two attempts, got %d", c.calls)
	}
	want := make([]byte, 64)
	c.points[1][0].FillBytes(want[:32])
	c.points[1][1].FillBytes(want[32:])
	if !bytes.Equal(ct[:64], want) {
		t.Fatal("C1 retained bytes from first attempt")
	}
	priv := &ecdsa.PrivateKey{D: big.NewInt(1), PublicKey: ecdsa.PublicKey{Curve: base, X: params.Gx, Y: params.Gy}}
	plain, err := Decrypt(priv, ct)
	if err != nil || !bytes.Equal(plain, msg) {
		t.Fatalf("retry ciphertext failed: %v", err)
	}
}
