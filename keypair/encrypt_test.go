package keypair

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ontio/ontology-crypto/ec"
)

var d = "3e47428fd73f915a7937bf1f8d3bffc27a45dbb6ef4e57bd9513c1a8bfbcbfd4"
var e = "2d7dfcbad0ed34e7c00449be4d930224099bfdd10bf0c8436830351ea5c18d3d"

func TestEncryptPrivate(t *testing.T) {
	D, _ := hex.DecodeString(d)
	pri := &ec.PrivateKey{
		Algorithm:  ec.ECDSA,
		PrivateKey: ec.ConstructPrivateKey(D, elliptic.P256()),
	}

	c, err := EncryptPrivateKey(pri, "test address", "test password")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("address:", c.Address)
	t.Log("algorithm:", c.Alg)
	t.Log("parameter:", c.Param)

	if hex.EncodeToString(c.Key) != e {
		t.Fatal("encryption result error")
	}

	_, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	pri1, err := DecryptPrivateKey(c, "test password")
	if err != nil {
		t.Fatal(err)
	}

	v, ok := pri1.(*ec.PrivateKey)
	if !ok {
		t.Fatal("decryption error: wrong key type")
	}
	if v.Algorithm != ec.ECDSA {
		t.Fatal("decryption error: wrong algorithm")
	}
	if v.D.Cmp(pri.D) != 0 {
		t.Fatal("decryption error: d value is wrong,", hex.EncodeToString(v.D.Bytes()))
	}
}
