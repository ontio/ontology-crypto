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

package keypair

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/sm2"
)

func TestKeyPairGeneration(t *testing.T) {
	t.Log("test ECDSA key with curve P256")
	testKeyGen(PK_ECDSA, P224, t)
	testKeyGen(PK_ECDSA, P256, t)
	testKeyGen(PK_ECDSA, P384, t)
	testKeyGen(PK_ECDSA, P521, t)

	t.Log("test SM2 key")
	testKeyGen(PK_SM2, SM2P256V1, t)

	t.Log("test EdDSA key")
	testKeyGen(PK_EDDSA, ED25519, t)
}

func BenchmarkGenKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateKeyPair(PK_ECDSA, P256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func testKeyGen(kt KeyType, param interface{}, t *testing.T) {
	private, public, err := GenerateKeyPair(kt, param)
	if err != nil {
		t.Fatal(err)
		return
	}

	buf0 := SerializePublicKey(public)
	buf1 := SerializePrivateKey(private)

	t.Logf("%v\n", buf0)

	_, err = DeserializePublicKey(buf0)
	if err != nil {
		t.Error(err)
	}

	_, err = DeserializePrivateKey(buf1)
	if err != nil {
		t.Error(err)
	}
}

func testECDeserialize(pkBytes []byte, pk *ec.PublicKey, t *testing.T) {
	pk1, err := DeserializePublicKey(pkBytes)
	if err != nil {
		t.Fatal(err)
		return
	}
	v, ok := pk1.(*ec.PublicKey)
	if !ok {
		t.Fatal("wrong key type")
		return
	}
	if v.Algorithm != pk.Algorithm {
		t.Fatal("wrong algorithm")
		return
	}
	if v.Curve.Params().Name != pk.Curve.Params().Name {
		t.Fatal("wrong curve")
		return
	}
	if v.X.Cmp(pk.X) != 0 {
		t.Fatal("wrong X value")
		return
	}
	if v.Y.Cmp(pk.Y) != 0 {
		t.Fatal("wrong Y value")
		return
	}
}

func TestECDSAKey(t *testing.T) {
	x, _ := new(big.Int).SetString("72c2826f07f5e4f310e2f708689548f0d6d0e007603bdc7e6a2512c673db54df", 16)
	y, _ := new(big.Int).SetString("aa87fed89e6e0bef66a30b12afcfc73221457402e2773828f5407606c41a9a36", 16)

	pk := &ec.PublicKey{
		Algorithm: ec.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
	}

	pkBytes, _ := hex.DecodeString("0272c2826f07f5e4f310e2f708689548f0d6d0e007603bdc7e6a2512c673db54df")

	// Serialization
	t.Log("Test ecdsa public key serialization")
	buf := SerializePublicKey(pk)
	if !bytes.Equal(pkBytes, buf) {
		t.Error("serialization error")
	}

	// Deserialization
	t.Log("Test ecdsa public key deserialization")
	testECDeserialize(pkBytes, pk, t)
}

func TestSM2Key(t *testing.T) {
	//d, _ := new(big.Int).SetString("5be7e4b09a761bf5562ddf8e6a33184e00d0c09c942c6adbad1141d5d08431f0", 16)
	x, _ := new(big.Int).SetString("bed1c52a2bb67d2cc82b0d099c5832b7886e21828c3745f84990c249cf8d5890", 16)
	y, _ := new(big.Int).SetString("762a3a2e07c0e4ef2dee435d4f2b76d8892b42e77727eef72b9cbfa29c5eb76b", 16)

	pk, _ := hex.DecodeString("131403bed1c52a2bb67d2cc82b0d099c5832b7886e21828c3745f84990c249cf8d5890")

	pub := &ec.PublicKey{
		Algorithm: ec.SM2,
		PublicKey: &ecdsa.PublicKey{
			Curve: sm2.SM2P256V1(),
			X:     x,
			Y:     y,
		},
	}

	buf := SerializePublicKey(pub)
	if !bytes.Equal(buf, pk) {
		t.Errorf(hex.EncodeToString(buf))
		t.Error("serialization error")
	}

	testECDeserialize(buf, pub, t)
}

func TestComparePublicKey(t *testing.T) {
	data, _ := hex.DecodeString("1202036b491aeedc763c769c139f759c4e5a7fc5862c19fe2d510f974bb99939137a95")

	pk0, err := DeserializePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}

	pk1, err := DeserializePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}

	if !ComparePublicKey(pk0, pk1) {
		t.Fatal("public keys not equal")
	}
}

func BenchmarkDeserilize(b *testing.B) {
	var opts byte
	opts = P256
	_, pub, _ := GenerateKeyPair(PK_ECDSA, opts)

	serPub := SerializePublicKey(pub)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := DeserializePublicKey(serPub)
		if err != nil {
			b.Fatal("bug:", err)
		}
	}
}

func TestWIF(t *testing.T) {
	wif := "KyaBriGFNXzaWf8Y7S1HxaCr1EhhFypdZYPdLJuFPqqW2d9cEtHw"
	hf := "46358132e7d8dd2bfc65748e95dc3a36384f6c3d592c1dd578708e8da219d7d4"
	t.Log("parse WIF key")
	pri, err := GetP256KeyPairFromWIF([]byte(wif))
	if err != nil {
		t.Fatal(err)
	}
	v, ok := pri.(*ec.PrivateKey)
	if !ok {
		t.Fatal("error key type")
	}
	if v.Algorithm != ec.ECDSA {
		t.Fatal("error algorithm")
	}
	if v.D.Text(16) != hf {
		t.Fatal("error key value")
	}
}
