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

package signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/stretchr/testify/require"
)

type ecdsaTestCase struct {
	private   string // serialized private key in hex
	r         string // R in hex
	s         string // S in hex
	signature string // serialized signature in hex
	scheme    SignatureScheme
}

var msg = []byte("test message")

func testECDSA(t *testing.T, tc *ecdsaTestCase) {
	r, _ := new(big.Int).SetString(tc.r, 16)
	s, _ := new(big.Int).SetString(tc.s, 16)
	sigBuf, _ := hex.DecodeString(tc.signature)
	buf, _ := hex.DecodeString(tc.private)
	pri, err := keypair.DeserializePrivateKey(buf)
	if err != nil {
		t.Error(err)
	}
	pub := pri.Public()

	sig := &Signature{
		Scheme: tc.scheme,
		Value: &DSASignature{
			R:     r,
			S:     s,
			Curve: pri.(*ec.PrivateKey).Curve,
		},
	}

	testSerialize(t, sig, sigBuf)
	testDeserialize(t, sigBuf, sig)
	testSignAndVerify(t, pri, pub, sig)
}

func testSignAndVerify(t *testing.T, pri keypair.PrivateKey, pub keypair.PublicKey, sig *Signature) {
	t.Log("test verify")
	if !Verify(pub, msg, sig) {
		t.Error("verification failed")
	}

	t.Log("test sign and verify")
	sig2, err := Sign(sig.Scheme, pri, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	ok := Verify(pub, msg, sig2)
	if !ok {
		t.Fatal("Verification failed")
	}
}

func testSerialize(t *testing.T, sig *Signature, control []byte) {
	t.Log("test serialize")
	sigBuf, err := Serialize(sig)
	if err != nil {
		t.Error(err)
	} else if !bytes.Equal(control, sigBuf) {
		t.Error("error serialization result")
	}
}

func testDeserialize(t *testing.T, data []byte, control *Signature) {
	t.Log("test deserialize")
	sig, err := Deserialize(data)
	if err != nil {
		t.Error(err)
	} else if sig.Scheme != control.Scheme {
		t.Error("error signature scheme")
	}
	switch v := sig.Value.(type) {
	case *DSASignature:
		v1, ok := control.Value.(*DSASignature)
		if !ok {
			t.Error("error signature type")
		} else if v.R.Cmp(v1.R) != 0 || v.S.Cmp(v1.S) != 0 {
			t.Error("error signature value")
		}
	case *SM2Signature:
		v1, ok := control.Value.(*SM2Signature)
		if !ok {
			t.Error("error signature type")
		} else if v.R.Cmp(v1.R) != 0 || v.S.Cmp(v1.S) != 0 || v.ID != v1.ID {
			t.Error("error signature value")
		}
	case []byte:
		v1, ok := control.Value.([]byte)
		if !ok {
			t.Error("error signature type")
		} else if !bytes.Equal(v, v1) {
			t.Error("error signature value")
		}
	}
}

func TestECDSA224(t *testing.T) {
	testcase := &ecdsaTestCase{
		"120128783953bd173b45df8a0d24c791cd5d59c65d72acbf7efba5365f2703519a401d7dfedb71dd8e0b9f3f511cce2ffd97bc33901fd42d006636",
		"9558f262ff324b035b97ce4628ed071c3e6d136b645a9c24c1f4d958",
		"671e338aed93255034c757840cc1f23c6017b118a245f501bc9663cf",
		"009558f262ff324b035b97ce4628ed071c3e6d136b645a9c24c1f4d958671e338aed93255034c757840cc1f23c6017b118a245f501bc9663cf",
		SHA224withECDSA,
	}
	testECDSA(t, testcase)
}

func TestECDSA256(t *testing.T) {
	testcase := &ecdsaTestCase{
		"120215724c7fce1387affd972f286e3cfe30fa271b8f3745a4d31f37a4983d834bb102d9f7e94812708f07b09bf31c03799a9ff3872341a4e1b01141f26713ba9b5ba4",
		"a4e5e7c481ce9680efa579e2a27520a396816c5b68ef2123ee43d6545adfbd99",
		"f06a4c5a200a0b7c1208f310d4dde8cadc2df310136f22d5b783ac35fbea07b7",
		"a4e5e7c481ce9680efa579e2a27520a396816c5b68ef2123ee43d6545adfbd99f06a4c5a200a0b7c1208f310d4dde8cadc2df310136f22d5b783ac35fbea07b7",
		SHA256withECDSA,
	}
	testECDSA(t, testcase)
}

func TestECDSA384(t *testing.T) {
	testcase := &ecdsaTestCase{
		"120356502d105ef8ed2a93d4873e1a26ceb7e4a6cbb5e88fc14b02ebbaa997dcb6ea915ef060d8710def11f47cf54116799502106af9b65f2d25ce40a2471dae1e2e9d507a734350e4496429b8150a272a7d711beb8eb54102d0f9dc771faad43a4d6c",
		"8f7663098861b034ca07f2c387301940a63feec401f90101a54ddc068d5317a5314ad607dd4eec2e8112c8928eb5a4d9",
		"7ca0e54e84ba5d0c3a72984cf79b7fb0a5b18ccaf2a112b897a99fedee9e8bd2bce9d2e0e899200fe0fd35f0d74e742b",
		"028f7663098861b034ca07f2c387301940a63feec401f90101a54ddc068d5317a5314ad607dd4eec2e8112c8928eb5a4d97ca0e54e84ba5d0c3a72984cf79b7fb0a5b18ccaf2a112b897a99fedee9e8bd2bce9d2e0e899200fe0fd35f0d74e742b",
		SHA384withECDSA,
	}
	testECDSA(t, testcase)
}

func TestECDSA512(t *testing.T) {
	testcase := &ecdsaTestCase{
		"12040171d7e5b73a5903643debaef32fa6678ac18c0db716572e3983d0c21aa0d2b20ef140cb85ceca6c7e466b32244c22802f7548d107d875d9e783cee2b46d3361b4990201589f6aea2a118f0d68f500c852041e5b862b62d26a40046cc03cdc805bdc89f06ab621137956b0c68348c46f38710758b5bc84820b33247c9795813d77c751d1c0",
		"019fc454c4b24df846221f0f00ac876e525a125d74e4707394153d2e6536a271f67a1c63284b4938e9e8f3955a481ed4e1d4c21fc19d233a6d0b32b5431f6fe5f463",
		"0034f170401130ef492e3446a16046686eb145ad7703a7e2751b3ca25d6116515a8fd08ede1ae9d0a97e4eb1fb1351f488d153df466f562d853b3e2fb21cad79904a",
		"03019fc454c4b24df846221f0f00ac876e525a125d74e4707394153d2e6536a271f67a1c63284b4938e9e8f3955a481ed4e1d4c21fc19d233a6d0b32b5431f6fe5f4630034f170401130ef492e3446a16046686eb145ad7703a7e2751b3ca25d6116515a8fd08ede1ae9d0a97e4eb1fb1351f488d153df466f562d853b3e2fb21cad79904a",
		SHA512withECDSA,
	}
	testECDSA(t, testcase)
}

func TestECDSA224SHA3(t *testing.T) {
	testcase := &ecdsaTestCase{
		"12013096de4dc9208a8df8ca7eaf36537b545ff52cdf10dd105779780ff60295e354d0f437e138e4a8af831bb5090a384da3c0ba10ca0485df4f24",
		"2cfa4113cf3bc81cd9f17f9a2e6b8cd07c684190b93c6dceab4c81ab",
		"a554bbb197225384231b480d4f6f870c79138fd1a593a96d9881838f",
		"042cfa4113cf3bc81cd9f17f9a2e6b8cd07c684190b93c6dceab4c81aba554bbb197225384231b480d4f6f870c79138fd1a593a96d9881838f",
		SHA3_224withECDSA,
	}
	testECDSA(t, testcase)
}

func TestECDSA256SHA3(t *testing.T) {
	testcase := &ecdsaTestCase{
		"12024273b35e7ca477f096d33519218c1b85f255b0655db600d965b6d2881f536c21036bbcd101d534b55da248eab37788e8b0a4c555045f94e34e1420abc1b2ea8911",
		"92c161269c6d4df2338ea856b254825925cd23d84a765bd35059c8350a7bf634",
		"f3f748c706a2bbfcb7915e98e1dc1953a505d8da3aec2064ebc7bfa2a2f34b9f",
		"0592c161269c6d4df2338ea856b254825925cd23d84a765bd35059c8350a7bf634f3f748c706a2bbfcb7915e98e1dc1953a505d8da3aec2064ebc7bfa2a2f34b9f",
		SHA3_256withECDSA,
	}
	testECDSA(t, testcase)
}

func TestECDSA384SHA3(t *testing.T) {
	testcase := &ecdsaTestCase{
		"12036bec622a3d59b424d7ecb69488ff0c2e69280ca132d1977ee87472f87df4914ebce8f38d28c588ad954fe8a6d51a5dfb02452ba0d1981dffeab4931f21fd834c44c6108c35ab2f6485cb244467f442491fecdf96797dd32455aa8e5a9d9bad7c70",
		"43731a8e0030a8d6a3ba9ff073805d196009f9bf90170dcf1b2f67766a489dffb6c2725d42d6780bc6f1990908cf04c0",
		"223b260af3d80188c98fef15c359a16ac2bcde7d7e5441fd659bf9c6daa8185adbcddf46773a3804ae4eb095530d3132",
		"0643731a8e0030a8d6a3ba9ff073805d196009f9bf90170dcf1b2f67766a489dffb6c2725d42d6780bc6f1990908cf04c0223b260af3d80188c98fef15c359a16ac2bcde7d7e5441fd659bf9c6daa8185adbcddf46773a3804ae4eb095530d3132",
		SHA3_384withECDSA,
	}
	testECDSA(t, testcase)
}

func TestECDSA512SHA3(t *testing.T) {
	testcase := &ecdsaTestCase{
		"12040159a7ecf17fc78849a8847b8fbbfe3ef6fc26d5c26f668be06af1443afacce81514bf3c766d67f705335c26cdf099632f67af27e42a72a0199aae3052ed43fa781a03011a6ae6b6c75b08429be63a690339c15598af51f4851034922a407adaf9a929afedfeb2172fd2914ae4bd461f64d94f1e87533153144cfa9822e613a7c06a389fb8",
		"018d125633746ead579fd5b6844d06032ad211b8c6193431c1fdab33e5c00da2c69905e0e42be057b8266f4795d5d806c10882d048d8f9f397723f90cb38718619ab",
		"009a63c9648382fa72499cc2de8d68d630ffd17db17143549763d8dbbc19a07c6aae08ad04f233bc08acca56922cc8d1ecf30da15c9f5642c1ed4ef4447768e1c027",
		"07018d125633746ead579fd5b6844d06032ad211b8c6193431c1fdab33e5c00da2c69905e0e42be057b8266f4795d5d806c10882d048d8f9f397723f90cb38718619ab009a63c9648382fa72499cc2de8d68d630ffd17db17143549763d8dbbc19a07c6aae08ad04f233bc08acca56922cc8d1ecf30da15c9f5642c1ed4ef4447768e1c027",
		SHA3_512withECDSA,
	}
	testECDSA(t, testcase)
}

func TestSM2(t *testing.T) {
	phex := "1314b4f1a616a66817973d504e60ddb1e1fae7ae2144989854b116e6ef3fc33ac51803651797d81d422c54c0b2be2daa7990c4588a8d8ab502f50e6cde76b43e6cbb6d"
	rhex := "6479e21d293b3f1886258fd38dd65d1dd658dc9a4a723fe4074f21d1ce86bee1"
	shex := "d113904fe1deac254f4d82734de2ad2ea4b4eb5dc8858ba6f59b7facfe95e6a1"
	sighex := "09757365726e616d65006479e21d293b3f1886258fd38dd65d1dd658dc9a4a723fe4074f21d1ce86bee1d113904fe1deac254f4d82734de2ad2ea4b4eb5dc8858ba6f59b7facfe95e6a1"
	id := "username"

	r, _ := new(big.Int).SetString(rhex, 16)
	s, _ := new(big.Int).SetString(shex, 16)
	sigBuf, _ := hex.DecodeString(sighex)
	buf, _ := hex.DecodeString(phex)
	pri, err := keypair.DeserializePrivateKey(buf)
	if err != nil {
		t.Error(err)
	}
	pub := pri.Public()

	sig := &Signature{
		Scheme: SM3withSM2,
		Value: &SM2Signature{
			ID: id,
			DSASignature: DSASignature{
				R:     r,
				S:     s,
				Curve: pri.(*ec.PrivateKey).Curve,
			},
		},
	}
	testSerialize(t, sig, sigBuf)
	testDeserialize(t, sigBuf, sig)
	testSignAndVerify(t, pri, pub, sig)
}

func TestEd25519(t *testing.T) {
	buf, _ := hex.DecodeString("141905c0b64315636742306dac8f303e0c2eb299d20952388f1c5eda0f4196302b7c724ae821ff34a976b6b36fdab1ea9445949951a2eb93277f7fe2144006d0bc42")
	pri, _ := keypair.DeserializePrivateKey(buf)
	pub := pri.Public()
	sigBuf, _ := hex.DecodeString("0ac963b05e49ce8f6d976f5b92b6122897ff37422fd48c460c2207af954fc8df2f8fb717d92fa6e6d42b988c4dc5ac3582d2fb7815131aacee9065d22218f8e30c")
	buf, _ = hex.DecodeString("c963b05e49ce8f6d976f5b92b6122897ff37422fd48c460c2207af954fc8df2f8fb717d92fa6e6d42b988c4dc5ac3582d2fb7815131aacee9065d22218f8e30c")

	sig := &Signature{
		Scheme: SHA512withEDDSA,
		Value:  buf,
	}

	testSerialize(t, sig, sigBuf)
	testDeserialize(t, sigBuf, sig)
	testSignAndVerify(t, pri, pub, sig)
}

func TestAllSchemeECDSA(t *testing.T) {
	for c := keypair.P224; c < keypair.P521; c++ {
		pri, _, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, c)
		if err != nil {
			t.Fatal(err)
		}

		for scheme := SHA224withECDSA; scheme < RIPEMD160withECDSA; scheme++ {
			sig, err := Sign(SHA256withECDSA, pri, msg, nil)
			if err != nil {
				t.Fatal(err)
			}

			buf, err := Serialize(sig)
			if err != nil {
				t.Fatal(err)
			}

			testDeserialize(t, buf, sig)
		}
	}
}

func TestSM2SV(t *testing.T) {
	buf, _ := hex.DecodeString("1314ab80a7ad086249c01e65c4d9bb6ce18de259dcfc218cd49f2455c539e9112ca3031220580679fda524f575ac48b39b9f74cb0a97993df4fac5798b04c702d07a39")
	pri, err := keypair.DeserializePrivateKey(buf)
	if err != nil {
		t.Fatal(err)
	}

	buf, _ = hex.DecodeString("0931323334353637383132333435363738000df57fa1e703c0166d74b965b202992d9b7653d60b9b539c99f8f356d9b0c0a129b56d16de076cdf30bc3d08b0bb691f362c29970af80e3cc8c62e4da56aa441")
	sig, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}

	msg, _ := hex.DecodeString("97b9ca0ce3a187b8605c409cd411125d5778c1b3a0538a4164d540746f9c530a")
	h := ""
	for _, b := range msg {
		h += fmt.Sprintf("0x%02x, ", b)
	}
	t.Log(h)

	sig1, err := Sign(SM3withSM2, pri, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	buf1, err := Serialize(sig1)
	t.Log(hex.EncodeToString(buf1))

	if !Verify(pri.Public(), msg, sig) {
		t.Fatal("verify error")
	}
}

func TestP256(t *testing.T) {
	pri, pub, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	t.Log("public:", hex.EncodeToString(keypair.SerializePublicKey(pub)))

	msg := []byte{1, 2, 3}
	t.Log("message:", hex.EncodeToString(msg))

	for i := 0; i < 100000; i++ {
		sig, err := Sign(SHA256withECDSA, pri, msg, nil)
		if err != nil {
			t.Fatal(err)
			continue
		}
		buf, err := Serialize(sig)
		if err != nil {
			t.Fatal(err)
			continue
		}
		size := len(buf)
		if size != 64 {
			t.Error("signature:", hex.EncodeToString(buf))
			t.Fatal("not 64:", size)
		}
		sig2, err := Deserialize(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pub, msg, sig2) {
			t.Fatal("failed")
		}
	}
}

func BenchmarkP224Sign(b *testing.B) {
	pri, _, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P224)
	for i := 0; i < b.N; i++ {
		Sign(SHA224withECDSA, pri, msg, nil)
	}
}

func BenchmarkP224Verify(b *testing.B) {
	x, _ := new(big.Int).SetString("28783953bd173b45df8a0d24c791cd5d59c65d72acbf7efba5365f270", 16)
	y, _ := new(big.Int).SetString("3519a401d7dfedb71dd8e0b9f3f511cce2ffd97bc33901fd42d006636", 16)
	pub := &ec.PublicKey{
		Algorithm: ec.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: elliptic.P224(),
		},
	}
	r, _ := new(big.Int).SetString("9558f262ff324b035b97ce4628ed071c3e6d136b645a9c24c1f4d958", 16)
	s, _ := new(big.Int).SetString("671e338aed93255034c757840cc1f23c6017b118a245f501bc9663cf", 16)
	sig := &Signature{
		Scheme: SHA224withECDSA,
		Value: &DSASignature{
			R:     r,
			S:     s,
			Curve: elliptic.P224(),
		},
	}

	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}

func BenchmarkP256Sign(b *testing.B) {
	pri, _, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
	for i := 0; i < b.N; i++ {
		Sign(SHA256withECDSA, pri, msg, nil)
	}
}

func BenchmarkP256Verify(b *testing.B) {
	x, _ := new(big.Int).SetString("d9f7e94812708f07b09bf31c03799a9ff3872341a4e1b01141f26713ba9b5ba4", 16)
	y, _ := new(big.Int).SetString("853143ff870951b7faae0417d2f45b3f4d8b63dcea6f2f127a3cba4a7c260292", 16)
	pub := &ec.PublicKey{
		Algorithm: ec.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: elliptic.P256(),
		},
	}
	r, _ := new(big.Int).SetString("a4e5e7c481ce9680efa579e2a27520a396816c5b68ef2123ee43d6545adfbd99", 16)
	s, _ := new(big.Int).SetString("f06a4c5a200a0b7c1208f310d4dde8cadc2df310136f22d5b783ac35fbea07b7", 16)
	sig := &Signature{
		Scheme: SHA256withECDSA,
		Value: &DSASignature{
			R:     r,
			S:     s,
			Curve: elliptic.P256(),
		},
	}

	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}

func BenchmarkP384Sign(b *testing.B) {
	pri, _, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P384)
	for i := 0; i < b.N; i++ {
		Sign(SHA384withECDSA, pri, msg, nil)
	}
}

func BenchmarkP384Verify(b *testing.B) {
	x, _ := new(big.Int).SetString("6bec622a3d59b424d7ecb69488ff0c2e69280ca132d1977ee87472f87df4914ebce8f38d28c588ad954fe8a6d51a5dfb0", 16)
	y, _ := new(big.Int).SetString("2452ba0d1981dffeab4931f21fd834c44c6108c35ab2f6485cb244467f442491fecdf96797dd32455aa8e5a9d9bad7c70", 16)
	pub := &ec.PublicKey{
		Algorithm: ec.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: elliptic.P384(),
		},
	}
	r, _ := new(big.Int).SetString("43731a8e0030a8d6a3ba9ff073805d196009f9bf90170dcf1b2f67766a489dffb6c2725d42d6780bc6f1990908cf04c0", 16)
	s, _ := new(big.Int).SetString("223b260af3d80188c98fef15c359a16ac2bcde7d7e5441fd659bf9c6daa8185adbcddf46773a3804ae4eb095530d3132", 16)
	sig := &Signature{
		Scheme: SHA384withECDSA,
		Value: &DSASignature{
			R:     r,
			S:     s,
			Curve: elliptic.P384(),
		},
	}

	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}

func BenchmarkP521Sign(b *testing.B) {
	pri, _, _ := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P521)
	for i := 0; i < b.N; i++ {
		Sign(SHA512withECDSA, pri, msg, nil)
	}
}

func BenchmarkP521Verify(b *testing.B) {
	x, _ := new(big.Int).SetString("0159a7ecf17fc78849a8847b8fbbfe3ef6fc26d5c26f668be06af1443afacce81514bf3c766d67f705335c26cdf099632f67af27e42a72a0199aae3052ed43fa781a0", 16)
	y, _ := new(big.Int).SetString("3011a6ae6b6c75b08429be63a690339c15598af51f4851034922a407adaf9a929afedfeb2172fd2914ae4bd461f64d94f1e87533153144cfa9822e613a7c06a389fb8", 16)
	pub := &ec.PublicKey{
		Algorithm: ec.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: elliptic.P521(),
		},
	}
	r, _ := new(big.Int).SetString("018d125633746ead579fd5b6844d06032ad211b8c6193431c1fdab33e5c00da2c69905e0e42be057b8266f4795d5d806c10882d048d8f9f397723f90cb38718619ab", 16)
	s, _ := new(big.Int).SetString("009a63c9648382fa72499cc2de8d68d630ffd17db17143549763d8dbbc19a07c6aae08ad04f233bc08acca56922cc8d1ecf30da15c9f5642c1ed4ef4447768e1c027", 16)
	sig := &Signature{
		Scheme: SHA512withECDSA,
		Value: &DSASignature{
			R:     r,
			S:     s,
			Curve: elliptic.P521(),
		},
	}

	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}

func BenchmarkSM2Sign(b *testing.B) {
	pri, _, _ := keypair.GenerateKeyPair(keypair.PK_SM2, keypair.SM2P256V1)
	for i := 0; i < b.N; i++ {
		Sign(SM3withSM2, pri, msg, nil)
	}
}

func BenchmarkSM2Verify(b *testing.B) {
	buf, _ := hex.DecodeString("1314b4f1a616a66817973d504e60ddb1e1fae7ae2144989854b116e6ef3fc33ac51803651797d81d422c54c0b2be2daa7990c4588a8d8ab502f50e6cde76b43e6cbb6d")
	pri, _ := keypair.DeserializePrivateKey(buf)
	pub := pri.Public()
	buf, _ = hex.DecodeString("09757365726e616d65006479e21d293b3f1886258fd38dd65d1dd658dc9a4a723fe4074f21d1ce86bee1d113904fe1deac254f4d82734de2ad2ea4b4eb5dc8858ba6f59b7facfe95e6a1")
	sig, _ := Deserialize(buf)

	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	pri, _, _ := keypair.GenerateKeyPair(keypair.PK_EDDSA, keypair.ED25519)
	for i := 0; i < b.N; i++ {
		Sign(SHA512withEDDSA, pri, msg, nil)
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	buf, _ := hex.DecodeString("141905c0b64315636742306dac8f303e0c2eb299d20952388f1c5eda0f4196302b7c724ae821ff34a976b6b36fdab1ea9445949951a2eb93277f7fe2144006d0bc42")
	pri, _ := keypair.DeserializePrivateKey(buf)
	pub := pri.Public()
	buf, _ = hex.DecodeString("0ac963b05e49ce8f6d976f5b92b6122897ff37422fd48c460c2207af954fc8df2f8fb717d92fa6e6d42b988c4dc5ac3582d2fb7815131aacee9065d22218f8e30c")
	sig, _ := Deserialize(buf)

	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}

func TestSignEthRawMsg(t *testing.T) {
	a := require.New(t)
	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ETHECDSA, nil)
	a.Nil(err, "fail")
	sig, err := Sign(KECCAK256WithECDSA, pri, msg, nil)
	a.Nil(err, "fail")
	a.Equal(sig.Scheme, KECCAK256WithECDSA, "fail")

	ret := Verify(pub, msg, sig)
	a.True(ret, "fail")

	b, err := Serialize(sig)
	a.Nil(err, "fail")
	a.Equal(len(b), int(66), "fail")

	recb, err := Deserialize(b)
	a.Nil(err, "fail")
	a.Equal(recb, sig, "fail")
}

func TestSignEthHashed(t *testing.T) {
	a := require.New(t)
	hasher := GetHash(KECCAK256WithECDSA)
	hasher.Write(msg)
	digest := hasher.Sum(nil)

	pri, pub, err := keypair.GenerateKeyPair(keypair.PK_ETHECDSA, nil)
	a.Nil(err, "fail")
	sig, err := Sign(KECCAK256WithECDSA, pri, digest, nil)
	a.Nil(err, "fail")
	a.Equal(sig.Scheme, KECCAK256WithECDSA, "fail")

	ret := Verify(pub, digest, sig)
	a.True(ret, "fail")

	b, err := Serialize(sig)
	a.Nil(err, "fail")
	a.Equal(len(b), int(66), "fail")

	recb, err := Deserialize(b)
	a.Nil(err, "fail")
	a.Equal(recb, sig, "fail")

	// should have same signed message
	ep := pri.(*ecdsa.PrivateKey)
	sig2, err := crypto.Sign(digest, ep)
	a.Nil(err, "fail")
	a.Equal(sig2, sig.Value.([]byte), "ethereum should have same sign with")
}
