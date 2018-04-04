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

package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"testing"
)

type Sm2Data struct {
	pubkey_x string
	pubkey_y string
	privkey  string
	message  string
	cipher   string
}

var (
	testcase_KDF = map[string]string{
		"B8": "ede42e70dcc68b522a79a4b47157c0eeff77a92df1e4416ba288ebc5f71a8851ce1424508a2e0840195fc0342696765c09225c077308a1e670ca403ffa8cc1a160be0a0fdfb9f9c2a620bc5cf0260608cdfb94823a888acc23166e3e77e363122dc40676734d14a010093d9d1769c43ae5355d057c85526e67f8235747d592ed1a1678e137ac1a920e900b2d85e6d45789317258d2af12fd14d751679c4abd91d6a292d11195ab0d06b05faf03f8a9ddbf7557c542afcc49e88a115ed9dbda348bc3f1ebd59940cf15d319fc604ba9aa4077e19a5f0ed4563776018718570466c9e21438d588300bc1d43a619709509cd2501976085460c6f02e3faf0837adae",
		"1AF8DBA88AA8D19CF1960F12960A0D54":                                                                                                 "7e50ea2b18ae40acc1067c09d634fad54016b09b9aea3ed07c34016b459f2b0b33bfcf9be0c18c66f91a169ac390adaa825358f15dd833f92fd8539e830bd88fc1d7c175db85727a7be92471929c3cd25a16945989945a4b7ea1eb353f73216e23aff65d71c2d92fe49fd1e718bc6bd5a99fde4306bfa5773ec67e9a29cbdc4762013e178d38b2883130efec561821e36eb178b82645f4e7bafe9e1fec8b44a5c9a4db9087b3361f7bcb74214f3dcf2ccdaa0880ba7dd13fccc61007b32124569ad08f7adf60a432993cb131c4edc5d65a8d6dc3db916117103999738814459f08b20de5814f17cfddd1d4400952989f14fdb335777a88b25553d66e3831f362",
		"23C596FA83D17C96B50252C421D5BAD604086549BD9D8A5BFD469FC838DC5D535532503F874D73B30B26F9D2F142477A9404907D2E1083E31FE0CBB6D6DBF0A3": "e22fb6de6deb671baefe6d1b7c846174bd486d1bcb0e9ce6fc3abf1eb62f8371566dca973c9e14be4f64e1449cbcd3117c61f2f7b0ae34858ecf0918be88d1231bd2c8a77c4bbc0413ec856fd9149609fa414587ad26f641cf33db2a838431a8726c8fbb5dfcb533ba75c80647ed8ff5a59dc29322020b2180db156667b1422cd462216f8fba01c264a33ba3b875272438f5968069d2c013518f208b9062e350208658aaf164dcd83fa41adcb30f10787eb70044e62f4e0ee10c03afbfcec9af85ba5d37bc5ceb5cfdd3078f2c89a3a0be7c70d988d47a2c0a384c833ee140e4fe1256c36b981829c079099dc14e992e653de0eabc357e1b0a3c9d4bf3201aac",
	}

	testcase_Dec = Sm2Data{
		privkey:  "700BE499A4EFE27A8369F58BFFE0F5563CDFF772E11832254DDE10E324A81755",
		pubkey_x: "BC4EADB005F9AADF6BB8573DE5C430A12B023A2471402813CB4D066FC3D68164",
		pubkey_y: "8F98951D3EE032E6F4A4AB2B79510D5721767492E94F31B82C1603731E6CB92A",
		message:  "ce8f1ce36e5e62b16772",
		cipher:   "E594A5745BBBD5539D68711C64CA55898A284C9081B65CA36E388062045A357C97AEFE68641FAB6E6A3E4E10855C7C3DE9B8F9417381E4FBB020E9303926BC77126D6F6F74993DD43233C284A0840040EF2E77B0383B9EF5F73B1803DB7F4503C66D9F3544BCB59239D5",
	}
)

func TestSm3Kdf(t *testing.T) {
	//out1, _ := sm3kdf([]byte{01}, 0)
	//if len(out1) != 0 {
	//	t.Error("sm3 kdf error!")
	//}

	for k, v := range testcase_KDF {
		in, _ := hex.DecodeString(k)
		res, _ := hex.DecodeString(v)
		out, siz := sm3kdf(in, 256)

		if reflect.DeepEqual(res, out) != true {
			fmt.Println(siz)
			fmt.Println(out)
			fmt.Println(res)
			t.Error("sm3 kdf error2!")
		}
	}
}

func TestSm2Dec(t *testing.T) {
	d, _ := new(big.Int).SetString(testcase_Dec.privkey, 16)
	x, _ := new(big.Int).SetString(testcase_Dec.pubkey_x, 16)
	y, _ := new(big.Int).SetString(testcase_Dec.pubkey_y, 16)

	cur := SM2P256V1()
	priKey := ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			X:     x,
			Y:     y,
			Curve: cur,
		}}

	m, _ := hex.DecodeString(testcase_Dec.message)
	c, _ := hex.DecodeString(testcase_Dec.cipher)

	//fmt.Println(m)
	//fmt.Println(c)
	out, err := Decrypt(&priKey, c)
	if err != nil {
		fmt.Println(err)
	}

	if reflect.DeepEqual(m, out) != true {
		t.Error("sm2 dec error!")
	}
}

func TestSm2Enc(t *testing.T) {
	p256 := SM2P256V1()
	for j := 0; j < 1000; j++ {
		for i := 1; i < 512; i++ {
			fmt.Println("round ", j, i)
			priKey, _ := ecdsa.GenerateKey(p256, rand.Reader)
			pubKey := &priKey.PublicKey
			msg := make([]byte, i)
			_, _ = io.ReadFull(rand.Reader, msg[:])

			c, err := Encrypt(pubKey, msg)
			if err != nil {
				fmt.Println(err)
				t.Error("sm2 enc error!")
			}
			m, err := Decrypt(priKey, c)
			if err != nil {
				fmt.Println(err)
				t.Error("sm2 enc error!")
			}

			if reflect.DeepEqual(msg, m) != true {
				t.Error("sm2 enc error!")
			}
		}
	}
}

func BenchmarkEnc(b *testing.B) {
	priKey, _ := ecdsa.GenerateKey(p256, rand.Reader)
	pubKey := &priKey.PublicKey
	msg := make([]byte, 256)
	_, _ = io.ReadFull(rand.Reader, msg[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(pubKey, msg)
	}
}

func BenchmarkDec(b *testing.B) {
	priKey, _ := ecdsa.GenerateKey(p256, rand.Reader)
	msg := make([]byte, 256)
	_, _ = io.ReadFull(rand.Reader, msg[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt(priKey, msg)
	}
}
