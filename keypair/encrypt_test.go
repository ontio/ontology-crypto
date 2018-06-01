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
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ontio/ontology-crypto/ec"
)

var d = "3e47428fd73f915a7937bf1f8d3bffc27a45dbb6ef4e57bd9513c1a8bfbcbfd4"
var pwd = []byte("test password")
var pwd1 = []byte("new password")
var addr = "test address"
var keyjson = `{
  "address":"test address",
  "enc-alg":"aes-256-gcm",
  "key":"8bfELeEADFDw4eHkPbvZIAgYkNCvsxUMHdEU7ylS1QYgqt3RhIzOsDZPdM6RHtNs",
  "algorithm":"ECDSA",
  "salt":"TTpMzpuoNkwfv6lt",
  "parameters":{"curve":"P-256"}
}`

func TestDecrypt(t *testing.T) {
	var pro ProtectedKey
	json.Unmarshal([]byte(keyjson), &pro)
	err := testDecrypt(&pro, pwd)
	if err != nil {
		t.Fatal(err)
	}
}

func testDecrypt(prot *ProtectedKey, pass []byte) error {
	pri, err := DecryptPrivateKey(prot, pass)
	if err != nil {
		return err
	}

	v, ok := pri.(*ec.PrivateKey)
	if !ok {
		return errors.New("decryption error: wrong key type")
	}
	if v.Algorithm != ec.ECDSA {
		return errors.New("decryption error: wrong algorithm")
	}
	if v.D.Text(16) != d {
		return errors.New("decryption error: d value is wrong, " + hex.EncodeToString(v.D.Bytes()))
	}
	return nil
}

func TestEncryptPrivate(t *testing.T) {
	D, _ := hex.DecodeString(d)
	pri := &ec.PrivateKey{
		Algorithm:  ec.ECDSA,
		PrivateKey: ec.ConstructPrivateKey(D, elliptic.P256()),
	}
	var pro ProtectedKey
	json.Unmarshal([]byte(keyjson), &pro)

	c, err := EncryptPrivateKey(pri, addr, pwd)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("address:", c.Address)
	t.Log("algorithm:", c.Alg)
	t.Log("parameter:", c.Param)

	_, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	err = testDecrypt(c, pwd)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReencrypt(t *testing.T) {
	var pro ProtectedKey
	json.Unmarshal([]byte(keyjson), &pro)

	sp0 := GetScryptParameters()
	sp1 := &ScryptParam{
		N:     4096,
		R:     8,
		P:     8,
		DKLen: 64,
	}

	pro1, err := ReencryptPrivateKey(&pro, pwd, pwd1, sp0, sp1)
	if err != nil {
		t.Fatal(err)
	}

	pri, err := DecryptWithCustomScrypt(pro1, pwd1, sp1)
	if err != nil {
		t.Fatal(err)
	}

	v, ok := pri.(*ec.PrivateKey)
	if !ok {
		t.Fatal("key type error")
	}
	if v.D.Text(16) != d {
		t.Fatal("decrypted key value error")
	}
}
