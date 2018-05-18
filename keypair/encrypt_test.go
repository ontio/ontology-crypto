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
	"testing"

	"github.com/ontio/ontology-crypto/ec"
)

var d = "3e47428fd73f915a7937bf1f8d3bffc27a45dbb6ef4e57bd9513c1a8bfbcbfd4"
var e = "2d7dfcbad0ed34e7c00449be4d930224099bfdd10bf0c8436830351ea5c18d3d"
var pwd = []byte("test password")
var pwd1 = []byte("new password")
var addr = "test address"

func TestEncryptPrivate(t *testing.T) {
	D, _ := hex.DecodeString(d)
	pri := &ec.PrivateKey{
		Algorithm:  ec.ECDSA,
		PrivateKey: ec.ConstructPrivateKey(D, elliptic.P256()),
	}

	c, err := EncryptPrivateKey(pri, addr, pwd)
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

	pri1, err := DecryptPrivateKey(c, pwd)
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

func TestReencrypt(t *testing.T) {
	k, _ := hex.DecodeString(e)
	pro := ProtectedKey{
		Key:     k,
		Address: addr,
		Alg:     "ECDSA",
		Hash:    "sha256",
		EncAlg:  "aes-256-ctr",
		Param:   map[string]string{"curve": "P-256"},
	}
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

	SetScryptParam(sp1)
	pri, err := DecryptPrivateKey(pro1, pwd1)
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
