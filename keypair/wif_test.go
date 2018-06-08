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
	"testing"

	"github.com/ontio/ontology-crypto/ec"
)

var dhex = "46358132e7d8dd2bfc65748e95dc3a36384f6c3d592c1dd578708e8da219d7d4"
var wif = "KyaBriGFNXzaWf8Y7S1HxaCr1EhhFypdZYPdLJuFPqqW2d9cEtHw"

func getPrivate() PrivateKey {
	D, _ := hex.DecodeString(dhex)
	pri := ec.ConstructPrivateKey(D, elliptic.P256())
	return &ec.PrivateKey{
		Algorithm:  ec.ECDSA,
		PrivateKey: pri,
	}
}

func TestKey2WIF(t *testing.T) {
	pri := getPrivate()
	res, err := Key2WIF(pri)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
	if string(res) != wif {
		t.Fatal("result incorrect")
	}
}

func TestWIF2Key(t *testing.T) {
	pri, err := WIF2Key([]byte(wif))
	if err != nil {
		t.Fatal(err)
	}
	v, ok := pri.(*ec.PrivateKey)
	if !ok {
		t.Fatal("key type error")
	}
	if v.Algorithm != ec.ECDSA {
		t.Fatal("not ECDSA key")
	}
	if v.Params().Name != elliptic.P256().Params().Name {
		t.Fatal("curve error")
	}
	if v.D.Text(16) != dhex {
		t.Fatal("key value error")
	}
}
