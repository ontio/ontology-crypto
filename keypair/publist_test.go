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
	"encoding/hex"
	"testing"
)

func TestSort(t *testing.T) {
	keys := []string{
		"0344422f19706e1433aa18d4e9fc586bbd8e707b1a8a9ca56668bf07dbb3a63a5b",
		"0244422f19706e1433aa18d4e9fc586bbd8e707b1a8a9ca56668bf07dbb3a63a5b",
		"026b302e2b2bece0f31aab29115833279f51ec1e2eb72bca79a5f2319b3e6e0801",
		"120403003ec1e93945b898b916a36d349f8495cdae04b4181c39b6a2cae159e0a9f75f2266bb9b943d5496d892ebe489cae61a927b2b44c8fc94aeda3d8b1457a215ae961e",
		"131402a7491e289e13cdea16833ccc0dd320abf8a7e93ebc4ae3854403910f3ce27ffc",
		"14193950df28273780665fbd586043903bb8f59e1e8fa8c81e3146a6fd01ec381608",
	}

	b0, _ := hex.DecodeString(keys[4])
	b1, _ := hex.DecodeString(keys[1])
	b2, _ := hex.DecodeString(keys[2])
	b3, _ := hex.DecodeString(keys[0])
	b4, _ := hex.DecodeString(keys[5])
	b5, _ := hex.DecodeString(keys[3])

	p0, _ := DeserializePublicKey(b0)
	p1, _ := DeserializePublicKey(b1)
	p2, _ := DeserializePublicKey(b2)
	p3, _ := DeserializePublicKey(b3)
	p4, _ := DeserializePublicKey(b4)
	p5, _ := DeserializePublicKey(b5)

	pl := []PublicKey{p0, p1, p2, p3, p4, p5}
	SortPublicKeys(pl)

	for i, v := range pl {
		tmp := hex.EncodeToString(SerializePublicKey(v))
		if tmp != keys[i] {
			t.Fatalf("pl[%d] error", i)
		}
	}
}
