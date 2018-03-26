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
)

// FindKey finds the specified public key in the list and returns its index
// or -1 if not found.
func FindKey(list []PublicKey, key PublicKey) int {
	for i, v := range list {
		if ComparePublicKey(v, key) {
			return i
		}
	}
	return -1
}

// PublicList is a container for serialized public keys.
// It implements the interface sort.Interface.
type PublicList [][]byte

func (l PublicList) Len() int {
	return len(l)
}

func (l PublicList) Less(i, j int) bool {
	return bytes.Compare(l[i], l[j]) < 0
}

func (l PublicList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// ConvertToPublicList converts the public keys to a PublicList.
func NewPublicList(keys []PublicKey) PublicList {
	res := make(PublicList, 0, len(keys))
	for _, k := range keys {
		res = append(res, SerializePublicKey(k))
	}

	return res
}
