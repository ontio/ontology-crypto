package keypair

import (
	"bytes"
	"crypto"
	"reflect"

	"github.com/OntologyNetwork/ont-crypto/ec"
)

// KeyIndex finds the specified public key in the list and returns its index
// or -1 if not found.
func KeyIndex(list []crypto.PublicKey, key crypto.PublicKey) int {
	for i, v := range list {
		t0 := reflect.TypeOf(key)
		t1 := reflect.TypeOf(v)
		if t0 != t1 {
			continue
		}

		switch v0 := key.(type) {
		case *ec.PublicKey:
			v1 := v.(*ec.PublicKey)
			if v0.Algorithm == v1.Algorithm && v0.Params().Name == v1.Params().Name && v0.X == v1.X {
				return i
			}

		default:
			continue
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
func ConvertToPublicList(keys []crypto.PublicKey) PublicList {
	res := make(PublicList, 0, len(keys))
	for _, k := range keys {
		res = append(res, SerializePublicKey(k))
	}

	return res
}
