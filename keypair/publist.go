package keypair

import (
	"bytes"
	"crypto"
)

// FindKey finds the specified public key in the list and returns its index
// or -1 if not found.
func FindKey(list []crypto.PublicKey, key crypto.PublicKey) int {
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
func NewPublicList(keys []crypto.PublicKey) PublicList {
	res := make(PublicList, 0, len(keys))
	for _, k := range keys {
		res = append(res, SerializePublicKey(k))
	}

	return res
}
