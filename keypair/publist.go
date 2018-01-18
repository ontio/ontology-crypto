package keypair

import (
	"bytes"
	"crypto"
)

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

func ConvertToPublicList(keys []crypto.PublicKey) PublicList {
	res := make(PublicList, 0, len(keys))
	for _, k := range keys {
		res = append(res, SerializePublicKey(k))
	}

	return res
}
