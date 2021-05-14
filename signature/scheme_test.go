package signature

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScheme(t *testing.T) {
	a := require.New(t)
	a.Equal(KECCAK256WithECDSA, SignatureScheme(0x0b), "fail")
	s := KECCAK256WithECDSA
	a.Equal(s.Name(), "KECCAK256WithECDSA", "fail")
}

func TestGetHash(t *testing.T) {
	a := require.New(t)

	hasher := GetHash(KECCAK256WithECDSA)
	h := hasher.Sum(nil)
	// empty hash of keccak256 is value below: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
	a.Equal("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", hex.EncodeToString(h), "fail")
}
