package signature

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScheme(t *testing.T) {
	a := require.New(t)
	a.Equal(KECCAK256WithECDSA, SignatureScheme(0x0b), "fail")
	s := KECCAK256WithECDSA
	a.Equal(s.Name(), "KECCAK256WithECDSA", "fail")
}

func TestAddr(t *testing.T) {

}
