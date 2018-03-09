package ec

import (
	"crypto/elliptic"
	"errors"
	"strings"

	"github.com/OntologyNetwork/ont-crypto/sm2"
)

const (
	// ECDSA curve label
	P224 byte = 1
	P256 byte = 2
	P384 byte = 3
	P521 byte = 4

	// SM2 curve label
	SM2P256V1 byte = 20
)

func GetCurveLabel(c elliptic.Curve) (byte, error) {
	return GetNamedCurveLabel(c.Params().Name)
}

func GetCurve(label byte) (elliptic.Curve, error) {
	switch label {
	case P224:
		return elliptic.P224(), nil
	case P256:
		return elliptic.P256(), nil
	case P384:
		return elliptic.P384(), nil
	case P521:
		return elliptic.P521(), nil
	case SM2P256V1:
		return sm2.SM2P256V1(), nil
	default:
		return nil, errors.New("unknown elliptic curve")
	}

}

func GetNamedCurve(name string) (elliptic.Curve, error) {
	label, err := GetNamedCurveLabel(name)
	if err != nil {
		return nil, err
	}
	return GetCurve(label)
}

func GetNamedCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return P224, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return P256, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return P384, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return P521, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return SM2P256V1, nil
	default:
		return 0, errors.New("unsupported elliptic curve")
	}
}
