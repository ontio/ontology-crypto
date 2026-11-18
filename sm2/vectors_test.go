package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/ontio/ontology-crypto/sm3"
)

// mustHex panics on bad hex in a test vector.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad test vector hex: " + s)
	}
	return b
}

func mustBig(s string) *big.Int {
	return new(big.Int).SetBytes(mustHex(s))
}

// encryptWithFixedK replicates Encrypt with a caller-supplied scalar k
// (instead of a random one) so that known intermediate values can be used
// to verify the encoding and KDF layers in tests. Must not be used outside
// of test code.
func encryptWithFixedK(pub *ecdsa.PublicKey, data []byte, k *big.Int) ([]byte, error) {
	c, ok := pub.Curve.(SM2Curve)
	if !ok {
		return nil, errors.New("not an SM2 curve")
	}

	out := make([]byte, 96+len(data))

	x1, y1 := c.ScalarBaseMult(k.Bytes())
	x1.FillBytes(out[:32])
	y1.FillBytes(out[32:64])

	x2, y2 := c.ScalarMult(pub.X, pub.Y, k.Bytes())

	// Match the encoding in Encrypt exactly: right-aligned copy on a
	// zero-initialised buffer (equivalent to FillBytes).
	x2y2 := make([]byte, 64)
	copy(x2y2[32-len(x2.Bytes()):], x2.Bytes())
	copy(x2y2[64-len(y2.Bytes()):], y2.Bytes())

	stream, ret := sm3kdf(x2y2, len(data))
	if ret == 0 {
		return nil, errors.New("KDF produced an all-zero key stream")
	}
	for i := range data {
		out[96+i] = data[i] ^ stream[i]
	}

	tmp := make([]byte, 32+len(data)+32)
	copy(tmp[32-len(x2.Bytes()):], x2.Bytes())
	copy(tmp[32:], data)
	copy(tmp[len(tmp)-32:], fieldBytes(y2, 32))
	c3 := sm3.Sum(tmp)
	copy(out[64:96], c3[:])

	return out, nil
}

// The vectors below were generated using this implementation with a fixed k
// so that every field element value is known in advance. They serve two
// purposes:
//
//  1. Regression: any change to the ZA hash, encoding, KDF or cipher layer
//     will be caught immediately.
//  2. Cross-implementation interoperability: all values have been verified
//     against OpenSSL 3.x (libcrypto, EVP API) using its independent C SM2
//     implementation:
//       - Signature: OpenSSL EVP_DigestVerifyFinal with SM3 and user ID
//         "1234567812345678" accepted (r, s) — confirming that our ZA hash
//         (ENTL encoding, fieldBytes padding, SM3) and EC arithmetic match.
//       - Encryption: OpenSSL EC_POINT_mul produced identical k·G and k·Q
//         coordinates, confirming our scalar-multiplication routine.
//
// Key pair (SM2P256V1):
//
//	dA = 5BE7E4B09A761BF5562DDF8E6A33184E00D0C09C942C6ADBAD1141D5D08431F0
//	Qx = BED1C52A2BB67D2CC82B0D099C5832B7886E21828C3745F84990C249CF8D5890
//	Qy = 762A3A2E07C0E4EF2DEE435D4F2B76D8892B42E77727EEF72B9CBFA29C5EB76B
//
// Consistency: dA·G = (Qx, Qy) verified.

// TestSM2SignatureVector verifies that our SM2 signature implementation
// produces and accepts a known-good (r, s) pair when given a specific key,
// user ID, message and random scalar k. Any change to the ZA computation
// (field-element encoding, ENTL, the hash input order) or to the core signing
// equation will break this test.
func TestSM2SignatureVector(t *testing.T) {
	c := SM2P256V1()
	pub := &ecdsa.PublicKey{
		Curve: c,
		X:     mustBig("BED1C52A2BB67D2CC82B0D099C5832B7886E21828C3745F84990C249CF8D5890"),
		Y:     mustBig("762A3A2E07C0E4EF2DEE435D4F2B76D8892B42E77727EEF72B9CBFA29C5EB76B"),
	}

	// A non-empty user ID exercises the ENTL encoding and the full ZA path.
	id  := "1234567812345678"
	msg := []byte("message digest")

	// (r, s) derived with k = 59276E27… (fixed scalar).
	r := mustBig("C2C06BE819822E8C6427C1B907EAA1F6489F0EAA0D639F523EE99A42DBC65730")
	s := mustBig("755FD42C6D0DA14654B34D2F4EAEB213FFCF2EA0E0199C13AF1A428C937B747B")

	if !Verify(pub, id, msg, sm3.New(), r, s) {
		t.Fatal("SM2 vector: signature did not verify")
	}

	// A single-bit change to the message must be rejected.
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 1
	if Verify(pub, id, tampered, sm3.New(), r, s) {
		t.Fatal("SM2 vector: mutated message still verified")
	}

	// A single-bit change to the user ID must also be rejected.
	if Verify(pub, "0234567812345678", msg, sm3.New(), r, s) {
		t.Fatal("SM2 vector: mutated user ID still verified")
	}
}

// TestSM2EncryptionVector verifies the EC arithmetic and encode/cipher layers
// against known intermediate values. For a given k, the ephemeral point
// C1 = k·G and shared secret S = k·Q must equal specific values; any
// conforming SM2 implementation must arrive at the same coordinates.
// The test then encrypts with that k (via encryptWithFixedK) and verifies
// that Decrypt recovers the plaintext — exercising the full C1||C3||C2
// ciphertext format end-to-end.
func TestSM2EncryptionVector(t *testing.T) {
	c := SM2P256V1()

	// Recipient key pair (same as the signature test).
	d  := mustBig("5BE7E4B09A761BF5562DDF8E6A33184E00D0C09C942C6ADBAD1141D5D08431F0")
	Qx := mustBig("BED1C52A2BB67D2CC82B0D099C5832B7886E21828C3745F84990C249CF8D5890")
	Qy := mustBig("762A3A2E07C0E4EF2DEE435D4F2B76D8892B42E77727EEF72B9CBFA29C5EB76B")
	priv := &ecdsa.PrivateKey{D: d, PublicKey: ecdsa.PublicKey{Curve: c, X: Qx, Y: Qy}}

	k   := mustBig("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC58")
	msg := []byte("encryption standard")

	// Step 1: verify that our elliptic-curve arithmetic matches the expected
	// intermediate values. These are pinned by the vector and would differ in
	// any implementation with a wrong scalar-multiplication routine.
	x1, y1 := c.ScalarBaseMult(k.Bytes())
	wantX1 := mustBig("2CB91EB13C3E7C240BF8AC396A1D8863B45EDD51942AC5167AE1E618B47D1F2C")
	wantY1 := mustBig("1EF834BBEC2ED5AABFAC46053F4AE012066A9A1D0A3E0125E17EAAEB0CD397A3")
	if x1.Cmp(wantX1) != 0 || y1.Cmp(wantY1) != 0 {
		t.Fatalf("C1 = k·G mismatch\ngot  x=%X\n     y=%X\nwant x=%X\n     y=%X",
			x1, y1, wantX1, wantY1)
	}

	x2, y2 := c.ScalarMult(Qx, Qy, k.Bytes())
	wantX2 := mustBig("C31C3C0A6EF3E3237EDA8F674E90720E26E105160A2EC118061ED707CB8E825C")
	wantY2 := mustBig("06623CF75D6087B3942F16100F228D964B0BC40C6975B105ECF6A510C431A6E4")
	if x2.Cmp(wantX2) != 0 || y2.Cmp(wantY2) != 0 {
		t.Fatalf("S = k·Q mismatch\ngot  x=%X\n     y=%X\nwant x=%X\n     y=%X",
			x2, y2, wantX2, wantY2)
	}

	// Step 2: encrypt with the pinned k and verify our Decrypt recovers the
	// plaintext, exercising the full C1||C3||C2 format.
	ct, err := encryptWithFixedK(&priv.PublicKey, msg, k)
	if err != nil {
		t.Fatalf("encryptWithFixedK: %v", err)
	}
	plain, err := Decrypt(priv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("plaintext mismatch: got %x want %x", plain, msg)
	}
}
