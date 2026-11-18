package keypair

import "testing"

func TestScryptLimits(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, p := range []*ScryptParam{nil, {N: 2, R: 0, P: 1, DKLen: 64}, {N: 2, R: 1, P: 0, DKLen: 64}, {N: 3, R: 1, P: 1, DKLen: 64}, {N: 2, R: -1, P: 1, DKLen: 64}, {N: 2, R: maxInt, P: 1, DKLen: 64}, {N: 2, R: 1, P: maxInt, DKLen: 64}, {N: 2, R: 1, P: 1, DKLen: maxInt}, {N: 1 << 21, R: 1, P: 1, DKLen: 64}, {N: 16384, R: 8, P: 129, DKLen: 64}} {
		if _, err := kdf([]byte("password"), []byte("salt"), p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	if _, err := kdf([]byte("password"), []byte("salt"), &ScryptParam{N: 2, R: 1, P: 1, DKLen: 64}); err != nil {
		t.Fatal(err)
	}
}
