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

/*
 * Package sm4 implements the Chinese SM4 Digest Algorithm,
 * according to "go/src/crypto/aes"
 * author: weizhang <d5c5ceb0@gmail.com>
 * 2017.02.24
 */

package sm4

import (
	"testing"
)

type CryptTest struct {
	key  []byte
	in   []byte
	out  []byte
	out2 []byte
}

var encryptTests = []CryptTest{
	{
		// Appendix B.
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		[]byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46},
		[]byte{0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66},
	},
}

func TestCipherEncrypt(t *testing.T) {
	for i, tt := range encryptTests {
		c, err := NewCipher(tt.key)
		if err != nil {
			t.Errorf("NewCipher(%d bytes) = %s", len(tt.key), err)
			continue
		}
		out := make([]byte, len(tt.in))
		c.Encrypt(out, tt.in)
		for j, v := range out {
			if v != tt.out[j] {
				t.Errorf("Cipher.Encrypt %d: out[%d] = %#x, want %#x", i, j, v, tt.out[j])
				break
			}
		}

		out2 := make([]byte, len(tt.in))
		copy(out, tt.in)
		for i := 0; i < 1000000/2; i++ {
			c.Encrypt(out2, out)
			c.Encrypt(out, out2)
		}
		for j, v := range out {
			if v != tt.out2[j] {
				t.Errorf("Cipher.Encrypt %d: out[%d] = %#x, want %#x", i, j, v, tt.out[j])
				break
			}
		}
	}
}

func TestCipherDecrypt(t *testing.T) {
	for i, tt := range encryptTests {
		c, err := NewCipher(tt.key)
		if err != nil {
			t.Errorf("NewCipher(%d bytes) = %s", len(tt.key), err)
			continue
		}
		plain := make([]byte, len(tt.in))
		c.Decrypt(plain, tt.out)
		for j, v := range plain {
			if v != tt.in[j] {
				t.Errorf("decryptBlock %d: plain[%d] = %#x, want %#x", i, j, v, tt.in[j])
				break
			}
		}

		plain2 := make([]byte, len(tt.in))

		copy(plain, tt.out2)
		for i := 0; i < 1000000/2; i++ {
			c.Decrypt(plain2, plain)
			c.Decrypt(plain, plain2)
		}
		for j, v := range plain {
			if v != tt.in[j] {
				t.Errorf("decryptBlock %d: plain[%d] = %#x, want %#x", i, j, v, tt.in[j])
				break
			}
		}
	}
}

/*
// Test short input/output.
// Assembly used to not notice.
func TestShortBlocks(t *testing.T) {
	bytes := func(n int) []byte { return make([]byte, n) }

	c, _ := NewCipher(bytes(16))

	mustPanic(t, "sm4: input not full block", func() { c.Encrypt(bytes(1), bytes(1)) })
	mustPanic(t, "sm4: input not full block", func() { c.Decrypt(bytes(1), bytes(1)) })
	mustPanic(t, "sm4: input not full block", func() { c.Encrypt(bytes(100), bytes(1)) })
	mustPanic(t, "sm4: input not full block", func() { c.Decrypt(bytes(100), bytes(1)) })
	mustPanic(t, "sm4: output not full block", func() { c.Encrypt(bytes(1), bytes(100)) })
	mustPanic(t, "sm4: output not full block", func() { c.Decrypt(bytes(1), bytes(100)) })
}

func mustPanic(t *testing.T, msg string, f func()) {
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf("function did not panic, wanted %q", msg)
		} else if err != msg {
			t.Errorf("got panic %v, wanted %q", err, msg)
		}
	}()
	f()
}
*/

func BenchmarkEncrypt(b *testing.B) {
	tt := encryptTests[0]
	c, err := NewCipher(tt.key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.in))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(out, tt.in)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	tt := encryptTests[0]
	c, err := NewCipher(tt.key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.out))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(out, tt.out)
	}
}
