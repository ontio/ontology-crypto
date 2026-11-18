# Authenticated private-key format

New encryption writes `aes-256-gcm-v2`. Its GCM additional authenticated data
is the JSON encoding of the fields Domain (the encryption algorithm label),
Address, Algorithm, Parameters, Salt and Hash, in that order. Parameter map
keys use Go encoding/json's sorted ordering; byte slices use base64 encoding.
The existing scrypt derivation and ciphertext layout are unchanged.

Use `DecryptAuthenticatedPrivateKey` for untrusted files: it accepts only v2
and rejects format downgrades. Older library versions cannot read v2.

`DecryptPrivateKey` and `DecryptWithCustomScrypt` retain legacy import support.
They cannot guarantee legacy metadata integrity, and must not be used where
authenticated metadata is required. Import legacy files only with an explicit
trust decision, verify the resulting public key/address against a trusted
record, and migrate with `ReencryptPrivateKey`, which writes v2. This library
does not define an address derivation scheme and cannot perform that identity
check for callers.

Encryption rejects empty passwords, matching decryption. The signature package
rejects NUL-containing SM2 IDs because its wire format uses NUL as a delimiter;
the lower-level SM2 signing algorithm continues to support arbitrary ID bytes.

Custom scrypt parameters must have a power-of-two N greater than one, positive
R/P, and DKLen between 32 and 1024. Derivation is limited to an estimated
256 MiB of scrypt buffers and N*R*P <= 16,777,216. Existing key files exceeding
these limits are rejected; defaults remain supported.

For Ethereum signatures, pair Sign(..., true) with VerifyEthereumMessage and
Sign(..., false) with VerifyEthereumDigest. The latter requires exactly 32
bytes. Legacy Verify retains its length-based interpretation for compatibility;
it cannot distinguish a 32-byte message from a digest.
