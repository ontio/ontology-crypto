# Ontology Crypto

Cryptography Library for Ontology Network

# Usage
## Key pair

Generate a key pair:

```go
import "github.com/ontio/ontology-crypto/keypair"

// Generate key pair
private, public, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
```

The first arguments indicates the key type used for specific algorithm.

Available key types:

    PK_ECDSA
    PK_SM2
    PK_EDDSA

The Second argument differs from the key types:

* as for to ECDSA, it indicates the curve which could be one of:

    `P224, P256, P384, P521`

* as for SM2, it indicates the curve similar to ECDSA but should be `SM2P256V1`.
* as for EdDSA, it sould be `ED25519`.


To serialize/deserialize the public key:

```
// Serialize public key
buf := keypair.SerializePublicKey(public)

// Deserialize public key
public, err := keypair.DeserializePublicKey(buf)
```

## Signature

To generate a signature for some message, a private key should be provided as
well as a specified signature scheme. Notice that the signature scheme should
match the private key.

Supported signture schemes:

    SHA224withECDSA
    SHA256withECDSA
    SHA384withECDSA
    SHA512withECDSA
    SHA3-224withECDSA
    SHA3-256withECDSA
    SHA3-384withECDSA
    SHA3-512withECDSA
    RIPEMD160withECDSA
    SM3withSM2
    SHA512withEdDSA

To verify a signature, just input the public key as well as the signature with
the original message.

```go
import "github.com/ontio/ontology-crypto/signature"

// Generate signature for @msg using private key @private
sig, err := signature.Sign(signature.SHA256withECDSA, private, msg, nil)

// Verify the signature using public key @public
ok := signature.Verify(public, msg, sig)
```

Serialization:

```
// Serialization
buf, err := signature.Serialize(sig)

// Deserialization
sig, err = signature.Deserialize(buf)
```

# License

Ontology Crypto is under LGPL v3.0 license. See [LICENSE](LICENSE) for details.
