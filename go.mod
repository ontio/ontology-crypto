module github.com/ontio/ontology-crypto

go 1.12

require (
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/itchyny/base58-go v0.1.0
	golang.org/x/crypto v0.0.0-20191029031824-8986dd9e96cf
)

replace golang.org/x/crypto => github.com/golang/crypto v0.0.0-20191029031824-8986dd9e96cf
