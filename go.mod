module github.com/ontio/ontology-crypto

go 1.18

require (
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/ethereum/go-ethereum v1.9.25
	github.com/itchyny/base58-go v0.1.0
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20210809222454-d867a43fc93e // indirect
	gopkg.in/yaml.v2 v2.3.0 // indirect
)

// Historical Ontology fork of golang.org/x/crypto. It is kept pinned until the
// upstream module has been validated against the standard vectors and the
// downstream users of this library; removing it blindly changes the ed25519
// implementation in use.
replace golang.org/x/crypto => github.com/golang/crypto v0.0.0-20191029031824-8986dd9e96cf
