package pdp

const Version = uint64(1)

type Block struct {
	Buffer BlockBuf
}

/*BlockBuf is a array that store one block which is generated from a file*/
type BlockBuf []byte

type Element struct {
	Buffer []byte
}

type Challenge struct {
	Index uint32
	Rand  uint32
}
