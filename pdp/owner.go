package pdp

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"os"

	"github.com/ontio/ontology-crypto/ate-bn256"
)

/**
Description: data基于双线性映射产生的BLS哈希
*/
func blsHash(g1 *bn256.G1, data []byte, index int) *bn256.G1 {
	bigInt := new(big.Int).Add(new(big.Int).SetBytes(data), new(big.Int).SetInt64(int64(index)))
	g := new(bn256.G1).ScalarMult(g1, bigInt)
	return g
}

/*
Description: 随机唯一的文件表示
*/
func generateFileID(path string) ([sha256.Size]byte, error) {
	f, err := os.Open(path)
	if nil != err {
		return [sha256.Size]byte{}, err
	}

	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [sha256.Size]byte{}, err
	}

	sum := h.Sum(nil)

	var result [sha256.Size]byte
	copy(result[:], sum[:])

	return result, nil
}

/**
Description: 存储客户端调用该接口，初始化该文件相关的全局证明数据
Params:
	path:	待存储文件路径
Returns:
	return1:	椭圆曲线G的基数g	(需要保存)
	return2:	文件相关的随机辅助变量, 值为椭圆曲线上的点 (需要保存)
	return3:	文件证明操作所需的公钥	(需要保存)
	return4:	文件证明所需的私钥
	return5:	随机的唯一文件表示	(需要保存)
*/
func Init(path string) ([]byte, []byte, []byte, []byte, []byte) {
	defer func() {
		if r := recover(); r != nil {
			Init(path)
		}
	}()

	// In a real application, generate this once and publish it
	_, g, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, []byte{}
	}
	_, g0, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, []byte{}
	}
	privKey, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, nil, nil, []byte{}
	}
	pubKey := new(bn256.G2).ScalarMult(g, privKey)

	fileID, err := generateFileID(path)
	if nil != err {
		return nil, nil, nil, nil, []byte{}
	}

	return g.Marshal(), g0.Marshal(), pubKey.Marshal(), privKey.Bytes(), fileID[:]
}

/**
Description:  针对特定的文件Block内容，生成该BLock的同态认证元数据
Params:
	block:		文件块内容
	fid:		Init()接口返回的随机唯一文件表示
	index:		当前block在文件中的块序号
	g0：			Init()接口返回的文件相关的随机辅助变量
	privKey:	Init()接口返回的文件存储所需的私钥
Returns:
	return1:	文件块对应的同态认证数据标签
	return2:	Error内容
*/
func SignGenerate(block []byte, fid []byte, index uint32, g0Bytes, privKeyBytes []byte) ([]byte, error) {

	g0, res := new(bn256.G1).Unmarshal(g0Bytes)
	if res != nil {
		return nil, errors.New("Convert g0Bytes to G-point Error in sign-generate")
	}
	privKey := new(big.Int).SetBytes(privKeyBytes)

	hValue := blsHash(g0, fid, int(index))
	if nil == hValue {
		return nil, errors.New("SignGenerate Error(return nil), when run blsHash")
	}

	_block := sha256.Sum256(block)
	intBlock := new(big.Int).SetBytes(_block[:]) //得到大数
	y := new(bn256.G1).ScalarMult(g0, intBlock)
	mulValue := new(bn256.G1).Add(y, hValue)
	if nil == mulValue {
		return nil, errors.New("Generate Multi-Point Value Error")
	}

	tag := new(bn256.G1).ScalarMult(mulValue, privKey)
	if nil == hValue {
		return nil, errors.New("Generate homo tag for the block Error")
	}

	return tag.Marshal(), nil
}
