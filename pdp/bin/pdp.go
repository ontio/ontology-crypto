package main

import (
	"fmt"
	"flag"
	"runtime"
	"io/ioutil"

	"github.com/ontio/ontology-crypto/pdp"
	"time"
)

var action = struct {
	init         bool
	cpuNum       int
}{}

func main() {
	flag.IntVar(&action.cpuNum, "cpuNum",  4,"cpu number")
	flag.BoolVar(&action.init, "init",  false,"init parameters")
	flag.Parse()

	var err error
	pdpService := pdp.NewPdp(1)

	if action.init {
		pdpService.InitParameters("./circuit", "./vk")
		if err = ioutil.WriteFile("nonce", []byte("1234567812345678123456781234567"), 0600); err != nil {
			fmt.Printf("WriteFile nonce error: %s\n", err.Error())
			return
		}
		if err = ioutil.WriteFile("block", []byte("123123123123123123123123123123123123"), 0600); err != nil {
			fmt.Printf("WriteFile nonce error: %s\n", err.Error())
			return
		}
	} else {
		fmt.Printf("runtime.NumCPU(): %d\n", runtime.NumCPU())
		fmt.Printf("set CPUNum: %d\n", action.cpuNum)
		runtime.GOMAXPROCS(action.cpuNum)

		time1 := time.Now().Unix()
		fmt.Printf("start build & verify test, time: %d\n", time1)
		buf, err := ioutil.ReadFile("block")
		if err != nil {
			fmt.Printf("read block file error: %s\n", err.Error())
			return
		}

		hash := pdpService.FileBlockHash(buf)
		nonceBuf, err := ioutil.ReadFile("nonce")
		if err != nil {
			fmt.Printf("read nonce file error %s\n", err.Error())
			return
		}

		paramBuf, err := ioutil.ReadFile("circuit")
		if err != nil {
			fmt.Printf("read circuit file error %s\n", err.Error())
			return
		}

		proof := pdpService.GenProofWithPerBlock(buf, nonceBuf, paramBuf)
		fmt.Printf("output proof array: %x\n", proof)

		vk, err := ioutil.ReadFile("vk")
		if err != nil {
			fmt.Printf("read circuit file error %s\n", err)
			return
		}

		ret := pdpService.VerifyProofWithPerBlock(vk, proof, nonceBuf, hash)
		time2 := time.Now().Unix()
		if !ret {
			fmt.Printf("VerifyProofWithPerBlock failed, time: %d\n", time2)
		} else {
			fmt.Printf("VerifyProofWithPerBlock success, time: %d\n", time2)
			fmt.Printf("Used time: %d", time2 - time1)
		}

	}
}
