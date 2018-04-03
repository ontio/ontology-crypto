package signature

import (
	"fmt"
	"testing"
)

func TestGetScheme(t *testing.T){
	SHA256withECDSA,_ := GetScheme("SHA256withECDSA")
	tmp,_ := GetScheme("")

	fmt.Printf("GetScheme('SHA256withECDSA'): %v \n", SHA256withECDSA)
	fmt.Printf("GetScheme(''): %v \n", tmp)
}
func TestGetHash(t *testing.T) {
	SHA256withECDSA, _ := GetScheme("SHA256withECDSA")
	GetHash(SHA256withECDSA)

	tmp, _ := GetScheme("")
	if( GetHash(tmp)!=nil ) {	t.Errorf("what???\n")}
}
func TestName(t *testing.T){
	for i:=0; i<11; i++ {
		SignatureScheme(i).Name()
	}
}