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

package pdp

import (
	"testing"
	"fmt"
	"crypto/rand"
)

func TestFilePdpHashSt_Serialize(t *testing.T) {
	var filePdpHashSt FilePdpHashSt

	pdpHash := make([]byte, 32)
	for i := 0; i < 4; i ++ {
		rand.Read(pdpHash)
		filePdpHashSt.BlockPdpHashes = append(filePdpHashSt.BlockPdpHashes, pdpHash)
	}

	filePdpHashStr1 := fmt.Sprintf("%v\n", filePdpHashSt)

	data := filePdpHashSt.Serialize()

	var filePdpHashSt2 FilePdpHashSt
	if err := filePdpHashSt2.Deserialize(data); err != nil {
		t.Errorf(err.Error())
	}

	filePdpHashStr2 := fmt.Sprintf("%v\n", filePdpHashSt2)
	if filePdpHashStr1 != filePdpHashStr2 {
		t.Error("Serialize failed")
	}
}