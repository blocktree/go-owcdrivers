package hcTransaction

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"testing"
)

func TestDecode(t *testing.T) {
	hcaddr := "HsX5APCXSpR49Ei1xnivBbTW35VqzaTARrX"
	hchash,_:=Decode(hcaddr, BitcoinAlphabet)
	fmt.Println(hex.EncodeToString(hchash))
	// 097fccee8d2713d60aaf8b67d8f8c54850ffacf18ff4 7e589864
	hash := owcrypt.Hash(hchash[:22], 0, owcrypt.HASH_ALG_BLAKE256)
	hash = owcrypt.Hash(hash, 0, owcrypt.HASH_ALG_BLAKE256)
	fmt.Println(hex.EncodeToString(hash))


	data ,_ := hex.DecodeString("01000000015bc8f84fdb914c0dae04d57a78bd4d0468b8c1c0e5fb22e81ac9b3057acdc5cf0200000000ffffffff02e0e8fbb30400000000001976a9142397dfb31634cda1df23fe2f4c5bfaa4355d431f88ac2c2d06bd6500000000001976a914d51c3a8a8234538336c93001d14f4e28d4d8e80c88ac0000000000000000")

	hash = owcrypt.Hash(data, 0, owcrypt.HASH_ALG_BLAKE256)
	fmt.Println(hex.EncodeToString(hash))

	pk,_:= hex.DecodeString("02289cfae6175cf7819007fd819a17da4514edbd428cee15267b14235bf970abf5")
	pk=owcrypt.PointDecompress(pk, owcrypt.ECC_CURVE_SECP256K1)
	fmt.Println(hex.EncodeToString(pk[1:]))

	pre, _ := hex.DecodeString("01000100015bc8f84fdb914c0dae04d57a78bd4d0468b8c1c0e5fb22e81ac9b3057acdc5cf0200000000ffffffff02e0e8fbb30400000000001976a9142397dfb31634cda1df23fe2f4c5bfaa4355d431f88ac2c2d06bd6500000000001976a914d51c3a8a8234538336c93001d14f4e28d4d8e80c88ac0000000000000000")

	witness,_ := hex.DecodeString("01000300011976a914d51c3a8a8234538336c93001d14f4e28d4d8e80c88ac")

	prehash := owcrypt.Hash(pre, 0, owcrypt.HASH_ALG_BLAKE256)
	whash := owcrypt.Hash(witness, 0, owcrypt.HASH_ALG_BLAKE256)

	data1,_ := hex.DecodeString("01000000")

	data1 = append(data1, prehash...)
	data1 = append(data1, whash...)
	fmt.Println(hex.EncodeToString(data1))

	txhash := owcrypt.Hash(data1, 0, owcrypt.HASH_ALG_BLAKE256)
	fmt.Println(hex.EncodeToString(txhash))


}