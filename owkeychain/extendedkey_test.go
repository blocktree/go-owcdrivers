package owkeychain

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/blocktree/go-owcrypt"
)

//normal private key extend based on secp256k1 private key
func Test_GenPrivateChild_fromPrivate_secp256k1_normal(t *testing.T) {

	passFlag := true
	//test cases based on secp256k1
	//set root private key
	rootPri := [32]byte{0x9e, 0xa1, 0x9e, 0x6e, 0xc2, 0x59, 0xf7, 0x85, 0x4e, 0xe4, 0x1b, 0x53, 0x07, 0xcf, 0xc4, 0xb8, 0xf4, 0x47, 0x75, 0x34, 0x20, 0x5e, 0xc9, 0x83, 0xc4, 0xd3, 0xa9, 0xb5, 0x6c, 0x0b, 0x27, 0x0c}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPriKey := NewExtendedKey(rootPri[:], rootChainCode[:], rootParentFP[:], 0, 0, true, owcrypt.ECC_CURVE_SECP256K1)

	//print root private key
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Println("父私钥 -----> 普通子私钥")
	fmt.Println("root private key data:")
	fmt.Println("key:", hex.EncodeToString(rooPriKey.key))
	fmt.Println("chaincode:", hex.EncodeToString(rooPriKey.chainCode))
	fmt.Println("parent FP:", hex.EncodeToString(rooPriKey.parentFP))
	fmt.Println("dpth:", rooPriKey.depth)
	fmt.Println("serializes", rooPriKey.serializes)
	fmt.Println("private flag:", rooPriKey.isPrivate)

	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

	//normal extend , serializes = 0x0
	serialize := uint32(0)
	//expect data
	expectChildPri := "f938a2e7fef45315b9b0c31b4db08e23a84b362e71876e7fc1880b2ea94e38f1"
	expectChildChainCode := "a9e25b8ef131d1180292e8b7ef967347004ed436abf02ea14929325952f72809"
	expectChildParentFP := "fb080f46"
	expectChildDpth := uint8(1)
	expectChildSerialize := serialize
	expectChildPriFlag := true

	childPriKey, err := rooPriKey.GenPrivateChild(serialize)

	if err != nil {
		t.Error("父私钥向子私钥扩展出错")
	} else {
		//check the result
		if expectChildPri != hex.EncodeToString(childPriKey.key) {
			t.Error("扩展的子私钥数据错误")
			passFlag = false
		}

		if expectChildChainCode != hex.EncodeToString(childPriKey.chainCode) {
			t.Error("扩展的子私钥链码数据错误")
			passFlag = false
		}

		if expectChildParentFP != hex.EncodeToString(childPriKey.parentFP) {
			t.Error("扩展的子私钥父指纹数据错误")
			passFlag = false
		}

		if expectChildDpth != childPriKey.depth {
			t.Error("扩展的子私钥深度数据错误")
			passFlag = false
		}

		if expectChildSerialize != childPriKey.serializes {
			t.Error("扩展的子私钥索引号数据错误")
			passFlag = false
		}

		if expectChildPriFlag != childPriKey.isPrivate {
			t.Error("扩展的子私钥公私钥标记数据错误")
			passFlag = false
		}
		//print child private key
		if passFlag {
			fmt.Println("child private key data:")
			fmt.Println("key:", hex.EncodeToString(childPriKey.key))
			fmt.Println("chaincode:", hex.EncodeToString(childPriKey.chainCode))
			fmt.Println("parent FP:", hex.EncodeToString(childPriKey.parentFP))
			fmt.Println("dpth:", childPriKey.depth)
			fmt.Println("serializes", childPriKey.serializes)
			fmt.Println("private flag:", childPriKey.isPrivate)
		}

		fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	}

}

//normal public key extend based on secp256k1 private key
func Test_GenPublicChild_fromPrivate_secp256k1_normal(t *testing.T) {
	passFlag := true

	//test cases based on secp256k1
	//set root private key
	rootPri := [32]byte{0x9e, 0xa1, 0x9e, 0x6e, 0xc2, 0x59, 0xf7, 0x85, 0x4e, 0xe4, 0x1b, 0x53, 0x07, 0xcf, 0xc4, 0xb8, 0xf4, 0x47, 0x75, 0x34, 0x20, 0x5e, 0xc9, 0x83, 0xc4, 0xd3, 0xa9, 0xb5, 0x6c, 0x0b, 0x27, 0x0c}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPriKey := NewExtendedKey(rootPri[:], rootChainCode[:], rootParentFP[:], 0, 0, true, owcrypt.ECC_CURVE_SECP256K1)

	//print root private key
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Println("父私钥 -----> 普通子公钥")
	fmt.Println("root private key data:")
	fmt.Println("key:", hex.EncodeToString(rooPriKey.key))
	fmt.Println("chaincode:", hex.EncodeToString(rooPriKey.chainCode))
	fmt.Println("parent FP:", hex.EncodeToString(rooPriKey.parentFP))
	fmt.Println("dpth:", rooPriKey.depth)
	fmt.Println("serializes", rooPriKey.serializes)
	fmt.Println("private flag:", rooPriKey.isPrivate)

	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

	//normal extend , serializes = 0x0
	serialize := uint32(0)
	//expect data
	expectChildPub := "0347e1f04775f36482cf78ea6d028ac71ab423199e37e04cbb448f31f973a63bba"
	expectChildChainCode := "a9e25b8ef131d1180292e8b7ef967347004ed436abf02ea14929325952f72809"
	expectChildParentFP := "fb080f46"
	expectChildDpth := uint8(1)
	expectChildSerialize := serialize
	expectChildPriFlag := false

	childPubKey, err := rooPriKey.GenPublicChild(serialize)

	if err != nil {
		t.Error("父私钥向子私钥扩展出错")
	} else {
		//check the result
		if expectChildPub != hex.EncodeToString(childPubKey.key) {
			t.Error("扩展的子私钥数据错误")
			passFlag = false
		}

		if expectChildChainCode != hex.EncodeToString(childPubKey.chainCode) {
			t.Error("扩展的子私钥链码数据错误")
			passFlag = false
		}

		if expectChildParentFP != hex.EncodeToString(childPubKey.parentFP) {
			t.Error("扩展的子私钥父指纹数据错误")
			passFlag = false
		}

		if expectChildDpth != childPubKey.depth {
			t.Error("扩展的子私钥深度数据错误")
			passFlag = false
		}

		if expectChildSerialize != childPubKey.serializes {
			t.Error("扩展的子私钥索引号数据错误")
			passFlag = false
		}

		if expectChildPriFlag != childPubKey.isPrivate {
			t.Error("扩展的子私钥公私钥标记数据错误")
			passFlag = false
		}
		//print child private key
		if passFlag {
			fmt.Println("child public key data:")
			fmt.Println("key:", hex.EncodeToString(childPubKey.key))
			fmt.Println("chaincode:", hex.EncodeToString(childPubKey.chainCode))
			fmt.Println("parent FP:", hex.EncodeToString(childPubKey.parentFP))
			fmt.Println("dpth:", childPubKey.depth)
			fmt.Println("serializes", childPubKey.serializes)
			fmt.Println("private flag:", childPubKey.isPrivate)
		}

		fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	}
}

//HD private key extend based on secp256k1 private key
func Test_GenPrivateChild_fromPrivate_secp256k1_hd(t *testing.T) {
	passFlag := true
	//test cases based on secp256k1
	//set root private key
	rootPri := [32]byte{0x9e, 0xa1, 0x9e, 0x6e, 0xc2, 0x59, 0xf7, 0x85, 0x4e, 0xe4, 0x1b, 0x53, 0x07, 0xcf, 0xc4, 0xb8, 0xf4, 0x47, 0x75, 0x34, 0x20, 0x5e, 0xc9, 0x83, 0xc4, 0xd3, 0xa9, 0xb5, 0x6c, 0x0b, 0x27, 0x0c}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPriKey := NewExtendedKey(rootPri[:], rootChainCode[:], rootParentFP[:], 0, 0, true, owcrypt.ECC_CURVE_SECP256K1)

	//print root private key
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Println("父私钥 -----> 强化子私钥")
	fmt.Println("root private key data:")
	fmt.Println("key:", hex.EncodeToString(rooPriKey.key))
	fmt.Println("chaincode:", hex.EncodeToString(rooPriKey.chainCode))
	fmt.Println("parent FP:", hex.EncodeToString(rooPriKey.parentFP))
	fmt.Println("dpth:", rooPriKey.depth)
	fmt.Println("serializes", rooPriKey.serializes)
	fmt.Println("private flag:", rooPriKey.isPrivate)

	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

	//HD extend , serializes = 0x80000000
	serialize := uint32(0x80000000)
	//expect data
	expectChildPri := "54d5bf2f8f82107ef1cd6a55c10a852643bde4653bfd4faa8d5ca1c14d9e7120"
	expectChildChainCode := "8f1b8987c2d267d31980afce919f0276cb93e98972d6e27d3ba79550f729cce1"
	expectChildParentFP := "fb080f46"
	expectChildDpth := uint8(1)
	expectChildSerialize := serialize
	expectChildPriFlag := true

	childPriKey, err := rooPriKey.GenPrivateChild(serialize)

	if err != nil {
		t.Error("父私钥向子私钥扩展出错")
	} else {
		//check the result
		if expectChildPri != hex.EncodeToString(childPriKey.key) {
			t.Error("扩展的子私钥数据错误")
			passFlag = false
		}

		if expectChildChainCode != hex.EncodeToString(childPriKey.chainCode) {
			t.Error("扩展的子私钥链码数据错误")
			passFlag = false
		}

		if expectChildParentFP != hex.EncodeToString(childPriKey.parentFP) {
			t.Error("扩展的子私钥父指纹数据错误")
			passFlag = false
		}

		if expectChildDpth != childPriKey.depth {
			t.Error("扩展的子私钥深度数据错误")
			passFlag = false
		}

		if expectChildSerialize != childPriKey.serializes {
			t.Error("扩展的子私钥索引号数据错误")
			passFlag = false
		}

		if expectChildPriFlag != childPriKey.isPrivate {
			t.Error("扩展的子私钥公私钥标记数据错误")
			passFlag = false
		}
		//print child private key
		if passFlag {
			fmt.Println("child private key data:")
			fmt.Println("key:", hex.EncodeToString(childPriKey.key))
			fmt.Println("chaincode:", hex.EncodeToString(childPriKey.chainCode))
			fmt.Println("parent FP:", hex.EncodeToString(childPriKey.parentFP))
			fmt.Println("dpth:", childPriKey.depth)
			fmt.Println("serializes", childPriKey.serializes)
			fmt.Println("private flag:", childPriKey.isPrivate)
		}

		fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	}

}

//HD public key extend based on secp256k1 private key
func Test_GenPublicChild_fromPrivate_secp256k1_hd(t *testing.T) {

	passFlag := true
	//test cases based on secp256k1
	//set root private key
	rootPri := [32]byte{0x9e, 0xa1, 0x9e, 0x6e, 0xc2, 0x59, 0xf7, 0x85, 0x4e, 0xe4, 0x1b, 0x53, 0x07, 0xcf, 0xc4, 0xb8, 0xf4, 0x47, 0x75, 0x34, 0x20, 0x5e, 0xc9, 0x83, 0xc4, 0xd3, 0xa9, 0xb5, 0x6c, 0x0b, 0x27, 0x0c}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPriKey := NewExtendedKey(rootPri[:], rootChainCode[:], rootParentFP[:], 0, 0, true, owcrypt.ECC_CURVE_SECP256K1)

	//print root private key
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Println("父私钥 -----> 强化子公钥")
	fmt.Println("root private key data:")
	fmt.Println("key:", hex.EncodeToString(rooPriKey.key))
	fmt.Println("chaincode:", hex.EncodeToString(rooPriKey.chainCode))
	fmt.Println("parent FP:", hex.EncodeToString(rooPriKey.parentFP))
	fmt.Println("dpth:", rooPriKey.depth)
	fmt.Println("serializes", rooPriKey.serializes)
	fmt.Println("private flag:", rooPriKey.isPrivate)

	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

	//normal extend , serializes = 0x80000000
	serialize := uint32(0x80000000)
	//expect data
	expectChildPub := "03f6130e91673fea46204c6f05115c501421fd1ff038ab8c3371e8e81a6060a8e4"
	expectChildChainCode := "8f1b8987c2d267d31980afce919f0276cb93e98972d6e27d3ba79550f729cce1"
	expectChildParentFP := "fb080f46"
	expectChildDpth := uint8(1)
	expectChildSerialize := serialize
	expectChildPriFlag := false

	childPubKey, err := rooPriKey.GenPublicChild(serialize)

	if err != nil {
		t.Error("父私钥向子私钥扩展出错")
	} else {
		//check the result
		if expectChildPub != hex.EncodeToString(childPubKey.key) {
			t.Error("扩展的子私钥数据错误")
			passFlag = false
		}

		if expectChildChainCode != hex.EncodeToString(childPubKey.chainCode) {
			t.Error("扩展的子私钥链码数据错误")
			passFlag = false
		}

		if expectChildParentFP != hex.EncodeToString(childPubKey.parentFP) {
			t.Error("扩展的子私钥父指纹数据错误")
			passFlag = false
		}

		if expectChildDpth != childPubKey.depth {
			t.Error("扩展的子私钥深度数据错误")
			passFlag = false
		}

		if expectChildSerialize != childPubKey.serializes {
			t.Error("扩展的子私钥索引号数据错误")
			passFlag = false
		}

		if expectChildPriFlag != childPubKey.isPrivate {
			t.Error("扩展的子私钥公私钥标记数据错误")
			passFlag = false
		}
		//print child private key
		if passFlag {
			fmt.Println("child public key data:")
			fmt.Println("key:", hex.EncodeToString(childPubKey.key))
			fmt.Println("chaincode:", hex.EncodeToString(childPubKey.chainCode))
			fmt.Println("parent FP:", hex.EncodeToString(childPubKey.parentFP))
			fmt.Println("dpth:", childPubKey.depth)
			fmt.Println("serializes", childPubKey.serializes)
			fmt.Println("private flag:", childPubKey.isPrivate)
		}

		fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	}
}

//normal private key extend based on secp256k1 public key
func Test_GenPrivateChild_fromPublic_secp256k1_normal(t *testing.T) {

	//test cases based on secp256k1
	//set root public key
	rootPub := [33]byte{0x02, 0x83, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPubKey := NewExtendedKey(rootPub[:], rootChainCode[:], rootParentFP[:], 0, 0, false, owcrypt.ECC_CURVE_SECP256K1)
	serialize := uint32(0)
	childPriKey, err := rooPubKey.GenPrivateChild(serialize)
	fmt.Println("父公钥 -----> 普通子私钥")
	if childPriKey != nil {
		t.Error("未能检出父公钥派生子私钥的非法操作")
	}
	if err != ErrNotPrivExtKey {
		t.Error("抛出了错误的异常")
	}

}

//HD private key extend based on secp256k1 public key
func Test_GenPrivateChild_fromPublic_secp256k1_HD(t *testing.T) {

	//test cases based on secp256k1
	//set root public key
	rootPub := [33]byte{0x02, 0x83, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPubKey := NewExtendedKey(rootPub[:], rootChainCode[:], rootParentFP[:], 0, 0, false, owcrypt.ECC_CURVE_SECP256K1)
	serialize := uint32(0x80000000)
	childPriKey, err := rooPubKey.GenPrivateChild(serialize)
	fmt.Println("父公钥 -----> 强化子私钥")
	if childPriKey != nil {
		t.Error("未能检出父公钥派生子私钥的非法操作")
	}
	if err != ErrNotPrivExtKey {
		t.Error("抛出了错误的异常")
	}

}

//normal public key extend based on secp256k1 public key
func Test_GenPublicChild_fromPublic_secp256k1_normal(t *testing.T) {

	passFlag := true
	//test cases based on secp256k1
	//set root public key
	rootPub := [33]byte{0x02, 0x83, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPubKey := NewExtendedKey(rootPub[:], rootChainCode[:], rootParentFP[:], 0, 0, false, owcrypt.ECC_CURVE_SECP256K1)

	//print root private key
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Println("父公钥 -----> 普通子公钥")
	fmt.Println("root private key data:")
	fmt.Println("key:", hex.EncodeToString(rooPubKey.key))
	fmt.Println("chaincode:", hex.EncodeToString(rooPubKey.chainCode))
	fmt.Println("parent FP:", hex.EncodeToString(rooPubKey.parentFP))
	fmt.Println("dpth:", rooPubKey.depth)
	fmt.Println("serializes", rooPubKey.serializes)
	fmt.Println("private flag:", rooPubKey.isPrivate)

	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	serialize := uint32(0)
	//expect data
	expectChildPub := "0347e1f04775f36482cf78ea6d028ac71ab423199e37e04cbb448f31f973a63bba"
	expectChildChainCode := "a9e25b8ef131d1180292e8b7ef967347004ed436abf02ea14929325952f72809"
	expectChildParentFP := "fb080f46"
	expectChildDpth := uint8(1)
	expectChildSerialize := serialize
	expectChildPriFlag := false
	childPubKey, err := rooPubKey.GenPublicChild(serialize)

	if err != nil {
		t.Error("父公钥向普通子公钥扩展错误")
	} else {
		if expectChildPub != hex.EncodeToString(childPubKey.key) {
			t.Error("扩展的子公钥数据错误")
			passFlag = false
		}
		if expectChildChainCode != hex.EncodeToString(childPubKey.chainCode) {
			t.Error("扩展的子公钥链码数据错误")
			passFlag = false
		}
		if expectChildParentFP != hex.EncodeToString(childPubKey.parentFP) {
			t.Error("扩展的子公钥父指纹数据错误")
			passFlag = false
		}
		if expectChildDpth != childPubKey.depth {
			t.Error("扩展的子公钥深度数据错误")
			passFlag = false
		}
		if expectChildSerialize != childPubKey.serializes {
			t.Error("扩展的子公钥索引号数据错误")
			passFlag = false
		}
		if expectChildPriFlag != childPubKey.isPrivate {
			t.Error("扩展的子公钥私钥标记数据错误")
			passFlag = false
		}
	}
	if passFlag {
		fmt.Println("child public key data:")
		fmt.Println("key:", hex.EncodeToString(childPubKey.key))
		fmt.Println("chaincode:", hex.EncodeToString(childPubKey.chainCode))
		fmt.Println("parent FP:", hex.EncodeToString(childPubKey.parentFP))
		fmt.Println("dpth:", childPubKey.depth)
		fmt.Println("serializes", childPubKey.serializes)
		fmt.Println("private flag:", childPubKey.isPrivate)
		fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	}

}

//HD public key extend based on secp256k1 public key
func Test_GenPublicChild_fromPublic_secp256k1_HD(t *testing.T) {

	//test cases based on secp256k1
	//set root public key
	rootPub := [33]byte{0x02, 0x83, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPubKey := NewExtendedKey(rootPub[:], rootChainCode[:], rootParentFP[:], 0, 0, false, owcrypt.ECC_CURVE_SECP256K1)
	serialize := uint32(0x80000000)

	childPubKey, err := rooPubKey.GenPublicChild(serialize)
	fmt.Println("父公钥 -----> 强化子公钥")
	if childPubKey != nil {
		t.Error("未检出父公钥扩展强化子密钥的非法操作")
	}
	if err != ErrDeriveHardFromPublic {
		t.Error("抛出了错误的异常")
	}
}

func Test_DerivedPublicKeyFromPath(t *testing.T) {
	rootPub := [33]byte{0x02, 0x83, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}
	rootChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	rootParentFP := [4]byte{0, 0, 0, 0}

	rooPubKey := NewExtendedKey(rootPub[:], rootChainCode[:], rootParentFP[:], 0, 0, false, owcrypt.ECC_CURVE_SECP256K1)

	path := "/0/0"

	childPubkey, err := rooPubKey.DerivedPublicKeyFromPath(path)
	fmt.Println(err)
	if err != nil {
		t.Error("相对路径扩展错误")
	}

	fmt.Println(hex.EncodeToString(childPubkey.key))
	fmt.Println(childPubkey.isPrivate)
	fmt.Println(hex.EncodeToString(childPubkey.chainCode))
}

func Test_DerivedPublicKeyFromSerializes(t *testing.T) {
	parentPub := [33]byte{0x02, 0x83, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}
	parentChainCode := [32]byte{0xab, 0xc9, 0xcc, 0x46, 0xa8, 0x16, 0x6d, 0x81, 0x55, 0xac, 0x1e, 0xd1, 0x2b, 0xe4, 0x11, 0xcd, 0x21, 0x3a, 0x3e, 0x28, 0xe4, 0xef, 0x46, 0x46, 0xfe, 0x03, 0xd7, 0x00, 0x2f, 0xef, 0x15, 0x2c}
	parentParentFP := [4]byte{0, 0, 0, 0}

	parentPubKey := NewExtendedKey(parentPub[:], parentChainCode[:], parentParentFP[:], 0, 0, false, owcrypt.ECC_CURVE_SECP256K1)

	for i := uint32(0); i < 100; i++ {
		tmp, err := parentPubKey.DerivedPublicKeyFromSerializes(i)
		if err != nil {
			t.Error(i)
		} else {
			fmt.Println(hex.EncodeToString(tmp.key))
		}
	}

}

func TestDecompressPoint(t *testing.T) {
	pin := [32]byte{0x83, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}

	for i := 0; i < 100; i++ {
		owcrypt.Point_mulBaseG(pin[:], owcrypt.ECC_CURVE_SECP256K1)
		//owcrypt.GenPubkey(pin[:], owcrypt.ECC_CURVE_SECP256K1)
		//fmt.Println(hex.EncodeToString(pout))

	}
}

func Test_banch_BIP32(t *testing.T) {
	seed := [32]byte{0x80, 0x84, 0x5E, 0x2B, 0x12, 0x0F, 0xB5, 0x96, 0x4E, 0x9F, 0x48, 0x7F, 0x1C, 0x87, 0xE8, 0x7A, 0xE9, 0xF7, 0xD1, 0x6F, 0x0A, 0x5E, 0x77, 0x13, 0x14, 0x7F, 0x9E, 0x84, 0xF4, 0xAD, 0x10, 0x06}
	path := "m/44'/88'"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_SECP256K1)
	if err != nil {
		t.Error("产生失败！")
	} else {
		fmt.Println(hex.EncodeToString(pkey.key))
	}
	for i := 0; i < 1000; i++ {
		ckey, err := pkey.DerivedPublicKeyFromSerializes(uint32(0x80000000 + i))
		if err != nil {
			t.Error("产生失败！")
		} else {
			fmt.Println(hex.EncodeToString(ckey.key))
		}
	}
}

func Test_privateKey_start_with_ZERO(t *testing.T) {
	seed := [64]byte{0x40, 0x3E, 0x5A, 0xB7, 0x1F, 0x5C, 0x1A, 0x4C, 0xCD, 0xD1, 0x0C, 0xE6, 0x9A, 0x02, 0x14, 0xF1, 0x0A, 0x47, 0x8B, 0xFD, 0x64, 0x6A, 0xD9, 0x31, 0xC9, 0x21, 0x22, 0x1E, 0xB3, 0xFA, 0xB3, 0x42, 0x2B, 0x14, 0xB5, 0x68, 0x5A, 0xAB, 0x4C, 0xB2, 0x75, 0x2A, 0xF0, 0xB0, 0x0B, 0x6B, 0x1B, 0x55, 0xCB, 0xBE, 0x24, 0xF7, 0x21, 0xCB, 0x73, 0x3D, 0x68, 0xE3, 0xB6, 0xF3, 0x02, 0xA6, 0x35, 0xF4}
	path := "m/44'/88'/1'/0/0"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_SECP256K1)
	if err != nil {
		t.Error("产生失败！")
	} else {
		if pkey.key[0] != byte(0x00) {
			t.Error("私钥前面为0时未能正确补齐！")
		} else {
			fmt.Println(hex.EncodeToString(pkey.key))
		}
	}
}

func Test_ed25519_extend(t *testing.T) {
	// owner, _ := OWDecode("owpubeyoV6GSa7Tbbxm6xsjgv9VtGACjZxFjBbsKDMybSWqjEF3CJpNVrTeSGuWGYQptoPLtGy5qqfWPguThJdiFm8omhknN1D2LWWkYu25jrM1yrvFtrY")

	// fmt.Println(hex.EncodeToString(owner.key))
	// fmt.Println(owner.OWEncode())
	//seed := [64]byte{0x40, 0x3E, 0x5A, 0xB7, 0x1F, 0x5C, 0x1A, 0x4C, 0xCD, 0xD1, 0x0C, 0xE6, 0x9A, 0x02, 0x14, 0xF1, 0x0A, 0x47, 0x8B, 0xFD, 0x64, 0x6A, 0xD9, 0x31, 0xC9, 0x21, 0x22, 0x1E, 0xB3, 0xFA, 0xB3, 0x42, 0x2B, 0x14, 0xB5, 0x68, 0x5A, 0xAB, 0x4C, 0xB2, 0x75, 0x2A, 0xF0, 0xB0, 0x0B, 0x6B, 0x1B, 0x55, 0xCB, 0xBE, 0x24, 0xF7, 0x21, 0xCB, 0x73, 0x3D, 0x68, 0xE3, 0xB6, 0xF3, 0x02, 0xA6, 0x35, 0xF4}
	seed := [32]byte{0x89, 0xb1, 0x79, 0x7a, 0x20, 0xba, 0x70, 0x0d, 0xe2, 0x73, 0xfe, 0xad, 0xac, 0x21, 0x0e, 0x0b, 0x15, 0x25, 0x53, 0x06, 0xac, 0x01, 0x14, 0x2d, 0x1f, 0x0a, 0x13, 0x38, 0x25, 0x71, 0xc3, 0xb0}
	path := "m/44'/88'/1'"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_ED25519)
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println("1: ", hex.EncodeToString(pkey.key))

	}

	ppub := pkey.GetPublicKey()
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println(hex.EncodeToString(ppub.key))

	}

	//fmt.Println(ppub.OWEncode())

	cpub, err := ppub.GenPublicChild(0)

	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println(hex.EncodeToString(cpub.key))

	}

	cpub1, err := cpub.GenPublicChild(0)

	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println("2 ", hex.EncodeToString(cpub1.key))

	}

	path = "m/44'/88'/1'/0/2"
	cpri, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_ED25519)
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println(hex.EncodeToString(cpri.key))

	}

	// path = "/0"
	// prikey, err := pkey.GenPublicChild(0)
	// if err != nil {
	// 	t.Error("产生失败！")
	// } else {

	// 	fmt.Println(hex.EncodeToString(prikey.key))

	// }
	// path = "/0"

	// pubkey, err := pkey.DerivedPublicKeyFromPath(path)
	// if err != nil {
	// 	t.Error("产生失败！")
	// } else {

	// 	fmt.Println(hex.EncodeToString(pubkey.key))

	// }
}

func Test_ed25519_extend2(t *testing.T) {
	seed := []byte{0x7a, 0xd1, 0xdf, 0x7c, 0x25, 0x13, 0xa5, 0xbe, 0xfe, 0x3e, 0x65, 0x2d, 0xcd, 0x1b, 0x67, 0xe2, 0x48, 0x40, 0x3c, 0x22, 0xd4, 0xc1, 0x55, 0x0e, 0x17, 0x1d, 0xf4, 0x6c, 0xea, 0xa3, 0x91, 0x35}
	path := "m/44'/88'/1'/0/0"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_ED25519)
	if err != nil {
		t.Error("产生失败！")
	} else {
		fmt.Println("1: ", hex.EncodeToString(pkey.key))
	}

	ppub := pkey.GetPublicKey()
	if err != nil {
		t.Error("产生失败! ")
	} else {
		fmt.Println(hex.EncodeToString(ppub.key))
	}

	chk := owcrypt.Point_mulBaseG(pkey.key, owcrypt.ECC_CURVE_ED25519_NORMAL)

	fmt.Println(hex.EncodeToString(chk))
}

func Test_tmp(t *testing.T) {
	//seed := [32]byte{0x89, 0xb1, 0x79, 0x7a, 0x20, 0xba, 0x70, 0x0d, 0xe2, 0x73, 0xfe, 0xad, 0xac, 0x21, 0x0e, 0x0b, 0x15, 0x25, 0x53, 0x06, 0xac, 0x01, 0x14, 0x2d, 0x1f, 0x0a, 0x13, 0x38, 0x25, 0x71, 0xc3, 0xb0}
	seed, _ := hex.DecodeString("279906609e7a5b80f3088ac9879eec3f1007aec1bf2999069c6a500032297427")
	path := "m/44'/88'/1'/0"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_X25519)
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println("1: ", hex.EncodeToString(pkey.key))

	}

	ppub := pkey.GetPublicKey()
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println(hex.EncodeToString(ppub.key))

	}

	//fmt.Println(ppub.OWEncode())
	for index := 0; index < 100; index++ {
		cpub, err := ppub.GenPublicChild(uint32(index))

		if err != nil {
			t.Error("产生失败！")
		} else {
			fmt.Println(index)
			fmt.Println(hex.EncodeToString(cpub.key))

		}
		cpri, err := pkey.GenPrivateChild(uint32(index))
		if err != nil {
			t.Error("产生失败！")
		} else {

			fmt.Println(hex.EncodeToString(cpri.key))

		}

		chk := owcrypt.Point_mulBaseG(cpri.key, owcrypt.ECC_CURVE_ED25519)
		fmt.Println(hex.EncodeToString(chk))

		xpub, _ := owcrypt.CURVE25519_convert_Ed_to_X(chk)
		fmt.Println(hex.EncodeToString(xpub))
		fmt.Println("------------------")
	}

}

func Test_tmpED(t *testing.T) {
	//seed := [32]byte{0x89, 0xb1, 0x79, 0x7a, 0x20, 0xba, 0x70, 0x0d, 0xe2, 0x73, 0xfe, 0xad, 0xac, 0x21, 0x0e, 0x0b, 0x15, 0x25, 0x53, 0x06, 0xac, 0x01, 0x14, 0x2d, 0x1f, 0x0a, 0x13, 0x38, 0x25, 0x71, 0xc3, 0xb0}
	seed, _ := hex.DecodeString("45BBA4E6271F8088F78BA5B1490C12CB5980C5287750A3E19E58F2C27CD91C91736CEC4B7F1A05AE7CBC0C132CABB47EF2D3647DB600944052388E0D8C78476F")
	path := "m/44'/88'/9'/0/0"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_ED25519)
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println("1: ", hex.EncodeToString(pkey.key))

	}

	ppub := pkey.GetPublicKey()
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println(hex.EncodeToString(ppub.key))

	}
	start, _ := ppub.GenPublicChild(0)
	newKey, _ := start.GenPublicChild(0)
	fmt.Println(hex.EncodeToString(newKey.key))
	//fmt.Println(ppub.OWEncode())
	for index := 0; index < 100; index++ {
		cpub, err := ppub.GenPublicChild(uint32(index))

		if err != nil {
			t.Error("产生失败！")
		} else {
			fmt.Println(index)
			fmt.Println(hex.EncodeToString(cpub.key))

		}
		cpri, err := pkey.GenPrivateChild(uint32(index))
		if err != nil {
			t.Error("产生失败！")
		} else {

			fmt.Println(hex.EncodeToString(cpri.key))

		}

		chk := owcrypt.Point_mulBaseG(cpri.key, owcrypt.ECC_CURVE_ED25519)
		fmt.Println(hex.EncodeToString(chk))

		fmt.Println("------------------")
	}

}
func Test_chkED(t *testing.T) {
	seed, _ := hex.DecodeString("3796231f98e5813e7b04268ba375e3789ee6fe59c591c582d38477d0d4d56235")
	path := "m/44'/88'/1'/0/0"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_ED25519)
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println("1: ", hex.EncodeToString(pkey.key))

	}
}

func Test_chkX(t *testing.T) {
	seed, _ := hex.DecodeString("3796231f98e5813e7b04268ba375e3789ee6fe59c591c582d38477d0d4d56235")
	path := "m/44'/88'/1'/0/0"
	pkey, err := DerivedPrivateKeyWithPath(seed[:], path, owcrypt.ECC_CURVE_X25519)
	if err != nil {
		t.Error("产生失败！")
	} else {

		fmt.Println("1: ", hex.EncodeToString(pkey.key))

	}
}

func Test_multi(t *testing.T) {
	// 各client持有seed，并产生账户索引下的第一个非强化扩展，作为多签扩展的parent
	// 账户索引为  m'/44'/7744'/0'
	parentPath := "m/44'/7744'/0'/0"

	// client A
	// seed
	seedA, _ := hex.DecodeString("FF747E55458A51830E5BCEB1A11D81392A0F0461B16EBDBA5432F6F7C36D1E906598D4459E5533BDF5D9EB31E3119F2A064AEF1B8432027BB5017966D4706167")
	// 父扩展密钥
	parentA, err := DerivedPrivateKeyWithPath(seedA, parentPath, owcrypt.ECC_CURVE_SECP256K1)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("parent key of client A is : \n", parentA.GetPublicKey().OWEncode())
	}

	// client B
	// seed
	seedB, _ := hex.DecodeString("AB4454DED39B44E4117D8DCD5EE3CA31152E3F7F8EF5D200C8F76446385C97B52313BA488A0B5C1405536FD087E7B8A94A852ACC10D51023107A4439E462DBEF")
	// 父扩展密钥
	parentB, err := DerivedPrivateKeyWithPath(seedB, parentPath, owcrypt.ECC_CURVE_SECP256K1)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("parent key of client B is : \n", parentB.GetPublicKey().OWEncode())
	}

	// client C
	// seed
	seedC, _ := hex.DecodeString("F3D99BF9DE88FA73D2C3E52ABCED5624957097330226361BFEA96D90BDF40F67EE5ABFA22CAE9B769E7767E4B6282512BFFBA3B1BD6BFADCFFAADA6A8A2EED81")
	// 父扩展密钥
	parentC, err := DerivedPrivateKeyWithPath(seedC, parentPath, owcrypt.ECC_CURVE_SECP256K1)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("parent key of client C is : \n", parentC.GetPublicKey().OWEncode())
	}
}

func Test_chain(t *testing.T) {
	key, _ := OWDecode("owpubeyoV6FsPHxyPwSA6LecMZYFzyJUd2mS9MH8LycSsZ312fCtMe4Xq5nKGzwx7TgZspQ12PebUgFX4HfWUMaRMrj5i8oVVqJRYEAPmAVEKVgv9xnMJQ")
	child, _ := key.GenPublicChild(0)
	fmt.Println(hex.EncodeToString(child.GetPublicKeyBytes()))
}

func Test_ed25519_chain(t *testing.T){
	// 各client持有seed，并产生账户索引下的第一个非强化扩展，作为多签扩展的parent
	// 账户索引为  m'/44'/7744'/0'
	parentPath := "m/44'/7744'/0'/0"

	// client A
	// seed
	seedA, _ := hex.DecodeString("FF747E55458A51830E5BCEB1A11D81392A0F0461B16EBDBA5432F6F7C36D1E906598D4459E5533BDF5D9EB31E3119F2A064AEF1B8432027BB5017966D4706167")
	// 父扩展密钥
	parentA, err := DerivedPrivateKeyWithPath(seedA, parentPath, owcrypt.ECC_CURVE_ED25519)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("parent key of client A is : \n", parentA.GetPublicKey().OWEncode())
	}

	key,_ := OWDecode("owpubeyoV6GSdfnQAvzdhrSLs8BpssT5Vj4Q32zDbDRDk5NM2Zf2zZdhbh5bEMFuYmt4njskFHmvMroQYZ8Y3osqmydCKpbqGPPvfY5phaKW911tA2g5zZ")
	fmt.Println("pubkey :  \n",hex.EncodeToString(key.GetPublicKeyBytes()))

	share,_ := GetMultiSigShareData("owpubeyoV6GSdfnQAvzdhrSLs8BpssT5Vj4Q32zDbDRDk5NM2Zf2zZdhbh5bEMFuYmt4njskFHmvMroQYZ8Y3osqmydCKpbqGPPvfY5phaKW911tA2g5zZ")
	fmt.Println("share data :\n",share)
	test, _ := ChainDecode(share)
	fmt.Println("check :  \n", hex.EncodeToString(test.Pubkey))
}