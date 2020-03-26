package owkeychain

import (
	"errors"
	"strconv"
	"strings"

	"github.com/blocktree/go-owcrypt"
)

var (
	ErrInvalidDerivedPath = errors.New("Invalid DerivedPath")
	ErrKeyIsNotPrivate    = errors.New("The key is not private")
)

//接口仅接受绝对路径
func DerivedPrivateKeyWithPath(seed []byte, derivedPath string, curveType uint32) (*ExtendedKey, error) {

	//移除空格
	path := strings.Replace(derivedPath, " ", "", -1)

	if path == "m" || path == "/" || path == "" {
		return InitRootKeyFromSeed(seed, curveType) //根私钥
	}

	if strings.Index(path, "m/") != 0 {
		return nil, ErrInvalidDerivedPath
	}

	priKey, err := InitRootKeyFromSeed(seed, curveType)
	if err != nil {
		return nil, err
	}

	path = path[2:]
	elements := strings.Split(path, "/")

	for _, elem := range elements {
		var hdSerializes uint32
		if len(elem) == 0 {
			return nil, ErrInvalidDerivedPath
		}

		if strings.Index(elem, "'") == len(elem)-1 {
			elem = elem[0 : len(elem)-1]
			index, err := strconv.Atoi(elem)
			if err != nil {
				return nil, ErrInvalidDerivedPath
			}
			hdSerializes = uint32(index) + HardenedKeyStart
		} else {
			index, err := strconv.Atoi(elem)
			if err != nil {
				return nil, ErrInvalidDerivedPath
			}
			hdSerializes = uint32(index)
		}

		priKey, err = priKey.GenPrivateChild(hdSerializes)
		if err != nil {
			return nil, err
		}

	}
	return priKey, nil
}

func GetCoinRootPublicKey(seed []byte, coinType CoinType) (*ExtendedKey, error) {
	tmpPrikey, err := DerivedPrivateKeyWithPath(seed, openwalletPrePath, coinType.curveType)
	if err != nil {
		return nil, err
	}
	coinRootPublicKey, err := tmpPrikey.GenPublicChild(coinType.hdIndex)
	if err != nil {
		return nil, err
	}
	return coinRootPublicKey, nil
}

func DerivedPrivateKeyBytes(seed []byte, coinType CoinType, serializes uint32) ([]byte, error) {
	tmpPrikey, err := DerivedPrivateKeyWithPath(seed, openwalletPrePath, coinType.curveType)
	if err != nil {
		return nil, err
	}
	coinRootPrivateKey, err := tmpPrikey.GenPrivateChild(coinType.hdIndex)
	if err != nil {
		return nil, err
	}
	privateKey, err := coinRootPrivateKey.GenPrivateChild(serializes)
	if err != nil {
		return nil, err
	}
	return privateKey.key, nil
}

//DerivedPublicKeyFromPath 从当前密钥k按照相对路径进行扩展
func (k *ExtendedKey) DerivedPublicKeyFromPath(derivedPath string) (*ExtendedKey, error) {
	path := strings.Replace(derivedPath, " ", "", -1)
	if strings.Index(path, "/") != 0 {
		return nil, errors.New("the relative path must started with /")
	}
	elements := strings.Split(path, "/")
	elements = elements[1:]
	pubkey := NewExtendedKey(k.key, k.chainCode, k.parentFP, k.depth, k.serializes, k.isPrivate, k.curveType)
	for _, elem := range elements {
		var hdSerializes uint32
		if len(elem) == 0 {
			return nil, ErrInvalidDerivedPath
		}

		if strings.Index(elem, "'") == len(elem)-1 {
			elem = elem[0 : len(elem)-1]
			index, err := strconv.Atoi(elem)
			if err != nil {
				return nil, ErrInvalidDerivedPath
			}
			hdSerializes = uint32(index) + HardenedKeyStart
		} else {
			index, err := strconv.Atoi(elem)
			if err != nil {
				return nil, ErrInvalidDerivedPath
			}
			hdSerializes = uint32(index)
		}
		err := errors.New("")
		pubkey, err = pubkey.GenPublicChild(hdSerializes)
		if err != nil {
			return nil, err
		}
	}

	return pubkey, nil
}

//DerivedPublicKeyFromSerializes 普通密钥扩展的单层深度派生
func (k *ExtendedKey) DerivedPublicKeyFromSerializes(serializes uint32) (*ExtendedKey, error) {
	return k.GenPublicChild(serializes)
}

//GetPublicKeyBytes 获取当前密钥对应的公钥
func (k *ExtendedKey) GetPublicKeyBytes() []byte {
	typeChoose := k.curveType
	if typeChoose == owcrypt.ECC_CURVE_X25519 || typeChoose == owcrypt.ECC_CURVE_CURVE25519_SHA256 {
		typeChoose = owcrypt.ECC_CURVE_ED25519
	}

	if k.isPrivate {
		return owcrypt.Point_mulBaseG(k.key, typeChoose)
	}
	return k.key
}

////GetPublicKeyUncompressedBytes 获取当前密钥对应的公钥(未压缩，且去除04)
func (k *ExtendedKey) GetUncompressedPublicKeyBytes() []byte {
	pubkey := []byte{}
	if k.isPrivate {
		pubkey = owcrypt.Point_mulBaseG(k.key, k.curveType)
	} else {
		pubkey = k.key
	}

	return owcrypt.PointDecompress(pubkey, k.curveType)[1:]
}

//GePublicKey 获取公钥结构体
func (k *ExtendedKey) GetPublicKey() *ExtendedKey {
	if !k.isPrivate {
		return k
	}
	typeChoose := k.curveType
	if typeChoose == owcrypt.ECC_CURVE_X25519 || typeChoose == owcrypt.ECC_CURVE_CURVE25519_SHA256 {
		typeChoose = owcrypt.ECC_CURVE_ED25519
	}

	return NewExtendedKey(owcrypt.Point_mulBaseG(k.key, typeChoose), k.chainCode, k.parentFP, k.depth, k.serializes, false, k.curveType)
}

//GetPrivateKey 获取当前密钥对应的私钥数组
func (k *ExtendedKey) GetPrivateKeyBytes() ([]byte, error) {
	if k.isPrivate {
		return k.key, nil
	}
	return nil, ErrKeyIsNotPrivate
}
