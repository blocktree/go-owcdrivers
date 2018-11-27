package ontologyTransaction

import (
	"errors"
)

type NativeInvoke struct {
	Version         byte
	ContractAddress []byte
	Method          string
	Param           TxState
}

func NewNativeInvoke(param TxState) NativeInvoke {
	var version byte
	var contractAddress string
	var method string
	if param.AssetType == AssetONT {
		version = ONTContractVersion
		contractAddress = ONTContractAddress
		method = MethodTransfer
	} else if param.AssetType == AssetONG {
		version = ONGContractVersion
		contractAddress = ONGContractAddress
		method = MethodTransfer
	} else {
		version = ONGContractVersion
		contractAddress = ONGContractAddress
		method = MethodTransferFrom
	}
	contractAddressBytes, _ := reverseHexToBytes(contractAddress)
	return NativeInvoke{version, contractAddressBytes, method, param}
}

func (ni NativeInvoke) ToBytes() ([]byte, error) {
	ret := []byte{0x00}

	ret = append(ret, OpCodeNewStruct, OpCodeToALTStack, OpCodeDupFromALTStack)

	prefix, inHash, err := DecodeCheck(ni.Param.From)
	if err != nil || prefix != AddressPrefix {
		return nil, errors.New("Invalid address!")
	}
	if len(inHash) != 0x14 {
		return nil, errors.New("Invalid length of hash data!")
	}

	ret = append(ret, 0x14)
	ret = append(ret, inHash...)

	ret = append(ret, OpCodeAppend, OpCodeDupFromALTStack)

	if ni.Param.AssetType == AssetONGWithdraw {
		from, _ := reverseHexToBytes(ONTContractAddress)
		ret = append(ret, 0x14)
		ret = append(ret, from...)
		ret = append(ret, OpCodeAppend, OpCodeDupFromALTStack)
	}
	prefix, outHash, err := DecodeCheck(ni.Param.To)
	if err != nil || prefix != AddressPrefix {
		return nil, errors.New("Invalid address!")
	}
	if len(outHash) != 0x14 {
		return nil, errors.New("Invalid length of hash data!")
	}

	ret = append(ret, 0x14)
	ret = append(ret, outHash...)

	ret = append(ret, OpCodeAppend, OpCodeDupFromALTStack)

	ret = append(ret, uint64ToEmitBytes(ni.Param.Amount)...)

	ret = append(ret, OpCodeAppend, OpCodeFromALTStack)

	if ni.Param.AssetType != AssetONGWithdraw {
		ret = append(ret, uint64ToEmitBytes(1)...) // number of contract // TODO : support more than one

		ret = append(ret, OpCodePack)
	}

	if len(ni.Method) == 0 {
		return nil, errors.New("Miss method!")
	}

	ret = append(ret, byte(len(ni.Method)))
	ret = append(ret, []byte(ni.Method)...)

	ret = append(ret, byte(len(ni.ContractAddress)))
	ret = append(ret, ni.ContractAddress...)
	ret = append(ret, ni.Version)

	ret = append(ret, OpCodeSysCall)

	ret = append(ret, byte(len(NativeInvokeName)))
	ret = append(ret, []byte(NativeInvokeName)...)

	return ret, nil
}
