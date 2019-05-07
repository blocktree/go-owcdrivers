# go-owcdrivers
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

##  说明
---
本包为依赖[go-owcrypt](https://github.com/blocktree/go-owcrypt)实现的一些基础功能以及若干币种的交易驱动和一些需要特殊处理的币种签名。
        

## 当前功能列表：
---

[addressEncoder](#addressEncoder) -  地址编解码

[owkeychain](#owkeychain) -  分层确定性密钥扩展

[btcLikeTxDriver](#btcLikeTxDriver)-  类比特币交易单驱动

[btcTransaction](#交易单驱动)-  类比特币交易单驱动，重构，支持全系地址

[bytomTransaction](#交易单驱动)-  比原链交易单驱动

[cosmosTransaction](#交易单驱动)-  ATOM交易单驱动

[omniTransaction](#交易单驱动)-  omni协议染色币交易单驱动

[ontologyTransaction](#交易单驱动)-  ONT/ONG交易单驱动

[virtualeconomyTransaction](#交易单驱动) -  VSYS交易单驱动

[signatureSet](#signatureSet)


## Detail
---

### addressEncoder
包含各个币种的地址编解码，以及某些币种的公私钥编解码等。当前支持的币种及地址类型有：
- BTC: P2PKH,P2SH,Bech32V0,PrivateWIF,PrivateWIFCompressed,PublicBIP32,PrivateBIP32
- LTC: P2PKH,P2SH,Bech32V0,PrivateWIF,PrivateWIFCompressed,PublicBIP32,PrivateBIP32
- XMR: PublicAddress,PublicSubAddress,InteratedAddress
- DOGE: P2Pkh,multisig
- ONT: 
- XRP:
- BTM: bech32
- ZEC: P2PKH,P2SH
- BCH: legacy,cash
- XTZ: tz1,tz2,tz3,edpk,edsk,edsk2,spsk,p2sk
- HC:
- ETH:
- QTOM: P2PKH,P2SH,Bech32V0,PrivateWIF,PrivateWIFCompressed,PublicBIP32,PrivateBIP32
- DCRD: P2PKH,P2SH,PKHEdwards,PKHSchnor,P2SH,Private
- NAS: account address, contract address
- TRON:
- ICX:
- VSYS:
- EOS: Public,PrivateWIF,PrivateWIFCompressed
- AE:
- ATOM:

注意事项：

- 添加新等币种支持时，可以在encoderProfile.go文件中添加相关的配置，对于与以上币种类似的地址，可以直接按照结构体添加配置。结构体内容为：
```
type AddressType struct {
	EncodeType   string //编码类型
	Alphabet     string //码表
	ChecksumType string //checksum类型(base32PolyMod时做前置字符串)
	HashType     string //地址hash类型，传入数据为公钥时起效
	HashLen      int    //编码前的数据长度
	Prefix       []byte //数据前面的填充,bech32时用作传入版本号
	Suffix       []byte //数据后面的填充
}
```
- HashType虽然提供了直接传入公钥来产生地址的功能， 但是由于各链差异性，不能做到全币种支持公钥传入，建议在外部计算哈希后直接传入来获取响应地址。

### owkeychain

owkeychain在[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)的基础之上进行了功能扩展，目前除了支持ECDSA系列的椭圆曲线算法之外，对于EDDSA系列的椭圆曲线算法也能良好支持。
当前支持的扩展算法包括：

- secp256k1
- secp256r1
- primev1
- NIST-p256
- sm2-std
- ed25519

注意事项：

针对EDDSA类算法，目前owkeychain对于curve25519、ed25519、x25519的分层确定性扩展都能良好都支持。值得注意的是，次3类曲线实际执行扩展操作的是ed25519，其执行结果经域转换可转换为x25519公钥。同时其可以直接作为curve25519的扩展结果，但是此时对应的私钥为通过sha512 extended后的前32字节。


### 交易单驱动
---

目前交易单驱动部分基本都提供了类似的功能，大致包含四个主要功能：

- 1. 创建空交易单

        空交易单用于保存交易的基本信息，以及后续的交易单合并等。

- 2. 创建交易单哈希

        创建用于签名的哈希，个别币种由于设计原因，可能此处返回的是原始消息。

- 3. 合并交易单

        即将签名之后的签名值插入空交易单，构建完整交易单用于广播

- 4. 验证交易单

        一般用于在交易合并之后，发送之前的合法性验证。


### signatureSet
---

包含了签名需要特殊处理的部分币种的签名功能。
