package signatureSet

import (
	"strings"

	"github.com/blocktree/ethereum-adapter/ethereum_txsigner"

	"github.com/assetsadapterstore/tivalue-adapter/tivalue_txsigner"
	"github.com/astaxie/beego/config"
	"github.com/blocktree/arkecosystem-adapter/arkecosystem_txsigner"
	bts_txsigner "github.com/blocktree/bitshares-adapter/txsigner"
	"github.com/blocktree/ddmchain-adapter/ddmchain_txsigner"
	"github.com/blocktree/eosio-adapter/eos_txsigner"
	"github.com/blocktree/futurepia-adapter/futurepia_txsigner"
	"github.com/blocktree/moacchain-adapter/moacchain_txsigner"
	"github.com/blocktree/nulsio-adapter/nulsio_txsigner"
	"github.com/blocktree/ontology-adapter/ontology_txsigner"
	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openwallet"
	"github.com/blocktree/ripple-adapter/ripple_txsigner"
	"github.com/blocktree/virtualeconomy-adapter/virtualeconomy_txsigner"
	"github.com/blocktree/waykichain-adapter/waykichain_txsigner"
)

func init() {
	//注册交易签名工具
	RegTxSigner("DDM", ddmchain_txsigner.Default)
	RegTxSigner("EOS", eos_txsigner.Default)
	RegTxSigner("ONT", ontology_txsigner.Default)
	RegTxSigner("PIA", futurepia_txsigner.Default)
	RegTxSigner("VSYS", virtualeconomy_txsigner.Default)
	RegTxSigner("TV", tivalue_txsigner.Default)
	RegTxSigner("WICC", waykichain_txsigner.Default)
	RegTxSigner("XRP", ripple_txsigner.Default)
	RegTxSigner("NULS", nulsio_txsigner.Default)
	RegTxSigner("MOAC", moacchain_txsigner.Default)
	RegTxSigner("ETH", ethereum_txsigner.Default)
	RegTxSigner("TRUE", ethereum_txsigner.Default)
	RegTxSigner("VCC", ethereum_txsigner.Default)
	RegTxSigner("BTS", bts_txsigner.Default)
	RegTxSigner("BAR", bts_txsigner.Default)
	RegTxSigner("ARK", arkecosystem_txsigner.Default)
	RegTxSigner("SINOC", ethereum_txsigner.Default)
	RegTxSigner("TGC", eos_txsigner.Default)
	RegTxSigner("ABBC", eos_txsigner.Default)
	RegTxSigner("GST", eos_txsigner.Default)
	RegTxSigner("BETH", ethereum_txsigner.Default)
	RegTxSigner("NTN", ethereum_txsigner.Default)
}

// 交易签名注册组
var txSignerManagers = make(map[string]openwallet.TransactionSigner)

// RegTxSigner 注册交易签名工具
// @param name 资产别名
// @param manager 交易签名工具
// @param config 加载配置
func RegTxSigner(name string, manager openwallet.TransactionSigner, config ...config.Configer) {
	name = strings.ToUpper(name)
	if manager == nil {
		panic("txSinger: Register txSinger is nil")
	}
	if _, ok := txSignerManagers[name]; ok {
		log.Warning("txSinger: Register called twice for txSinger ", name)
		return
	}

	txSignerManagers[name] = manager
}

// GetTxSigner 根据币种类型获取已注册的交易签名工具
func GetTxSigner(symbol string) openwallet.TransactionSigner {
	symbol = strings.ToUpper(symbol)
	manager, ok := txSignerManagers[symbol]
	if !ok {
		return nil
	}
	return manager
}
