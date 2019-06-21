package signatureSet

import (
	"strings"

	"github.com/assetsadapterstore/tivalue-adapter/tivalue_txsigner"
	"github.com/astaxie/beego/config"
	"github.com/blocktree/ddmchain-adapter/ddmchain_txsigner"
	"github.com/blocktree/eosio-adapter/eos_txsigner"
	"github.com/blocktree/futurepia-adapter/futurepia_txsigner"
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
