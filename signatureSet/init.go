package signatureSet

import (
	"github.com/astaxie/beego/config"
	"github.com/blocktree/ddmchain-adapter/ddmchain_txsigner"
	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openwallet"
	"strings"
)

func init() {
	//注册交易签名工具
	RegTxSigner("DDM", ddmchain_txsigner.Default)
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