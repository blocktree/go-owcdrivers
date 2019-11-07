package waykichainTransaction

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	owcrypt "github.com/blocktree/go-owcrypt"
)

type CommonTx struct {
	TxType      byte
	Version     []byte
	ValidHeight []byte
	FromUserID  []byte
	ToID        []byte
	Fee         []byte
	Amount      []byte
}

func NewCommonTx(fromUserID, toAddress string, amount, fee, validHeight int64) (*CommonTx, error) {
	var commonTx CommonTx

	commonTx.TxType = TxType_COMMON
	commonTx.Version = int64ToUvarint(Version)
	if validHeight < 0 {
		return nil, errors.New("Negative valid height!")
	}
	commonTx.ValidHeight = int64ToUvarint(validHeight)

	if !isRegIdStr(fromUserID) {
		return nil, errors.New("Invalid from register ID!")
	}
	ids := strings.Split(fromUserID, "-")
	idBytes := []byte{}
	for _, id := range ids {
		data, _ := strconv.ParseInt(id, 10, 64)
		idBytes = append(idBytes, int64ToUvarint(data)...)
	}
	commonTx.FromUserID = append([]byte{byte(len(idBytes))}, idBytes...)

	destID, err := GetProgramHashFromAddress(toAddress)
	if err != nil {
		return nil, err
	}
	destID = append([]byte{byte(len(destID))}, destID...)
	commonTx.ToID = destID

	commonTx.Fee = int64ToUvarint(fee)

	commonTx.Amount = int64ToUvarint(amount)

	return &commonTx, nil
}

func (tx CommonTx) ToBytes() []byte {
	txBytes := make([]byte, 0)

	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.FromUserID...)
	txBytes = append(txBytes, tx.ToID...)
	txBytes = append(txBytes, tx.Fee...)
	txBytes = append(txBytes, tx.Amount...)
	txBytes = append(txBytes, byte(0x00)) // empty contract script data

	return txBytes
}

func (tx CommonTx) GetHash() []byte {
	txBytes := make([]byte, 0)

	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.FromUserID...)
	txBytes = append(txBytes, tx.ToID...)
	txBytes = append(txBytes, tx.Fee...)
	txBytes = append(txBytes, tx.Amount...)
	txBytes = append(txBytes, byte(0x00)) // empty contract script data

	return owcrypt.Hash(txBytes, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
}

type RegisterAccountTx struct {
	TxType      byte
	Version     []byte
	ValidHeight []byte
	UserID      []byte
	Fee         []byte
}

func NewRegisterAccountTx(fromPubkey string, fee, validHeight int64) (*RegisterAccountTx, error) {
	var registerAccountTx RegisterAccountTx

	registerAccountTx.TxType = TxType_REGACCT
	registerAccountTx.Version = int64ToUvarint(Version)
	if validHeight < 0 {
		return nil, errors.New("Negative valid height!")
	}
	registerAccountTx.ValidHeight = int64ToUvarint(validHeight)
	pubkey, err := hex.DecodeString(fromPubkey)
	if err != nil || len(pubkey) != 0x21 {
		return nil, errors.New("Invalid public key data to register account!")
	}
	pubkey = append([]byte{byte(0x21)}, pubkey...)
	registerAccountTx.UserID = pubkey

	registerAccountTx.Fee = int64ToUvarint(fee)

	return &registerAccountTx, nil
}

func (tx RegisterAccountTx) ToBytes() []byte {
	txBytes := make([]byte, 0)

	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.UserID...)
	txBytes = append(txBytes, byte(0x00)) // empty miner id
	txBytes = append(txBytes, tx.Fee...)

	return txBytes
}

func (tx RegisterAccountTx) GetHash() []byte {
	txBytes := make([]byte, 0)

	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.UserID...)
	txBytes = append(txBytes, byte(0x00)) // empty miner id
	txBytes = append(txBytes, tx.Fee...)

	return owcrypt.Hash(txBytes, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
}

type CallContractTx struct {
	TxType      byte
	Version     []byte
	ValidHeight []byte
	FromUserID  []byte
	AppID       []byte
	Fee         []byte
	Amount      []byte
	ContractHex []byte
}

func NewCallContractTx(fromUserID, appID, contractHex string, validHeight, fee, amount int64) (*CallContractTx, error) {
	var contractTx CallContractTx

	contractTx.TxType = TxType_CONTRACT
	contractTx.Version = int64ToUvarint(Version)
	if validHeight < 0 {
		return nil, errors.New("Negative valid height!")
	}
	contractTx.ValidHeight = int64ToUvarint(validHeight)
	if !isRegIdStr(fromUserID) {
		return nil, errors.New("Invalid from register ID!")
	}
	ids := strings.Split(fromUserID, "-")
	idBytes := []byte{}
	for _, id := range ids {
		data, _ := strconv.ParseInt(id, 10, 64)
		idBytes = append(idBytes, int64ToUvarint(data)...)
	}
	contractTx.FromUserID = append([]byte{byte(len(idBytes))}, idBytes...)

	if !isRegIdStr(appID) {
		return nil, errors.New("Invalid from register ID!")
	}
	ids = strings.Split(appID, "-")
	idBytes = []byte{}
	for _, id := range ids {
		data, _ := strconv.ParseInt(id, 10, 64)
		idBytes = append(idBytes, int64ToUvarint(data)...)
	}
	contractTx.AppID = append([]byte{byte(len(idBytes))}, idBytes...)

	contractTx.Fee = int64ToUvarint(fee)

	contractTx.Amount = int64ToUvarint(amount)

	contract, err := hex.DecodeString(contractHex)
	if err != nil {
		return nil, errors.New("Invalid contract hex!")
	}
	contractTx.ContractHex = append([]byte{byte(len(contract))}, contract...)

	return &contractTx, nil
}

func (tx CallContractTx) ToBytes() []byte {
	txBytes := make([]byte, 0)
	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.FromUserID...)
	txBytes = append(txBytes, tx.AppID...)
	txBytes = append(txBytes, tx.Fee...)
	txBytes = append(txBytes, tx.Amount...)
	txBytes = append(txBytes, tx.ContractHex...)
	return txBytes
}

func (tx CallContractTx) GetHash() []byte {
	txBytes := make([]byte, 0)
	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.FromUserID...)
	txBytes = append(txBytes, tx.AppID...)
	txBytes = append(txBytes, tx.Fee...)
	txBytes = append(txBytes, tx.Amount...)
	txBytes = append(txBytes, tx.ContractHex...)
	return owcrypt.Hash(txBytes, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
}

// 仅实现了单币种转账
type UcoinTransferTx struct {
	TxType      byte
	Version     []byte
	ValidHeight []byte
	FromUserID  []byte
	FeeSymbol   []byte
	FeeAmount   []byte
	To          []byte
	CoinName    []byte
	CoinAmount  []byte
}

func NewUcoinTransferTx(fromUserID, toAddress, coin string, validHeight, fee, amount int64) (*UcoinTransferTx, error) {
	var ucoinTransferTx UcoinTransferTx

	ucoinTransferTx.TxType = TxType_UcoinTransfer
	ucoinTransferTx.Version = int64ToUvarint(Version)

	if validHeight < 0 {
		return nil, errors.New("Negative valid height!")
	}
	ucoinTransferTx.ValidHeight = int64ToUvarint(validHeight)

	ids := strings.Split(fromUserID, "-")
	idBytes := []byte{}
	for _, id := range ids {
		data, _ := strconv.ParseInt(id, 10, 64)
		idBytes = append(idBytes, int64ToUvarint(data)...)
	}
	ucoinTransferTx.FromUserID = append([]byte{byte(len(idBytes))}, idBytes...)

	ucoinTransferTx.FeeSymbol = append([]byte{byte(len(DefaultFeeSymbol))}, []byte(DefaultFeeSymbol)...)

	ucoinTransferTx.FeeAmount = int64ToUvarint(fee)

	destID, err := GetProgramHashFromAddress(toAddress)
	if err != nil {
		return nil, err
	}

	ucoinTransferTx.To = append([]byte{byte(len(destID))}, destID...)

	if coin == "" {
		return nil, errors.New("Invalid coin name!")
	}

	ucoinTransferTx.CoinName = append([]byte{byte(len(coin))}, []byte(coin)...)

	ucoinTransferTx.CoinAmount = int64ToUvarint(amount)

	return &ucoinTransferTx, nil
}

func (tx UcoinTransferTx) ToBytes() []byte {
	txBytes := make([]byte, 0)

	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.FromUserID...)
	txBytes = append(txBytes, tx.FeeSymbol...)
	txBytes = append(txBytes, tx.FeeAmount...)
	txBytes = append(txBytes, 0x01) // output count, fixed to 1
	txBytes = append(txBytes, tx.To...)
	txBytes = append(txBytes, tx.CoinName...)
	txBytes = append(txBytes, tx.CoinAmount...)
	txBytes = append(txBytes, 0x00) // don't support memo

	return txBytes
}

func (tx UcoinTransferTx) GetHash() []byte {
	txBytes := make([]byte, 0)

	txBytes = append(txBytes, tx.Version...)
	txBytes = append(txBytes, tx.TxType)
	txBytes = append(txBytes, tx.ValidHeight...)
	txBytes = append(txBytes, tx.FromUserID...)
	txBytes = append(txBytes, tx.FeeSymbol...)
	txBytes = append(txBytes, tx.FeeAmount...)
	txBytes = append(txBytes, 0x01) // output count, fixed to 1
	txBytes = append(txBytes, tx.To...)
	txBytes = append(txBytes, tx.CoinName...)
	txBytes = append(txBytes, tx.CoinAmount...)
	txBytes = append(txBytes, 0x00) // don't support memo

	return owcrypt.Hash(txBytes, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
}

func getHashFromEmptyRawTrans(emptyTrans string) ([]byte, error) {
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return nil, errors.New("Invalid transaction hex data!")
	}

	if (txBytes[0] != TxType_COMMON && txBytes[0] != TxType_REGACCT && txBytes[0] != TxType_CONTRACT && txBytes[0] != TxType_UcoinTransfer) || txBytes[1] != byte(Version) {
		return nil, errors.New("Invalid transaction hex data!")
	}

	tmp := txBytes[0]
	txBytes[0] = txBytes[1]
	txBytes[1] = tmp

	return owcrypt.Hash(txBytes, 0, owcrypt.HASh_ALG_DOUBLE_SHA256), nil
}