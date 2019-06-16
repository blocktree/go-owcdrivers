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

type RegisterAccountTx struct {
	TxType      byte
	Version     []byte
	ValidHeight []byte
	UserID      []byte
	Fee         []byte
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

func getHashFromEmptyRawTrans(emptyTrans string) ([]byte, error) {
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return nil, errors.New("Invalid transaction hex data!")
	}

	if (txBytes[0] != TxType_COMMON && txBytes[0] != TxType_REGACCT) || txBytes[1] != byte(Version) {
		return nil, errors.New("Invalid transaction hex data!")
	}

	tmp := txBytes[0]
	txBytes[0] = txBytes[1]
	txBytes[1] = tmp

	return owcrypt.Hash(txBytes, 0, owcrypt.HASh_ALG_DOUBLE_SHA256), nil
}
