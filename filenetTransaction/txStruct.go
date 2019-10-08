package filenetTransaction

import (
	"encoding/hex"
	"errors"
	"github.com/blocktree/go-owcrypt"
	"sort"
	"time"
)

type TxStruct struct {
	From []byte
	Amount []byte
	ToCount []byte
	TimeStamp []byte
	To []ToStruct
}

type ToStruct struct {
	To []byte
	Amount []byte
}

func NewTxStruct(in Vin, outs Vouts) (*TxStruct, error) {
	var trans TxStruct

	if in.Address == "" {
		return nil, errors.New("Miss input!")
	}

	fromBytes, err := decodeAddress(in.Address)
	if err != nil {
		return nil, errors.New("Invalid from address!")
	}

	trans.From = fromBytes

	if outs == nil {
		return nil, errors.New("Miss output!")
	}

	outCount := len(outs) ; if outCount == 0 {
		return nil, errors.New("Miss output!")
	}

	trans.ToCount = uint64ToLittleEndianBytes(uint64(outCount))

	sort.Sort(outs)

	totleAmount := uint64(0)
	for _, out := range outs {
		if out.Address == "" {
			return nil, errors.New("Invalid to address!")
		}
		if out.Amount == 0 {
			return nil, errors.New("Invalid amount!")
		}

		totleAmount += out.Amount

		toBytes, err := decodeAddress(out.Address)
		if err != nil {
			return nil, errors.New("Invalid to address!")
		}

		trans.To = append(trans.To, ToStruct{
			To:     toBytes,
			Amount: uint64ToLittleEndianBytes(out.Amount),
		})
	}

	trans.Amount = uint64ToLittleEndianBytes(totleAmount)
	trans.TimeStamp = uint64ToLittleEndianBytes((uint64)(time.Now().Unix()))

	return &trans, nil
}

func (t *TxStruct) ToBytes() []byte {
	txBytes := make([]byte, 0)

	txBytes = append(txBytes, t.From...)
	txBytes = append(txBytes, t.ToCount...)
	txBytes = append(txBytes, t.Amount...)
	txBytes = append(txBytes, t.TimeStamp...)

	for _, to := range t.To {
		txBytes = append(txBytes, to.To...)
		txBytes = append(txBytes, to.Amount...)
	}

	return txBytes
}

type Transfer struct {
	TxId            string           `json:"txid"`      //转账交易ID，hash(sha356)
	From            string           `json:"from"`      //转出地址/base58(hex([20]byte[:]))
	ToCount         uint64           `json:"tocount"`   //转入地址个数
	Value           uint64           `json:"value"`     //转入总金额/1e-9FN
	Timestamp       int64            `json:"timestamp"` //时间戳/秒
	TransferDetails *TransferDetails `json:"transferdetails"`
	Sign            string           `json:"sign"` //签名(secp256k1)
}

type Transfers []*Transfer

type TransferDetail struct {
	To    string `json:"to"`    //转入地址，兼具索引功能
	Value uint64 `json:"value"` //每个地址转入金额
}

type TransferDetails []*TransferDetail //按照To字段进行排序


func decodeRawTransaction(emptyTrans, signature string) (*Transfer, error) {
	var transfer Transfer

	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil || len(txBytes) == 0 {
		return nil, errors.New("Invalid empty transaction hex string!")
	}

	txid := owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_SHA256)
	transfer.TxId = hex.EncodeToString(txid)

	var (
		index = 0
		limit = len(txBytes)
	)

	if index + 20 > limit {
		return nil, errors.New("Invalid empty transaction hex string!")
	}

	fromAddr, err := encodeAddress(txBytes[index:index+20])
	if err != nil {
		return nil, errors.New("Invalid empty transaction hex string!")
	}
	transfer.From = fromAddr
	index += 20

	if index + 8 > limit {
		return nil, errors.New("Invalid empty transaction hex string!")
	}
	toCount := littleEndianBytesToUint64(txBytes[index:index+8])
	transfer.ToCount = toCount
	index += 8

	if index + 8 > limit {
		return nil, errors.New("Invalid empty transaction hex string!")
	}
	value := littleEndianBytesToUint64(txBytes[index:index+8])
	transfer.Value = value
	index += 8

	if index + 8 > limit {
		return nil, errors.New("Invalid empty transaction hex string!")
	}
	transfer.Timestamp = int64(littleEndianBytesToUint64(txBytes[index:index+8]))
	index += 8

	txDetalis := make(TransferDetails, toCount)
	for i := 0; i < int(toCount); i ++ {
		if index + 28 > limit {
			return nil, errors.New("Invalid empty transaction hex string!")
		}
		toAddr, err := encodeAddress(txBytes[index:index+20])
		if err != nil {
			return nil, errors.New("Invalid empty transaction hex string!")
		}

		toAmount := littleEndianBytesToUint64(txBytes[index+20:index+28])

		index += 28

		 txDetalis[i] = &TransferDetail{
			To: toAddr,
			Value: toAmount,
		}
	}

	transfer.TransferDetails = &txDetalis

	if index != limit {
		return nil, errors.New("Invalid empty transaction hex string!")
	}

	if signature == "" || len(signature) != 128 {
		return nil, errors.New("Miss signature!")
	}

	_, err = hex.DecodeString(signature)
	if err != nil {
		return nil, errors.New("Invalid signature!")
	}

	transfer.Sign = signature

	return &transfer, nil
}