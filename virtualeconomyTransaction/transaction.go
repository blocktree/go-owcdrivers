package virtualeconomyTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	owcrypt "github.com/blocktree/go-owcrypt"
	"github.com/tidwall/gjson"
)

type TxStruct struct {
	TxType     byte
	To         string
	Amount     uint64
	Fee        uint64
	FeeScale   uint16
	Attachment string
}

type SignaturePubkey struct {
	Signature []byte
	PublicKey []byte
}

// 创建空交易单
// only transfer for now
func CreateEmptyTransaction(ts TxStruct) (string, error) {
	timestamp := make([]byte, 8)
	amount := make([]byte, 8)
	fee := make([]byte, 8)
	feeScale := make([]byte, 2)
	attachmentLen := []byte{0x00, 0x00}
	txBytes := []byte{}
	txBytes = append(txBytes, ts.TxType)
	binary.BigEndian.PutUint64(timestamp, uint64((time.Now().UnixNano()/1000)*1000))
	txBytes = append(txBytes, timestamp...)
	binary.BigEndian.PutUint64(amount, ts.Amount)
	txBytes = append(txBytes, amount...)
	binary.BigEndian.PutUint64(fee, ts.Fee)
	txBytes = append(txBytes, fee...)
	binary.BigEndian.PutUint16(feeScale, ts.FeeScale)
	txBytes = append(txBytes, feeScale...)
	recipient, err := DecodeCheck(ts.To)
	if err != nil {
		return "", errors.New("Trying to send VSYS to an invalid address!")
	}
	txBytes = append(txBytes, recipient...)
	if ts.Attachment == "" {
		txBytes = append(txBytes, attachmentLen...)
	}

	return hex.EncodeToString(txBytes), nil
}

// 对空交易单进行签名
func SignTransaction(emptyTrans string, prikey []byte) (*SignaturePubkey, error) {
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return nil, errors.New("Invalid empty transaction hex!")
	}

	sig, ret := owcrypt.Signature(prikey, nil, 0, txBytes, uint16(len(txBytes)), owcrypt.ECC_CURVE_X25519)
	if ret != owcrypt.SUCCESS {
		return nil, errors.New("Failed to sign the transaction!")
	}

	pub := owcrypt.Point_mulBaseG(prikey, owcrypt.ECC_CURVE_X25519)

	// cpub, err := owcrypt.CURVE25519_convert_X_to_Ed(pub)
	// if err != nil {
	// 	return nil, errors.New("Failed to sign the transaction!")
	// }
	return &SignaturePubkey{
		Signature: sig,
		PublicKey: pub,
	}, nil
}

// 对签名结果进行验证
func VerifyTransaction(emptyTrans string, sp *SignaturePubkey) bool {
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return false
	}

	pass := owcrypt.Verify(sp.PublicKey, nil, 0, txBytes, uint16(len(txBytes)), sp.Signature, owcrypt.ECC_CURVE_X25519)

	if pass != owcrypt.SUCCESS {
		return false
	}

	return true
}

// 发送交易单
func CreateJSONRawForSendTransaction(emptyTrans string, sp *SignaturePubkey) (*gjson.Result, error) {
	var (
		body = make(map[string]interface{}, 0)
	)

	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return nil, errors.New("Invalid transaction hex string!")
	}

	ts, timestamp, err := TxStructDecode(txBytes)
	if err != nil {
		return nil, err
	}

	body["timestamp"] = timestamp
	body["amount"] = ts.Amount
	body["fee"] = ts.Fee
	body["feeScale"] = ts.FeeScale
	body["recipient"] = ts.To
	body["senderPublicKey"] = Encode(sp.PublicKey, BitcoinAlphabet)
	body["attachment"] = ts.Attachment
	body["signature"] = Encode(sp.Signature, BitcoinAlphabet)

	json, _ := json.Marshal(body)

	ret := gjson.ParseBytes(json)
	return &ret, nil

}
