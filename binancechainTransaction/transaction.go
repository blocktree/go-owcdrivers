package binancechainTransaction

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/binance-chain/go-sdk/types/msg"
	"github.com/binance-chain/go-sdk/types/tx"
	"github.com/blocktree/go-owcrypt"
)

func CreateEmptyTransactionAndHash(from , to, denom string, amount, accountNumber, sequence, source int64, memo string) (string, string, error) {
	sendMsg, err := CreateSendMsg(from, to, denom, amount)
	if err != nil {
		return "", "", err
	}

	signMsg := tx.StdSignMsg{
		ChainID:ChainID,
		AccountNumber:accountNumber,
		Sequence:sequence,
		Memo:memo,
		Msgs:[]msg.Msg{sendMsg},
		Source:source,
	}

	emptyTrans := signMsg.Bytes()

	hash := tx.StdSignBytes(ChainID, accountNumber, sequence, []msg.Msg{sendMsg}, memo, signMsg.Source, signMsg.Data)
	return string(emptyTrans), hex.EncodeToString(owcrypt.Hash(hash, 0, owcrypt.HASH_ALG_SHA256)), nil
}

func SignRawTransaction(hash string, prikey []byte) ([]byte, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 32 {
		return nil, errors.New("Invalid tansaction hash!")
	}

	signature,_, retCode := owcrypt.Signature(prikey, nil, hashBytes, owcrypt.ECC_CURVE_SECP256K1)
	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Sign transaction failed!")
	}

	signature = serilizeS(signature)

	return signature, nil
}

func VerifyAndCombineRawTransaction(emptyTrans, signature, pubkey string) (bool, string) {
	var signMsg tx.StdSignMsg
	var stdSignDoc tx.StdSignDoc
	var sendMsg msg.SendMsg

	err := tx.Cdc.UnmarshalJSON([]byte(emptyTrans), &stdSignDoc)
	if err != nil {
		return false, ""
	}
	signMsg.Memo = stdSignDoc.Memo
	err = json.Unmarshal(stdSignDoc.Msgs[0], &sendMsg)
	if err != nil {
		return false, ""
	}

	signMsg.Msgs = []msg.Msg{sendMsg}
	signMsg.Sequence = stdSignDoc.Sequence
	signMsg.AccountNumber = stdSignDoc.AccountNumber
	signMsg.ChainID = stdSignDoc.ChainID
	signMsg.Source = stdSignDoc.Source
	signMsg.Data = stdSignDoc.Data

	//err = tx.Cdc.UnmarshalJSON([]byte(emptyTrans), &signMsg)
	//if err != nil {
	//	return false, ""
	//}

	sigBytes, err := hex.DecodeString(signature)
	if err != nil || len(sigBytes) != 64 {
		return false, ""
	}

	pubBytes, err := hex.DecodeString(pubkey)
	if err != nil || len(pubBytes) != 33 {
		 return false, ""
	}

	pubUncompressedBytes := owcrypt.PointDecompress(pubBytes, owcrypt.ECC_CURVE_SECP256K1)[1:]
	hash := tx.StdSignBytes(ChainID, signMsg.AccountNumber, signMsg.Sequence, signMsg.Msgs, signMsg.Memo, signMsg.Source, signMsg.Data)

	hash = owcrypt.Hash(hash, 0, owcrypt.HASH_ALG_SHA256)

	if owcrypt.SUCCESS != owcrypt.Verify(pubUncompressedBytes, nil, hash, sigBytes, owcrypt.ECC_CURVE_SECP256K1) {
		return false, ""
	}

	stdSignature := tx.StdSignature{
		AccountNumber:signMsg.AccountNumber,
		Sequence:signMsg.Sequence,
		PubKey:NewPubkey(pubBytes),
		Signature:sigBytes,
	}

	newTx := tx.NewStdTx(signMsg.Msgs, []tx.StdSignature{stdSignature}, signMsg.Memo, signMsg.Source, signMsg.Data)
	bz, err := tx.Cdc.MarshalBinaryLengthPrefixed(&newTx)
	if err != nil {
		return false, ""
	}
	return true, hex.EncodeToString(bz)
}

func DecodeRawTransaction(trx []byte) (*tx.StdTx, error) {
	var stdTx tx.StdTx

	err := tx.Cdc.UnmarshalBinaryLengthPrefixed(trx, &stdTx)
	if err != nil {
		return nil, err
	}

	return &stdTx, nil
}