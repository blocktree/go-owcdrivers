package mateverseTransaction

import (
	"encoding/hex"
	"errors"
	"strings"
)

type TxInput struct {
	txID 		string
	vout 		uint32
	lockScript  string
	sequence    uint32
	hash 		string
	signature   string
	pubkey      string
}

func (tx *TxInput) GetTxID () string {
	return tx.txID
}

func (tx *TxInput) GetVout () uint32 {
	return tx.vout
}

func (tx *TxInput) SetLockScript (script string) {
	tx.lockScript = script
}

func (tx *TxInput) GetHash () string {
	return tx.hash
}

func (tx *TxInput) SetSignature(signature string) {
	tx.signature = signature
}

func (tx *TxInput) SetPubKey(pubkey string) {
	tx.pubkey = pubkey
}

func decodeEmptyTx(tx []byte) ([]*TxInput, int,  error) {
	var inputs []*TxInput

	limit := len(tx)
	index := 0

	if index + 4 > limit {
		return nil, 0, errors.New("Invalid tx data!")
	}
	if littleEndianBytesToUint32(tx[index:index + 4]) != DefaultTxVersion {
		return nil, 0, errors.New("Invalid tx data!")
	}
	index += 4

	if index + 1 > limit {
		return nil, 0, errors.New("Invalid tx data!")
	}

	var inputCount int
	if tx[index] != 0xfd {
		inputCount = int(tx[index])
		if inputCount == 0 {
			return nil, 0, errors.New("Invalid tx data!")
		}
		index ++
	} else {
		index ++
		if index + 2 > limit {
			return nil, 0, errors.New("Invalid tx data!")
		}
		inputCount = int(littleEndianBytesToUint16(tx[index:index+2]))
		index += 2
	}

	for i := 0; i < inputCount; i ++ {
		var input TxInput
		if index + 32 > limit {
			return nil, 0, errors.New("Invalid tx data!")
		}
		input.txID = reverseBytesToHex(tx[index:index+32])
		index += 32
		if index + 4 > limit {
			return nil, 0, errors.New("Invalid tx data!")
		}
		input.vout = littleEndianBytesToUint32(tx[index:index+4])
		index += 4

		if index + 1 > limit {
			return nil, 0, errors.New("Invalid tx data!")
		}
		if tx[index] != 0 {
			return nil, 0, errors.New("Transaction is not empty!")
		}
		index += 1

		if index + 4 > limit {
			return nil, 0, errors.New("Invalid tx data!")
		}
		input.sequence = littleEndianBytesToUint32(tx[index:index+4])
		index += 4

		inputs = append(inputs, &input)
	}

	if index == limit {
		return nil, 0, errors.New("Invalid tx data!")
	}

	return inputs, index, nil
}

func getHashFromLockScript(script string) string {
	script = strings.ReplaceAll(script, " ", "")
	script = strings.ReplaceAll(script, "duphash160[", "76a914")
	script = strings.ReplaceAll(script, "]equalverifychecksig", "88ac")
	script = strings.ReplaceAll(script, "checkattenuationverify", "b2")
	script = strings.ReplaceAll(script, "[", "")

	slices := strings.Split(script, "]")

	script = ""
	if len(slices) == 1 {
		script = slices[0]
	} else if len(slices) == 3 {
		script += "4d"
		script += hex.EncodeToString(uint16ToLittleEndianBytes(uint16(len(slices[0]) / 2)))
		script += slices[0]
		script += hex.EncodeToString([]byte{byte(len(slices[1]) / 2)})
		script += slices[1]
		script += slices[2]
	} else {
		script = "unknown"
	}

	return script
}

func getHashCalcBytes(inputs []*TxInput, index int) []byte {
	tx := make([]byte, 0)

	tx = append(tx, uint32ToLittleEndianBytes(DefaultTxVersion)...)
	if len(inputs) < 0xfd {
		tx = append(tx, byte(len(inputs)))
	} else {
		tx = append(tx, 0xfd)
		tx = append(tx,uint16ToLittleEndianBytes(uint16(len(inputs)))...)
	}

	for i, input := range inputs {
		txid, _ := reverseHexToBytes(input.txID)
		tx = append(tx, txid...)
		tx = append(tx, uint32ToLittleEndianBytes(input.vout)...)
		if i == index {
			lockScript, _ := hex.DecodeString(input.lockScript)
			tx = append(tx, byte(len(lockScript)))
			tx = append(tx, lockScript...)
		} else {
			tx = append(tx, 0x00)
		}
		tx = append(tx, uint32ToLittleEndianBytes(input.sequence)...)
	}
	return tx
}

func getSubmitBytes(inputs []*TxInput, emptyTrans string) []byte {
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return nil
	}
	_, inputEnd, err := decodeEmptyTx(txBytes)
	if err != nil {
		return nil
	}

	tx := make([]byte, 0)
	tx = append(tx, uint32ToLittleEndianBytes(DefaultTxVersion)...)
	tx = append(tx, uint32ToLittleEndianBytes(DefaultTxVersion)...)
	if len(inputs) < 0xfd {
		tx = append(tx, byte(len(inputs)))
	} else {
		tx = append(tx, 0xfd)
		tx = append(tx,uint16ToLittleEndianBytes(uint16(len(inputs)))...)
	}

	for _, input := range inputs {
		txid, err := reverseHexToBytes(input.txID)
		if err != nil {
			return nil
		}
		tx = append(tx, txid...)
		tx = append(tx, uint32ToLittleEndianBytes(input.vout)...)
		sig, _ := hex.DecodeString(input.signature)
		pub, _ := hex.DecodeString(input.pubkey)

		sp := SignaturePubkey{
			Signature: sig,
			Pubkey:    pub,
		}

		tx = append(tx, sp.encodeToScript(byte(SigHashAll))...)

		tx = append(tx, uint32ToLittleEndianBytes(input.sequence)...)
	}

	return append(tx, txBytes[inputEnd:]...)
}