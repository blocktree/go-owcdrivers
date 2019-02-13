package virtualeconomyTransaction

import (
	"encoding/binary"
	"errors"
)

func TxStructDecode(tx []byte) (*TxStruct, uint64, error) {
	var ts TxStruct

	limit := len(tx)
	index := 0

	if index+1 > limit {
		return nil, 0, errors.New("Invalid transaction data!")
	}
	ts.TxType = tx[index]
	index++

	if index+8 > limit {
		return nil, 0, errors.New("Invalid transaction data!")
	}
	timestamp := binary.BigEndian.Uint64(tx[index : index+8])
	index += 8

	if index+8 > limit {
		return nil, 0, errors.New("Invalid transaction data!")
	}
	ts.Amount = binary.BigEndian.Uint64(tx[index : index+8])
	index += 8

	if index+8 > limit {
		return nil, 0, errors.New("Invalid transaction data!")
	}
	ts.Fee = binary.BigEndian.Uint64(tx[index : index+8])
	index += 8

	if index+2 > limit {
		return nil, 0, errors.New("Invalid transaction data!")
	}
	ts.FeeScale = binary.BigEndian.Uint16(tx[index : index+2])
	index += 2

	if index+26 > limit {
		return nil, 0, errors.New("Invalid transaction data!")
	}
	ts.To = Encode(tx[index:index+26], BitcoinAlphabet)
	index += 26

	if index+2 > limit {
		return nil, 0, errors.New("Invalid transaction data!")
	}
	if tx[index] == 0 && tx[index+1] == 0 {
		ts.Attachment = ""
		index += 2
		if index != limit {
			return nil, 0, errors.New("Invalid transaction data!")
		}

	} else {
		return nil, 0, errors.New("Non-empty attachment is not supported yet!")
	}

	return &ts, timestamp, nil
}
