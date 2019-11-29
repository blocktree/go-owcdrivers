package evaioTransaction

type MsgSend struct {
	Amount      Coins  `json:"amount"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}

type Message struct {
	Type  string  `json:"type"`
	Value MsgSend `json:"value"`
}

func NewMsgSend(fromAddr, toAddr string, amount Coins) MsgSend {
	return MsgSend{FromAddress: fromAddr, ToAddress: toAddr, Amount: amount}
}

func NewMessage(msgType string, value MsgSend) Message {
	return Message{Type: msgType, Value: value}
}
