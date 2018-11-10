package omniTransaction

type OmniStruct struct {
	TxType     int
	PropertyId uint32
	Amount     uint64
	Ecosystem  byte
	Memo       string
	Address    string
}

func (os OmniStruct) getPayload() []byte {
	payload := []byte{}
	switch os.TxType {
	case SimpleSend:
		payload = createPayloadSimpleSend(os.PropertyId, os.Amount)
		break
	case SendAll:
		payload = createPayloadSendAll(os.Ecosystem)
		break
	case DExAccept:
		payload = createPayloadDExAccept(os.PropertyId, os.Amount)
		break
	case MetaDExCancelEcosystem:
		payload = createPayloadMetaDExCancelEcosystem(os.Ecosystem)
		break
	case CloseCrowdsale:
		payload = createPayloadCloseCrowdsale(os.PropertyId)
		break
	case Grant:
		payload = createPayloadGrant(os.PropertyId, os.Amount, os.Memo)
		break
	case Revoke:
		payload = createPayloadRevoke(os.PropertyId, os.Amount, os.Memo)
		break
	case ChangeIssuer:
		payload = createPayloadChangeIssuer(os.PropertyId)
		break
	case EnableFreezing:
		payload = createPayloadEnableFreezing(os.PropertyId)
		break
	case DisableFreezing:
		payload = createPayloadDisableFreezing(os.PropertyId)
		break
	case FreezeTokens:
		payload = createPayloadFreezeTokens(os.PropertyId, os.Amount, os.Address)
		break
	case UnfreezeTokens:
		payload = createPayloadUnfreezeTokens(os.PropertyId, os.Amount, os.Address)
		break
	default:
		return nil
	}

	payload = append(OmniPrefix[:], payload...)
	payload = append([]byte{OpReturn, byte(len(payload))}, payload...)
	return payload
}
