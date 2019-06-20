package rippleTransaction

type enc struct {
	typ, field byte
}

func getEncBytes(e enc) []byte {
	switch {
	case e.typ < 16 && e.field < 16:
		return []byte{e.typ<<4 | e.field}
	case e.typ < 16:
		return []byte{e.typ << 4, e.field}
	case e.field < 16:
		return []byte{e.field, e.typ}
	default:
		return []byte{0, e.typ, e.field}
	}
}
