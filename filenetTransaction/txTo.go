package filenetTransaction

func (d Vouts) Len() int {
	return len(d)
}

func (d Vouts) Swap (i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (d Vouts) Less(i, j int) bool {
	return d[i].Address < d[j].Address
}