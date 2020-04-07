package codec

func MinInt(a int, b int) int {
	if a > b {
		return b
	}
	return a
}

func RevertBytes(input []byte) (output []byte) {
	for i := len(input) - 1; i >= 0; i-- {
		output = append(output, input[i])
	}
	return
}

func ExtendLEBytes(input []byte, length int) []byte {
	diff := length - len(input)
	if diff == 0 {
		return input
	}
	for i := 0; i < diff; i++ {
		input = append(input, 0)
	}
	return input
}

func RemoveExtraLEBytes(input []byte) []byte {
	index := len(input)
	for {
		if input[index-1] != 0 {
			break
		} else {
			index--
		}
	}
	return input[:index]
}
