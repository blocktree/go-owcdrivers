package addressEncoder

import(
"encoding/binary"
)

func CRC32(s []byte) []byte {
	var table [256]uint32
	for i := range table {
        word := uint32(i)
        for j := 0; j < 8; j++ {
            if word&1 == 1 {
                word = (word >> 1) ^ 0xedb88320
            } else {
                word >>= 1
            }
        }
        table[i] = word
    }
	crc := ^uint32(0)
	crcbuf:=make([]byte,4)
    for i := 0; i < len(s); i++ {
        crc = table[byte(crc)^s[i]] ^ (crc >> 8)
	}
	binary.BigEndian.PutUint32(crcbuf,^crc)
    return crcbuf
}