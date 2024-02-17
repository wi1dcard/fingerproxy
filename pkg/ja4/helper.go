package ja4

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
)

func sortUint16(sl []uint16) {
	sort.Slice(sl, func(x int, y int) bool { return sl[x] < sl[y] })
}

func joinUint16(slice []uint16, sep string) string {
	var buffer bytes.Buffer
	for i, u := range slice {
		if i != 0 {
			buffer.WriteString(sep)
		}
		buffer.WriteString(fmt.Sprintf("%04x", u))
	}
	return buffer.String()
}

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func truncatedSha256(in string) string {
	sha := sha256.New()
	sha.Write([]byte(in))
	return fmt.Sprintf("%x", sha.Sum(nil))[:12]
}
