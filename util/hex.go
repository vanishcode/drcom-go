package util

import (
	"fmt"
	"strings"
)

// HexDump returns a hex dump string of data, similar to xxd/hexdump output.
func HexDump(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(&sb, "%08x: ", i)
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(&sb, "%02x ", data[i+j])
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteByte(' ')
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				c := data[i+j]
				if c >= 0x20 && c <= 0x7e {
					sb.WriteByte(c)
				} else {
					sb.WriteByte('.')
				}
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
