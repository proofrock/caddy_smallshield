package caddy_smallshield

import (
	"strconv"
	"strings"
)

func cutToColon(input string) string {
	index := strings.Index(input, ":")

	if index != -1 {
		return input[:index]
	}
	return input
}

func getPrintableSlice(m [24]bool) string {
	ret := make([]string, 0)
	for i, b := range m {
		if b {
			ret = append(ret, strconv.Itoa(i))
		}
	}

	return "[" + strings.Join(ret, ", ") + "]"
}
