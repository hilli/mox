package managesieveserver

import (
	"encoding/base64"
	"strconv"
)

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
