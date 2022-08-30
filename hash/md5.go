package hash

import (
	"crypto/md5"
	"fmt"
)

func MD5(str string) string {
	hash := md5.New()
	hash.Write([]byte(str))
	return fmt.Sprintf("%X", hash.Sum(nil))
}
