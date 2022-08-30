package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

func SHA224(str string) string {
	hash := sha256.New224()
	hash.Write([]byte(str))
	return fmt.Sprintf("%X", hash.Sum(nil))
}

func SHA256(str string) string {
	hash := sha256.New()
	hash.Write([]byte(str))
	return fmt.Sprintf("%X", hash.Sum(nil))
}

func SHA384(str string) string {
	hash := sha512.New384()
	hash.Write([]byte(str))
	return fmt.Sprintf("%X", hash.Sum(nil))
}

func SHA512(str string) string {
	hash := sha512.New()
	hash.Write([]byte(str))
	return fmt.Sprintf("%X", hash.Sum(nil))
}
