package hash

import "testing"

const (
	md5Encrypt123456 = "E10ADC3949BA59ABBE56E057F20F883E"
)

func TestMD5(t *testing.T) {
	if MD5("123456") != md5Encrypt123456 {
		t.Fatalf("md5 encrypt failed\n")
	}
}
