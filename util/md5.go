package util

import "crypto/md5"

// MD5Sum returns the MD5 digest of data.
func MD5Sum(data []byte) [16]byte {
	return md5.Sum(data)
}
