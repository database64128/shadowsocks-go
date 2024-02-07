package ss2022

import (
	"crypto/rand"
	"strconv"
)

func newRandomCipherConfigTupleNoEIH(method string, enableUDP bool) (clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, err error) {
	keySize, err := PSKLengthForMethod(method)
	if err != nil {
		return
	}
	psk := make([]byte, keySize)
	if _, err = rand.Read(psk); err != nil {
		return
	}
	clientCipherConfig, err = NewClientCipherConfig(psk, nil, enableUDP)
	if err != nil {
		return
	}
	userCipherConfig, err = NewUserCipherConfig(psk, enableUDP)
	return
}

func newRandomCipherConfigTupleWithEIH(method string, enableUDP bool) (clientCipherConfig *ClientCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap, err error) {
	keySize, err := PSKLengthForMethod(method)
	if err != nil {
		return
	}

	iPSK := make([]byte, keySize)
	if _, err = rand.Read(iPSK); err != nil {
		return
	}
	iPSKs := [][]byte{iPSK}

	var uPSK []byte
	userLookupMap = make(UserLookupMap, 7)
	for i := range 7 {
		uPSK = make([]byte, keySize)
		if _, err = rand.Read(uPSK); err != nil {
			return
		}

		uPSKHash := PSKHash(uPSK)
		var c *ServerUserCipherConfig
		c, err = NewServerUserCipherConfig(strconv.Itoa(i), uPSK, enableUDP)
		if err != nil {
			return
		}

		userLookupMap[uPSKHash] = c
	}

	clientCipherConfig, err = NewClientCipherConfig(uPSK, iPSKs, enableUDP)
	if err != nil {
		return
	}
	identityCipherConfig, err = NewServerIdentityCipherConfig(iPSK, enableUDP)
	return
}
