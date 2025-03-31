package ss2022

import (
	"crypto/rand"
	"strconv"
)

var (
	methodCases = [...]string{
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
	}

	cipherCases = [...]struct {
		name            string
		newCipherConfig func(method string, enableUDP bool) (
			clientCipherConfig *ClientCipherConfig,
			userCipherConfig UserCipherConfig,
			identityCipherConfig ServerIdentityCipherConfig,
			userLookupMap UserLookupMap,
			username string,
			err error,
		)
	}{
		{
			name:            "NoEIH",
			newCipherConfig: newRandomCipherConfigTupleNoEIH,
		},
		{
			name:            "WithEIH",
			newCipherConfig: newRandomCipherConfigTupleWithEIH,
		},
	}
)

func newRandomCipherConfigTupleNoEIH(method string, enableUDP bool) (clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, _ ServerIdentityCipherConfig, _ UserLookupMap, _ string, err error) {
	keySize, err := PSKLengthForMethod(method)
	if err != nil {
		return
	}
	psk := make([]byte, keySize)
	rand.Read(psk)
	clientCipherConfig, err = NewClientCipherConfig(psk, nil, enableUDP)
	if err != nil {
		return
	}
	userCipherConfig, err = NewUserCipherConfig(psk, enableUDP)
	return
}

func newRandomCipherConfigTupleWithEIH(method string, enableUDP bool) (clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap, username string, err error) {
	keySize, err := PSKLengthForMethod(method)
	if err != nil {
		return
	}

	iPSK := make([]byte, keySize)
	rand.Read(iPSK)
	iPSKs := [][]byte{iPSK}

	var uPSK []byte
	userLookupMap = make(UserLookupMap, 7)
	for i := range 7 {
		uPSK = make([]byte, keySize)
		rand.Read(uPSK)
		username = strconv.Itoa(i)

		uPSKHash := PSKHash(uPSK)
		var c ServerUserCipherConfig
		c, err = NewServerUserCipherConfig(username, uPSK, enableUDP)
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
