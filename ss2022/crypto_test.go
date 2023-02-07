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

func newRandomCipherConfigTupleWithEIH(method string, enableUDP bool) (clientCipherConfig *ClientCipherConfig, identityCipherConfig ServerIdentityCipherConfig, uPSKMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig, err error) {
	keySize, err := PSKLengthForMethod(method)
	if err != nil {
		return
	}

	iPSK := make([]byte, keySize)
	if _, err = rand.Read(iPSK); err != nil {
		return
	}
	iPSKs := [][]byte{iPSK}

	userMap := make(map[string][]byte, 7)
	for i := 0; i < 7; i++ {
		psk := make([]byte, keySize)
		if _, err = rand.Read(psk); err != nil {
			return
		}
		userMap[strconv.Itoa(i)] = psk
	}
	uPSK := userMap["0"]

	clientCipherConfig, err = NewClientCipherConfig(uPSK, iPSKs, enableUDP)
	if err != nil {
		return
	}
	identityCipherConfig, err = NewServerIdentityCipherConfig(iPSK, enableUDP)
	if err != nil {
		return
	}
	uPSKMap, err = NewUPSKMap(keySize, userMap, enableUDP)
	return
}
