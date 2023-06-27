package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type AES256GCM interface {
	Encrypt(nonce []byte, data []byte, key []byte) ([]byte, error)
	Decrypt(nonce []byte, data []byte, key []byte) ([]byte, error)
}

type gcm struct{}

func NewGCM() AES256GCM {
	return &gcm{}
}

func (e *gcm) Encrypt(nonce []byte, data []byte, key []byte) ([]byte, error) {
	err := e.isNonceSizeValid(nonce)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, data, nil), nil
}

func (e *gcm) Decrypt(nonce []byte, data []byte, key []byte) ([]byte, error) {
	err := e.isNonceSizeValid(nonce)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ret, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (e *gcm) isNonceSizeValid(nonce []byte) error {
	if len(nonce) != 12 {
		return errors.New("nonce size must be equal to 12 bytes")
	}
	return nil
}
