package aes256

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGCM(t *testing.T) {
	assert := assert.New(t)
	t.Run("Should return encrypted data", func(t *testing.T) {
		sut := NewGCM()
		encrypted, _ := sut.Encrypt(make([]byte, 12), []byte("any_data"), []byte("AES256Key-32Characters1234567890"))
		assert.Equal(24, len(encrypted))
	})

	t.Run("Should return decrypted data", func(t *testing.T) {
		sut := NewGCM()
		nonce := make([]byte, 12)
		secretKey := []byte("AES256Key-32Characters1234567890")
		encrypted, _ := sut.Encrypt(nonce, []byte("any_data"), secretKey)
		decrypted, _ := sut.Decrypt(nonce, encrypted, secretKey)
		assert.Equal([]byte("any_data"), decrypted)
	})
}
