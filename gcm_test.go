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
}
