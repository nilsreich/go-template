package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var Params = Argon2Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func GenerateSalt(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func HashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, Params.Iterations, Params.Memory, Params.Parallelism, Params.KeyLength)
}

func ComparePasswordAndHash(password string, salt []byte, encodedHash []byte) bool {
	otherHash := HashPassword(password, salt)
	if subtle.ConstantTimeCompare(encodedHash, otherHash) == 1 {
		return true
	}
	return false
}

func CreatePasswordHash(password string) (hash []byte, salt []byte, err error) {
	salt, err = GenerateSalt(Params.SaltLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	hash = HashPassword(password, salt)
	return hash, salt, nil
}
