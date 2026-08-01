package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Vault struct {
	aead cipher.AEAD
	key  []byte
}

func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("vault key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead, key: append([]byte(nil), key...)}, nil
}

func (v *Vault) Encrypt(plain string, purpose string) (string, error) {
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := v.aead.Seal(nonce, nonce, []byte(plain), []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (v *Vault) Decrypt(encoded string, purpose string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < v.aead.NonceSize() {
		return "", errors.New("invalid encrypted value")
	}
	nonce, ciphertext := sealed[:v.aead.NonceSize()], sealed[v.aead.NonceSize():]
	plain, err := v.aead.Open(nil, nonce, ciphertext, []byte(purpose))
	if err != nil {
		return "", errors.New("encrypted value authentication failed")
	}
	return string(plain), nil
}

func (v *Vault) Namespace(parts ...string) string {
	mac := hmac.New(sha256.New, v.key)
	for _, part := range parts {
		_, _ = mac.Write([]byte(part))
		_, _ = mac.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18])
}

func randomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// passwordHash deliberately uses a self-contained PBKDF2-HMAC-SHA256
// implementation so the lite gateway has no password-library runtime
// dependency. The high iteration count and per-value salt are encoded with the
// result and can be raised on a future successful login.
func passwordHash(password string, iterations int) (string, error) {
	if len(password) < 6 {
		return "", errors.New("secret must contain at least 6 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := pbkdf2SHA256([]byte(password), salt, iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iterations,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(digest)), nil
}

func passwordVerify(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 10000 || iterations > 2_000_000 {
		return false
	}
	salt, err1 := base64.RawURLEncoding.DecodeString(parts[2])
	want, err2 := base64.RawURLEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) != 32 {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	blocks := (keyLen + sha256.Size - 1) / sha256.Size
	result := make([]byte, 0, blocks*sha256.Size)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}
