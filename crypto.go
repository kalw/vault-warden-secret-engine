package vaultwardensecrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// deriveMasterKey derives the 32-byte master key from the user's email and master password.
// kdfType 0 = PBKDF2-SHA256, kdfType 1 = Argon2id.
// memory is in MiB (only for Argon2id); 0 defaults to 64 MiB.
// parallelism is thread count (only for Argon2id); 0 defaults to 4.
func deriveMasterKey(email, masterPassword string, kdfType, iterations, memory, parallelism int) ([]byte, error) {
	password := []byte(masterPassword)
	emailNorm := []byte(strings.ToLower(strings.TrimSpace(email)))

	switch kdfType {
	case 0: // PBKDF2-SHA256
		if iterations <= 0 {
			iterations = 600000
		}
		return pbkdf2.Key(password, emailNorm, iterations, 32, sha256.New), nil

	case 1: // Argon2id
		if iterations <= 0 {
			iterations = 3
		}
		if memory <= 0 {
			memory = 64
		}
		if parallelism <= 0 {
			parallelism = 4
		}
		// Argon2id salt is SHA-256(email) per Bitwarden spec.
		saltHash := sha256.Sum256(emailNorm)
		// memory parameter for argon2.IDKey is in KiB; kdfMemory from server is MiB.
		return argon2.IDKey(password, saltHash[:], uint32(iterations), uint32(memory)*1024, uint8(parallelism), 32), nil

	default:
		return nil, fmt.Errorf("unsupported KDF type %d", kdfType)
	}
}

// stretchMasterKey expands the 32-byte master key into separate 32-byte AES and MAC keys
// using HKDF-Expand (RFC 5869 §2.3) with "enc" and "mac" as info strings.
func stretchMasterKey(masterKey []byte) (encKey, macKey []byte, err error) {
	encKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdf.Expand(sha256.New, masterKey, []byte("enc")), encKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf expand enc: %w", err)
	}
	macKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdf.Expand(sha256.New, masterKey, []byte("mac")), macKey); err != nil {
		return nil, nil, fmt.Errorf("hkdf expand mac: %w", err)
	}
	return encKey, macKey, nil
}

// encString holds the parsed components of a Bitwarden EncryptedString.
// Format: "<type>.<iv>|<ciphertext>|<mac>" for AES types, or "<type>.<ciphertext>" for RSA.
type encString struct {
	encType int
	iv      []byte
	ct      []byte
	mac     []byte
}

func parseEncString(s string) (*encString, error) {
	if s == "" {
		return nil, fmt.Errorf("empty enc string")
	}
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return nil, fmt.Errorf("enc string missing type prefix")
	}

	var t int
	if _, err := fmt.Sscanf(s[:dot], "%d", &t); err != nil {
		return nil, fmt.Errorf("enc string bad type %q", s[:dot])
	}

	parts := strings.Split(s[dot+1:], "|")
	e := &encString{encType: t}

	decode := func(s string) ([]byte, error) {
		return base64.StdEncoding.DecodeString(s)
	}

	switch t {
	case 0: // AesCbc256_B64: iv|ct (no HMAC)
		if len(parts) != 2 {
			return nil, fmt.Errorf("type 0: expected 2 parts, got %d", len(parts))
		}
		var err error
		if e.iv, err = decode(parts[0]); err != nil {
			return nil, fmt.Errorf("type 0: iv: %w", err)
		}
		if e.ct, err = decode(parts[1]); err != nil {
			return nil, fmt.Errorf("type 0: ct: %w", err)
		}

	case 2: // AesCbc256_HmacSha256_B64: iv|ct|mac
		if len(parts) != 3 {
			return nil, fmt.Errorf("type 2: expected 3 parts, got %d", len(parts))
		}
		var err error
		if e.iv, err = decode(parts[0]); err != nil {
			return nil, fmt.Errorf("type 2: iv: %w", err)
		}
		if e.ct, err = decode(parts[1]); err != nil {
			return nil, fmt.Errorf("type 2: ct: %w", err)
		}
		if e.mac, err = decode(parts[2]); err != nil {
			return nil, fmt.Errorf("type 2: mac: %w", err)
		}

	case 4: // Rsa2048_OaepSha1_B64: just RSA ciphertext
		if len(parts) != 1 {
			return nil, fmt.Errorf("type 4: expected 1 part, got %d", len(parts))
		}
		var err error
		if e.ct, err = decode(parts[0]); err != nil {
			return nil, fmt.Errorf("type 4: ct: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported enc type %d", t)
	}
	return e, nil
}

// decryptSymmetric decrypts an AES-CBC enc string with the given enc/mac key pair.
func decryptSymmetric(e *encString, encKey, macKey []byte) ([]byte, error) {
	if len(e.mac) > 0 {
		// Verify HMAC-SHA256(macKey, iv || ciphertext).
		h := hmac.New(sha256.New, macKey)
		h.Write(e.iv)
		h.Write(e.ct)
		if !hmac.Equal(h.Sum(nil), e.mac) {
			return nil, fmt.Errorf("HMAC verification failed")
		}
	}

	block, err := aes.NewCipher(encKey[:32])
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	if len(e.ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length not a multiple of block size")
	}

	plaintext := make([]byte, len(e.ct))
	cipher.NewCBCDecrypter(block, e.iv).CryptBlocks(plaintext, e.ct)

	return pkcs7Unpad(plaintext)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty plaintext after decryption")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(data) {
		return nil, fmt.Errorf("invalid PKCS7 padding byte: %d", pad)
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("inconsistent PKCS7 padding")
		}
	}
	return data[:len(data)-pad], nil
}

// decryptEncString decrypts a Bitwarden EncryptedString using symmetric keys.
func decryptEncString(s string, encKey, macKey []byte) ([]byte, error) {
	e, err := parseEncString(s)
	if err != nil {
		return nil, err
	}
	switch e.encType {
	case 0, 2:
		return decryptSymmetric(e, encKey, macKey)
	default:
		return nil, fmt.Errorf("enc type %d cannot be decrypted with symmetric keys", e.encType)
	}
}

// decryptStr decrypts an EncryptedString to a UTF-8 string.
// Returns "" for empty or nil inputs without error.
func decryptStr(s *string, encKey, macKey []byte) string {
	if s == nil || *s == "" {
		return ""
	}
	b, err := decryptEncString(*s, encKey, macKey)
	if err != nil {
		return ""
	}
	return string(b)
}

// decryptUserSymKey decrypts the user's 64-byte symmetric key stored encrypted in profile.Key.
// The encrypted key was created by encrypting 64 random bytes with the stretched master key.
func decryptUserSymKey(encKey string, masterEncKey, masterMacKey []byte) (userEncKey, userMacKey []byte, err error) {
	plaintext, err := decryptEncString(encKey, masterEncKey, masterMacKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt user sym key: %w", err)
	}
	if len(plaintext) != 64 {
		return nil, nil, fmt.Errorf("user sym key: expected 64 bytes, got %d", len(plaintext))
	}
	return plaintext[:32], plaintext[32:], nil
}

// decryptRSAPrivateKey decrypts the user's PKCS8 RSA private key from profile.PrivateKey.
func decryptRSAPrivateKey(encPrivKey string, userEncKey, userMacKey []byte) (*rsa.PrivateKey, error) {
	der, err := decryptEncString(encPrivKey, userEncKey, userMacKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt RSA private key: %w", err)
	}
	raw, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	rsaKey, ok := raw.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA key, got %T", raw)
	}
	return rsaKey, nil
}

// decryptOrgKey decrypts an organization's 64-byte symmetric key using the user's RSA private key.
// Org keys are encrypted with RSA-OAEP-SHA1 (enc type 4).
func decryptOrgKey(encOrgKey string, rsaKey *rsa.PrivateKey) (orgEncKey, orgMacKey []byte, err error) {
	e, err := parseEncString(encOrgKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse org key: %w", err)
	}
	if e.encType != 4 {
		return nil, nil, fmt.Errorf("org key: expected type 4, got %d", e.encType)
	}
	plaintext, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, rsaKey, e.ct, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA-OAEP decrypt org key: %w", err)
	}
	if len(plaintext) != 64 {
		return nil, nil, fmt.Errorf("org key: expected 64 bytes, got %d", len(plaintext))
	}
	return plaintext[:32], plaintext[32:], nil
}
