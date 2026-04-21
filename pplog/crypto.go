package pplog

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher provides ChaCha20-Poly1305 AEAD encryption using a key derived from UUID.
type Cipher struct {
	aead      cipher.AEAD
	keyHint   [4]byte // SHA-256(UUID)[0:4]
	sessionID [8]byte // random per startup (8 bytes for collision resistance)
	seq       uint32  // not used here; Reporter manages seq
}

// NewCipher creates a new Cipher from a 16-byte UUID.
// Key = SHA-256(UUID_bytes), sessionID = 4 random bytes.
func NewCipher(uuid [16]byte) (*Cipher, error) {
	hash := sha256.Sum256(uuid[:])

	aead, err := chacha20poly1305.New(hash[:])
	if err != nil {
		return nil, err
	}

	var sessionID [8]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, err
	}

	var keyHint [4]byte
	copy(keyHint[:], hash[:4])

	return &Cipher{
		aead:      aead,
		keyHint:   keyHint,
		sessionID: sessionID,
	}, nil
}

// NewCipherWithSession creates a Cipher with a specific sessionID (for testing).
func NewCipherWithSession(uuid [16]byte, sessionID [8]byte) (*Cipher, error) {
	hash := sha256.Sum256(uuid[:])

	aead, err := chacha20poly1305.New(hash[:])
	if err != nil {
		return nil, err
	}

	var keyHint [4]byte
	copy(keyHint[:], hash[:4])

	return &Cipher{
		aead:      aead,
		keyHint:   keyHint,
		sessionID: sessionID,
	}, nil
}

// BuildNonce constructs a 12-byte nonce: SessionID(8B) + SeqNum(4B BE).
func (c *Cipher) BuildNonce(seq uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:8], c.sessionID[:])
	binary.BigEndian.PutUint32(nonce[8:12], seq)
	return nonce
}

// Seal encrypts plaintext with additional data, allocating a new buffer.
func (c *Cipher) Seal(nonce [12]byte, plaintext, ad []byte) []byte {
	return c.aead.Seal(nil, nonce[:], plaintext, ad)
}

// SealTo encrypts plaintext with additional data, appending to dst.
// Callers can pass a pre-allocated slice to avoid heap allocation.
func (c *Cipher) SealTo(dst []byte, nonce [12]byte, plaintext, ad []byte) []byte {
	return c.aead.Seal(dst, nonce[:], plaintext, ad)
}

// Open decrypts ciphertext with additional data.
func (c *Cipher) Open(nonce []byte, ciphertext, ad []byte) ([]byte, error) {
	return c.aead.Open(nil, nonce, ciphertext, ad)
}

// KeyHint returns the 4-byte key hint (first 4 bytes of SHA-256(UUID)).
func (c *Cipher) KeyHint() [4]byte {
	return c.keyHint
}

// Overhead returns the AEAD tag size (16 bytes for Poly1305).
func (c *Cipher) Overhead() int {
	return c.aead.Overhead()
}
