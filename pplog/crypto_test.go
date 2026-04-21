package pplog

import (
	"crypto/sha256"
	"testing"
)

func testUUID() [16]byte {
	return [16]byte{0x99, 0x0c, 0x7c, 0x49, 0xdb, 0xb2, 0x47, 0x0b,
		0xbb, 0x05, 0x2f, 0x82, 0x60, 0x28, 0x17, 0x59}
}

func TestCipher_RoundTrip(t *testing.T) {
	uuid := testUUID()
	c, err := NewCipher(uuid)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plaintext := []byte("hello pplog encryption")
	ad := []byte("header-data")
	nonce := c.BuildNonce(1)

	ciphertext := c.Seal(nonce, plaintext, ad)
	decrypted, err := c.Open(nonce[:], ciphertext, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestCipher_WrongKey(t *testing.T) {
	uuid1 := testUUID()
	uuid2 := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

	c1, _ := NewCipher(uuid1)
	c2, _ := NewCipher(uuid2)

	plaintext := []byte("secret data")
	ad := []byte("ad")
	nonce := c1.BuildNonce(1)

	ciphertext := c1.Seal(nonce, plaintext, ad)
	_, err := c2.Open(nonce[:], ciphertext, ad)
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

func TestCipher_TamperedCiphertext(t *testing.T) {
	uuid := testUUID()
	c, _ := NewCipher(uuid)

	plaintext := []byte("important data")
	ad := []byte("ad")
	nonce := c.BuildNonce(1)

	ciphertext := c.Seal(nonce, plaintext, ad)
	// Tamper with ciphertext
	ciphertext[0] ^= 0xff

	_, err := c.Open(nonce[:], ciphertext, ad)
	if err == nil {
		t.Error("expected decryption failure with tampered ciphertext")
	}
}

func TestCipher_TamperedAD(t *testing.T) {
	uuid := testUUID()
	c, _ := NewCipher(uuid)

	plaintext := []byte("important data")
	ad := []byte("original-ad")
	nonce := c.BuildNonce(1)

	ciphertext := c.Seal(nonce, plaintext, ad)
	_, err := c.Open(nonce[:], ciphertext, []byte("tampered-ad"))
	if err == nil {
		t.Error("expected decryption failure with tampered AD")
	}
}

func TestCipher_KeyHint(t *testing.T) {
	uuid := testUUID()
	c, _ := NewCipher(uuid)

	hash := sha256.Sum256(uuid[:])
	hint := c.KeyHint()

	for i := 0; i < 4; i++ {
		if hint[i] != hash[i] {
			t.Errorf("keyHint[%d] = %02x, want %02x", i, hint[i], hash[i])
		}
	}
}

func TestCipher_NonceUniqueness(t *testing.T) {
	uuid := testUUID()
	c, _ := NewCipher(uuid)

	n1 := c.BuildNonce(1)
	n2 := c.BuildNonce(2)

	if n1 == n2 {
		t.Error("nonces with different seq should differ")
	}

	// Same seq should produce same nonce
	n1b := c.BuildNonce(1)
	if n1 != n1b {
		t.Error("same seq should produce same nonce")
	}
}

func TestCipher_NonceStructure(t *testing.T) {
	uuid := testUUID()
	sid := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44}
	c, _ := NewCipherWithSession(uuid, sid)

	nonce := c.BuildNonce(0x12345678)

	// First 8 bytes = sessionID
	for i := 0; i < 8; i++ {
		if nonce[i] != sid[i] {
			t.Errorf("sessionID[%d] = %02x, want %02x", i, nonce[i], sid[i])
		}
	}
	// Last 4 bytes = seq big-endian
	if nonce[8] != 0x12 || nonce[9] != 0x34 || nonce[10] != 0x56 || nonce[11] != 0x78 {
		t.Errorf("seq portion: %02x%02x%02x%02x", nonce[8], nonce[9], nonce[10], nonce[11])
	}
}
