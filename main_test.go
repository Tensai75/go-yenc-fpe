package yEncFPE

import (
	"bytes"
	"strings"
	"testing"
)

// Test data constants
const (
	testPassword  = "testPassword123"
	testYEncBlock = "=ybegin line=128 size=18 name=file.bin\r\n" +
		"abcDEF123\r\n" +
		"=yend size=18\r\n"
	testYEncWithPart = "=ybegin line=128 size=18 name=file.bin\r\n" +
		"=ypart begin=1 end=18\r\n" +
		"abcDEF123\r\n" +
		"=yend size=18\r\n"
)

func TestNewAlphabet(t *testing.T) {
	alphabet := NewAlphabet()

	// Test alphabet length (should be 253 characters)
	if len(alphabet) != 253 {
		t.Errorf("Expected alphabet length 253, got %d", len(alphabet))
	}

	// Test that CR (0x0D), LF (0x0A) and null byte (0x00) are not in alphabet
	for _, b := range alphabet {
		if b == 0x0D || b == 0x0A || b == 0x00 {
			t.Errorf("Alphabet contains forbidden character: 0x%02X", b)
		}
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "Basic yEnc block",
			input:    testYEncBlock,
			expected: "=ybegin line=128 size=18 name=file.bin\xFFabcDEF123=yend size=18",
			wantErr:  false,
		},
		{
			name:     "yEnc block with ypart",
			input:    testYEncWithPart,
			expected: "=ybegin line=128 size=18 name=file.bin=ypart begin=1 end=18\xFFabcDEF123=yend size=18",
			wantErr:  false,
		},
		{
			name:    "Invalid block - missing ybegin",
			input:   "invalid data\r\n=yend size=18\r\n",
			wantErr: true,
		},
		{
			name:    "Invalid block - missing yend",
			input:   "=ybegin line=128 size=18 name=file.bin\r\nabcDEF123\r\n",
			wantErr: true,
		},
		{
			name:    "Empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Normalize(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDeriveKeys(t *testing.T) {
	salt := []byte("1234567890123456") // 16 bytes

	masterKey, encKey := deriveKeys(testPassword, salt)

	// Test master key length (should be 32 bytes for Argon2id)
	if len(masterKey) != 32 {
		t.Errorf("Expected master key length 32, got %d", len(masterKey))
	}

	// Test encryption key length (should be 32 bytes for SHA256)
	if len(encKey) != 32 {
		t.Errorf("Expected encryption key length 32, got %d", len(encKey))
	}

	// Test deterministic behavior
	masterKey2, encKey2 := deriveKeys(testPassword, salt)
	if !bytes.Equal(masterKey, masterKey2) {
		t.Error("Master key derivation is not deterministic")
	}
	if !bytes.Equal(encKey, encKey2) {
		t.Error("Encryption key derivation is not deterministic")
	}

	// Test different passwords produce different keys
	masterKey3, _ := deriveKeys("differentPassword", salt)
	if bytes.Equal(masterKey, masterKey3) {
		t.Error("Different passwords produce same master key")
	}

	// Test different salts produce different keys
	salt2 := []byte("6543210987654321")
	masterKey4, _ := deriveKeys(testPassword, salt2)
	if bytes.Equal(masterKey, masterKey4) {
		t.Error("Different salts produce same master key")
	}
}

func TestGenerateTweak(t *testing.T) {
	masterKey := make([]byte, 32)
	copy(masterKey, "test-master-key-32-bytes-long!!!")

	// Test basic tweak generation
	tweak := generateTweak(masterKey, 1)
	if len(tweak) != 8 {
		t.Errorf("Expected tweak length 8, got %d", len(tweak))
	}

	// Test deterministic behavior
	tweak2 := generateTweak(masterKey, 1)
	if !bytes.Equal(tweak, tweak2) {
		t.Error("Tweak generation is not deterministic")
	}

	// Test different segment indices produce different tweaks
	tweak3 := generateTweak(masterKey, 2)
	if bytes.Equal(tweak, tweak3) {
		t.Error("Different segment indices produce same tweak")
	}

	// Test different master keys produce different tweaks
	masterKey2 := make([]byte, 32)
	copy(masterKey2, "different-master-key-32-bytes!!!")
	tweak4 := generateTweak(masterKey2, 1)
	if bytes.Equal(tweak, tweak4) {
		t.Error("Different master keys produce same tweak")
	}
}

func TestGenerateSalt(t *testing.T) {
	alphabet := NewAlphabet()

	salt, err := generateSalt(alphabet)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Test salt length
	if len(salt) != SaltLength {
		t.Errorf("Expected salt length %d, got %d", SaltLength, len(salt))
	}

	// Test all salt bytes are from alphabet
	for _, b := range salt {
		found := false
		for _, ab := range alphabet {
			if b == ab {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Salt contains byte 0x%02X not in alphabet", b)
		}
	}

	// Test randomness (two calls should produce different salts)
	salt2, err := generateSalt(alphabet)
	if err != nil {
		t.Errorf("Unexpected error on second call: %v", err)
	}

	if bytes.Equal(salt, salt2) {
		t.Error("Two salt generations produced identical results (very unlikely)")
	}
}

func TestFF1EncryptDecrypt(t *testing.T) {
	alphabet := NewAlphabet()
	key := make([]byte, 32)
	copy(key, "test-encryption-key-32-bytes!!!!")
	tweak := []byte("testtwe8") // 8 bytes

	testCases := []string{
		"hello world",
		"test\xFF\x01\x02data", // Include sentinel and other bytes
		"=ybegin line=128 size=18 name=file.bin\xFFabcDEF123=yend size=18",
	}

	for _, plaintext := range testCases {
		t.Run("plaintext_"+plaintext[:min(10, len(plaintext))], func(t *testing.T) {
			// Test encryption
			ciphertext, err := FF1Encrypt(plaintext, key, tweak, alphabet)
			if err != nil {
				t.Errorf("Encryption failed: %v", err)
				return
			}

			// Test ciphertext length equals plaintext length
			if len(ciphertext) != len(plaintext) {
				t.Errorf("Ciphertext length %d != plaintext length %d", len(ciphertext), len(plaintext))
			}

			// Test decryption
			decrypted, err := FF1Decrypt(ciphertext, key, tweak, alphabet)
			if err != nil {
				t.Errorf("Decryption failed: %v", err)
				return
			}

			// Test round-trip
			if decrypted != plaintext {
				t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestDenormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "Basic normalized data",
			input:    "=ybegin line=128 size=18 name=file.bin\xFFabcDEF123=yend size=18",
			expected: "=ybegin line=128 size=18 name=file.bin\r\nabcDEF123\r\n=yend size=18\r\n",
			wantErr:  false,
		},
		{
			name:     "With ypart header",
			input:    "=ybegin line=128 size=18 name=file.bin=ypart begin=1 end=18\xFFabcDEF123=yend size=18",
			expected: "=ybegin line=128 size=18 name=file.bin=ypart begin=1 end=18\r\nabcDEF123\r\n=yend size=18\r\n",
			wantErr:  false,
		},
		{
			name:    "Missing sentinel",
			input:   "=ybegin line=128 size=18 name=file.binabcDEF123=yend size=18",
			wantErr: true,
		},
		{
			name:    "Missing yend",
			input:   "=ybegin line=128 size=18 name=file.bin\xFFabcDEF123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Denormalize(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAddLineBreaks(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		lineLen  int
		expected string
	}{
		{
			name:     "Basic line breaks",
			data:     "abcdefghijklmnop",
			lineLen:  4,
			expected: "abcd\r\nefgh\r\nijkl\r\nmnop",
		},
		{
			name:     "Exact multiple",
			data:     "abcdefgh",
			lineLen:  4,
			expected: "abcd\r\nefgh",
		},
		{
			name:     "Zero line length",
			data:     "abcdefgh",
			lineLen:  0,
			expected: "abcdefgh",
		},
		{
			name:     "Line length longer than data",
			data:     "abc",
			lineLen:  10,
			expected: "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addLineBreaks(tt.data, tt.lineLen)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestRemoveLineBreaks(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "With line breaks",
			input:    "abc\r\ndef\nghi\rjkl\n\rmno",
			expected: "abcdefghijklmno",
		},
		{
			name:     "No line breaks",
			input:    "abcdefghi",
			expected: "abcdefghi",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Only line breaks",
			input:    "\r\n\n\r\n\r\r",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeLineBreaks(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	config := Config{
		SegmentIndex: 1,
		LineLength:   128,
		Password:     testPassword,
	}

	// Test round-trip encryption/decryption
	encrypted, err := Encrypt(testYEncBlock, config)
	if err != nil {
		t.Errorf("Encryption failed: %v", err)
		return
	}

	// Encrypted data should not be empty
	if encrypted == "" {
		t.Error("Encrypted data is empty")
		return
	}

	// Encrypted data should be different from original
	if encrypted == testYEncBlock {
		t.Error("Encrypted data identical to original")
	}

	// Test decryption
	decrypted, err := Decrypt(encrypted, config)
	if err != nil {
		t.Errorf("Decryption failed: %v", err)
		return
	}

	// Test round-trip
	if decrypted != testYEncBlock {
		t.Errorf("Round-trip failed:\nOriginal:  %q\nDecrypted: %q", testYEncBlock, decrypted)
	}
}

func TestEncryptDecryptWithDifferentSegments(t *testing.T) {
	config1 := Config{
		SegmentIndex: 1,
		LineLength:   128,
		Password:     testPassword,
	}

	config2 := Config{
		SegmentIndex: 2,
		LineLength:   128,
		Password:     testPassword,
	}

	// Same plaintext with different segment indices should produce different ciphertexts
	encrypted1, err := Encrypt(testYEncBlock, config1)
	if err != nil {
		t.Errorf("Encryption 1 failed: %v", err)
		return
	}

	encrypted2, err := Encrypt(testYEncBlock, config2)
	if err != nil {
		t.Errorf("Encryption 2 failed: %v", err)
		return
	}

	if encrypted1 == encrypted2 {
		t.Error("Different segment indices produced identical ciphertexts")
	}

	// Each should decrypt correctly with its own config
	decrypted1, err := Decrypt(encrypted1, config1)
	if err != nil {
		t.Errorf("Decryption 1 failed: %v", err)
	} else if decrypted1 != testYEncBlock {
		t.Error("Decryption 1 round-trip failed")
	}

	decrypted2, err := Decrypt(encrypted2, config2)
	if err != nil {
		t.Errorf("Decryption 2 failed: %v", err)
	} else if decrypted2 != testYEncBlock {
		t.Error("Decryption 2 round-trip failed")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	config := Config{
		SegmentIndex: 1,
		LineLength:   128,
		Password:     testPassword,
	}

	tests := []struct {
		name string
		data string
	}{
		{
			name: "Too short data",
			data: "short",
		},
		{
			name: "Invalid salt length",
			data: strings.Repeat("a", 15), // 15 bytes < SaltLength
		},
		{
			name: "Wrong password",
			data: func() string {
				// Encrypt with one password, try to decrypt with another
				encrypted, _ := Encrypt(testYEncBlock, config)
				return encrypted
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Wrong password" {
				// Change password for decryption
				wrongConfig := config
				wrongConfig.Password = "wrongPassword"
				_, err := Decrypt(tt.data, wrongConfig)
				if err == nil {
					t.Error("Expected decryption to fail with wrong password")
				}
			} else {
				_, err := Decrypt(tt.data, config)
				if err == nil {
					t.Error("Expected decryption to fail but it succeeded")
				}
			}
		})
	}
}

func TestFormatBodyWithLineBreaks(t *testing.T) {
	tests := []struct {
		name     string
		bodyText string
		lineLen  int
		expected string
	}{
		{
			name:     "Empty body text",
			bodyText: "",
			lineLen:  10,
			expected: "",
		},
		{
			name:     "Basic line breaks",
			bodyText: "abcdefghijklmnop",
			lineLen:  4,
			expected: "abcd\r\nefgh\r\nijkl\r\nmnop",
		},
		{
			name:     "Exact multiple length",
			bodyText: "abcdefgh",
			lineLen:  4,
			expected: "abcd\r\nefgh",
		},
		{
			name:     "Shorter than line length",
			bodyText: "abc",
			lineLen:  10,
			expected: "abc",
		},
		{
			name:     "Escape character at boundary",
			bodyText: "abc=def",
			lineLen:  4,
			expected: "abc=d\r\nef",
		},
		{
			name:     "Escape character exactly at end of segment",
			bodyText: "abc=xyz123",
			lineLen:  4,
			expected: "abc=x\r\nyz12\r\n3",
		},
		{
			name:     "Multiple escape characters",
			bodyText: "ab=cd=ef=gh",
			lineLen:  3,
			expected: "ab=c\r\nd=e\r\nf=g\r\nh",
		},
		{
			name:     "Escape at very end of text",
			bodyText: "abcdef=",
			lineLen:  4,
			expected: "abcd\r\nef=",
		},
		{
			name:     "Line length of 1",
			bodyText: "a=bc",
			lineLen:  1,
			expected: "a\r\n=b\r\nc",
		},
		{
			name:     "Escape at position that would cause overflow",
			bodyText: "abc=defghijklmnop",
			lineLen:  4,
			expected: "abc=d\r\nefgh\r\nijkl\r\nmnop",
		},
		{
			name:     "Multiple consecutive escapes",
			bodyText: "ab==cd",
			lineLen:  3,
			expected: "ab==\r\ncd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBodyWithLineBreaks(tt.bodyText, tt.lineLen)
			if result != tt.expected {
				t.Errorf("formatBodyWithLineBreaks(%q, %d)\nExpected: %q\nGot:      %q",
					tt.bodyText, tt.lineLen, tt.expected, result)
			}
		})
	}
}

// Helper function for Go versions that don't have min built-in
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
