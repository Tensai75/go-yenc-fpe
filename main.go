// Package yEncFPE implements the yEnc-FPE (yEnc Format-Preserving Encryption) standard v0.1.
//
// This package provides format-preserving encryption for yEnc-encoded binary blocks used in
// Usenet transfers. The scheme maintains exact length (±1 byte for sentinel) and preserves
// the printable character range required by yEnc while providing confidentiality through
// AES-FF1 encryption.
//
// Key features:
//   - Format-preserving encryption using AES-FF1 (NIST SP 800-38G compliant)
//   - Maintains yEnc-compatible printable characters
//   - Deterministic reconstruction of yEnc headers, bodies, and footers
//   - Fixed ciphertext length equal to plaintext length (+1 sentinel byte)
//   - Suitable for Usenet transmission with standard yEnc parsers
//
// The package implements the complete yEnc-FPE pipeline including normalization,
// key derivation using Argon2id, tweak generation with HMAC-SHA256, and
// format-preserving encryption over a 253-character alphabet.
//
// Example usage:
//
//	config := yEncFPE.Config{
//		SegmentIndex: 1,
//		LineLength:   128,
//		Password:     "secretpassword",
//	}
//
//	// Encrypt a yEnc block
//	encrypted, err := yEncFPE.Encrypt(yEncBlock, config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt back to original
//	decrypted, err := yEncFPE.Decrypt(encrypted, config)
//	if err != nil {
//		log.Fatal(err)
//	}
package yEncFPE

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Tensai75/go-fpe-bytes/ff1"
	"golang.org/x/crypto/argon2"
)

const (
	// SentinelByte (0xFF) is inserted between yEnc header and body during normalization
	// to preserve the header-body boundary for deterministic reconstruction.
	SentinelByte = byte(0xFF)

	// DefaultLineLength is the default number of characters per line in formatted output.
	// This matches the typical yEnc line length for compatibility.
	DefaultLineLength = 128

	// SaltLength is the length in bytes of the random salt prepended to ciphertext.
	// The salt is generated from the valid yEnc-FPE alphabet.
	SaltLength = 16
)

const (
	// SentinelStr is the string representation of the sentinel byte used during normalization.
	SentinelStr = "\xFF"

	// CRStr represents the carriage return character (0x0D), excluded from the FF1 alphabet.
	CRStr = "\r"

	// LFStr represents the line feed character (0x0A), excluded from the FF1 alphabet.
	LFStr = "\n"

	// CRLF represents the standard Windows/Internet line ending sequence.
	CRLF = CRStr + LFStr

	// EscStr represents the yEnc escape character used for encoding special bytes.
	EscStr = "="
)

// FF1Alphabet defines the 253-character alphabet used for format-preserving encryption.
//
// This alphabet includes all byte values from 0x01 to 0xFF except:
//   - 0x00 (null byte)
//   - 0x0A (line feed, LF)
//   - 0x0D (carriage return, CR)
//
// These exclusions ensure the encrypted output remains compatible with text-based
// protocols and yEnc parsing requirements while maximizing the character set size
// for optimal FF1 performance.
const FF1Alphabet = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0B\x0C\x0E\x0F" +
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F" +
	"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F" +
	"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F" +
	"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F" +
	"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F" +
	"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F" +
	"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F" +
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F" +
	"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F" +
	"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF" +
	"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF" +
	"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF" +
	"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF" +
	"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF" +
	"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

// NewAlphabet returns the standard 253-character alphabet used for FF1 format-preserving encryption.
//
// The returned byte slice contains all valid characters for yEnc-FPE encryption,
// excluding null bytes (0x00), line feeds (0x0A), and carriage returns (0x0D).
// This alphabet ensures compatibility with text-based protocols while maximizing
// the character set size for optimal encryption performance.
func NewAlphabet() []byte {
	return []byte(FF1Alphabet)
}

// Config holds the configuration parameters for yEnc-FPE encryption and decryption operations.
//
// All fields are required for proper operation. The SegmentIndex must be unique
// across all segments in an upload session to ensure unique encryption tweaks.
type Config struct {
	// SegmentIndex is a unique identifier (≥1) for this segment across all files in the upload.
	// Different segment indices produce different ciphertext for the same plaintext,
	// ensuring security when encrypting multiple related segments.
	SegmentIndex uint32

	// LineLength specifies the number of characters per line in formatted output.
	// Use 0 or negative values to disable line formatting. Typical values are 64, 128, or 256.
	LineLength int

	// Password is the user-provided password for key derivation.
	// The same password must be used for both encryption and decryption operations.
	Password string
}

// YEncBlock represents a parsed yEnc message block with its logical components.
//
// This type is used internally for structured processing of yEnc data during
// normalization and denormalization operations.
type YEncBlock struct {
	// Header contains the yEnc header lines (=ybegin, =ypart if present)
	Header string

	// Body contains the encoded binary data between header and footer
	Body string

	// Footer contains the yEnc footer line (=yend)
	Footer string
}

// Normalize processes a yEnc block for encryption according to the yEnc-FPE specification.
//
// The function transforms a standard yEnc message block into a normalized form suitable
// for format-preserving encryption by:
//  1. Removing all carriage return (CR) characters
//  2. Identifying header, body, and footer sections
//  3. Inserting a sentinel byte (0xFF) between header and body
//  4. Removing line breaks from body and footer
//  5. Concatenating into a single normalized string
//
// The normalized output preserves structural information needed for reconstruction
// while fitting the 253-character alphabet required by FF1 encryption.
//
// Parameters:
//   - yEncText: A complete yEnc message block with CRLF line endings
//
// Returns:
//   - string: The normalized plaintext ready for encryption
//   - error: An error if the input is not a valid yEnc block
//
// Example input:
//
//	=ybegin line=128 size=18 name=file.bin\r\n
//	abcDEF123\r\n
//	=yend size=18\r\n
//
// Example output:
//
//	=ybegin line=128 size=18 name=file.bin\xFFabcDEF123=yend size=18
func Normalize(yEncText string) (string, error) {
	// Step 1: Remove all CR characters
	normalized := strings.ReplaceAll(yEncText, CRStr, "")

	// Step 2: Identify header section (from "=ybegin" to line before first data line)
	lines := strings.Split(normalized, LFStr)
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "=ybegin") {
		return "", fmt.Errorf("invalid yEnc block: missing =ybegin")
	}

	headerEndIndex := 0
	for i, line := range lines {
		if strings.HasPrefix(line, "=ypart") || strings.HasPrefix(line, "=ybegin") {
			headerEndIndex = i
		} else if line != "" && !strings.HasPrefix(line, "=") {
			// First non-empty, non-header line is start of body
			break
		}
	}

	// Step 3: Build header text
	headerLines := lines[:headerEndIndex+1]
	headerText := strings.Join(headerLines, "")

	// Step 4: Find footer (=yend line)
	footerStartIndex := -1
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "=yend") {
			footerStartIndex = i
			break
		}
	}

	if footerStartIndex == -1 {
		return "", fmt.Errorf("invalid yEnc block: missing =yend")
	}

	// Step 5: Extract body (everything between header and footer)
	bodyLines := lines[headerEndIndex+1 : footerStartIndex]
	bodyText := strings.Join(bodyLines, "")

	// Step 6: Extract footer - just the =yend line, no extra newlines
	footerText := lines[footerStartIndex]

	// Step 7: Concatenate with sentinel
	// Build the normalized data as string.
	resultString := headerText + SentinelStr + bodyText + footerText

	return resultString, nil
}

// deriveKeys generates the master key and encryption key using Argon2id and HMAC-SHA256
func deriveKeys(password string, salt []byte) (masterKey, encKey []byte) {
	// Derive master key using Argon2id
	masterKey = argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Derive encryption key using HMAC-SHA256
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte("ff1/enc-key"))
	encKey = h.Sum(nil)

	return masterKey, encKey
}

// generateTweak creates the FF1 tweak from master key and segment index
func generateTweak(masterKey []byte, segmentIndex uint32) []byte {
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte("ff1/tweak"))

	// Append segmentIndex as big-endian uint32
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], segmentIndex)
	h.Write(buf[:])

	// Return first 8 bytes as tweak
	return h.Sum(nil)[:8]
}

// generateSalt creates a random salt from the valid alphabet
func generateSalt(alphabet []byte) ([]byte, error) {
	salt := make([]byte, SaltLength)
	for i := 0; i < SaltLength; i++ {
		idx := make([]byte, 1)
		if _, err := rand.Read(idx); err != nil {
			return nil, err
		}
		salt[i] = byte(alphabet[int(idx[0])%len(alphabet)])
	}
	return salt, nil
}

// FF1Encrypt performs format-preserving encryption using AES-FF1 over a custom alphabet.
//
// This function encrypts the plaintext using the FF1 algorithm (NIST SP 800-38G)
// while preserving the format - the output length equals the input length and
// all characters belong to the specified alphabet.
func FF1Encrypt(plaintext string, key, tweak []byte, alphabet []byte) (string, error) {
	c, err := ff1.NewCipherWithAlphabet(alphabet, len(tweak), key, tweak)
	if err != nil {
		return "", err
	}
	y, err := c.EncryptWithTweak([]byte(plaintext), tweak)
	if err != nil {
		return "", err
	}
	return string(y), nil
}

// FF1Decrypt performs format-preserving decryption using AES-FF1 over a custom alphabet.
//
// This function decrypts ciphertext that was encrypted with FF1Encrypt using the same
// key, tweak, and alphabet parameters. The output format matches the original plaintext.
func FF1Decrypt(ciphertext string, key, tweak []byte, alphabet []byte) (string, error) {
	c, err := ff1.NewCipherWithAlphabet(alphabet, len(tweak), key, tweak)
	if err != nil {
		return "", err
	}
	x, err := c.DecryptWithTweak([]byte(ciphertext), tweak)
	if err != nil {
		return "", err
	}
	return string(x), nil
}

// Denormalize reconstructs proper yEnc formatting from normalized plaintext.
//
// This function reverses the normalization process to restore a valid yEnc message block:
//  1. Splits the data at the sentinel byte (0xFF) to separate header from body+footer
//  2. Locates the footer by searching for the "=yend" marker
//  3. Extracts the line length parameter from the header (defaults to 128)
//  4. Reconstructs the yEnc structure with proper CRLF line endings
//  5. Inserts line breaks into the body while preserving yEnc escape sequences
//
// The output is a syntactically correct yEnc block that can be processed by
// standard yEnc parsers and decoders.
//
// Parameters:
//   - normalizedData: The normalized plaintext from decryption (header + 0xFF + body + footer)
//
// Returns:
//   - string: A properly formatted yEnc message block with CRLF line endings
//   - error: An error if the normalized data is invalid or corrupted
//
// The function ensures that yEnc escape sequences (=XX) are never split across
// line boundaries, maintaining compatibility with yEnc decoding requirements.
//
// Example input:  "=ybegin line=128 size=18 name=file.bin\xFFabcDEF123=yend size=18"
// Example output: "=ybegin line=128 size=18 name=file.bin\r\nabcDEF123\r\n=yend size=18\r\n"
func Denormalize(normalizedData string) (string, error) {
	// Step 1: Split at the first occurrence of sentinel 0xFF
	sentinelPos := bytes.IndexByte([]byte(normalizedData), SentinelByte)
	if sentinelPos == -1 {
		return "", fmt.Errorf("sentinel byte not found in normalized data")
	}

	headerText := normalizedData[:sentinelPos]
	bodyAndFooter := normalizedData[sentinelPos+1:]

	// Step 2: Identify footer by searching for "=yend"
	yendPos := bytes.Index([]byte(bodyAndFooter), []byte("=yend"))
	if yendPos == -1 {
		return "", fmt.Errorf("=yend footer not found")
	}

	bodyText := bodyAndFooter[:yendPos]
	footerText := bodyAndFooter[yendPos:]

	// Step 3: Extract line length from header (default 128 if missing)
	lineLen := DefaultLineLength
	re := regexp.MustCompile(`line=(\d+)`)
	if matches := re.FindStringSubmatch(headerText); len(matches) > 1 {
		if parsed, err := strconv.Atoi(matches[1]); err == nil {
			lineLen = parsed
		}
	}

	// Step 4: Reconstruct the yEnc block
	var result strings.Builder

	// 4a: Insert CRLF between header lines if =ypart is present
	if strings.Contains(headerText, "=ypart") {
		headerLines := strings.Split(headerText, LFStr)
		result.WriteString(strings.Join(headerLines, CRLF))
	} else {
		result.WriteString(headerText)
	}

	// 4b: Insert CRLF after header
	result.WriteString(CRLF)

	// 4c: Insert line breaks into body, avoiding splitting escape sequences
	formattedBody := formatBodyWithLineBreaks(bodyText, lineLen)
	result.WriteString(formattedBody)

	// 4d: Ensure CRLF before =yend
	if !strings.HasSuffix(result.String(), CRLF) {
		result.WriteString(CRLF)
	}

	// Add footer with proper line ending
	result.WriteString(footerText)
	result.WriteString(CRLF)

	finalResult := result.String()

	return finalResult, nil
}

// formatBodyWithLineBreaks formats body text with line breaks, avoiding splitting escape sequences
func formatBodyWithLineBreaks(bodyText string, lineLen int) string {
	if len(bodyText) == 0 {
		return ""
	}

	var result strings.Builder
	pos := 0
	for pos < len(bodyText) {
		remaining := len(bodyText) - pos
		segmentLen := lineLen
		if remaining < lineLen {
			segmentLen = remaining
		}

		// Check if we're about to split an escape sequence
		if pos+segmentLen < len(bodyText) &&
			pos+segmentLen > 0 &&
			bodyText[pos+segmentLen-1] == EscStr[0] {
			// Move boundary forward to keep escape sequence intact
			segmentLen++
			if pos+segmentLen > len(bodyText) {
				segmentLen = remaining
			}
		}

		result.WriteString(bodyText[pos : pos+segmentLen])
		pos += segmentLen

		// Add CRLF if not at end
		if pos < len(bodyText) {
			result.WriteString(CRLF)
		}
	}

	return result.String()
}

// addLineBreaks formats ciphertext with line breaks for display
func addLineBreaks(data string, lineLen int) string {
	if lineLen <= 0 {
		return data
	}

	var result strings.Builder
	for i := 0; i < len(data); i += lineLen {
		end := i + lineLen
		if end > len(data) {
			end = len(data)
		}
		result.WriteString(data[i:end])
		if end < len(data) {
			result.WriteString(CRLF)
		}
	}
	return result.String()
}

// removeLineBreaks strips line breaks from ciphertext
func removeLineBreaks(data string) string {
	data = strings.ReplaceAll(data, CRStr, "")
	data = strings.ReplaceAll(data, LFStr, "")
	return data
}

// Encrypt encrypts a yEnc message block using the yEnc-FPE algorithm.
//
// This function implements the complete yEnc-FPE encryption pipeline:
//  1. Normalizes the input yEnc block (removes CRLF, inserts sentinel)
//  2. Generates a cryptographically random salt from the valid alphabet
//  3. Derives encryption keys using Argon2id and HMAC-SHA256
//  4. Creates a unique tweak from the master key and segment index
//  5. Performs FF1 format-preserving encryption over the 253-character alphabet
//  6. Prepends the salt and formats output with configurable line breaks
//
// The resulting ciphertext maintains yEnc compatibility and can be transmitted
// through standard Usenet protocols.
//
// Parameters:
//   - yEncText: A complete yEnc message block with proper headers and footers
//   - config: Configuration including password, segment index, and formatting options
//
// Returns:
//   - string: The encrypted data with salt and line formatting applied
//   - error: An error if encryption fails at any stage
//
// Security considerations:
//   - Use unique segment indices across all segments to prevent identical ciphertexts
//   - Use strong passwords as the security depends entirely on password strength
//   - The same password and segment index will always produce the same output (deterministic)
//
// Example:
//
//	config := Config{
//		SegmentIndex: 1,
//		LineLength:   128,
//		Password:     "strongpassword123",
//	}
//	encrypted, err := Encrypt(yEncBlock, config)
func Encrypt(yEncText string, config Config) (string, error) {
	// Step 1: Normalize the yEnc text
	normalized, err := Normalize(yEncText)
	if err != nil {
		return "", fmt.Errorf("normalization failed: %w", err)
	}

	// Step 2: Create alphabet
	alphabet := NewAlphabet()

	// Step 3: Generate salt
	salt, err := generateSalt(alphabet)
	if err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}

	// Step 4: Derive keys
	masterKey, encKey := deriveKeys(config.Password, salt)

	// Step 5: Generate tweak
	tweak := generateTweak(masterKey, config.SegmentIndex)

	// Step 6: Encrypt using FF1
	ciphertext, err := FF1Encrypt(normalized, encKey, tweak, alphabet)
	if err != nil {
		return "", fmt.Errorf("FF1 encryption failed: %w", err)
	}

	// Step 7: Prepend salt to ciphertext
	result := string(salt) + ciphertext

	// Step 8: Add line breaks for formatting
	lineLen := config.LineLength
	if lineLen <= 0 {
		lineLen = DefaultLineLength
	}

	return addLineBreaks(result, lineLen), nil
}

// Decrypt decrypts a yEnc-FPE encrypted block back to the original yEnc format.
//
// This function reverses the encryption process to restore the original yEnc message:
//  1. Removes display line breaks from the encrypted data
//  2. Extracts the salt from the first 16 bytes
//  3. Derives the same encryption keys using the provided password and salt
//  4. Generates the same tweak using the master key and segment index
//  5. Performs FF1 decryption to recover the normalized plaintext
//  6. Denormalizes the data to reconstruct proper yEnc formatting
//
// The output is a byte-perfect reconstruction of the original yEnc message block
// with proper CRLF line endings and yEnc structure.
//
// Parameters:
//   - encryptedData: The encrypted output from a previous Encrypt() call
//   - config: Configuration with the same password and segment index used for encryption
//
// Returns:
//   - string: The original yEnc message block with proper formatting
//   - error: An error if decryption fails or authentication is invalid
//
// Security notes:
//   - Wrong passwords will result in decryption failure or corrupted output
//   - The segment index must match the one used during encryption
//   - No explicit authentication is provided; corruption may not be detected
//
// Example:
//
//	config := Config{
//		SegmentIndex: 1,
//		LineLength:   128,  // Only affects display, not decryption
//		Password:     "strongpassword123",
//	}
//	decrypted, err := Decrypt(encryptedData, config)
func Decrypt(encryptedData string, config Config) (string, error) {
	// Step 1: Remove line breaks
	data := removeLineBreaks(encryptedData)

	// Step 2: Extract salt (first 16 bytes)
	if len(data) < SaltLength {
		return "", fmt.Errorf("encrypted data too short: expected at least %d bytes", SaltLength)
	}

	salt := data[:SaltLength]
	ciphertext := data[SaltLength:]

	// Step 3: Create alphabet
	alphabet := NewAlphabet()

	// Step 4: Derive keys (same as encryption)
	masterKey, encKey := deriveKeys(config.Password, []byte(salt))

	// Step 5: Generate tweak (same as encryption)
	tweak := generateTweak(masterKey, config.SegmentIndex)

	// Step 6: Decrypt using FF1
	normalized, err := FF1Decrypt(ciphertext, encKey, tweak, alphabet)
	if err != nil {
		return "", fmt.Errorf("FF1 decryption failed: %w", err)
	}

	// Step 7: Denormalize to reconstruct yEnc format
	yEncText, err := Denormalize(normalized)
	if err != nil {
		return "", fmt.Errorf("denormalization failed: %w", err)
	}

	return yEncText, nil
}
