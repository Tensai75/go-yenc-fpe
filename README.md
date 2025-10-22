# yEnc-FPE: Format-Preserving Encryption for yEnc Blocks

[![Go Reference](https://pkg.go.dev/badge/github.com/Tensai75/go-yEnc-FPE.svg)](https://pkg.go.dev/github.com/Tensai75/go-yEnc-FPE)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Go implementation of the **[yEnc-FPE (yEnc Format-Preserving Encryption) standard](https://github.com/Tensai75/yEnc-FPE-standard)** that provides secure, format-preserving encryption for yEnc-encoded binary blocks used in Usenet transfers.

## What is yEnc-FPE?

yEnc-FPE is a cryptographic scheme that encrypts yEnc message blocks while preserving their format and compatibility with standard yEnc parsers. It combines:

- **Format-Preserving Encryption**: Uses AES-FF1 (NIST SP 800-38G compliant)
- **yEnc Compatibility**: Maintains printable character requirements
- **Deterministic Structure**: Enables perfect reconstruction of headers, bodies, and footers
- **Usenet Ready**: Output suitable for transmission through standard protocols

## Key Features

- **Strong Security**: AES-256 with Argon2id key derivation and HMAC-SHA256 tweaks
- **Length Preservation**: Ciphertext length equals plaintext length (±1 sentinel byte)
- **Format Compliance**: All output characters remain within yEnc-compatible range
- **Perfect Round-trip**: Byte-perfect reconstruction of original yEnc blocks
- **High Performance**: Optimized 253-character alphabet for FF1 efficiency
- **Segment Security**: Unique tweaks per segment prevent identical ciphertexts

## Installation

```bash
go get github.com/Tensai75/go-yEnc-FPE
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    yEncFPE "github.com/Tensai75/go-yEnc-FPE"
)

func main() {
    // Original yEnc block
    yEncBlock := `=ybegin line=128 size=18 name=test.bin
Hello World!
=yend size=18
`

    // Configuration
    config := yEncFPE.Config{
        SegmentIndex: 1,                    // Unique per segment
        LineLength:   128,                  // Output formatting
        Password:     "your-strong-password", // Encryption key
    }

    // Encrypt
    encrypted, err := yEncFPE.Encrypt(yEncBlock, config)
    if err != nil {
        log.Fatal("Encryption failed:", err)
    }

    fmt.Println("Encrypted:")
    fmt.Println(encrypted)

    // Decrypt
    decrypted, err := yEncFPE.Decrypt(encrypted, config)
    if err != nil {
        log.Fatal("Decryption failed:", err)
    }

    fmt.Println("Decrypted:")
    fmt.Println(decrypted)

    // Verify round-trip
    if decrypted == yEncBlock {
        fmt.Println("Perfect round-trip!")
    }
}
```

## Documentation

### Core Functions

#### `Encrypt(yEncText string, config Config) (string, error)`

Encrypts a yEnc message block using the yEnc-FPE algorithm.

```go
encrypted, err := yEncFPE.Encrypt(yEncBlock, config)
```

#### `Decrypt(encryptedData string, config Config) (string, error)`

Decrypts a yEnc-FPE encrypted block back to the original yEnc format.

```go
decrypted, err := yEncFPE.Decrypt(encrypted, config)
```

### Configuration

```go
type Config struct {
    SegmentIndex uint32  // Unique identifier (≥1) for this segment
    LineLength   int     // Characters per line in output (0 = no formatting)
    Password     string  // Encryption password
}
```

### Advanced Usage

#### Custom Alphabets

```go
alphabet := yEncFPE.NewAlphabet()  // 253-character alphabet
// alphabet excludes: 0x00 (null), 0x0A (LF), 0x0D (CR)
```

#### Normalization

```go
normalized, err := yEncFPE.Normalize(yEncBlock)
// Converts: "=ybegin...\r\ndata\r\n=yend..."
// To: "=ybegin...\xFFdata=yend..."
```

## Security Model

### Cryptographic Components

- **Key Derivation**: Argon2id with configurable salt
- **Encryption**: AES-256 in FF1 mode (NIST SP 800-38G)
- **Tweaks**: HMAC-SHA256(masterKey, "ff1/tweak" || segmentIndex)
- **Alphabet**: 253 characters (excludes null, CR, LF)

### Security Considerations

- **Deterministic**: Same password + segment index = same output
- **Password Dependent**: Security relies entirely on password strength
- **Unique Segments**: Use different segment indices to prevent identical ciphertexts
- **No Authentication**: Provides confidentiality only, not integrity### Best Practices

```go
// Good: Unique segment indices
config1 := Config{SegmentIndex: 1, Password: "strong-password"}
config2 := Config{SegmentIndex: 2, Password: "strong-password"}

// Bad: Reusing segment indices
config1 := Config{SegmentIndex: 1, Password: "strong-password"}
config2 := Config{SegmentIndex: 1, Password: "strong-password"} // Same output!
```

## Command Line Tool

A ready-to-use CLI tool is included:

```bash
# Build the tool
go build -o yenc-fpe ./cmd

# Encrypt a file
./yenc-fpe -s input.yenc -d encrypted.out -p "password" -o encode -i 1

# Decrypt a file
./yenc-fpe -s encrypted.out -d decrypted.yenc -p "password" -o decode -i 1
```

See [cmd/README.md](cmd/README.md) for detailed CLI documentation.

## Algorithm Overview

### Encryption Pipeline

1. **Normalize** yEnc block (remove CRLF, insert sentinel)
2. **Generate** random salt from valid alphabet
3. **Derive** keys using Argon2id + HMAC-SHA256
4. **Create** unique tweak from master key + segment index
5. **Encrypt** with FF1 over 253-character alphabet
6. **Format** output with salt + line breaks

### Decryption Pipeline

1. **Parse** salt and ciphertext
2. **Derive** same keys from password + salt
3. **Generate** same tweak from segment index
4. **Decrypt** with FF1 to recover normalized text
5. **Denormalize** to reconstruct yEnc structure

## Testing

Run the comprehensive test suite:

```bash
# All tests
go test -v

# With coverage
go test -cover

# Specific function tests
go test -run TestEncryptDecrypt -v
```

Test coverage: **71.6%** with extensive edge case validation.

## Performance

- **Alphabet Size**: 253 characters (optimal for FF1)
- **Memory Usage**: Minimal - processes data in single pass
- **Speed**: Dominated by Argon2id key derivation (~50ms)
- **Overhead**: +1 byte (sentinel) + 16 bytes (salt) per message

## Technical Specifications

### yEnc-FPE Standard

- **Specification**: Based on [yEnc-FPE Encryption Standard](https://github.com/Tensai75/yEnc-FPE-standard)
- **FF1 Compliance**: NIST SP 800-38G Format-Preserving Encryption
- **Key Derivation**: Argon2id(password, salt, t=1, m=64MB, p=4)
- **Tweak Generation**: HMAC-SHA256(master, "ff1/tweak" || segmentIndex)[0:8]
- **Salt Length**: 16 bytes from valid alphabet
- **Sentinel**: 0xFF inserted between header and body

### Dependencies

- `github.com/Tensai75/go-fpe-bytes/ff1` - FF1 implementation
- `golang.org/x/crypto/argon2` - Key derivation

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/Tensai75/go-yEnc-FPE.git
cd go-yEnc-FPE
go mod tidy
go test -v
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **[yEnc-FPE Standard](https://github.com/Tensai75/yEnc-FPE-standard)** for the encryption specification
- **NIST SP 800-38G** for FF1 format-preserving encryption specification
- **yEnc Standard** for binary-to-text encoding used in Usenet
- **Argon2** team for password hashing algorithm
- **Go Community** for excellent cryptographic libraries

## Support

- **Documentation**: [pkg.go.dev](https://pkg.go.dev/github.com/Tensai75/go-yEnc-FPE)
- **Issues**: [GitHub Issues](https://github.com/Tensai75/go-yEnc-FPE/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Tensai75/go-yEnc-FPE/discussions)
