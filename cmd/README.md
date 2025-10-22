# yEnc-FPE Command Line Tool

A powerful command-line interface for encrypting and decrypting yEnc files using the [yEnc-FPE (Format-Preserving Encryption)](https://github.com/Tensai75/yEnc-FPE-standard) algorithm.

## Overview

The yEnc-FPE CLI tool provides an easy way to encrypt and decrypt yEnc message blocks from the command line, making it perfect for:

- **Batch Processing**: Encrypt multiple yEnc files in automated scripts
- **Testing**: Quick verification of encryption/decryption functionality
- **Integration**: Use in existing workflows and build pipelines
- **Usenet Preparation**: Secure yEnc blocks before upload

## Quick Start

### Build the Tool

```bash
# From the project root
go build -o yenc-fpe ./cmd

# Or with custom name
go build -o yenc-fpe.exe ./cmd  # Windows
```

### Basic Usage

```bash
# Encrypt a yEnc file
./yenc-fpe -s input.yenc -d encrypted.out -p "mypassword" -o encode -i 1

# Decrypt back to original
./yenc-fpe -s encrypted.out -d decrypted.yenc -p "mypassword" -o decode -i 1
```

## Command Reference

### Synopsis

```
yenc-fpe [options]
```

### Required Options

| Option        | Short | Description                     | Example          |
| ------------- | ----- | ------------------------------- | ---------------- |
| `--source`    | `-s`  | Source file path                | `-s input.yenc`  |
| `--dest`      | `-d`  | Destination file path           | `-d output.enc`  |
| `--password`  | `-p`  | Encryption/decryption password  | `-p "secret123"` |
| `--operation` | `-o`  | Operation: `encode` or `decode` | `-o encode`      |

### Optional Options

| Option          | Short | Default | Description        |
| --------------- | ----- | ------- | ------------------ |
| `--segment`     | `-i`  | `1`     | Segment index (≥1) |
| `--line-length` | `-l`  | `128`   | Output line length |
| `--help`        | `-h`  | -       | Show help message  |

## Examples

### Basic Encryption

```bash
# Encrypt a yEnc file with default settings
./yenc-fpe -s message.yenc -d message.enc -p "strongpassword" -o encode
```

### Multi-Segment Processing

```bash
# Process multiple segments with unique indices
./yenc-fpe -s part1.yenc -d part1.enc -p "password" -o encode -i 1
./yenc-fpe -s part2.yenc -d part2.enc -p "password" -o encode -i 2
./yenc-fpe -s part3.yenc -d part3.enc -p "password" -o encode -i 3
```

### Custom Line Length

```bash
# Use shorter lines for compatibility
./yenc-fpe -s input.yenc -d output.enc -p "secret" -o encode -l 64

# Disable line formatting
./yenc-fpe -s input.yenc -d output.enc -p "secret" -o encode -l 0
```

### Decryption

```bash
# Decrypt with same parameters used for encryption
./yenc-fpe -s encrypted.enc -d original.yenc -p "strongpassword" -o decode -i 1
```

### Pipeline Usage

```bash
# Use in shell pipelines (file-based)
./yenc-fpe -s <(echo "$YENC_DATA") -d encrypted.tmp -p "$PASSWORD" -o encode -i 1
cat encrypted.tmp | ./process-encrypted-data.sh
```

## File Format Examples

### Input yEnc File

```
=ybegin line=128 size=1024 name=document.pdf
<binary data encoded as yEnc>
=yend size=1024
```

### Encrypted Output

```
<16-byte-salt><encrypted-data-with-line-breaks>
```

### Decrypted Output

```
=ybegin line=128 size=1024 name=document.pdf
<original binary data>
=yend size=1024
```

## Configuration

### Segment Index Strategy

The segment index is crucial for security. Use a **continuous numbering scheme** across all files:

````bash
# Correct: Continuous numbering
File1-Part1: -i 1
File1-Part2: -i 2
File1-Part3: -i 3
File2-Part1: -i 4  # Continue from previous
File2-Part2: -i 5

# Wrong: Reusing indices
File1-Part1: -i 1
File2-Part1: -i 1  # Same index = identical ciphertext!
### Password Security

- **Length**: Use passwords of 12+ characters
- **Complexity**: Include numbers, symbols, upper/lowercase
- **Uniqueness**: Different passwords for different upload sessions
- **Storage**: Never store passwords in scripts or logs

```bash
# Good password practices
export YENC_PASSWORD="MyStr0ng!P@ssw0rd#2024"
./yenc-fpe -s input.yenc -d output.enc -p "$YENC_PASSWORD" -o encode

# Avoid weak passwords
./yenc-fpe -s input.yenc -d output.enc -p "123456" -o encode
```
## Advanced Usage

### Batch Processing Script

```bash
#!/bin/bash
# encrypt-batch.sh

PASSWORD="$1"
INPUT_DIR="$2"
OUTPUT_DIR="$3"

if [ $# -ne 3 ]; then
    echo "Usage: $0 <password> <input_dir> <output_dir>"
    exit 1
fi

segment_index=1
for file in "$INPUT_DIR"/*.yenc; do
    if [ -f "$file" ]; then
        basename=$(basename "$file" .yenc)
        echo "Encrypting: $basename (segment $segment_index)"

        ./yenc-fpe \
            -s "$file" \
            -d "$OUTPUT_DIR/${basename}.enc" \
            -p "$PASSWORD" \
            -o encode \
            -i $segment_index

        if [ $? -eq 0 ]; then
            echo "Success: $basename"
        else
            echo "Failed: $basename"
            exit 1
        fi

        ((segment_index++))
    fi
done

echo "Batch encryption complete: $((segment_index-1)) files processed"
````

### Verification Script

```bash
#!/bin/bash
# verify-encryption.sh

# Test round-trip encryption
TEST_FILE="test.yenc"
ENCRYPTED="test.enc"
DECRYPTED="test_decrypted.yenc"
PASSWORD="test-password"

# Encrypt
./yenc-fpe -s "$TEST_FILE" -d "$ENCRYPTED" -p "$PASSWORD" -o encode -i 1

# Decrypt
./yenc-fpe -s "$ENCRYPTED" -d "$DECRYPTED" -p "$PASSWORD" -o decode -i 1

# Compare
if cmp -s "$TEST_FILE" "$DECRYPTED"; then
    echo "Round-trip test PASSED"
    rm -f "$ENCRYPTED" "$DECRYPTED"
    exit 0
else
    echo "Round-trip test FAILED"
    exit 1
fi
```

## Error Handling

### Common Error Messages

| Error                                    | Cause                  | Solution                          |
| ---------------------------------------- | ---------------------- | --------------------------------- |
| `source file path is required`           | Missing `-s` parameter | Add `-s <filepath>`               |
| `operation must be 'encode' or 'decode'` | Invalid `-o` value     | Use `-o encode` or `-o decode`    |
| `source file does not exist`             | File not found         | Check file path and permissions   |
| `FF1 decryption failed`                  | Wrong password/segment | Verify password and segment index |
| `=yend footer not found`                 | Corrupted data         | Check file integrity              |

### Exit Codes

- **0**: Success
- **1**: Error (invalid parameters, file issues, encryption/decryption failure)

### Troubleshooting

```bash
# Test with verbose error output
./yenc-fpe -s test.yenc -d test.enc -p "password" -o encode -i 1 2>&1

# Verify file permissions
ls -la input.yenc output.enc

# Check file is valid yEnc format
head -n 1 input.yenc  # Should start with "=ybegin"
tail -n 1 input.yenc  # Should contain "=yend"
```

## Security Notes

### Command Line Security

- **Password Visibility**: Passwords may be visible in process lists
- **History**: Commands are saved in shell history
- **Logs**: Avoid logging commands with passwords

### Secure Password Handling

```bash
# Read password from file
./yenc-fpe -s input.yenc -d output.enc -p "$(cat password.txt)" -o encode

# Read from environment variable
export YENC_PASSWORD="secret"
./yenc-fpe -s input.yenc -d output.enc -p "$YENC_PASSWORD" -o encode

# Interactive input (future enhancement)
# ./yenc-fpe -s input.yenc -d output.enc --prompt-password -o encode
```

## Performance Tips

### Large Files

- **Memory Usage**: Tool processes entire files in memory
- **Progress**: No progress indication for large files
- **Streaming**: Consider splitting very large files

### Optimization

```bash
# Process files in parallel (with unique segment indices)
./yenc-fpe -s file1.yenc -d file1.enc -p "$PWD" -o encode -i 1 &
./yenc-fpe -s file2.yenc -d file2.enc -p "$PWD" -o encode -i 2 &
./yenc-fpe -s file3.yenc -d file3.enc -p "$PWD" -o encode -i 3 &
wait
```

## Building from Source

### Prerequisites

- Go 1.21 or later
- Git

### Build Steps

```bash
# Clone repository
git clone https://github.com/Tensai75/go-yEnc-FPE.git
cd go-yEnc-FPE

# Build CLI tool
go build -o yenc-fpe ./cmd

# Build with optimization
go build -ldflags="-w -s" -o yenc-fpe ./cmd

# Cross-compilation examples
GOOS=windows GOARCH=amd64 go build -o yenc-fpe.exe ./cmd
GOOS=linux GOARCH=amd64 go build -o yenc-fpe-linux ./cmd
GOOS=darwin GOARCH=amd64 go build -o yenc-fpe-macos ./cmd
```

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Contributing

Contributions to improve the CLI tool are welcome! Areas for enhancement:

- Interactive password prompts
- Progress bars for large files
- Configuration file support
- Batch processing modes
- Integration with popular Usenet tools

---

**Part of the [yEnc-FPE](../README.md) project**
