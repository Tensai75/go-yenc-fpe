package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	yEncFPE "github.com/Tensai75/go-yEnc-FPE"
)

const (
	// Default line length for formatting
	defaultLineLength = 128
)

// Config holds command line arguments
type cmdConfig struct {
	sourcePath   string
	destPath     string
	password     string
	segmentIndex uint32
	operation    string // "encode" or "decode"
	lineLength   int
	showHelp     bool
}

func main() {
	config := parseCmdArgs()

	if config.showHelp {
		printUsage()
		return
	}

	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		printUsage()
		os.Exit(1)
	}

	if err := processFile(config); err != nil {
		fmt.Fprintf(os.Stderr, "Processing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully %sd file: %s -> %s\n", config.operation, config.sourcePath, config.destPath)
}

// parseCmdArgs parses command line arguments
func parseCmdArgs() cmdConfig {
	var config cmdConfig

	flag.StringVar(&config.sourcePath, "source", "", "Source file path")
	flag.StringVar(&config.sourcePath, "s", "", "Source file path (shorthand)")

	flag.StringVar(&config.destPath, "dest", "", "Destination file path")
	flag.StringVar(&config.destPath, "d", "", "Destination file path (shorthand)")

	flag.StringVar(&config.password, "password", "", "Password for encryption/decryption")
	flag.StringVar(&config.password, "p", "", "Password for encryption/decryption (shorthand)")

	var segmentIndexStr string
	flag.StringVar(&segmentIndexStr, "segment", "1", "Segment index (default: 1)")
	flag.StringVar(&segmentIndexStr, "i", "1", "Segment index (shorthand)")

	flag.StringVar(&config.operation, "operation", "", "Operation: 'encode' or 'decode'")
	flag.StringVar(&config.operation, "o", "", "Operation: 'encode' or 'decode' (shorthand)")

	flag.IntVar(&config.lineLength, "line-length", defaultLineLength, "Line length for output formatting (default: 128)")
	flag.IntVar(&config.lineLength, "l", defaultLineLength, "Line length for output formatting (shorthand)")

	flag.BoolVar(&config.showHelp, "help", false, "Show help message")
	flag.BoolVar(&config.showHelp, "h", false, "Show help message (shorthand)")

	flag.Parse()

	// Parse segment index
	if segmentIndex, err := strconv.ParseUint(segmentIndexStr, 10, 32); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid segment index: %v\n", err)
		config.segmentIndex = 1
	} else {
		config.segmentIndex = uint32(segmentIndex)
	}

	// Normalize operation to lowercase
	config.operation = strings.ToLower(config.operation)

	return config
}

// validateConfig validates the command line configuration
func validateConfig(config cmdConfig) error {
	if config.sourcePath == "" {
		return fmt.Errorf("source file path is required")
	}

	if config.destPath == "" {
		return fmt.Errorf("destination file path is required")
	}

	if config.password == "" {
		return fmt.Errorf("password is required")
	}

	if config.operation != "encode" && config.operation != "decode" {
		return fmt.Errorf("operation must be 'encode' or 'decode', got '%s'", config.operation)
	}

	if config.segmentIndex == 0 {
		return fmt.Errorf("segment index must be greater than 0")
	}

	if config.lineLength <= 0 {
		return fmt.Errorf("line length must be greater than 0")
	}

	// Check if source file exists
	if _, err := os.Stat(config.sourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source file does not exist: %s", config.sourcePath)
	}

	// Create destination directory if it doesn't exist
	destDir := filepath.Dir(config.destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %v", err)
	}

	return nil
}

// processFile handles the encoding or decoding operation
func processFile(config cmdConfig) error {
	// Read source file
	sourceData, err := os.ReadFile(config.sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %v", err)
	}

	// Create yEnc-FPE configuration
	yEncConfig := yEncFPE.Config{
		SegmentIndex: config.segmentIndex,
		LineLength:   config.lineLength,
		Password:     config.password,
	}

	var result string

	switch config.operation {
	case "encode":
		result, err = yEncFPE.Encrypt(string(sourceData), yEncConfig)
		if err != nil {
			return fmt.Errorf("encoding failed: %v", err)
		}
		fmt.Printf("Encoded %d bytes to %d characters\n", len(sourceData), len(result))

	case "decode":
		result, err = yEncFPE.Decrypt(string(sourceData), yEncConfig)
		if err != nil {
			return fmt.Errorf("decoding failed: %v", err)
		}
		fmt.Printf("Decoded %d characters to %d bytes\n", len(sourceData), len(result))

	default:
		return fmt.Errorf("invalid operation: %s", config.operation)
	}

	// Write result to destination file
	if err := os.WriteFile(config.destPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("failed to write destination file: %v", err)
	}

	return nil
}

// printUsage prints the usage information
func printUsage() {
	fmt.Printf(`yEnc-FPE Command Line Tool

Usage:
  %s [options]

Required Options:
  -s, --source <path>      Source file path
  -d, --dest <path>        Destination file path
  -p, --password <pwd>     Password for encryption/decryption
  -o, --operation <op>     Operation: 'encode' or 'decode'

Optional Options:
  -i, --segment <index>    Segment index (default: 1)
  -l, --line-length <len>  Line length for output formatting (default: 128)
  -h, --help              Show this help message

Examples:
  # Encode a yEnc file
  %s -s input.yenc -d output.enc -p "mypassword" -o encode -i 1

  # Decode an encrypted file
  %s -s encrypted.enc -d decoded.yenc -p "mypassword" -o decode -i 1

  # Encode with custom line length
  %s -s input.yenc -d output.enc -p "secret" -o encode -i 2 -l 64

Description:
  This tool encrypts or decrypts files using the yEnc-FPE (Format-Preserving 
  Encryption) algorithm. The input for encoding should be a valid yEnc block,
  and the output will be an encrypted version that maintains yEnc compatibility.
  
  The segment index should be unique for each segment in your upload sequence
  to ensure unique encryption tweaks.

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
