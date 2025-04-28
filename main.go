package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

// --- Constants ---
//
//goland:noinspection GoUnusedConst
const (
	backupFileHeaderMagic   = "ANDROID BACKUP\n"
	backupFileV1            = 1
	backupFileV2            = 2
	backupFileV3            = 3
	backupFileV4            = 4
	backupFileV5            = 5
	backupManifestVersionV1 = 1

	encryptionAlgorithmName = "AES-256"
	pbkdf2KeySize           = 256
	pbkdf2SaltSize          = 512
	masterKeySize           = 256

	debug = false
)

// --- Errors ---
var (
	ErrInvalidMagic          = errors.New("invalid magic string")
	ErrUnsupportedVersion    = errors.New("unsupported backup version")
	ErrUnsupportedEncryption = errors.New("unsupported encryption algorithm")
	ErrPasswordRequired      = errors.New("password is required for encrypted backup")
	ErrInvalidSaltLength     = errors.New("invalid salt length")
	ErrInvalidKeyLength      = errors.New("invalid master key length")
	ErrChecksumMismatch      = errors.New("master key checksum mismatch (likely incorrect password)")
	ErrInvalidPadding        = errors.New("invalid PKCS7 padding")
	ErrUnexpectedEOF         = errors.New("unexpected end of file during header read or data copy")
	ErrSmallFile             = errors.New("backup file too small")
)

// --- Core Extraction Logic ---

// Extractor manages the state and configuration for extracting an Android backup file.
type Extractor struct {
	backupReader *bufio.Reader
	tarWriter    io.Writer
	password     string

	version      int
	isCompressed bool
	isEncrypted  bool

	// Encryption-specific fields
	userSalt           []byte
	masterKeySalt      []byte
	pbkdf2Rounds       int
	masterKeyIv        []byte
	decryptedMasterKey []byte
	useUtf8Derivation  bool // PBKDF2 method depends on backup version
}

// NewExtractor creates a new Extractor instance.
func NewExtractor(backupReader io.Reader, tarWriter io.Writer, password string) *Extractor {
	return &Extractor{
		backupReader: bufio.NewReader(backupReader),
		tarWriter:    tarWriter,
		password:     password,
	}
}

// Extract reads the backup header, sets up the necessary streams, and extracts the payload.
func (e *Extractor) Extract() error {
	log.Println("Starting backup extraction process...")

	if err := e.readHeader(); err != nil {
		return fmt.Errorf("failed to read backup header: %w", err)
	}

	var payloadStream io.Reader = e.backupReader // Start with the stream after the header

	// Setup decryption if needed
	if e.isEncrypted {
		log.Println("Backup is encrypted. Setting up decryption stream...")
		decryptionStream, err := e.setupDecryptionStream(payloadStream)
		if err != nil {
			return fmt.Errorf("failed to set up decryption: %w", err)
		}
		payloadStream = decryptionStream
		log.Println("Decryption stream configured.")
	} else {
		log.Println("Backup is not encrypted.")
	}

	// Set up decompression if needed
	var finalStream = payloadStream
	if e.isCompressed {
		log.Println("Backup is compressed. Setting up decompression stream...")
		zlibReader, err := zlib.NewReader(payloadStream)
		if err != nil {
			// Checksum errors or decryption failures can cause zlib init failure
			return fmt.Errorf("failed to create zlib reader (check for corruption/password): %w", err)
		}
		//goland:noinspection GoUnhandledErrorResult
		defer zlibReader.Close() // Ensure the zlib reader is closed
		finalStream = zlibReader
		log.Println("Decompression stream configured.")
	} else {
		log.Println("Backup is not compressed.")
	}

	// Copy the payload to the output
	log.Println("Starting payload extraction...")
	bytesWritten, err := io.Copy(e.tarWriter, finalStream)
	if err != nil {
		// Handle specific errors from underlying streams
		if errors.Is(err, zlib.ErrChecksum) {
			log.Println("WARN: zlib checksum error during decompression. Data might be corrupted but proceeding.")
			// Continue despite checksum error, but log it. If strictness is needed, return the error.
			// Return fmt.Errorf("zlib checksum error: %w", err)
		} else if errors.Is(err, ErrInvalidPadding) {
			log.Println("ERROR: Decryption failed due to invalid padding. Likely incorrect password or file corruption.")
			return fmt.Errorf("invalid padding detected during copy: %w", err) // Return padding error
		} else if errors.Is(err, io.ErrUnexpectedEOF) && e.isEncrypted {
			log.Println("ERROR: Unexpected end of encrypted data stream. File might be truncated or corrupted.")
			return fmt.Errorf("unexpected EOF during encrypted copy: %w", err)
		} else if err != io.EOF { // EOF itself is not an error from io.Copy
			// General copy error
			return fmt.Errorf("error copying payload data: %w", err)
		}
		// If err is io.EOF, it means Copy finished successfully reading until the end.
	}

	log.Printf("Successfully extracted %d bytes to the output.", bytesWritten)
	return nil
}

// --- Header Processing ---

// readHeader parses the Android Backup file header.
func (e *Extractor) readHeader() error {
	log.Println("Reading backup header...")

	// Magic String
	magicLine, err := readLine(e.backupReader)
	if err != nil {
		return fmt.Errorf("reading magic line: %w", err)
	}
	expectedMagic := strings.TrimSuffix(backupFileHeaderMagic, "\n")
	if magicLine != expectedMagic {
		return fmt.Errorf("%w: expected '%s', got '%s'", ErrInvalidMagic, expectedMagic, magicLine)
	}
	log.Printf("Magic: %s", magicLine)

	// Backup Format Version
	versionLine, err := readLine(e.backupReader)
	if err != nil {
		return fmt.Errorf("reading version line: %w", err)
	}
	e.version, err = strconv.Atoi(versionLine)
	if err != nil {
		return fmt.Errorf("parsing version '%s': %w", versionLine, err)
	}
	log.Printf("Version: %d", e.version)
	if e.version < backupFileV1 || e.version > backupFileV5 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, e.version)
	}
	// Determine PBKDF2 method based on a version (V2+ uses UTF-8 bytes for password)
	e.useUtf8Derivation = e.version >= backupFileV2
	log.Printf("Use UTF-8 for key derivation: %t (version %d >= V%d)", e.useUtf8Derivation, e.version, backupFileV2)

	// Compression Flag
	compressedLine, err := readLine(e.backupReader)
	if err != nil {
		return fmt.Errorf("reading compression flag line: %w", err)
	}
	compressedInt, err := strconv.Atoi(compressedLine)
	if err != nil || (compressedInt != 0 && compressedInt != 1) {
		return fmt.Errorf("parsing compression flag '%s': %w", compressedLine, err)
	}
	e.isCompressed = compressedInt == 1
	log.Printf("Compressed: %t", e.isCompressed)

	// Encryption Algorithm Name
	encryptionAlgLine, err := readLine(e.backupReader)
	if err != nil {
		return fmt.Errorf("reading encryption algorithm line: %w", err)
	}
	log.Printf("Encryption Algorithm: %s", encryptionAlgLine)

	if encryptionAlgLine == encryptionAlgorithmName {
		e.isEncrypted = true
	} else if encryptionAlgLine == "none" {
		e.isEncrypted = false
	} else {
		return fmt.Errorf("%w: %s", ErrUnsupportedEncryption, encryptionAlgLine)
	}

	// Read encryption parameters if necessary
	if e.isEncrypted {
		log.Println("Reading encryption parameters...")
		if e.password == "" {
			return ErrPasswordRequired
		}

		// User Salt (hex)
		userSaltHex, err := readLine(e.backupReader)
		if err != nil {
			return fmt.Errorf("reading user salt: %w", err)
		}
		e.userSalt, err = hex.DecodeString(userSaltHex)
		if err != nil {
			return fmt.Errorf("decoding user salt hex '%s': %w", userSaltHex, err)
		}
		if len(e.userSalt) != pbkdf2SaltSize/8 {
			return fmt.Errorf("%w: user salt expected %d bytes, got %d", ErrInvalidSaltLength, pbkdf2SaltSize/8, len(e.userSalt))
		}
		if debug {
			log.Printf("User Salt: %s", userSaltHex)
		}

		// Checksum Salt (hex)
		ckSaltHex, err := readLine(e.backupReader)
		if err != nil {
			return fmt.Errorf("reading checksum salt: %w", err)
		}
		e.masterKeySalt, err = hex.DecodeString(ckSaltHex)
		if err != nil {
			return fmt.Errorf("decoding checksum salt hex '%s': %w", ckSaltHex, err)
		}
		// No strict length check on checksum salt, but maybe log if unusual?
		if debug {
			log.Printf("Checksum Salt: %s", ckSaltHex)
		}

		// PBKDF2 Rounds
		roundsLine, err := readLine(e.backupReader)
		if err != nil {
			return fmt.Errorf("reading PBKDF2 rounds: %w", err)
		}
		e.pbkdf2Rounds, err = strconv.Atoi(roundsLine)
		if err != nil {
			return fmt.Errorf("parsing PBKDF2 rounds '%s': %w", roundsLine, err)
		}
		log.Printf("PBKDF2 Rounds: %d", e.pbkdf2Rounds)

		// User IV (hex) - used to decrypt the master key blob
		userIvHex, err := readLine(e.backupReader)
		if err != nil {
			return fmt.Errorf("reading user IV: %w", err)
		}
		userIv, err := hex.DecodeString(userIvHex) // Local variable, not stored in Extractor
		if err != nil {
			return fmt.Errorf("decoding user IV hex '%s': %w", userIvHex, err)
		}
		if len(userIv) != aes.BlockSize {
			return fmt.Errorf("invalid user IV size: %d (expected %d)", len(userIv), aes.BlockSize)
		}
		if debug {
			log.Printf("User IV: %s", userIvHex)
		}

		// Master Key Blob (hex, encrypted)
		masterKeyBlobHex, err := readLine(e.backupReader)
		if err != nil {
			return fmt.Errorf("reading master key blob: %w", err)
		}
		encryptedMasterKeyBlob, err := hex.DecodeString(masterKeyBlobHex)
		if err != nil {
			return fmt.Errorf("decoding master key blob hex: %w", err)
		}
		if debug {
			log.Printf("Encrypted Master Key Blob: %s...", masterKeyBlobHex[:min(len(masterKeyBlobHex), 32)])
		}

		// Decrypt the master key blob and verify its checksum
		err = e.decryptAndVerifyMasterKey(encryptedMasterKeyBlob, userIv)
		if err != nil {
			return err // Return error from decryption/verification
		}
	}

	log.Println("Header successfully read and parsed.")
	return nil
}

// --- Decryption and Key Handling ---

// decryptAndVerifyMasterKey decrypts the master key blob and verifies the checksum,
// implementing the V1 fallback logic.
func (e *Extractor) decryptAndVerifyMasterKey(encryptedBlob, userIv []byte) error {
	log.Println("Deriving user key and decrypting master key blob...")

	// Derive the user key using the method determined by the backup version.
	userKey := deriveKeyPbkdf2(e.password, e.userSalt, e.pbkdf2Rounds, e.useUtf8Derivation)
	if debug {
		log.Printf("Derived User Key (useUtf8=%t): %s", e.useUtf8Derivation, hex.EncodeToString(userKey))
	}

	// Decrypt the blob using AES-CBC.
	block, err := aes.NewCipher(userKey)
	if err != nil {
		return fmt.Errorf("creating user key cipher: %w", err)
	}
	if len(encryptedBlob)%aes.BlockSize != 0 {
		return fmt.Errorf("invalid encrypted blob size: %d (not multiple of %d)", len(encryptedBlob), aes.BlockSize)
	}
	if len(userIv) != aes.BlockSize {
		return fmt.Errorf("invalid user IV size: %d (expected %d)", len(userIv), aes.BlockSize)
	}

	mode := cipher.NewCBCDecrypter(block, userIv)
	paddedMasterKeyBlob := make([]byte, len(encryptedBlob))
	mode.CryptBlocks(paddedMasterKeyBlob, encryptedBlob)

	// Remove PKCS7 padding.
	masterKeyBlob, err := pkcs7Unpad(paddedMasterKeyBlob, aes.BlockSize)
	if err != nil {
		log.Printf("WARN: Failed to unpad master key blob. Usually incorrect password or corruption. Error: %v", err)
		// Return the specific error most likely for the user
		return ErrChecksumMismatch
	}
	if debug {
		log.Println("Master key blob decrypted and unpadded.")
	}

	// Parse the decrypted blob: [IV_Len][IV][MK_Len][MK][CK_Len][Checksum]
	reader := bytes.NewReader(masterKeyBlob)

	// Read Master Key IV (for payload)
	ivLenByte, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("reading MK IV length: %w", err)
	}
	ivLen := int(ivLenByte)
	if ivLen <= 0 || ivLen > 64 { // Sanity check IV length
		return fmt.Errorf("unreasonable MK IV length: %d", ivLen)
	}
	e.masterKeyIv = make([]byte, ivLen)
	if _, err = io.ReadFull(reader, e.masterKeyIv); err != nil {
		return fmt.Errorf("reading MK IV (%d bytes): %w", ivLen, err)
	}
	if debug {
		log.Printf("Master Key IV (for payload): %s", hex.EncodeToString(e.masterKeyIv))
	}

	// Read Master Key
	mkLenByte, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("reading MK length: %w", err)
	}
	mkLen := int(mkLenByte)
	if mkLen != masterKeySize/8 {
		return fmt.Errorf("%w: MK expected %d bytes, got %d", ErrInvalidKeyLength, masterKeySize/8, mkLen)
	}
	e.decryptedMasterKey = make([]byte, mkLen)
	if _, err = io.ReadFull(reader, e.decryptedMasterKey); err != nil {
		return fmt.Errorf("reading MK (%d bytes): %w", mkLen, err)
	}
	if debug {
		log.Printf("Decrypted Master Key: %s", hex.EncodeToString(e.decryptedMasterKey))
	}

	// Read Master Key Checksum
	ckLenByte, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("reading MK checksum length: %w", err)
	}
	ckLen := int(ckLenByte)
	if ckLen <= 0 || ckLen > 64 { // Sanity check checksum length
		return fmt.Errorf("unreasonable MK checksum length: %d", ckLen)
	}
	masterKeyChecksumHeader := make([]byte, ckLen)
	if _, err = io.ReadFull(reader, masterKeyChecksumHeader); err != nil {
		// Check for unexpected EOF indicating a malformed blob structure
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return fmt.Errorf("unexpected end of MK blob reading checksum (%d bytes). Corrupted blob? Err: %w", ckLen, err)
		}
		return fmt.Errorf("reading MK checksum (%d bytes): %w", ckLen, err)
	}
	if debug {
		log.Printf("Master Key Checksum (from header): %s", hex.EncodeToString(masterKeyChecksumHeader))
	}

	// **Checksum Verification with Fallback Logic**
	calculatedChecksum := makeKeyChecksum(e.decryptedMasterKey, e.masterKeySalt, e.pbkdf2Rounds, e.useUtf8Derivation)
	if debug {
		log.Printf("Calculated MK Checksum (useUtf8=%t): %s", e.useUtf8Derivation, hex.EncodeToString(calculatedChecksum))
	}

	checksumMatches := bytes.Equal(calculatedChecksum, masterKeyChecksumHeader)

	// If checksum fails, and it's a V1 backup, try the alternate PBKDF2 method for the checksum.
	if !checksumMatches && e.version == backupFileV1 {
		alternateUtf8 := !e.useUtf8Derivation // Toggle the method
		log.Printf("WARN: Initial checksum mismatch for V1 backup. Retrying checksum calculation with useUtf8=%t...", alternateUtf8)
		calculatedChecksum = makeKeyChecksum(e.decryptedMasterKey, e.masterKeySalt, e.pbkdf2Rounds, alternateUtf8)
		log.Printf("Recalculated MK Checksum (useUtf8=%t): %s", alternateUtf8, hex.EncodeToString(calculatedChecksum))

		if bytes.Equal(calculatedChecksum, masterKeyChecksumHeader) {
			log.Println("Checksum matched using the alternate V1 fallback method. Proceeding.")
			checksumMatches = true // Mark as matched
		} else {
			log.Println("Checksum mismatch even after V1 fallback.")
			return ErrChecksumMismatch // Still doesn't match
		}
	} else if !checksumMatches {
		// Checksum failed, and it's not a V1 backup eligible for fallback.
		return ErrChecksumMismatch
	}

	log.Println("Master key successfully decrypted and verified.")
	return nil
}

// cipherDecrypterReader handles streaming decryption and PKCS7 unpadding.
type cipherDecrypterReader struct {
	r         io.Reader        // Underlying encrypted reader
	mode      cipher.BlockMode // CBC decrypter mode
	blockSize int              // Block size (e.g., 16 for AES)
	buf       []byte           // Internal buffer for reading encrypted data
	decrypted []byte           // Buffer for storing decrypted (but possibly padded) data
	plainOff  int              // Offset within the decrypted plaintext buffer
	plainLim  int              // Limit of valid plaintext data in a decrypted buffer
	eof       bool             // True if the underlying reader reached EOF
	err       error            // Stores any encountered error
}

// newCipherDecrypterReader creates a new reader. bufSize should be a multiple of blockSize.
func newCipherDecrypterReader(r io.Reader, mode cipher.BlockMode) *cipherDecrypterReader {
	blockSize := mode.BlockSize()
	// Use a reasonable buffer size, e.g., 8192, ensuring it's a multiple of block size
	bufSize := 8192
	if bufSize < blockSize {
		bufSize = blockSize
	} else {
		bufSize = (bufSize / blockSize) * blockSize // Ensure multiple
	}
	return &cipherDecrypterReader{
		r:         r,
		mode:      mode,
		blockSize: blockSize,
		buf:       make([]byte, bufSize),
		decrypted: make([]byte, bufSize), // Buffer for decrypted data
	}
}

// Read implements io.Reader, decrypting, and unpadding on the fly.
func (cr *cipherDecrypterReader) Read(p []byte) (n int, err error) {
	// If a previous error occurred, return it
	if cr.err != nil {
		return 0, cr.err
	}

	// If we have leftover plaintext, serve it first
	if cr.plainOff < cr.plainLim {
		n = copy(p, cr.decrypted[cr.plainOff:cr.plainLim])
		cr.plainOff += n
		return n, nil
	}

	// If we previously hit EOF and have no more data, return EOF
	if cr.eof {
		return 0, io.EOF
	}

	// Reset plaintext buffer pointers
	cr.plainOff = 0
	cr.plainLim = 0

	// Read more encrypted data
	// We try to read a full buffer but handle partial reads, especially near EOF.
	nr, readErr := io.ReadFull(cr.r, cr.buf) // Try to fill the buffer

	// Handle read errors or EOF *after* processing any data read (nr > 0)
	if nr > 0 {
		// We must have read a multiple of the block size, except possibly at EOF
		if nr%cr.blockSize != 0 {
			// If not EOF, this is an error in the ciphertext stream
			if readErr == nil || (readErr != io.EOF && !errors.Is(readErr, io.ErrUnexpectedEOF)) {
				cr.err = fmt.Errorf("read %d bytes, not a multiple of block size %d", nr, cr.blockSize)
				return 0, cr.err
			}
			// If it is EOF but not block aligned, the ciphertext is likely truncated/corrupt before padding
			if readErr == io.EOF || errors.Is(readErr, io.ErrUnexpectedEOF) {
				cr.err = fmt.Errorf("ciphertext truncated or corrupted before final block (read %d bytes)", nr)
				return 0, cr.err
			}
		}

		// Decrypt the data read
		cr.mode.CryptBlocks(cr.decrypted[:nr], cr.buf[:nr]) // Decrypt in place into a decrypted buffer
		cr.plainLim = nr                                    // Initially, the limit is the number of bytes read/decrypted
	}

	// Check for read errors *after* attempting decryption of read bytes
	if readErr != nil {
		if readErr == io.EOF || errors.Is(readErr, io.ErrUnexpectedEOF) {
			cr.eof = true // Mark that we've hit the end of the source stream

			// If we decrypted data *in this read cycle* (nr > 0), try to unpad it
			if cr.plainLim > 0 {
				unpaddedData, unpadErr := pkcs7Unpad(cr.decrypted[:cr.plainLim], cr.blockSize)
				if unpadErr != nil {
					cr.err = fmt.Errorf("final block unpadding failed: %w", unpadErr)
					return 0, cr.err // Return padding error immediately
				}
				// Update the limit to the actual plaintext length
				cr.plainLim = len(unpaddedData)
			}
			// If plainLim is now 0 (the last block was just padding), the next Read call will correctly return EOF.
			// If plainLim > 0, we have some final plaintext to return first.
		} else {
			// A non-EOF read error occurred
			cr.err = fmt.Errorf("reading underlying stream: %w", readErr)
			return 0, cr.err
		}
	}

	// Now, serve data from the newly filled (and potentially unpadded) decrypted buffer
	if cr.plainOff < cr.plainLim {
		n = copy(p, cr.decrypted[cr.plainOff:cr.plainLim])
		cr.plainOff += n
		// Don't return EOF yet, even if cr.eof is true, because we have data to return.
		// The *next* call will return EOF if appropriate.
		return n, nil
	}

	// If we get here, it means:
	// - We didn't have leftover data (plainOff >= plainLim)
	// - We read 0 bytes OR the last read resulted only in padding after unpadding (plainLim = 0)
	// - AND we hit EOF on the read.
	if cr.eof {
		return 0, io.EOF
	}

	// Should ideally not be reached if read logic is correct.
	// If cr.err is nil, force an error state.
	if cr.err == nil {
		cr.err = errors.New("cipher decrypter in unexpected state")
	}
	return 0, cr.err
}

// setupDecryptionStream needs to use the new reader
func (e *Extractor) setupDecryptionStream(encryptedStream io.Reader) (io.Reader, error) {
	block, err := aes.NewCipher(e.decryptedMasterKey)
	if err != nil {
		return nil, fmt.Errorf("creating payload cipher: %w", err)
	}
	if len(e.masterKeyIv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid payload IV size: %d (expected %d)", len(e.masterKeyIv), aes.BlockSize)
	}
	payloadMode := cipher.NewCBCDecrypter(block, e.masterKeyIv)

	// Use the revised reader
	decrypterReader := newCipherDecrypterReader(encryptedStream, payloadMode)

	log.Println("Using revised CBC decrypter reader with PKCS7 unpadding for payload.")
	return decrypterReader, nil
}

// --- Key Derivation and Checksum ---

// deriveKeyPbkdf2 derives a key using PBKDF2WithHmacSHA1, handling Android version differences.
func deriveKeyPbkdf2(password string, salt []byte, rounds int, useUtf8 bool) []byte {
	var pwBytes []byte
	if useUtf8 {
		// V2+ uses standard UTF-8 bytes
		pwBytes = []byte(password)
		if debug {
			log.Println("PBKDF2 (User Key): Using UTF-8 password bytes.")
		}
	} else {
		// V1 uses lower 8 bits of each char
		runes := []rune(password)
		pwBytes = make([]byte, len(runes))
		for i, r := range runes {
			pwBytes[i] = byte(r & 0xFF)
		}
		if debug {
			log.Println("PBKDF2 (User Key): Using low-byte password bytes (V1 style).")
		}
	}
	key := pbkdf2.Key(pwBytes, salt, rounds, pbkdf2KeySize/8, sha1.New)
	return key
}

// makeKeyChecksum derives the checksum key from the master key using PBKDF2WithHmacSHA1.
// This version carefully simulates Java's byte-to-char casting for PBKDF2 input preparation based on a backup version.
func makeKeyChecksum(masterKeyBytes []byte, salt []byte, rounds int, useUtf8 bool) []byte {
	var pseudoPasswordBytes []byte

	// Simulate Java's byte (signed) to char (unsigned 16-bit) cast.
	// A Java byte b is cast to char c as: c = (char) b;
	// If b >= 0, c has the value of b.
	// If b < 0, c has value 65536 + b (due to sign extension then taking lower 16 bits).
	// Go's byte is unsigned (0-255). We need to map masterKeyBytes (interpreted as Java's signed byte)
	// to the corresponding Java char value, then encode that value.
	masterKeyJavaChars := make([]rune, len(masterKeyBytes))
	for i, b := range masterKeyBytes {
		javaByteValue := int8(b) // Interpret Go byte as Java's signed byte
		var charValue int
		if javaByteValue >= 0 {
			charValue = int(javaByteValue)
		} else {
			// Simulate sign extension to 16 bits and take the unsigned value
			charValue = 0x10000 + int(javaByteValue) // 65536 + negative value
		}
		masterKeyJavaChars[i] = rune(charValue)
	}

	if useUtf8 {
		// V2+: Simulate Java's PBEKeySpec(char[]) likely converting the char array
		// back to bytes using UTF-8 encoding when "PBKDF2WithHmacSHA1" is used.
		var utf8Buf bytes.Buffer
		// Go's utf8.EncodeRune handles converting the simulated Java char (as rune) to UTF-8 bytes.
		utf8Bytes := make([]byte, utf8.UTFMax) // Max bytes for one rune
		for _, r := range masterKeyJavaChars {
			n := utf8.EncodeRune(utf8Bytes, r)
			utf8Buf.Write(utf8Bytes[:n])
		}
		pseudoPasswordBytes = utf8Buf.Bytes()
		if debug {
			log.Println("PBKDF2 (Checksum): Using UTF-8 encoded bytes derived from simulated Java char cast of MK bytes for PBKDF2 input (V2+ style).")
			// log.Printf("PBKDF2 (Checksum): Intermediate UTF-8 Bytes: %s", hex.EncodeToString(pseudoPasswordBytes)) // 디버깅 시 주석 해제
		}
	} else {
		// V1: Simulate Java's PBEKeySpec(char[]) likely using the low-byte (8-bit)
		// conversion when "PBKDF2WithHmacSHA1And8bit" is used.
		pseudoPasswordBytes = make([]byte, len(masterKeyJavaChars))
		for i, r := range masterKeyJavaChars {
			pseudoPasswordBytes[i] = byte(r & 0xFF) // Extract low byte from the simulated char value
		}
		if debug {
			log.Println("PBKDF2 (Checksum): Using low-byte converted bytes derived from simulated Java char cast of MK bytes for PBKDF2 input (V1 style).")
		}
	}

	// Derive the checksum key using the prepared pseudo-password bytes.
	checksumKey := pbkdf2.Key(pseudoPasswordBytes, salt, rounds, pbkdf2KeySize/8, sha1.New)
	return checksumKey
}

// --- PKCS7 Padding ---

// pkcs7Unpad removes PKCS7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("cannot unpad empty data")
	}

	paddingLen := int(data[length-1])
	if paddingLen < 1 || paddingLen > blockSize {
		log.Printf("WARN: Invalid PKCS7 padding len: %d (must be 1..%d)", paddingLen, blockSize)
		return nil, ErrInvalidPadding // Return specific error
	}
	// Check padding bytes integrity
	padStart := length - paddingLen
	if padStart < 0 { // Should not happen if paddingLen <= blockSize and length >= paddingLen
		log.Printf("WARN: Invalid PKCS7 padding calculation: len=%d, padLen=%d", length, paddingLen)
		return nil, ErrInvalidPadding
	}
	for i := padStart; i < length-1; i++ {
		if data[i] != byte(paddingLen) {
			log.Printf("WARN: Invalid PKCS7 padding byte at %d: expected %d, got %d", i, byte(paddingLen), data[i])
			return nil, ErrInvalidPadding // Return specific error
		}
	}
	return data[:padStart], nil
}

// --- I/O and Utility Functions ---

// readLine reads until newline, trims space, handles EOF correctly for header lines.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	trimmedLine := strings.TrimSpace(line)

	if err != nil {
		if err == io.EOF && len(trimmedLine) > 0 {
			// Reached EOF but got data - valid for the last header line
			return trimmedLine, nil
		} else if err == io.EOF {
			// Reached EOF with no data read on this call
			return "", fmt.Errorf("%w: %w", ErrUnexpectedEOF, err)
		}
		// Other read error
		return "", fmt.Errorf("reading line: %w", err)
	}
	return trimmedLine, nil
}

// getInputStream handles opening a file or using stdin. Includes basic size checks.
func getInputStream(filename string) (io.ReadCloser, error) {
	if filename == "-" {
		log.Println("Reading backup from standard input")
		return io.NopCloser(os.Stdin), nil
	}
	log.Printf("Opening input file: %s", filename)
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening input '%s': %w", filename, err)
	}

	// File Size Sanity Check
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("getting file info for '%s': %w", filename, err)
	}
	if info.Size() == 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: input '%s' is empty", ErrSmallFile, filename)
	}
	const minHeaderSize = 64 // Approx minimum size for a valid (even unencrypted) header
	if info.Size() < minHeaderSize {
		log.Printf("WARN: Input file '%s' is very small (%d bytes). May be incomplete.", filename, info.Size())
	}

	return file, nil
}

// getOutputStream handles creating a file or using stdout.
func getOutputStream(filename string) (io.WriteCloser, error) {
	if filename == "-" {
		log.Println("Writing extracted tar to standard output")
		return os.Stdout, nil
	}
	log.Printf("Creating output file: %s", filename)
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("creating output '%s': %w", filename, err)
	}
	return file, nil
}

// min returns the smaller of two integers.
//
//goland:noinspection GoReservedWordUsedAsName
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- Main Function and Command-Line Handling ---

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "Usage:\n")
	_, _ = fmt.Fprintf(os.Stderr, "  abugo unpack <backup.ab> <backup.tar> [password]\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "Arguments:\n")
	_, _ = fmt.Fprintf(os.Stderr, "  <backup.ab>   Path to the Android backup file (.ab) or '-' for stdin.\n")
	_, _ = fmt.Fprintf(os.Stderr, "  <backup.tar>  Path to write the extracted tar file or '-' for stdout.\n")
	_, _ = fmt.Fprintf(os.Stderr, "  [password]    Optional password for encrypted backups.\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "If the password argument is not provided, the ABUGO_PASSWD environment variable will be checked.\n")
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime)

	if len(os.Args) < 4 || os.Args[1] != "unpack" {
		usage()
		os.Exit(1)
	}

	backupFilename := os.Args[2]
	tarFilename := os.Args[3]
	password := ""
	if len(os.Args) > 4 {
		password = os.Args[4]
	}

	// Check env var for password if not provided
	if password == "" {
		envPassword := os.Getenv("ABUGO_PASSWD")
		if envPassword != "" {
			log.Println("Using password from ABUGO_PASSWD environment variable.")
			password = envPassword
		}
	}

	// Setup Input
	backupReadCloser, err := getInputStream(backupFilename)
	if err != nil {
		log.Fatalf("ERROR opening input: %v", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer backupReadCloser.Close()

	// Setup Output
	tarWriteCloser, err := getOutputStream(tarFilename)
	if err != nil {
		log.Fatalf("ERROR creating output: %v", err)
	}
	defer func() {
		if cerr := tarWriteCloser.Close(); cerr != nil {
			// Log error on close, especially for file output
			if tarFilename != "-" {
				log.Printf("WARN: Error closing output file '%s': %v", tarFilename, cerr)
			}
		}
	}()

	// Extract
	extractor := NewExtractor(backupReadCloser, tarWriteCloser, password)
	err = extractor.Extract()
	if err != nil {
		// Provide more user-friendly error messages for common failures
		if errors.Is(err, ErrChecksumMismatch) {
			log.Fatalf("ERROR: Master key checksum mismatch. Likely incorrect password or corrupted backup file.")
		} else if errors.Is(err, ErrPasswordRequired) {
			log.Fatalf("ERROR: Encrypted backup requires a password. Provide via argument or ABE_PASSWD env var.")
		} else if errors.Is(err, ErrInvalidPadding) {
			log.Fatalf("ERROR: Invalid padding during decryption. Likely incorrect password or data corruption.")
		} else if errors.Is(err, ErrUnsupportedVersion) || errors.Is(err, ErrUnsupportedEncryption) {
			log.Fatalf("ERROR: Unsupported backup format: %v", err)
		} else if errors.Is(err, ErrInvalidMagic) {
			log.Fatalf("ERROR: Input is not a valid Android Backup file (invalid magic string).")
		} else {
			log.Fatalf("ERROR: Extraction failed: %v", err) // General error
		}
	}

	log.Println("Extraction process completed successfully.")
}
