package driver

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

type encryptedRecord struct {
	Name       string `json:"name"`
	UID        string `json:"uid"`
	GID        string `json:"gid"`
	Mode       string `json:"mode"`
	RewrapText string `json:"rewrapText"`
}

type encryptedEnvelope struct {
	EncryptionAlgorithm string      `json:"encryptionAlgorithm"`
	EncryptedText       string      `json:"encryptedText"`
	HashAlgorithm       string      `json:"hashAlgorithm"`
	EncryptedKey        rsaEnvelope `json:"encryptedKey"`
	Signature           string      `json:"signature"`
}

type rsaEnvelope struct {
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
	EncryptedText       string `json:"encryptedText"`
	HashAlgorithm       string `json:"hashAlgorithm"`
}

type aesEnvelope struct {
	Nonce      []byte
	Algorithm  string
	CipherText []byte
}

type materializedFile struct {
	Name    string
	Content []byte
	UID     int
	GID     int
	Mode    os.FileMode
}

type Decryptor struct {
	privateKey     *rsa.PrivateKey
	maxSecretBytes int64
	maxTotalBytes  int64
	maxSecrets     int
}

func LoadDecryptor(keyPath string, maxSecretBytes, maxTotalBytes int64, maxSecrets int) (*Decryptor, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, errors.New("unable to read host identity key")
	}
	defer zeroBytes(keyData)
	privateKey, err := parsePrivateKey(keyData)
	if err != nil {
		return nil, errors.New("unable to parse host identity key")
	}
	if privateKey.N.BitLen() < 2048 {
		return nil, errors.New("host identity key is too small")
	}
	return &Decryptor{
		privateKey:     privateKey,
		maxSecretBytes: maxSecretBytes,
		maxTotalBytes:  maxTotalBytes,
		maxSecrets:     maxSecrets,
	}, nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, remainder := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}
	if len(bytes.TrimSpace(remainder)) != 0 {
		return nil, errors.New("unexpected data follows the identity key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not RSA")
	}
	return key, nil
}

func (decryptor *Decryptor) DecryptRecords(records []encryptedRecord) ([]materializedFile, error) {
	if len(records) == 0 || len(records) > decryptor.maxSecrets {
		return nil, errors.New("encrypted secret count is out of range")
	}
	result := make([]materializedFile, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	var total int64
	for _, record := range records {
		if !validRelativeSecretPath(record.Name) {
			return nil, errors.New("encrypted secret path is invalid")
		}
		canonical := strings.ToLower(record.Name)
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("encrypted secret path is duplicated")
		}
		seen[canonical] = struct{}{}
		content, err := decryptor.decryptRecord(record)
		if err != nil {
			clearMaterialized(result)
			return nil, err
		}
		if int64(len(content)) > decryptor.maxSecretBytes || total > decryptor.maxTotalBytes-int64(len(content)) {
			zeroBytes(content)
			clearMaterialized(result)
			return nil, errors.New("decoded secret payload exceeds its limit")
		}
		total += int64(len(content))
		uid, err := parseBoundedInt(record.UID, 1<<31-1)
		if err != nil {
			zeroBytes(content)
			clearMaterialized(result)
			return nil, err
		}
		gid, err := parseBoundedInt(record.GID, 1<<31-1)
		if err != nil {
			zeroBytes(content)
			clearMaterialized(result)
			return nil, err
		}
		mode, err := parseMode(record.Mode)
		if err != nil {
			zeroBytes(content)
			clearMaterialized(result)
			return nil, err
		}
		result = append(result, materializedFile{Name: record.Name, Content: content, UID: uid, GID: gid, Mode: mode})
	}
	return result, nil
}

func (decryptor *Decryptor) decryptRecord(record encryptedRecord) ([]byte, error) {
	encodedEnvelope, err := base64.StdEncoding.Strict().DecodeString(record.RewrapText)
	if err != nil || len(encodedEnvelope) == 0 || len(encodedEnvelope) > int(decryptor.maxSecretBytes)+16<<10 {
		return nil, errors.New("encrypted secret envelope is invalid")
	}
	var envelope encryptedEnvelope
	if err := decodeStrictJSON(encodedEnvelope, &envelope); err != nil {
		return nil, errors.New("encrypted secret envelope is invalid")
	}
	if envelope.EncryptionAlgorithm != "aes256-gcm96" ||
		(envelope.EncryptedKey.EncryptionAlgorithm != "PKCS1_OAEP" &&
			envelope.EncryptedKey.EncryptionAlgorithm != "rsa-oaep") ||
		envelope.EncryptedKey.HashAlgorithm != "sha256" ||
		envelope.EncryptedKey.EncryptedText == "" ||
		envelope.EncryptedText == "" ||
		envelope.Signature == "" {
		return nil, errors.New("encrypted secret envelope algorithm is unsupported")
	}
	encryptedKey, err := base64.StdEncoding.Strict().DecodeString(envelope.EncryptedKey.EncryptedText)
	if err != nil || len(encryptedKey) != decryptor.privateKey.Size() {
		return nil, errors.New("encrypted secret key is invalid")
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, decryptor.privateKey, encryptedKey, nil)
	if err != nil || len(aesKey) != 32 {
		zeroBytes(aesKey)
		return nil, errors.New("encrypted secret key cannot be opened")
	}
	defer zeroBytes(aesKey)
	if err := verifyEnvelopeSignature(aesKey, envelope.Signature, envelope.EncryptedText); err != nil {
		return nil, err
	}
	var payload aesEnvelope
	if err := decodeStrictJSON([]byte(envelope.EncryptedText), &payload); err != nil ||
		payload.Algorithm != "aes256-gcm" || len(payload.Nonce) != 12 ||
		len(payload.CipherText) < 16 || int64(len(payload.CipherText)) > decryptor.maxSecretBytes+16 {
		return nil, errors.New("encrypted secret payload is invalid")
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.New("encrypted secret key is invalid")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("encrypted secret cipher is invalid")
	}
	clearText, err := gcm.Open(nil, payload.Nonce, payload.CipherText, nil)
	if err != nil {
		return nil, errors.New("encrypted secret authentication failed")
	}
	defer zeroBytes(clearText)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(clearText)))
	length, err := base64.StdEncoding.Strict().Decode(decoded, clearText)
	if err != nil {
		zeroBytes(decoded)
		return nil, errors.New("encrypted secret content encoding is invalid")
	}
	return decoded[:length], nil
}

func verifyEnvelopeSignature(key []byte, encodedSignature, message string) error {
	signature, err := base64.StdEncoding.Strict().DecodeString(encodedSignature)
	if err != nil || len(signature) != 12+1+sha256.Size || signature[12] != ':' {
		return errors.New("encrypted secret signature is invalid")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(signature[:12])
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write([]byte(message))
	if !hmac.Equal(signature[13:], mac.Sum(nil)) {
		return errors.New("encrypted secret signature verification failed")
	}
	return nil
}

func parseMode(value string) (os.FileMode, error) {
	if value == "" {
		return 0o444, nil
	}
	switch value {
	case "400", "0400":
		return 0o400, nil
	case "440", "0440":
		return 0o440, nil
	case "444", "0444":
		return 0o444, nil
	default:
		return 0, errors.New("encrypted secret mode is not permitted")
	}
}

func validRelativeSecretPath(value string) bool {
	if value == "" || len(value) > 240 || strings.Contains(value, "\\") || path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 64 {
			return false
		}
		for _, character := range part {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON documents are not allowed")
	}
	return nil
}

func clearMaterialized(files []materializedFile) {
	for index := range files {
		zeroBytes(files[index].Content)
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func formatOwnership(uid, gid int) string {
	return fmt.Sprintf("%d:%d", uid, gid)
}
