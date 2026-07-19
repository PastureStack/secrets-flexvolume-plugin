package driver

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type staticFetcher struct {
	records []encryptedRecord
	err     error
	token   []byte
}

func (fetcher *staticFetcher) Fetch(_ context.Context, token []byte) ([]encryptedRecord, error) {
	fetcher.token = append(fetcher.token[:0], token...)
	if fetcher.err != nil {
		return nil, fetcher.err
	}
	return append([]encryptedRecord(nil), fetcher.records...), nil
}

type memoryMounter struct {
	mu      sync.Mutex
	mounted map[string]bool
}

func newMemoryMounter() *memoryMounter {
	return &memoryMounter{mounted: make(map[string]bool)}
}

func (mounter *memoryMounter) IsMounted(path string) (bool, error) {
	mounter.mu.Lock()
	defer mounter.mu.Unlock()
	return mounter.mounted[path], nil
}

func (mounter *memoryMounter) MountTmpfs(path string, _ int64) error {
	mounter.mu.Lock()
	defer mounter.mu.Unlock()
	if mounter.mounted[path] {
		return errors.New("already mounted")
	}
	mounter.mounted[path] = true
	return nil
}

func (mounter *memoryMounter) Unmount(path string) error {
	mounter.mu.Lock()
	defer mounter.mu.Unlock()
	if !mounter.mounted[path] {
		return errors.New("not mounted")
	}
	delete(mounter.mounted, path)
	return nil
}

func TestDriverMaterializesAndErasesEncryptedVolume(t *testing.T) {
	privateKey := testPrivateKey(t)
	record := encryptTestRecord(t, &privateKey.PublicKey, "database-password", []byte("correct horse battery staple"))
	config := testConfig(t)
	fetcher := &staticFetcher{records: []encryptedRecord{record}}
	mounter := newMemoryMounter()
	decryptor := &Decryptor{
		privateKey: privateKey, maxSecretBytes: config.MaxSecretBytes,
		maxTotalBytes: config.MaxTotalBytes, maxSecrets: config.MaxSecrets,
	}
	driver, err := NewDriver(config, fetcher, decryptor, mounter, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	token := []byte(`{"opaque":"request"}`)
	tokenEnvelope, err := json.Marshal(struct {
		Value []byte `json:"value"`
	}{Value: token})
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.create(createRequest{
		Name: "secret-volume-test",
		Opts: map[string]any{currentTokenOption: string(tokenEnvelope)},
	}); err != nil {
		t.Fatal(err)
	}
	mountpoint, err := driver.mount(context.Background(), "secret-volume-test", "consumer-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fetcher.token, token) {
		t.Fatal("request token was not passed through exactly")
	}
	content, err := os.ReadFile(filepath.Join(mountpoint, "database-password"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "correct horse battery staple" {
		t.Fatal("materialized content differs")
	}
	info, err := os.Stat(filepath.Join(mountpoint, "database-password"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("unexpected file mode: %o", info.Mode().Perm())
	}
	if err := driver.unmount("secret-volume-test", "consumer-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mountpoint); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unmount did not erase the private volume")
	}
	if err := driver.remove("secret-volume-test"); err != nil {
		t.Fatal(err)
	}
}

func TestDriverPreservesVolumeUntilLastConsumer(t *testing.T) {
	privateKey := testPrivateKey(t)
	config := testConfig(t)
	fetcher := &staticFetcher{records: []encryptedRecord{
		encryptTestRecord(t, &privateKey.PublicKey, "value", []byte("shared")),
	}}
	mounter := newMemoryMounter()
	driver, err := NewDriver(config, fetcher, &Decryptor{
		privateKey: privateKey, maxSecretBytes: config.MaxSecretBytes,
		maxTotalBytes: config.MaxTotalBytes, maxSecrets: config.MaxSecrets,
	}, mounter, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokenEnvelope, _ := json.Marshal(struct {
		Value []byte `json:"value"`
	}{Value: []byte("opaque")})
	if err := driver.create(createRequest{Name: "shared", Opts: map[string]any{currentTokenOption: string(tokenEnvelope)}}); err != nil {
		t.Fatal(err)
	}
	first, err := driver.mount(context.Background(), "shared", "consumer-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := driver.mount(context.Background(), "shared", "consumer-b")
	if err != nil || first != second {
		t.Fatal("second consumer did not share the same private mount")
	}
	if err := driver.unmount("shared", "consumer-a"); err != nil {
		t.Fatal(err)
	}
	if mounted, _ := mounter.IsMounted(first); !mounted {
		t.Fatal("first consumer removal erased a still-used volume")
	}
	if err := driver.unmount("shared", "consumer-b"); err != nil {
		t.Fatal(err)
	}
	if mounted, _ := mounter.IsMounted(first); mounted {
		t.Fatal("last consumer removal did not erase the volume")
	}
}

func TestDecryptorRejectsTamperingAndUnsafePaths(t *testing.T) {
	privateKey := testPrivateKey(t)
	decryptor := &Decryptor{
		privateKey: privateKey, maxSecretBytes: 1 << 20,
		maxTotalBytes: 2 << 20, maxSecrets: 8,
	}
	record := encryptTestRecord(t, &privateKey.PublicKey, "safe", []byte("content"))
	raw, err := base64.StdEncoding.DecodeString(record.RewrapText)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[len(signature)-1] ^= 1
	envelope.Signature = base64.StdEncoding.EncodeToString(signature)
	tampered, _ := json.Marshal(envelope)
	record.RewrapText = base64.StdEncoding.EncodeToString(tampered)
	if _, err := decryptor.DecryptRecords([]encryptedRecord{record}); err == nil {
		t.Fatal("tampered signature was accepted")
	}

	unsafe := encryptTestRecord(t, &privateKey.PublicKey, "../escape", []byte("content"))
	if _, err := decryptor.DecryptRecords([]encryptedRecord{unsafe}); err == nil {
		t.Fatal("unsafe secret path was accepted")
	}
}

func TestReadOnlyModeCompatibility(t *testing.T) {
	for input, expected := range map[string]os.FileMode{
		"": 0o444, "400": 0o400, "0400": 0o400,
		"440": 0o440, "0440": 0o440,
		"444": 0o444, "0444": 0o444,
	} {
		actual, err := parseMode(input)
		if err != nil || actual != expected {
			t.Fatalf("mode %q: got %o, %v", input, actual, err)
		}
	}
	for _, input := range []string{"0000", "0600", "0640", "0777", "4000", "invalid"} {
		if _, err := parseMode(input); err == nil {
			t.Fatalf("writable, executable, or special mode %q was accepted", input)
		}
	}
}

func TestAPIFetcherBoundsAndAuthenticatesRequest(t *testing.T) {
	var observedToken []byte
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v2-beta/secrets" {
			t.Error("unexpected request target")
		}
		if request.Header.Get("Content-Type") != "application/x-api-secrets-token" {
			t.Error("missing compatible secret-token content type")
		}
		user, password, ok := request.BasicAuth()
		if !ok || user != "access" || password != "secret" {
			t.Error("missing compatible control-plane authentication")
		}
		observedToken, _ = io.ReadAll(request.Body)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[{"name":"entry","uid":"0","gid":"0","mode":"0400","rewrapText":"opaque"}]`))
	}))
	defer server.Close()
	config := testConfig(t)
	config.ControlPlaneURL = server.URL + "/v2-beta"
	config.AccessKey = "access"
	config.SecretKey = "secret"
	config.RequestTimeout = 2 * time.Second
	fetcher, err := NewAPIFetcher(config)
	if err != nil {
		t.Fatal(err)
	}
	records, err := fetcher.Fetch(context.Background(), []byte("token-body"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || string(observedToken) != "token-body" {
		t.Fatal("encrypted secret API contract was not preserved")
	}
}

func TestTokenOptionRequiresBoundedStructuredValue(t *testing.T) {
	envelope, _ := json.Marshal(struct {
		Value []byte `json:"value"`
	}{Value: []byte("opaque")})
	token, err := tokenFromOptions(map[string]any{currentTokenOption: string(envelope)})
	if err != nil || string(token) != "opaque" {
		t.Fatal("valid token option was rejected")
	}
	for _, options := range []map[string]any{
		nil,
		{currentTokenOption: 7},
		{currentTokenOption: `{}`},
		{currentTokenOption: string(envelope), compatibilityTokenOption(): string(envelope)},
	} {
		if _, err := tokenFromOptions(options); err == nil {
			t.Fatal("invalid token option was accepted")
		}
	}
}

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		DriverName:       DefaultDriverName,
		SocketPath:       filepath.Join(root, "plugins", "driver.sock"),
		VolumeRoot:       filepath.Join(root, "volumes"),
		HostKeyPath:      filepath.Join(root, "host-key"),
		HealthListen:     "127.0.0.1:0",
		ControlPlaneURL:  "http://127.0.0.1:8080/v2-beta",
		AccessKey:        "access",
		SecretKey:        "secret",
		MaxResponseBytes: DefaultMaxResponseBytes,
		MaxSecretBytes:   DefaultMaxSecretBytes,
		MaxTotalBytes:    DefaultMaxTotalBytes,
		MaxSecrets:       DefaultMaxSecrets,
		RequestTimeout:   2 * time.Second,
	}
}

func testPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encryptTestRecord(t *testing.T, publicKey *rsa.PublicKey, name string, content []byte) encryptedRecord {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	plainText := []byte(base64.StdEncoding.EncodeToString(content))
	cipherText := gcm.Seal(nil, nonce, plainText, nil)
	zeroBytes(plainText)
	encodedPayload, err := json.Marshal(aesEnvelope{Nonce: nonce, Algorithm: "aes256-gcm", CipherText: cipherText})
	if err != nil {
		t.Fatal(err)
	}
	signingNonce := make([]byte, 12)
	if _, err := rand.Read(signingNonce); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(signingNonce)
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write(encodedPayload)
	signature := append(append(append([]byte(nil), signingNonce...), ':'), mac.Sum(nil)...)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope := encryptedEnvelope{
		EncryptionAlgorithm: "aes256-gcm96",
		EncryptedText:       string(encodedPayload),
		EncryptedKey: rsaEnvelope{
			EncryptionAlgorithm: "PKCS1_OAEP",
			EncryptedText:       base64.StdEncoding.EncodeToString(encryptedKey),
			HashAlgorithm:       "sha256",
		},
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	encodedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encryptedRecord{
		Name: name, UID: "0", GID: "0", Mode: "0400",
		RewrapText: base64.StdEncoding.EncodeToString(encodedEnvelope),
	}
}
