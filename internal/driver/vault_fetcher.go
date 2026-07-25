package driver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const vaultSignatureHeader = "X-PastureStack-Host-Signature"

type vaultIssueRequest struct {
	Version    int      `json:"version"`
	HostUUID   string   `json:"hostUuid"`
	VolumeName string   `json:"volumeName"`
	Policies   []string `json:"policies"`
	File       string   `json:"file"`
	UID        string   `json:"uid"`
	GID        string   `json:"gid"`
	Mode       string   `json:"mode"`
	Timestamp  string   `json:"timestamp"`
	Nonce      string   `json:"nonce"`
}

type vaultRevokeRequest struct {
	Version    int    `json:"version"`
	HostUUID   string `json:"hostUuid"`
	VolumeName string `json:"volumeName"`
	Timestamp  string `json:"timestamp"`
	Nonce      string `json:"nonce"`
}

type vaultIssueResponse struct {
	Records []encryptedRecord `json:"records"`
}

type VaultFetcher struct {
	issueEndpoint  *url.URL
	revokeEndpoint *url.URL
	metadataUUID   *url.URL
	privateKey     *rsa.PrivateKey
	maxResponse    int64
	bridgeClient   *http.Client
	metadataClient *http.Client

	hostMu   sync.Mutex
	hostUUID string
}

func NewVaultFetcher(config Config, privateKey *rsa.PrivateKey) (*VaultFetcher, error) {
	if privateKey == nil || privateKey.N.BitLen() < 2048 {
		return nil, errors.New("host identity key is invalid")
	}
	bridge, err := validateServiceURL(config.VaultBridgeURL)
	if err != nil {
		return nil, err
	}
	metadata, err := validateServiceURL(config.MetadataURL)
	if err != nil {
		return nil, err
	}
	issueEndpoint := appendServicePath(bridge, "/v1/leases")
	revokeEndpoint := appendServicePath(bridge, "/v1/leases/revoke")
	metadataUUID := appendServicePath(metadata, "/self/host/uuid")
	return &VaultFetcher{
		issueEndpoint:  issueEndpoint,
		revokeEndpoint: revokeEndpoint,
		metadataUUID:   metadataUUID,
		privateKey:     privateKey,
		maxResponse:    config.MaxResponseBytes,
		bridgeClient:   vaultHTTPClient(config.RequestTimeout, bridge.Scheme == "http"),
		metadataClient: vaultHTTPClient(config.RequestTimeout, metadata.Scheme == "http"),
	}, nil
}

func (fetcher *VaultFetcher) Fetch(ctx context.Context, volumeName string, requestToken []byte) (FetchResult, error) {
	if !validVolumeName(volumeName) {
		return FetchResult{}, errors.New("Vault volume name is invalid")
	}
	var volumeRequest vaultVolumeRequest
	if len(requestToken) == 0 || len(requestToken) > 64<<10 ||
		decodeStrictJSON(requestToken, &volumeRequest) != nil {
		return FetchResult{}, errors.New("Vault volume request is invalid")
	}
	hostUUID, err := fetcher.getHostUUID(ctx)
	if err != nil {
		return FetchResult{}, err
	}
	nonce, err := randomRequestNonce()
	if err != nil {
		return FetchResult{}, errors.New("unable to create Vault request nonce")
	}
	payload := vaultIssueRequest{
		Version:    1,
		HostUUID:   hostUUID,
		VolumeName: volumeName,
		Policies:   append([]string(nil), volumeRequest.Policies...),
		File:       volumeRequest.File,
		UID:        volumeRequest.UID,
		GID:        volumeRequest.GID,
		Mode:       volumeRequest.Mode,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Nonce:      nonce,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return FetchResult{}, errors.New("unable to encode Vault lease request")
	}
	responseBody, status, err := fetcher.signedRequest(ctx, http.MethodPost, fetcher.issueEndpoint, body)
	if err != nil {
		return FetchResult{}, err
	}
	if status != http.StatusOK {
		return FetchResult{}, errors.New("Vault lease request was rejected")
	}
	var response vaultIssueResponse
	if len(responseBody) == 0 || decodeStrictJSON(responseBody, &response) != nil {
		return FetchResult{}, errors.New("Vault lease response is invalid")
	}
	return FetchResult{Records: response.Records, LeaseIssued: true}, nil
}

func (fetcher *VaultFetcher) Revoke(ctx context.Context, volumeName string) error {
	if !validVolumeName(volumeName) {
		return errors.New("Vault volume name is invalid")
	}
	hostUUID, err := fetcher.getHostUUID(ctx)
	if err != nil {
		return err
	}
	nonce, err := randomRequestNonce()
	if err != nil {
		return errors.New("unable to create Vault request nonce")
	}
	body, err := json.Marshal(vaultRevokeRequest{
		Version:    1,
		HostUUID:   hostUUID,
		VolumeName: volumeName,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Nonce:      nonce,
	})
	if err != nil {
		return errors.New("unable to encode Vault revoke request")
	}
	_, status, err := fetcher.signedRequest(ctx, http.MethodPost, fetcher.revokeEndpoint, body)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return errors.New("Vault lease revoke was rejected")
	}
	return nil
}

func (fetcher *VaultFetcher) signedRequest(ctx context.Context, method string, endpoint *url.URL, body []byte) ([]byte, int, error) {
	digest := sha256.Sum256(body)
	signature, err := rsa.SignPSS(rand.Reader, fetcher.privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return nil, 0, errors.New("unable to sign Vault lease request")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("unable to create Vault lease request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set(vaultSignatureHeader, base64.StdEncoding.EncodeToString(signature))
	response, err := fetcher.bridgeClient.Do(request)
	if err != nil {
		return nil, 0, errors.New("Vault lease request failed")
	}
	defer response.Body.Close()
	bodyReader := io.LimitReader(response.Body, fetcher.maxResponse+1)
	responseBody, readErr := io.ReadAll(bodyReader)
	if readErr != nil || int64(len(responseBody)) > fetcher.maxResponse {
		return nil, 0, errors.New("Vault lease response exceeds its limit")
	}
	return responseBody, response.StatusCode, nil
}

func (fetcher *VaultFetcher) getHostUUID(ctx context.Context) (string, error) {
	fetcher.hostMu.Lock()
	defer fetcher.hostMu.Unlock()
	if fetcher.hostUUID != "" {
		return fetcher.hostUUID, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fetcher.metadataUUID.String(), nil)
	if err != nil {
		return "", errors.New("unable to create host metadata request")
	}
	request.Header.Set("Accept", "text/plain, application/json")
	response, err := fetcher.metadataClient.Do(request)
	if err != nil {
		return "", errors.New("host metadata request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", errors.New("host metadata request was rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 513))
	if err != nil || len(body) > 512 {
		return "", errors.New("host metadata response exceeds its limit")
	}
	candidate := strings.TrimSpace(string(body))
	if strings.HasPrefix(candidate, `"`) {
		var decoded string
		if json.Unmarshal(body, &decoded) != nil {
			return "", errors.New("host metadata response is invalid")
		}
		candidate = strings.TrimSpace(decoded)
	}
	if !validHostUUID(candidate) {
		return "", errors.New("host metadata response is invalid")
	}
	fetcher.hostUUID = candidate
	return candidate, nil
}

func appendServicePath(base *url.URL, suffix string) *url.URL {
	result := *base
	result.Path = strings.TrimRight(result.Path, "/") + suffix
	result.RawPath = ""
	return &result
}

func randomRequestNonce() (string, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(nonce), nil
}

func validHostUUID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func vaultHTTPClient(timeout time.Duration, privateOnly bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	dialContext := dialer.DialContext
	if privateOnly {
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("upstream address is invalid")
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(addresses) == 0 {
				return nil, errors.New("upstream address could not be resolved")
			}
			for _, address := range addresses {
				ip := address.IP
				if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					continue
				}
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return connection, nil
				}
			}
			return nil, errors.New("unencrypted upstream resolved outside the private network")
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          6,
			MaxIdleConnsPerHost:   3,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect was rejected")
		},
	}
}
