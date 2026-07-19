package driver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SecretFetcher interface {
	Fetch(context.Context, []byte) ([]encryptedRecord, error)
}

type APIFetcher struct {
	endpoint         *url.URL
	accessKey        string
	secretKey        string
	maxResponseBytes int64
	client           *http.Client
}

func NewAPIFetcher(config Config) (*APIFetcher, error) {
	baseURL, err := validateControlPlaneURL(config.ControlPlaneURL)
	if err != nil {
		return nil, err
	}
	endpoint := *baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/secrets"
	client := &http.Client{
		Timeout: config.RequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: config.RequestTimeout,
		},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > 2 || request.URL.Scheme != endpoint.Scheme || !strings.EqualFold(request.URL.Host, endpoint.Host) {
				return errors.New("compatible control-plane redirect was rejected")
			}
			return nil
		},
	}
	return &APIFetcher{
		endpoint:         &endpoint,
		accessKey:        config.AccessKey,
		secretKey:        config.SecretKey,
		maxResponseBytes: config.MaxResponseBytes,
		client:           client,
	}, nil
}

func (fetcher *APIFetcher) Fetch(ctx context.Context, token []byte) ([]encryptedRecord, error) {
	if len(token) == 0 || len(token) > 64<<10 {
		return nil, errors.New("secret request token is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fetcher.endpoint.String(), bytes.NewReader(token))
	if err != nil {
		return nil, errors.New("unable to create encrypted secret request")
	}
	request.Header.Set("Content-Type", "application/x-api-secrets-token")
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(fetcher.accessKey, fetcher.secretKey)
	response, err := fetcher.client.Do(request)
	if err != nil {
		return nil, errors.New("encrypted secret request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("encrypted secret request returned status %d", response.StatusCode)
	}
	reader := io.LimitReader(response.Body, fetcher.maxResponseBytes+1)
	body, err := io.ReadAll(reader)
	if err != nil || int64(len(body)) > fetcher.maxResponseBytes {
		return nil, errors.New("encrypted secret response exceeds its limit")
	}
	var records []encryptedRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&records); err != nil {
		return nil, errors.New("encrypted secret response is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("encrypted secret response contains multiple documents")
	}
	return records, nil
}
