package driver

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	vaultPoliciesOption = "io.pasturestack.vault.policies"
	vaultFileOption     = "io.pasturestack.vault.file"
	vaultUIDOption      = "io.pasturestack.vault.uid"
	vaultGIDOption      = "io.pasturestack.vault.gid"
	vaultModeOption     = "io.pasturestack.vault.mode"
)

type vaultVolumeRequest struct {
	Policies []string `json:"policies"`
	File     string   `json:"file"`
	UID      string   `json:"uid"`
	GID      string   `json:"gid"`
	Mode     string   `json:"mode"`
}

func requestFromOptions(provider string, options map[string]any) ([]byte, error) {
	if provider == ProviderControlPlane {
		return tokenFromOptions(options)
	}
	if provider != ProviderVault {
		return nil, errors.New("secret provider is unsupported")
	}
	request, err := vaultRequestFromOptions(options)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("Vault volume options are invalid")
	}
	return encoded, nil
}

func vaultRequestFromOptions(options map[string]any) (vaultVolumeRequest, error) {
	if len(options) == 0 || len(options) > 64 {
		return vaultVolumeRequest{}, errors.New("Vault volume options are invalid")
	}
	rawPolicies, err := vaultStringOption(options, vaultPoliciesOption, "policies", "")
	if err != nil || rawPolicies == "" {
		return vaultVolumeRequest{}, errors.New("Vault policy option is required")
	}
	policies := make([]string, 0, 8)
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(rawPolicies, ",") {
		policy := strings.TrimSpace(raw)
		if !validVaultPolicy(policy) {
			return vaultVolumeRequest{}, errors.New("Vault policy option is invalid")
		}
		if _, exists := seen[policy]; exists {
			continue
		}
		seen[policy] = struct{}{}
		policies = append(policies, policy)
	}
	if len(policies) == 0 || len(policies) > 16 {
		return vaultVolumeRequest{}, errors.New("Vault policy count is out of range")
	}
	sort.Strings(policies)

	file, err := vaultStringOption(options, vaultFileOption, "file", "token")
	if err != nil || !validRelativeSecretPath(file) {
		return vaultVolumeRequest{}, errors.New("Vault token file path is invalid")
	}
	uidText, err := vaultStringOption(options, vaultUIDOption, "uid", "0")
	if err != nil {
		return vaultVolumeRequest{}, errors.New("Vault token UID is invalid")
	}
	uid, err := parseBoundedInt(uidText, 1<<31-1)
	if err != nil {
		return vaultVolumeRequest{}, errors.New("Vault token UID is invalid")
	}
	gidText, err := vaultStringOption(options, vaultGIDOption, "gid", "0")
	if err != nil {
		return vaultVolumeRequest{}, errors.New("Vault token GID is invalid")
	}
	gid, err := parseBoundedInt(gidText, 1<<31-1)
	if err != nil {
		return vaultVolumeRequest{}, errors.New("Vault token GID is invalid")
	}
	modeText, err := vaultStringOption(options, vaultModeOption, "mode", "0400")
	if err != nil {
		return vaultVolumeRequest{}, errors.New("Vault token mode is invalid")
	}
	mode, err := parseMode(modeText)
	if err != nil {
		return vaultVolumeRequest{}, errors.New("Vault token mode is invalid")
	}

	return vaultVolumeRequest{
		Policies: policies,
		File:     file,
		UID:      fmt.Sprintf("%d", uid),
		GID:      fmt.Sprintf("%d", gid),
		Mode:     fmt.Sprintf("%04o", mode.Perm()),
	}, nil
}

func vaultStringOption(options map[string]any, current, neutral, fallback string) (string, error) {
	value := fallback
	found := false
	for _, name := range []string{current, neutral} {
		raw, exists := options[name]
		if !exists {
			continue
		}
		text, ok := raw.(string)
		if !ok || found {
			return "", errors.New("duplicate or non-string Vault option")
		}
		value = strings.TrimSpace(text)
		found = true
	}
	return value, nil
}

func validVaultPolicy(value string) bool {
	if value == "" || len(value) > 64 {
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
