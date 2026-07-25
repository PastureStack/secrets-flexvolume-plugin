package driver

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	ProviderControlPlane    = "control-plane"
	ProviderVault           = "vault"
	DefaultDriverName       = "pasturestack-secret-volume"
	DefaultSocketPath       = "/run/docker/plugins/pasturestack-secret-volume.sock"
	DefaultVolumeRoot       = "/var/lib/pasturestack/volumes/secret-volume"
	DefaultHostKeyPath      = "/var/lib/pasturestack/etc/ssl/host.key"
	DefaultHealthListen     = "0.0.0.0:8093"
	DefaultMetadataURL      = "http://169.254.169.250/2016-07-29"
	DefaultMaxResponseBytes = int64(10 << 20)
	DefaultMaxSecretBytes   = int64(1 << 20)
	DefaultMaxTotalBytes    = int64(8 << 20)
	DefaultMaxSecrets       = 128
)

type Config struct {
	Provider         string
	DriverName       string
	SocketPath       string
	VolumeRoot       string
	HostKeyPath      string
	HealthListen     string
	ControlPlaneURL  string
	VaultBridgeURL   string
	MetadataURL      string
	AccessKey        string
	SecretKey        string
	MaxResponseBytes int64
	MaxSecretBytes   int64
	MaxTotalBytes    int64
	MaxSecrets       int
	RequestTimeout   time.Duration
}

func ParseConfig(args []string, stderr io.Writer) (Config, error) {
	flags := flag.NewFlagSet("secrets-flexvolume-plugin serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := Config{}
	flags.StringVar(&config.Provider, "provider", envOr("PASTURESTACK_SECRET_PROVIDER", ProviderControlPlane), "secret provider: control-plane or vault")
	flags.StringVar(&config.DriverName, "driver-name", envOr("PASTURESTACK_SECRET_DRIVER_NAME", DefaultDriverName), "Docker volume driver name")
	flags.StringVar(&config.SocketPath, "socket-path", envOr("PASTURESTACK_SECRET_SOCKET", DefaultSocketPath), "Docker volume plugin socket")
	flags.StringVar(&config.VolumeRoot, "volume-root", envOr("PASTURESTACK_SECRET_VOLUME_ROOT", DefaultVolumeRoot), "shared tmpfs volume root")
	flags.StringVar(&config.HostKeyPath, "host-key-path", envOr("PASTURESTACK_HOST_KEY_PATH", DefaultHostKeyPath), "host RSA private key")
	flags.StringVar(&config.HealthListen, "health-listen", envOr("PASTURESTACK_SECRET_HEALTH_LISTEN", DefaultHealthListen), "health endpoint listen address")
	flags.StringVar(&config.ControlPlaneURL, "control-plane-url", firstEnv("CATTLE_URL", "PASTURESTACK_CONTROL_PLANE_URL"), "compatible control-plane API URL")
	flags.StringVar(&config.VaultBridgeURL, "vault-bridge-url", envOr("PASTURESTACK_VAULT_BRIDGE_URL", ""), "Vault lease bridge URL")
	flags.StringVar(&config.MetadataURL, "metadata-url", envOr("PASTURESTACK_METADATA_URL", DefaultMetadataURL), "host metadata API URL")
	flags.StringVar(&config.AccessKey, "access-key", firstEnv("CATTLE_"+"AGENT_ACCESS_KEY", "CATTLE_ACCESS_KEY", "PASTURESTACK_ACCESS_KEY"), "compatible control-plane access key")
	flags.StringVar(&config.SecretKey, "secret-key", firstEnv("CATTLE_"+"AGENT_SECRET_KEY", "CATTLE_SECRET_KEY", "PASTURESTACK_SECRET_KEY"), "compatible control-plane secret key")
	flags.Int64Var(&config.MaxResponseBytes, "max-response-bytes", DefaultMaxResponseBytes, "maximum encrypted API response")
	flags.Int64Var(&config.MaxSecretBytes, "max-secret-bytes", DefaultMaxSecretBytes, "maximum decoded bytes per secret")
	flags.Int64Var(&config.MaxTotalBytes, "max-total-bytes", DefaultMaxTotalBytes, "maximum decoded bytes per volume")
	flags.IntVar(&config.MaxSecrets, "max-secrets", DefaultMaxSecrets, "maximum files per volume")
	flags.DurationVar(&config.RequestTimeout, "request-timeout", 10*time.Second, "control-plane request timeout")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, errors.New("unexpected positional arguments")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.Provider != ProviderControlPlane && config.Provider != ProviderVault {
		return errors.New("invalid secret provider")
	}
	if !validDriverName(config.DriverName) {
		return errors.New("invalid driver name")
	}
	if err := validateAbsolutePath(config.SocketPath, "/run/docker/plugins"); err != nil {
		return fmt.Errorf("invalid socket path: %w", err)
	}
	if err := validateAbsolutePath(config.VolumeRoot, "/var/lib/pasturestack/volumes"); err != nil {
		return fmt.Errorf("invalid volume root: %w", err)
	}
	if !filepath.IsAbs(config.HostKeyPath) || filepath.Clean(config.HostKeyPath) != config.HostKeyPath {
		return errors.New("invalid host key path")
	}
	if _, _, err := net.SplitHostPort(config.HealthListen); err != nil {
		return errors.New("invalid health listen address")
	}
	if config.MaxResponseBytes < 1024 || config.MaxResponseBytes > 32<<20 ||
		config.MaxSecretBytes < 1 || config.MaxSecretBytes > 4<<20 ||
		config.MaxTotalBytes < config.MaxSecretBytes || config.MaxTotalBytes > 16<<20 ||
		config.MaxSecrets < 1 || config.MaxSecrets > 512 ||
		config.RequestTimeout < time.Second || config.RequestTimeout > time.Minute {
		return errors.New("invalid safety limit")
	}
	switch config.Provider {
	case ProviderControlPlane:
		if config.AccessKey == "" || config.SecretKey == "" {
			return errors.New("compatible control-plane credentials are required")
		}
		if _, err := validateServiceURL(config.ControlPlaneURL); err != nil {
			return fmt.Errorf("invalid compatible control-plane URL: %w", err)
		}
	case ProviderVault:
		if _, err := validateServiceURL(config.VaultBridgeURL); err != nil {
			return fmt.Errorf("invalid Vault bridge URL: %w", err)
		}
		if _, err := validateServiceURL(config.MetadataURL); err != nil {
			return fmt.Errorf("invalid metadata URL: %w", err)
		}
	}
	return nil
}

func validateControlPlaneURL(raw string) (*url.URL, error) {
	return validateServiceURL(raw)
}

func validateServiceURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("URL is invalid")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("URL scheme is unsupported")
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && !isPrivateHost(host) {
		return nil, errors.New("unencrypted URL must use a private address")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func isPrivateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return validInternalHostname(host)
}

func validInternalHostname(host string) bool {
	if host == "" || len(host) > 63 || strings.Contains(host, ".") ||
		host[0] == '-' || host[len(host)-1] == '-' {
		return false
	}
	for _, character := range host {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validateAbsolutePath(path, requiredRoot string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be clean and absolute")
	}
	root := filepath.Clean(requiredRoot)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("path is outside its required root")
	}
	return nil
}

func validDriverName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func parseBoundedInt(text string, maximum int64) (int, error) {
	if text == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(text, 10, 32)
	if err != nil || value < 0 || value > maximum {
		return 0, errors.New("numeric ownership value is out of range")
	}
	return int(value), nil
}
