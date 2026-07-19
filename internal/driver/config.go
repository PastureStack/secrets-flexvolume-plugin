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
	DefaultDriverName       = "pasturestack-secret-volume"
	DefaultSocketPath       = "/run/docker/plugins/pasturestack-secret-volume.sock"
	DefaultVolumeRoot       = "/var/lib/pasturestack/volumes/secret-volume"
	DefaultHostKeyPath      = "/var/lib/pasturestack/etc/ssl/host.key"
	DefaultHealthListen     = "0.0.0.0:8093"
	DefaultMaxResponseBytes = int64(10 << 20)
	DefaultMaxSecretBytes   = int64(1 << 20)
	DefaultMaxTotalBytes    = int64(8 << 20)
	DefaultMaxSecrets       = 128
)

type Config struct {
	DriverName       string
	SocketPath       string
	VolumeRoot       string
	HostKeyPath      string
	HealthListen     string
	ControlPlaneURL  string
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
	flags.StringVar(&config.DriverName, "driver-name", envOr("PASTURESTACK_SECRET_DRIVER_NAME", DefaultDriverName), "Docker volume driver name")
	flags.StringVar(&config.SocketPath, "socket-path", envOr("PASTURESTACK_SECRET_SOCKET", DefaultSocketPath), "Docker volume plugin socket")
	flags.StringVar(&config.VolumeRoot, "volume-root", envOr("PASTURESTACK_SECRET_VOLUME_ROOT", DefaultVolumeRoot), "shared tmpfs volume root")
	flags.StringVar(&config.HostKeyPath, "host-key-path", envOr("PASTURESTACK_HOST_KEY_PATH", DefaultHostKeyPath), "host RSA private key")
	flags.StringVar(&config.HealthListen, "health-listen", envOr("PASTURESTACK_SECRET_HEALTH_LISTEN", DefaultHealthListen), "health endpoint listen address")
	flags.StringVar(&config.ControlPlaneURL, "control-plane-url", firstEnv("CATTLE_URL", "PASTURESTACK_CONTROL_PLANE_URL"), "compatible control-plane API URL")
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
	if config.AccessKey == "" || config.SecretKey == "" {
		return errors.New("compatible control-plane credentials are required")
	}
	if _, err := validateControlPlaneURL(config.ControlPlaneURL); err != nil {
		return err
	}
	return nil
}

func validateControlPlaneURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid compatible control-plane URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("unsupported compatible control-plane URL scheme")
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && !isPrivateHost(host) {
		return nil, errors.New("unencrypted compatible control-plane URL must use a private address")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func isPrivateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
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
