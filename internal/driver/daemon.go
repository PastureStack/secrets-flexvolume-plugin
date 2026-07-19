package driver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const currentTokenOption = "io.pasturestack.secrets.token"

func compatibilityTokenOption() string {
	return strings.Join([]string{"io.", "ranch", "er.secrets.token"}, "")
}

type volumeState struct {
	mu          sync.Mutex
	name        string
	path        string
	token       []byte
	mountIDs    map[string]struct{}
	mounted     bool
	lastSuccess time.Time
}

type Driver struct {
	config    Config
	fetcher   SecretFetcher
	decryptor *Decryptor
	mounter   MountManager
	logger    *log.Logger

	mu      sync.RWMutex
	volumes map[string]*volumeState
	ready   bool
}

func NewDriver(config Config, fetcher SecretFetcher, decryptor *Decryptor, mounter MountManager, logger *log.Logger) (*Driver, error) {
	if fetcher == nil || decryptor == nil || mounter == nil {
		return nil, errors.New("driver dependencies are incomplete")
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if err := os.MkdirAll(config.VolumeRoot, 0o700); err != nil {
		return nil, errors.New("unable to prepare the private volume root")
	}
	if err := os.Chmod(config.VolumeRoot, 0o700); err != nil {
		return nil, errors.New("unable to protect the private volume root")
	}
	driver := &Driver{
		config:    config,
		fetcher:   fetcher,
		decryptor: decryptor,
		mounter:   mounter,
		logger:    logger,
		volumes:   make(map[string]*volumeState),
		ready:     true,
	}
	if err := driver.recoverExisting(); err != nil {
		return nil, err
	}
	return driver, nil
}

func (driver *Driver) recoverExisting() error {
	entries, err := os.ReadDir(driver.config.VolumeRoot)
	if err != nil {
		return errors.New("unable to inspect the private volume root")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validVolumeName(entry.Name()) {
			continue
		}
		path := filepath.Join(driver.config.VolumeRoot, entry.Name())
		mounted, err := driver.mounter.IsMounted(path)
		if err != nil {
			return errors.New("unable to inspect an existing private volume")
		}
		if mounted {
			driver.volumes[entry.Name()] = &volumeState{
				name:     entry.Name(),
				path:     path,
				mounted:  true,
				mountIDs: make(map[string]struct{}),
			}
		}
	}
	return nil
}

type createRequest struct {
	Name string         `json:"Name"`
	Opts map[string]any `json:"Opts"`
}

type nameRequest struct {
	Name string `json:"Name"`
}

type mountRequest struct {
	Name string `json:"Name"`
	ID   string `json:"ID"`
}

type basicResponse struct {
	Err string `json:"Err,omitempty"`
}

type mountResponse struct {
	Mountpoint string `json:"Mountpoint,omitempty"`
	Err        string `json:"Err,omitempty"`
}

type pathResponse struct {
	Mountpoint string `json:"Mountpoint,omitempty"`
	Err        string `json:"Err,omitempty"`
}

type volumeInfo struct {
	Name       string `json:"Name"`
	Mountpoint string `json:"Mountpoint"`
}

type getResponse struct {
	Volume *volumeInfo `json:"Volume,omitempty"`
	Err    string      `json:"Err,omitempty"`
}

type listResponse struct {
	Volumes []volumeInfo `json:"Volumes"`
	Err     string       `json:"Err,omitempty"`
}

type activateResponse struct {
	Implements []string `json:"Implements"`
}

type capabilitiesResponse struct {
	Capabilities struct {
		Scope string `json:"Scope"`
	} `json:"Capabilities"`
}

func (driver *Driver) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	if request.Method != http.MethodPost {
		response.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(response).Encode(basicResponse{Err: "method not allowed"})
		return
	}
	switch request.URL.Path {
	case "/Plugin.Activate":
		_ = json.NewEncoder(response).Encode(activateResponse{Implements: []string{"VolumeDriver"}})
	case "/VolumeDriver.Create":
		var input createRequest
		if !decodePluginRequest(response, request, &input) {
			return
		}
		_ = json.NewEncoder(response).Encode(basicResponse{Err: safeError(driver.create(input))})
	case "/VolumeDriver.Remove":
		var input nameRequest
		if !decodePluginRequest(response, request, &input) {
			return
		}
		_ = json.NewEncoder(response).Encode(basicResponse{Err: safeError(driver.remove(input.Name))})
	case "/VolumeDriver.Mount":
		var input mountRequest
		if !decodePluginRequest(response, request, &input) {
			return
		}
		mountpoint, err := driver.mount(request.Context(), input.Name, input.ID)
		_ = json.NewEncoder(response).Encode(mountResponse{Mountpoint: mountpoint, Err: safeError(err)})
	case "/VolumeDriver.Unmount":
		var input mountRequest
		if !decodePluginRequest(response, request, &input) {
			return
		}
		_ = json.NewEncoder(response).Encode(basicResponse{Err: safeError(driver.unmount(input.Name, input.ID))})
	case "/VolumeDriver.Path":
		var input nameRequest
		if !decodePluginRequest(response, request, &input) {
			return
		}
		path, err := driver.path(input.Name)
		_ = json.NewEncoder(response).Encode(pathResponse{Mountpoint: path, Err: safeError(err)})
	case "/VolumeDriver.Get":
		var input nameRequest
		if !decodePluginRequest(response, request, &input) {
			return
		}
		volume, err := driver.get(input.Name)
		_ = json.NewEncoder(response).Encode(getResponse{Volume: volume, Err: safeError(err)})
	case "/VolumeDriver.List":
		var input struct{}
		if !decodePluginRequest(response, request, &input) {
			return
		}
		_ = json.NewEncoder(response).Encode(listResponse{Volumes: driver.list()})
	case "/VolumeDriver.Capabilities":
		var input struct{}
		if !decodePluginRequest(response, request, &input) {
			return
		}
		output := capabilitiesResponse{}
		output.Capabilities.Scope = "local"
		_ = json.NewEncoder(response).Encode(output)
	default:
		response.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(response).Encode(basicResponse{Err: "endpoint not found"})
	}
}

func decodePluginRequest(response http.ResponseWriter, request *http.Request, destination any) bool {
	reader := http.MaxBytesReader(response, request.Body, 1<<20)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		response.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(response).Encode(basicResponse{Err: "invalid plugin request"})
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		response.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(response).Encode(basicResponse{Err: "invalid plugin request"})
		return false
	}
	return true
}

func (driver *Driver) create(request createRequest) error {
	if !validVolumeName(request.Name) {
		return errors.New("invalid volume name")
	}
	token, err := tokenFromOptions(request.Opts)
	if err != nil {
		return err
	}
	defer zeroBytes(token)
	driver.mu.Lock()
	state := driver.volumes[request.Name]
	if state == nil {
		state = &volumeState{
			name:     request.Name,
			path:     filepath.Join(driver.config.VolumeRoot, request.Name),
			mountIDs: make(map[string]struct{}),
		}
		driver.volumes[request.Name] = state
	}
	driver.mu.Unlock()

	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.mountIDs) > 0 && len(state.token) > 0 &&
		(len(state.token) != len(token) || subtle.ConstantTimeCompare(state.token, token) != 1) {
		return errors.New("active volume token cannot be replaced")
	}
	zeroBytes(state.token)
	state.token = append(state.token[:0], token...)
	return nil
}

func (driver *Driver) mount(ctx context.Context, name, mountID string) (string, error) {
	if !validVolumeName(name) || !validMountID(mountID) {
		return "", errors.New("invalid mount request")
	}
	state := driver.lookup(name)
	if state == nil {
		return "", errors.New("volume does not exist")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.mounted {
		mounted, err := driver.mounter.IsMounted(state.path)
		if err != nil {
			return "", errors.New("unable to inspect the private volume")
		}
		if mounted {
			state.mountIDs[mountID] = struct{}{}
			return state.path, nil
		}
		state.mounted = false
	}
	if len(state.token) == 0 {
		return "", errors.New("volume token is unavailable")
	}
	if err := os.MkdirAll(state.path, 0o700); err != nil {
		return "", errors.New("unable to create the private volume")
	}
	if err := os.Chmod(state.path, 0o700); err != nil {
		return "", errors.New("unable to protect the private volume")
	}
	if err := driver.mounter.MountTmpfs(state.path, driver.config.MaxTotalBytes+(1<<20)); err != nil {
		_ = os.RemoveAll(state.path)
		return "", errors.New("unable to mount the private memory volume")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = driver.mounter.Unmount(state.path)
			_ = os.RemoveAll(state.path)
		}
	}()
	fetchContext, cancel := context.WithTimeout(ctx, driver.config.RequestTimeout)
	defer cancel()
	records, err := driver.fetcher.Fetch(fetchContext, state.token)
	if err != nil {
		return "", err
	}
	files, err := driver.decryptor.DecryptRecords(records)
	if err != nil {
		return "", err
	}
	defer clearMaterialized(files)
	if err := writeMaterializedFiles(state.path, files); err != nil {
		return "", err
	}
	state.mounted = true
	state.mountIDs[mountID] = struct{}{}
	state.lastSuccess = time.Now().UTC()
	cleanup = false
	return state.path, nil
}

func (driver *Driver) unmount(name, mountID string) error {
	if !validVolumeName(name) || !validMountID(mountID) {
		return errors.New("invalid unmount request")
	}
	state := driver.lookup(name)
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	delete(state.mountIDs, mountID)
	if len(state.mountIDs) != 0 || !state.mounted {
		return nil
	}
	mounted, err := driver.mounter.IsMounted(state.path)
	if err != nil {
		return errors.New("unable to inspect the private volume")
	}
	if mounted {
		if err := driver.mounter.Unmount(state.path); err != nil {
			return errors.New("unable to unmount the private memory volume")
		}
	}
	state.mounted = false
	state.lastSuccess = time.Time{}
	if err := os.RemoveAll(state.path); err != nil {
		return errors.New("unable to remove the private volume")
	}
	return nil
}

func (driver *Driver) remove(name string) error {
	if !validVolumeName(name) {
		return errors.New("invalid volume name")
	}
	state := driver.lookup(name)
	if state == nil {
		return nil
	}
	state.mu.Lock()
	if len(state.mountIDs) != 0 {
		state.mu.Unlock()
		return errors.New("volume is still in use")
	}
	if state.mounted {
		mounted, err := driver.mounter.IsMounted(state.path)
		if err != nil {
			state.mu.Unlock()
			return errors.New("unable to inspect the private volume")
		}
		if mounted {
			if err := driver.mounter.Unmount(state.path); err != nil {
				state.mu.Unlock()
				return errors.New("unable to unmount the private memory volume")
			}
		}
	}
	zeroBytes(state.token)
	state.token = nil
	state.mounted = false
	state.mu.Unlock()
	if err := os.RemoveAll(state.path); err != nil {
		return errors.New("unable to remove the private volume")
	}
	driver.mu.Lock()
	delete(driver.volumes, name)
	driver.mu.Unlock()
	return nil
}

func (driver *Driver) path(name string) (string, error) {
	if !validVolumeName(name) {
		return "", errors.New("invalid volume name")
	}
	state := driver.lookup(name)
	if state == nil {
		return "", errors.New("volume does not exist")
	}
	return state.path, nil
}

func (driver *Driver) get(name string) (*volumeInfo, error) {
	path, err := driver.path(name)
	if err != nil {
		return nil, err
	}
	return &volumeInfo{Name: name, Mountpoint: path}, nil
}

func (driver *Driver) list() []volumeInfo {
	driver.mu.RLock()
	names := make([]string, 0, len(driver.volumes))
	for name := range driver.volumes {
		names = append(names, name)
	}
	driver.mu.RUnlock()
	sort.Strings(names)
	result := make([]volumeInfo, 0, len(names))
	for _, name := range names {
		result = append(result, volumeInfo{Name: name, Mountpoint: filepath.Join(driver.config.VolumeRoot, name)})
	}
	return result
}

func (driver *Driver) lookup(name string) *volumeState {
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	return driver.volumes[name]
}

func (driver *Driver) healthHandler(version string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"status": "healthy", "version": version})
	})
	mux.HandleFunc("/readyz", func(response http.ResponseWriter, _ *http.Request) {
		driver.mu.RLock()
		ready := driver.ready
		volumeCount := len(driver.volumes)
		driver.mu.RUnlock()
		status := http.StatusOK
		state := "ready"
		if !ready {
			status = http.StatusServiceUnavailable
			state = "not-ready"
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(status)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"status": state, "version": version, "volume_count": volumeCount,
		})
	})
	return mux
}

func (driver *Driver) close() {
	driver.mu.Lock()
	driver.ready = false
	states := make([]*volumeState, 0, len(driver.volumes))
	for _, state := range driver.volumes {
		states = append(states, state)
	}
	driver.mu.Unlock()
	for _, state := range states {
		state.mu.Lock()
		zeroBytes(state.token)
		state.token = nil
		state.mu.Unlock()
	}
}

func RunServe(args []string, stdout, stderr io.Writer, version string) int {
	config, err := ParseConfig(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "invalid runtime configuration")
		return 2
	}
	logger := log.New(stderr, "secrets-flexvolume-plugin: ", log.LstdFlags|log.LUTC)
	decryptor, err := LoadDecryptor(config.HostKeyPath, config.MaxSecretBytes, config.MaxTotalBytes, config.MaxSecrets)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fetcher, err := NewAPIFetcher(config)
	if err != nil {
		fmt.Fprintln(stderr, "invalid compatible control-plane configuration")
		return 1
	}
	driver, err := NewDriver(config, fetcher, decryptor, newMountManager(), logger)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer driver.close()

	if err := prepareSocket(config.SocketPath); err != nil {
		fmt.Fprintln(stderr, "unable to prepare the Docker volume plugin socket")
		return 1
	}
	listener, err := net.Listen("unix", config.SocketPath)
	if err != nil {
		fmt.Fprintln(stderr, "unable to listen on the Docker volume plugin socket")
		return 1
	}
	defer listener.Close()
	defer os.Remove(config.SocketPath)
	if err := os.Chmod(config.SocketPath, 0o660); err != nil {
		fmt.Fprintln(stderr, "unable to protect the Docker volume plugin socket")
		return 1
	}
	healthListener, err := net.Listen("tcp", config.HealthListen)
	if err != nil {
		fmt.Fprintln(stderr, "unable to start the health endpoint")
		return 1
	}
	defer healthListener.Close()

	pluginServer := &http.Server{
		Handler:           driver,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	healthServer := &http.Server{
		Handler:           driver.healthHandler(version),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- pluginServer.Serve(listener) }()
	go func() { errorsChannel <- healthServer.Serve(healthListener) }()

	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case serveError := <-errorsChannel:
		if serveError != nil && serveError != http.ErrServerClosed {
			fmt.Fprintln(stderr, "runtime endpoint stopped unexpectedly")
			return 1
		}
	case <-runContext.Done():
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = pluginServer.Shutdown(shutdownContext)
	_ = healthServer.Shutdown(shutdownContext)
	fmt.Fprintln(stdout, "secret volume driver stopped; active memory mounts were preserved")
	return 0
}

func prepareSocket(socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("existing plugin path is not a socket")
	}
	return os.Remove(socketPath)
}

func tokenFromOptions(options map[string]any) ([]byte, error) {
	if len(options) == 0 || len(options) > 64 {
		return nil, errors.New("secret volume options are invalid")
	}
	var raw string
	for _, key := range []string{currentTokenOption, compatibilityTokenOption()} {
		if value, exists := options[key]; exists {
			text, ok := value.(string)
			if !ok || raw != "" {
				return nil, errors.New("secret request token option is invalid")
			}
			raw = text
		}
	}
	if raw == "" {
		return nil, errors.New("secret request token option is required")
	}
	if len(raw) > 128<<10 {
		return nil, errors.New("secret request token option exceeds its limit")
	}
	candidate := strings.TrimSpace(raw)
	for attempt := 0; attempt < 3; attempt++ {
		var envelope struct {
			Value []byte `json:"value"`
		}
		if err := decodeStrictJSON([]byte(candidate), &envelope); err == nil && len(envelope.Value) > 0 && len(envelope.Value) <= 64<<10 {
			return envelope.Value, nil
		}
		var unquoted string
		if err := json.Unmarshal([]byte(candidate), &unquoted); err == nil && unquoted != candidate {
			candidate = strings.TrimSpace(unquoted)
			continue
		}
		if strings.Contains(candidate, `\"`) {
			candidate = strings.ReplaceAll(candidate, `\"`, `"`)
			continue
		}
		break
	}
	return nil, errors.New("secret request token option is invalid")
}

func writeMaterializedFiles(root string, files []materializedFile) error {
	for _, file := range files {
		fullPath := filepath.Join(root, filepath.FromSlash(file.Name))
		relative, err := filepath.Rel(root, fullPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("materialized secret path escaped its volume")
		}
		if err := ensurePrivateParents(root, filepath.Dir(fullPath)); err != nil {
			return err
		}
		var randomSuffix [12]byte
		if _, err := rand.Read(randomSuffix[:]); err != nil {
			return errors.New("unable to create an atomic secret file")
		}
		temporary := fullPath + ".tmp-" + hex.EncodeToString(randomSuffix[:])
		handle, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.Mode)
		if err != nil {
			return errors.New("unable to create a secret file")
		}
		writeError := writeAndSync(handle, file.Content)
		closeError := handle.Close()
		if writeError != nil || closeError != nil {
			_ = os.Remove(temporary)
			return errors.New("unable to write a secret file")
		}
		if err := setOwnership(temporary, file.UID, file.GID); err != nil {
			_ = os.Remove(temporary)
			return errors.New("unable to set secret file ownership")
		}
		if err := os.Chmod(temporary, file.Mode); err != nil {
			_ = os.Remove(temporary)
			return errors.New("unable to set secret file mode")
		}
		if err := os.Rename(temporary, fullPath); err != nil {
			_ = os.Remove(temporary)
			return errors.New("unable to activate a secret file")
		}
	}
	return nil
}

func ensurePrivateParents(root, destination string) error {
	relative, err := filepath.Rel(root, destination)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("secret directory escaped its volume")
	}
	current := root
	if relative == "." {
		return nil
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return errors.New("unable to create a private secret directory")
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private secret directory is unsafe")
		}
		if err := os.Chmod(current, 0o755); err != nil {
			return errors.New("unable to protect a private secret directory")
		}
	}
	return nil
}

func writeAndSync(destination *os.File, content []byte) error {
	if _, err := io.Copy(destination, bytes.NewReader(content)); err != nil {
		return err
	}
	return destination.Sync()
}

func validVolumeName(value string) bool {
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
	return value != "." && value != ".."
}

func validMountID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
