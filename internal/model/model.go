// Package model validates and models secret-volume lifecycle intent without
// performing any network, key, filesystem, mount, or execution operation.
package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PastureStack/secrets-flexvolume-plugin/internal/strictjson"
)

const (
	APIVersion           = "pasturestack.io/secrets-flexvolume-plugin/v1alpha1"
	ManifestVersion      = uint64(1)
	MaxEntries           = 256
	MaxEntryClaimedBytes = uint64(1 * 1024 * 1024)
	MaxTotalClaimedBytes = uint64(10 * 1024 * 1024)
	MaxUIDGID            = uint64(1<<31 - 1)
	MaxLeaseCount        = uint64(1<<31 - 1)
	MaxLogicalNameBytes  = 255
	MaxLogicalSegments   = 16
	MaxLogicalSegment    = 63
)

var ErrInvalidRequest = errors.New("invalid request")

type Request struct {
	APIVersion     string
	Operation      string
	VolumeRef      string
	OwnerRef       string
	RequestRef     string
	IdempotencyRef string
	SourceRef      string
	Manifest       Manifest
	Lifecycle      Lifecycle
	Assertions     Assertions
}

type Manifest struct {
	ManifestRef        string
	Version            uint64
	Generation         uint64
	ExpectedGeneration uint64
	NotBefore          string
	RotateAt           string
	ExpiresAt          string
	Entries            []Entry
}

type Entry struct {
	Name          string
	Type          string
	ClaimedBytes  uint64
	ClaimedDigest string
	UID           uint64
	GID           uint64
	Mode          string
}

type Lifecycle struct {
	CurrentState string
	LeaseCount   uint64
}

type Assertions struct {
	Redacted  bool
	Encrypted bool
	Attested  bool
}

type Controls struct {
	Network    bool `json:"network"`
	SecretAPI  bool `json:"secretAPI"`
	KeyRead    bool `json:"keyRead"`
	Decrypt    bool `json:"decrypt"`
	FSWrite    bool `json:"fsWrite"`
	Tmpfs      bool `json:"tmpfs"`
	BindMount  bool `json:"bindMount"`
	Chown      bool `json:"chown"`
	Chmod      bool `json:"chmod"`
	StateWrite bool `json:"stateWrite"`
	Execution  bool `json:"execution"`
}

type AssertionStatus struct {
	Redaction   string `json:"redaction"`
	Encryption  string `json:"encryption"`
	Attestation string `json:"attestation"`
}

type Summary struct {
	EntryCount        int    `json:"entryCount"`
	TotalClaimedBytes uint64 `json:"totalClaimedBytes"`
}

type Transition struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Step struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type Gate struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type Plan struct {
	PlanID      string
	Operation   string
	Transition  Transition
	Summary     Summary
	Assertions  AssertionStatus
	Steps       []Step
	Gates       []Gate
	Diagnostics []string
	Controls    Controls
}

// Parse validates the complete exact-case schema and its lifecycle semantics.
func Parse(reader interface{ Read([]byte) (int, error) }) (*Request, error) {
	root, err := strictjson.Parse(reader)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	request, err := parseRequest(root)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	return request, nil
}

func parseRequest(value strictjson.Value) (*Request, error) {
	object, err := exactObject(value, []string{
		"apiVersion", "operation", "volumeRef", "ownerRef", "requestRef",
		"idempotencyRef", "sourceRef", "manifest", "lifecycle", "assertions",
	})
	if err != nil {
		return nil, err
	}

	request := &Request{}
	if request.APIVersion, err = stringValue(object["apiVersion"]); err != nil || request.APIVersion != APIVersion {
		return nil, ErrInvalidRequest
	}
	if request.Operation, err = stringValue(object["operation"]); err != nil || !oneOf(request.Operation, "stage", "activate", "rotate", "revoke", "cleanup") {
		return nil, ErrInvalidRequest
	}
	for destination, key := range map[*string]string{
		&request.VolumeRef: "volumeRef", &request.OwnerRef: "ownerRef", &request.RequestRef: "requestRef",
		&request.IdempotencyRef: "idempotencyRef", &request.SourceRef: "sourceRef",
	} {
		if *destination, err = stringValue(object[key]); err != nil || !validSHA256Ref(*destination) {
			return nil, ErrInvalidRequest
		}
	}
	if request.Manifest, err = parseManifest(object["manifest"]); err != nil {
		return nil, err
	}
	if request.Lifecycle, err = parseLifecycle(object["lifecycle"]); err != nil {
		return nil, err
	}
	if request.Assertions, err = parseAssertions(object["assertions"]); err != nil {
		return nil, err
	}
	if err := validateTransition(request); err != nil {
		return nil, err
	}
	return request, nil
}

func parseManifest(value strictjson.Value) (Manifest, error) {
	object, err := exactObject(value, []string{
		"manifestRef", "version", "generation", "expectedGeneration", "notBefore",
		"rotateAt", "expiresAt", "entries",
	})
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{}
	if manifest.ManifestRef, err = stringValue(object["manifestRef"]); err != nil || !validSHA256Ref(manifest.ManifestRef) {
		return Manifest{}, ErrInvalidRequest
	}
	if manifest.Version, err = uintValue(object["version"]); err != nil || manifest.Version != ManifestVersion {
		return Manifest{}, ErrInvalidRequest
	}
	if manifest.Generation, err = uintValue(object["generation"]); err != nil {
		return Manifest{}, err
	}
	if manifest.ExpectedGeneration, err = uintValue(object["expectedGeneration"]); err != nil {
		return Manifest{}, err
	}
	if manifest.NotBefore, err = canonicalTimeValue(object["notBefore"]); err != nil {
		return Manifest{}, err
	}
	if manifest.RotateAt, err = canonicalTimeValue(object["rotateAt"]); err != nil {
		return Manifest{}, err
	}
	if manifest.ExpiresAt, err = canonicalTimeValue(object["expiresAt"]); err != nil {
		return Manifest{}, err
	}
	notBefore, _ := time.Parse(time.RFC3339, manifest.NotBefore)
	rotateAt, _ := time.Parse(time.RFC3339, manifest.RotateAt)
	expiresAt, _ := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if !notBefore.Before(rotateAt) || !rotateAt.Before(expiresAt) {
		return Manifest{}, ErrInvalidRequest
	}

	entriesValue := object["entries"]
	if entriesValue.Kind != strictjson.KindArray || len(entriesValue.Array) == 0 || len(entriesValue.Array) > MaxEntries {
		return Manifest{}, ErrInvalidRequest
	}
	manifest.Entries = make([]Entry, 0, len(entriesValue.Array))
	seenNames := make(map[string]struct{}, len(entriesValue.Array))
	var total uint64
	for _, item := range entriesValue.Array {
		entry, parseErr := parseEntry(item)
		if parseErr != nil {
			return Manifest{}, parseErr
		}
		if _, exists := seenNames[entry.Name]; exists {
			return Manifest{}, ErrInvalidRequest
		}
		seenNames[entry.Name] = struct{}{}
		if entry.ClaimedBytes > MaxTotalClaimedBytes-total {
			return Manifest{}, ErrInvalidRequest
		}
		total += entry.ClaimedBytes
		manifest.Entries = append(manifest.Entries, entry)
	}
	return manifest, nil
}

func parseEntry(value strictjson.Value) (Entry, error) {
	object, err := exactObject(value, []string{
		"name", "type", "claimedBytes", "claimedDigest", "uid", "gid", "mode",
	})
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{}
	if entry.Name, err = stringValue(object["name"]); err != nil || !validLogicalName(entry.Name) {
		return Entry{}, ErrInvalidRequest
	}
	if entry.Type, err = stringValue(object["type"]); err != nil || entry.Type != "regular" {
		return Entry{}, ErrInvalidRequest
	}
	if entry.ClaimedBytes, err = uintValue(object["claimedBytes"]); err != nil || entry.ClaimedBytes > MaxEntryClaimedBytes {
		return Entry{}, ErrInvalidRequest
	}
	if entry.ClaimedDigest, err = stringValue(object["claimedDigest"]); err != nil || !validSHA256Ref(entry.ClaimedDigest) {
		return Entry{}, ErrInvalidRequest
	}
	if entry.UID, err = uintValue(object["uid"]); err != nil || entry.UID > MaxUIDGID {
		return Entry{}, ErrInvalidRequest
	}
	if entry.GID, err = uintValue(object["gid"]); err != nil || entry.GID > MaxUIDGID {
		return Entry{}, ErrInvalidRequest
	}
	if entry.Mode, err = stringValue(object["mode"]); err != nil || (entry.Mode != "0400" && entry.Mode != "0440") {
		return Entry{}, ErrInvalidRequest
	}
	return entry, nil
}

func parseLifecycle(value strictjson.Value) (Lifecycle, error) {
	object, err := exactObject(value, []string{"currentState", "leaseCount"})
	if err != nil {
		return Lifecycle{}, err
	}
	lifecycle := Lifecycle{}
	if lifecycle.CurrentState, err = stringValue(object["currentState"]); err != nil || !oneOf(lifecycle.CurrentState, "absent", "staged", "active", "revoked", "cleaned") {
		return Lifecycle{}, ErrInvalidRequest
	}
	if lifecycle.LeaseCount, err = uintValue(object["leaseCount"]); err != nil {
		return Lifecycle{}, err
	}
	if lifecycle.LeaseCount > MaxLeaseCount {
		return Lifecycle{}, ErrInvalidRequest
	}
	return lifecycle, nil
}

func parseAssertions(value strictjson.Value) (Assertions, error) {
	object, err := exactObject(value, []string{"redacted", "encrypted", "attested"})
	if err != nil {
		return Assertions{}, err
	}
	assertions := Assertions{}
	if assertions.Redacted, err = boolValue(object["redacted"]); err != nil || !assertions.Redacted {
		return Assertions{}, ErrInvalidRequest
	}
	if assertions.Encrypted, err = boolValue(object["encrypted"]); err != nil || !assertions.Encrypted {
		return Assertions{}, ErrInvalidRequest
	}
	if assertions.Attested, err = boolValue(object["attested"]); err != nil || !assertions.Attested {
		return Assertions{}, ErrInvalidRequest
	}
	return assertions, nil
}

func validateTransition(request *Request) error {
	generation := request.Manifest.Generation
	expected := request.Manifest.ExpectedGeneration
	leases := request.Lifecycle.LeaseCount
	switch request.Operation {
	case "stage":
		if request.Lifecycle.CurrentState != "absent" || expected != 0 || generation != 1 || leases != 0 {
			return ErrInvalidRequest
		}
	case "activate":
		if request.Lifecycle.CurrentState != "staged" || expected == 0 || generation != expected || leases != 0 {
			return ErrInvalidRequest
		}
	case "rotate":
		if request.Lifecycle.CurrentState != "active" || expected == 0 || expected == ^uint64(0) || generation != expected+1 {
			return ErrInvalidRequest
		}
	case "revoke":
		if request.Lifecycle.CurrentState != "active" || expected == 0 || generation != expected {
			return ErrInvalidRequest
		}
	case "cleanup":
		if request.Lifecycle.CurrentState != "revoked" || expected == 0 || generation != expected || leases != 0 {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

// BuildPlan produces a deterministic, non-executable semantic plan.
func BuildPlan(request *Request) Plan {
	steps := []Step{
		{ID: "bind-idempotency", Status: "modeled"},
		{ID: "bind-manifest", Status: "modeled"},
		{ID: "check-lifecycle-transition", Status: "modeled"},
		{ID: "model-" + request.Operation, Status: "modeled"},
	}
	sort.Slice(steps, func(left, right int) bool { return steps[left].ID < steps[right].ID })
	gates := []Gate{
		{ID: "atomic-activation", Status: "blocked"},
		{ID: "idempotency-state-lookup", Status: "blocked"},
		{ID: "rollback", Status: "blocked"},
		{ID: "secure-cleanup", Status: "blocked"},
		{ID: "trusted-clock", Status: "blocked"},
		{ID: "unmount-and-revoke", Status: "blocked"},
		{ID: "verified-attestation", Status: "blocked"},
		{ID: "verified-encryption", Status: "blocked"},
		{ID: "verified-redaction", Status: "blocked"},
	}
	sort.Slice(gates, func(left, right int) bool { return gates[left].ID < gates[right].ID })
	diagnostics := []string{"effects-disabled", "source-assertions-unverified", "state-unverified"}
	sort.Strings(diagnostics)
	return Plan{
		PlanID:      semanticPlanID(request),
		Operation:   request.Operation,
		Transition:  Transition{From: request.Lifecycle.CurrentState, To: targetState(request.Operation)},
		Summary:     RequestSummary(request),
		Assertions:  UnverifiedAssertions(),
		Steps:       steps,
		Gates:       gates,
		Diagnostics: diagnostics,
		Controls:    DisabledControls(),
	}
}

func RequestSummary(request *Request) Summary {
	var total uint64
	for _, entry := range request.Manifest.Entries {
		total += entry.ClaimedBytes
	}
	return Summary{EntryCount: len(request.Manifest.Entries), TotalClaimedBytes: total}
}

func DisabledControls() Controls { return Controls{} }

func UnverifiedAssertions() AssertionStatus {
	return AssertionStatus{
		Redaction:   "asserted-unverified",
		Encryption:  "asserted-unverified",
		Attestation: "asserted-unverified",
	}
}

func semanticPlanID(request *Request) string {
	hasher := sha256.New()
	writeString(hasher, request.APIVersion)
	writeString(hasher, request.Operation)
	writeString(hasher, request.VolumeRef)
	writeString(hasher, request.OwnerRef)
	writeString(hasher, request.RequestRef)
	writeString(hasher, request.IdempotencyRef)
	writeString(hasher, request.SourceRef)
	writeString(hasher, request.Manifest.ManifestRef)
	writeUint(hasher, request.Manifest.Version)
	writeUint(hasher, request.Manifest.Generation)
	writeUint(hasher, request.Manifest.ExpectedGeneration)
	writeString(hasher, request.Manifest.NotBefore)
	writeString(hasher, request.Manifest.RotateAt)
	writeString(hasher, request.Manifest.ExpiresAt)
	writeString(hasher, request.Lifecycle.CurrentState)
	writeUint(hasher, request.Lifecycle.LeaseCount)

	entries := append([]Entry(nil), request.Manifest.Entries...)
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name < entries[right].Name })
	writeUint(hasher, uint64(len(entries)))
	for _, entry := range entries {
		writeString(hasher, entry.Name)
		writeString(hasher, entry.Type)
		writeUint(hasher, entry.ClaimedBytes)
		writeString(hasher, entry.ClaimedDigest)
		writeUint(hasher, entry.UID)
		writeUint(hasher, entry.GID)
		writeString(hasher, entry.Mode)
	}
	writeUint(hasher, boolUint(request.Assertions.Redacted))
	writeUint(hasher, boolUint(request.Assertions.Encrypted))
	writeUint(hasher, boolUint(request.Assertions.Attested))
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

func writeString(destination hash.Hash, value string) {
	writeUint(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeUint(destination hash.Hash, value uint64) {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	_, _ = destination.Write(buffer[:])
}

func boolUint(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func targetState(operation string) string {
	switch operation {
	case "stage":
		return "staged"
	case "activate", "rotate":
		return "active"
	case "revoke":
		return "revoked"
	case "cleanup":
		return "cleaned"
	default:
		return ""
	}
}

func exactObject(value strictjson.Value, fields []string) (map[string]strictjson.Value, error) {
	if value.Kind != strictjson.KindObject || len(value.Object) != len(fields) {
		return nil, ErrInvalidRequest
	}
	for _, field := range fields {
		if _, exists := value.Object[field]; !exists {
			return nil, ErrInvalidRequest
		}
	}
	return value.Object, nil
}

func stringValue(value strictjson.Value) (string, error) {
	if value.Kind != strictjson.KindString {
		return "", ErrInvalidRequest
	}
	return value.String, nil
}

func uintValue(value strictjson.Value) (uint64, error) {
	if value.Kind != strictjson.KindNumber {
		return 0, ErrInvalidRequest
	}
	parsed, err := strconv.ParseUint(value.Number, 10, 64)
	if err != nil {
		return 0, ErrInvalidRequest
	}
	return parsed, nil
}

func boolValue(value strictjson.Value) (bool, error) {
	if value.Kind != strictjson.KindBool {
		return false, ErrInvalidRequest
	}
	return value.Bool, nil
}

func canonicalTimeValue(value strictjson.Value) (string, error) {
	text, err := stringValue(value)
	if err != nil || !strings.HasSuffix(text, "Z") {
		return "", ErrInvalidRequest
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != text {
		return "", ErrInvalidRequest
	}
	return text, nil
}

func validSHA256Ref(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for index := len("sha256:"); index < len(value); index++ {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validLogicalName(name string) bool {
	if len(name) == 0 || len(name) > MaxLogicalNameBytes || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	if len(name) >= 2 && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) && name[1] == ':' {
		return false
	}
	segments := strings.Split(name, "/")
	if len(segments) == 0 || len(segments) > MaxLogicalSegments {
		return false
	}
	for _, segment := range segments {
		if !validLogicalSegment(segment) {
			return false
		}
	}
	return true
}

func validLogicalSegment(segment string) bool {
	if len(segment) == 0 || len(segment) > MaxLogicalSegment || segment == "." || segment == ".." || strings.HasSuffix(segment, ".") {
		return false
	}
	for index := 0; index < len(segment); index++ {
		character := segment[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	upper := strings.ToUpper(segment)
	deviceName := upper
	if dot := strings.IndexByte(deviceName, '.'); dot >= 0 {
		deviceName = deviceName[:dot]
	}
	if oneOf(deviceName, "CON", "PRN", "AUX", "NUL") {
		return false
	}
	if len(deviceName) == 4 && (strings.HasPrefix(deviceName, "COM") || strings.HasPrefix(deviceName, "LPT")) && deviceName[3] >= '1' && deviceName[3] <= '9' {
		return false
	}
	return true
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
