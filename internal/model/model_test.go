package model

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var testDigest = "sha256:" + strings.Repeat("a", 64)

func testEntry(name string, size uint64) string {
	return fmt.Sprintf(`{"name":%q,"type":"regular","claimedBytes":%d,"claimedDigest":%q,"uid":1000,"gid":1000,"mode":"0400"}`,
		name, size, testDigest)
}

func testDocument(operation, state string, expected, generation, leases uint64, entries string) string {
	return fmt.Sprintf(`{
"apiVersion":%q,
"operation":%q,
"volumeRef":%q,
"ownerRef":%q,
"requestRef":%q,
"idempotencyRef":%q,
"sourceRef":%q,
"manifest":{"manifestRef":%q,"version":1,"generation":%d,"expectedGeneration":%d,"notBefore":"2026-01-01T00:00:00Z","rotateAt":"2026-01-02T00:00:00Z","expiresAt":"2026-01-03T00:00:00Z","entries":[%s]},
"lifecycle":{"currentState":%q,"leaseCount":%d},
"assertions":{"redacted":true,"encrypted":true,"attested":true}
}`, APIVersion, operation, testDigest, testDigest, testDigest, testDigest, testDigest,
		testDigest, generation, expected, entries, state, leases)
}

func parseTestDocument(t *testing.T, document string) *Request {
	t.Helper()
	request, err := Parse(strings.NewReader(document))
	if err != nil {
		t.Fatalf("expected valid document: %v", err)
	}
	return request
}

func TestLifecycleTransitions(t *testing.T) {
	tests := []struct {
		operation  string
		state      string
		expected   uint64
		generation uint64
		leases     uint64
		target     string
	}{
		{operation: "stage", state: "absent", expected: 0, generation: 1, target: "staged"},
		{operation: "activate", state: "staged", expected: 4, generation: 4, target: "active"},
		{operation: "rotate", state: "active", expected: 4, generation: 5, leases: 2, target: "active"},
		{operation: "revoke", state: "active", expected: 4, generation: 4, leases: 2, target: "revoked"},
		{operation: "cleanup", state: "revoked", expected: 4, generation: 4, target: "cleaned"},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			request := parseTestDocument(t, testDocument(test.operation, test.state, test.expected, test.generation, test.leases, testEntry("application/key", 32)))
			plan := BuildPlan(request)
			if plan.Transition.From != test.state || plan.Transition.To != test.target {
				t.Fatalf("unexpected transition: %+v", plan.Transition)
			}
		})
	}
}

func TestLifecycleRejectsInvalidTransitionsAndOverflow(t *testing.T) {
	tests := []string{
		testDocument("stage", "active", 0, 1, 0, testEntry("a", 1)),
		testDocument("activate", "staged", 2, 2, 1, testEntry("a", 1)),
		testDocument("rotate", "active", 2, 2, 0, testEntry("a", 1)),
		testDocument("rotate", "active", ^uint64(0), ^uint64(0), 0, testEntry("a", 1)),
		testDocument("revoke", "staged", 2, 2, 0, testEntry("a", 1)),
		testDocument("cleanup", "revoked", 2, 2, 1, testEntry("a", 1)),
	}
	for index, document := range tests {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("case %d: expected rejection", index)
		}
	}
}

func TestLogicalEntryNamesEnforceUnixAndWindowsSafety(t *testing.T) {
	invalid := []string{
		"../escape", "/absolute", "nested//name", `nested\name`, "C:/host", "//server/share",
		".", "..", "segment.", "NUL", "con", "CON.txt", "AUX.key", "COM1/value", "LPT9.txt", "control\nname",
	}
	for _, name := range invalid {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			document := testDocument("stage", "absent", 0, 1, 0, testEntry(name, 1))
			if _, err := Parse(strings.NewReader(document)); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestRefsMustBeLowercaseSHA256Only(t *testing.T) {
	base := testDocument("stage", "absent", 0, 1, 0, testEntry("safe", 1))
	for _, replacement := range []string{
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha512:" + strings.Repeat("a", 64),
		"https://source.invalid/value",
		strings.Repeat("YQ==", 16),
	} {
		document := strings.Replace(base, testDigest, replacement, 1)
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("expected reference %q to be rejected", replacement)
		}
	}
}

func TestSchemaHasNoSymlinkOrPayloadSurface(t *testing.T) {
	base := testDocument("stage", "absent", 0, 1, 0, testEntry("safe/name", 1))
	tests := []string{
		strings.Replace(base, `"type":"regular"`, `"type":"symlink"`, 1),
		strings.Replace(base, `"type":"regular"`, `"type":"regular","linkTarget":"outside"`, 1),
		strings.Replace(base, `"sourceRef":`, `"plaintext":"do-not-accept","sourceRef":`, 1),
		strings.Replace(base, `"sourceRef":`, `"token":"do-not-accept","sourceRef":`, 1),
		strings.Replace(base, `"sourceRef":`, `"hostPath":"C:/host","sourceRef":`, 1),
		strings.Replace(base, `"sourceRef":`, `"command":"run","sourceRef":`, 1),
	}
	for index, document := range tests {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("case %d: expected rejection", index)
		}
	}
}

func TestModesRejectWorldExecuteAndAmbiguousForms(t *testing.T) {
	base := testDocument("stage", "absent", 0, 1, 0, testEntry("safe", 1))
	for _, mode := range []string{"0444", "0777", "0401", "440", "400", "10400"} {
		document := strings.Replace(base, `"mode":"0400"`, fmt.Sprintf(`"mode":%q`, mode), 1)
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("expected mode %q to be rejected", mode)
		}
	}
	valid := strings.Replace(base, `"mode":"0400"`, `"mode":"0440"`, 1)
	parseTestDocument(t, valid)
}

func TestSizeBoundsAndOverflowSafety(t *testing.T) {
	tooLarge := testDocument("stage", "absent", 0, 1, 0, testEntry("safe", MaxEntryClaimedBytes+1))
	if _, err := Parse(strings.NewReader(tooLarge)); err == nil {
		t.Fatal("expected oversized entry rejection")
	}
	entries := make([]string, 11)
	for index := range entries {
		entries[index] = testEntry(fmt.Sprintf("entry-%02d", index), MaxEntryClaimedBytes)
	}
	totalTooLarge := testDocument("stage", "absent", 0, 1, 0, strings.Join(entries, ","))
	if _, err := Parse(strings.NewReader(totalTooLarge)); err == nil {
		t.Fatal("expected oversized total rejection")
	}
	uintOverflow := strings.Replace(
		testDocument("stage", "absent", 0, 1, 0, testEntry("safe", 1)),
		`"claimedBytes":1`, `"claimedBytes":18446744073709551616`, 1,
	)
	if _, err := Parse(strings.NewReader(uintOverflow)); err == nil {
		t.Fatal("expected uint overflow rejection")
	}
}

func TestEntryAndLeaseCountsAreBounded(t *testing.T) {
	entries := make([]string, MaxEntries+1)
	for index := range entries {
		entries[index] = testEntry(fmt.Sprintf("entry-%03d", index), 0)
	}
	tooMany := testDocument("stage", "absent", 0, 1, 0, strings.Join(entries, ","))
	if _, err := Parse(strings.NewReader(tooMany)); err == nil {
		t.Fatal("expected excessive entry count rejection")
	}
	tooManyLeases := testDocument("revoke", "active", 1, 1, MaxLeaseCount+1, testEntry("safe", 1))
	if _, err := Parse(strings.NewReader(tooManyLeases)); err == nil {
		t.Fatal("expected excessive lease count rejection")
	}
}

func TestTimeMustBeCanonicalUTCAndOrdered(t *testing.T) {
	base := testDocument("stage", "absent", 0, 1, 0, testEntry("safe", 1))
	tests := []string{
		strings.Replace(base, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00", 1),
		strings.Replace(base, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000Z", 1),
		strings.Replace(base, "2026-01-02T00:00:00Z", "2025-12-31T00:00:00Z", 1),
		strings.Replace(base, "2026-01-03T00:00:00Z", "2026-01-02T00:00:00Z", 1),
	}
	for index, document := range tests {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("case %d: expected time rejection", index)
		}
	}
}

func TestExactCaseUnknownDuplicateAndNullAreRejected(t *testing.T) {
	base := testDocument("stage", "absent", 0, 1, 0, testEntry("safe", 1))
	tests := []string{
		strings.Replace(base, `"apiVersion"`, `"ApiVersion"`, 1),
		strings.Replace(base, `"operation":"stage"`, `"operation":"stage","operation":"stage"`, 1),
		strings.Replace(base, `"operation":"stage"`, `"operation":null`, 1),
		strings.Replace(base, `"operation":"stage"`, `"unknown":true,"operation":"stage"`, 1),
		base + "\n" + base,
		strings.Replace(base, `"generation":1`, `"generation":1e0`, 1),
	}
	for index, document := range tests {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("case %d: expected strict schema rejection", index)
		}
	}
}

func TestEntryNamesAreUnique(t *testing.T) {
	entries := testEntry("same", 1) + "," + testEntry("same", 2)
	if _, err := Parse(strings.NewReader(testDocument("stage", "absent", 0, 1, 0, entries))); err == nil {
		t.Fatal("expected duplicate entry rejection")
	}
}

func TestSemanticPlanIDIsDeterministicAndOrderIndependent(t *testing.T) {
	first := parseTestDocument(t, testDocument("stage", "absent", 0, 1, 0, testEntry("a", 1)+","+testEntry("b", 2)))
	second := parseTestDocument(t, testDocument("stage", "absent", 0, 1, 0, testEntry("b", 2)+","+testEntry("a", 1)))
	firstPlan := BuildPlan(first)
	secondPlan := BuildPlan(second)
	if firstPlan.PlanID != secondPlan.PlanID {
		t.Fatal("entry order changed semantic plan ID")
	}
	if !sort.SliceIsSorted(firstPlan.Steps, func(left, right int) bool { return firstPlan.Steps[left].ID < firstPlan.Steps[right].ID }) {
		t.Fatal("steps are not sorted")
	}
	if !sort.SliceIsSorted(firstPlan.Gates, func(left, right int) bool { return firstPlan.Gates[left].ID < firstPlan.Gates[right].ID }) {
		t.Fatal("gates are not sorted")
	}
	if !sort.StringsAreSorted(firstPlan.Diagnostics) {
		t.Fatal("diagnostics are not sorted")
	}
}

func TestAllControlsRemainFalseAndAssertionsUnverified(t *testing.T) {
	controls := DisabledControls()
	value := reflect.ValueOf(controls)
	for index := 0; index < value.NumField(); index++ {
		if value.Field(index).Bool() {
			t.Fatalf("control %s is enabled", value.Type().Field(index).Name)
		}
	}
	assertions := UnverifiedAssertions()
	if assertions.Redaction != "asserted-unverified" || assertions.Encryption != "asserted-unverified" || assertions.Attestation != "asserted-unverified" {
		t.Fatal("assertions were represented as verified")
	}
}

func TestAssertionsMustBePresentButRemainUnverified(t *testing.T) {
	base := testDocument("stage", "absent", 0, 1, 0, testEntry("safe", 1))
	for _, field := range []string{"redacted", "encrypted", "attested"} {
		document := strings.Replace(base, fmt.Sprintf(`%q:true`, field), fmt.Sprintf(`%q:false`, field), 1)
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("expected false %s assertion rejection", field)
		}
	}
}
