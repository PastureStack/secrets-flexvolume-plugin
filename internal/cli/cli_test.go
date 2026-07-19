package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/PastureStack/secrets-flexvolume-plugin/internal/model"
)

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("stdin was read") }

func cliDocument(entryName string) string {
	digest := "sha256:" + strings.Repeat("b", 64)
	return fmt.Sprintf(`{
"apiVersion":%q,"operation":"stage","volumeRef":%q,"ownerRef":%q,"requestRef":%q,"idempotencyRef":%q,"sourceRef":%q,
"manifest":{"manifestRef":%q,"version":1,"generation":1,"expectedGeneration":0,"notBefore":"2026-01-01T00:00:00Z","rotateAt":"2026-01-02T00:00:00Z","expiresAt":"2026-01-03T00:00:00Z","entries":[{"name":%q,"type":"regular","claimedBytes":12,"claimedDigest":%q,"uid":1000,"gid":1000,"mode":"0400"}]},
"lifecycle":{"currentState":"absent","leaseCount":0},"assertions":{"redacted":true,"encrypted":true,"attested":true}}`,
		model.APIVersion, digest, digest, digest, digest, digest, digest, entryName, digest)
}

func runCLI(args []string, input string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestCapabilitiesNeverReadsStdin(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"capabilities"}, panicReader{}, &stdout, &stderr); code != 0 {
		t.Fatalf("unexpected exit %d: %s", code, stderr.String())
	}
	if !allControlsFalse(t, stdout.Bytes()) {
		t.Fatal("a capability control was enabled")
	}
}

func TestValidateAndPlanDoNotEchoNamesOrRefs(t *testing.T) {
	input := cliDocument("do-not-echo-marker")
	for _, command := range []string{"validate", "plan"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runCLI([]string{command}, input)
			if code != 0 {
				t.Fatalf("unexpected exit %d: %s", code, stderr)
			}
			if strings.Contains(stdout, "do-not-echo-marker") || strings.Contains(stdout, strings.Repeat("b", 64)) {
				t.Fatal("output echoed request metadata")
			}
			if strings.Contains(stdout, `"verified"`) {
				t.Fatal("output represented assertions as verified")
			}
			if !allControlsFalse(t, []byte(stdout)) {
				t.Fatal("a control was enabled")
			}
		})
	}
}

func TestInvalidInputUsesGenericNonEchoingError(t *testing.T) {
	input := strings.Replace(cliDocument("safe"), `"sourceRef":`, `"plaintext":"TOP-SECRET-MARKER","sourceRef":`, 1)
	code, stdout, stderr := runCLI([]string{"plan"}, input)
	if code == 0 || stdout != "" {
		t.Fatal("invalid input unexpectedly succeeded")
	}
	if strings.Contains(stderr, "TOP-SECRET-MARKER") || strings.Contains(stderr, "plaintext") {
		t.Fatal("error echoed rejected input")
	}
	if !strings.Contains(stderr, `"code":"invalid-input"`) {
		t.Fatal("missing generic error code")
	}
}

func TestCommandsAreStdinOnlyAndUsageErrorsDoNotRead(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"plan", "unexpected-argument"}, panicReader{}, &stdout, &stderr); code == 0 {
		t.Fatal("positional input was accepted")
	}
	if !strings.Contains(stderr.String(), `"code":"invalid-usage"`) {
		t.Fatal("missing generic usage error")
	}
}

func TestLocaleParity(t *testing.T) {
	input := cliDocument("safe")
	enCode, enOut, enErr := runCLI([]string{"--locale", LocaleEnglish, "plan"}, input)
	zhCode, zhOut, zhErr := runCLI([]string{"--locale", LocaleChinese, "plan"}, input)
	if enCode != 0 || zhCode != 0 {
		t.Fatalf("locale run failed: en=%s zh=%s", enErr, zhErr)
	}
	var english map[string]any
	var chinese map[string]any
	if err := json.Unmarshal([]byte(enOut), &english); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(zhOut), &chinese); err != nil {
		t.Fatal(err)
	}
	stripLocalizedFields(english)
	stripLocalizedFields(chinese)
	if !reflect.DeepEqual(english, chinese) {
		t.Fatal("locales changed semantic output")
	}
	if !strings.Contains(zhOut, "所有外部效果皆已停用") || !strings.Contains(enOut, "All external effects are disabled") {
		t.Fatal("localized diagnostics are missing")
	}
}

func TestPlanOutputIsDeterministic(t *testing.T) {
	input := cliDocument("safe")
	firstCode, first, firstErr := runCLI([]string{"plan"}, input)
	secondCode, second, secondErr := runCLI([]string{"plan"}, input)
	if firstCode != 0 || secondCode != 0 {
		t.Fatalf("plan failed: %s %s", firstErr, secondErr)
	}
	if first != second {
		t.Fatal("identical requests produced different output")
	}
}

func TestUnsupportedLocaleIsGeneric(t *testing.T) {
	code, stdout, stderr := runCLI([]string{"--locale", "invalid", "capabilities"}, "ignored")
	if code == 0 || stdout != "" || !strings.Contains(stderr, `"code":"invalid-usage"`) {
		t.Fatal("unsupported locale was not rejected generically")
	}
}

func allControlsFalse(t *testing.T, output []byte) bool {
	t.Helper()
	var decoded struct {
		Controls map[string]bool `json:"controls"`
	}
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Controls) != 11 {
		t.Fatalf("unexpected control count: %d", len(decoded.Controls))
	}
	for _, enabled := range decoded.Controls {
		if enabled {
			return false
		}
	}
	return true
}

func stripLocalizedFields(output map[string]any) {
	delete(output, "locale")
	if diagnostics, ok := output["diagnostics"].([]any); ok {
		for _, item := range diagnostics {
			if diagnostic, ok := item.(map[string]any); ok {
				delete(diagnostic, "message")
			}
		}
	}
}
